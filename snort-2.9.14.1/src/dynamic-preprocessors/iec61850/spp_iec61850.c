/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 * Author: Chamara Devanarayana
 *
 * Dynamic preprocessor for the MMS protocol
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <string.h>

#include "sf_types.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_plugin_api.h"
#include "snort_debug.h"
#include "mempool.h"

#include "preprocids.h"
#include "spp_iec61850.h"


#include "iec61850_paf.h"
#include "iec61850_reassembly.h"


#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats iec61850PerfStats;
#endif

#ifdef DUMP_BUFFER
#include "iec61850_buffer_dump.h"
void dumpBufferInit(void);
#endif

#ifdef SNORT_RELOAD
#include "appdata_adjuster.h"
static APPDATA_ADJUSTER *ada;
#endif

#ifdef REG_TEST
#include "reg_test.h"
#endif

const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 1;
const int BUILD_VERSION = 1;
const char *PREPROC_NAME = "SF_IEC61850";

#define SetupIEC61850 DYNAMIC_PREPROC_SETUP

/* Preprocessor config objects */
static tSfPolicyUserContextId iec61850_context_id = NULL;
static iec61850_config_t *iec61850_eval_config = NULL;

static MemPool *iec61850_mempool = NULL;


/* Target-based app ID */
#ifdef TARGET_BASED
int16_t iec61850_app_id = SFTARGET_UNKNOWN_PROTOCOL;
#endif

/* Prototypes */
static void IEC61850Init(struct _SnortConfig *, char *);
static inline void IEC61850OneTimeInit(struct _SnortConfig *);
static inline iec61850_config_t *IEC61850PerPolicyInit(struct _SnortConfig *, tSfPolicyUserContextId);
static void IEC61850RegisterPerPolicyCallbacks(struct _SnortConfig *, iec61850_config_t *);
static boolean IEC61850GlobalIsEnabled(tSfPolicyUserContextId context_id);
static void IEC61850InitializeMempool(tSfPolicyUserContextId context_id);
static int IEC61850IsEnabled(struct _SnortConfig *sc, tSfPolicyUserContextId context_id,
            tSfPolicyId policy_id, void *data);

static void ProcessIEC61850(void *, void *);

#ifdef SNORT_RELOAD
static void IEC61850Reload(struct _SnortConfig *, char *, void **);
static int IEC61850ReloadVerify(struct _SnortConfig *, void *);
static void * IEC61850ReloadSwap(struct _SnortConfig *, void *);
static void IEC61850ReloadSwapFree(void *);
//static boolean IEC61850ReloadAdjustFunc(bool idle, tSfPolicyId raPolicyId, void *userData);
#endif


static void _addPortsToStreamFilter(struct _SnortConfig *, iec61850_config_t *, tSfPolicyId);
#ifdef TARGET_BASED
static void _addServicesToStreamFilter(struct _SnortConfig *, tSfPolicyId);
#endif

static void IEC61850FreeConfig(tSfPolicyUserContextId context_id);
static void FreeIEC61850Data(void *);
static int IEC61850CheckConfig(struct _SnortConfig *);
static void IEC61850CleanExit(int, void *);

static void ParseIEC61850Args(struct _SnortConfig *, iec61850_config_t *, char *);
static void PrintIEC61850Config(iec61850_config_t *config);

static int IEC61850PortCheck(iec61850_config_t *config, SFSnortPacket *packet);
static MemBucket * IEC61850CreateSessionData(SFSnortPacket *);

static size_t IEC61850MemInUse();

/* Default memcap is defined as MAX_TCP_SESSIONS * .05 * 20 bytes */
#define IEC61850_DEFAULT_MEMCAP (256 * 1024)

/* Register init callback */
void SetupIEC61850(void)
{
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("mms", IEC61850Init);

#else
    _dpd.registerPreproc("mms", IEC61850Init, IEC61850Reload,
    		IEC61850ReloadVerify, IEC61850ReloadSwap, IEC61850ReloadSwapFree);
#endif
#ifdef DUMP_BUFFER
    _dpd.registerBufferTracer(getIEC61850Buffers, IEC61850_BUFFER_DUMP_FUNC);
#endif
}

#ifdef SNORT_RELOAD
static bool IEC61850ReloadAdjustFunc(bool idle, tSfPolicyId raPolicyId, void *userData)
{
    unsigned int max_sessions;
    unsigned maxwork = idle ? 512 : 32;

    if (ada_reload_adjust_func(idle, raPolicyId, userData))
    {
       //check if mempool is being deleted or just resized
       if (IEC61850GlobalIsEnabled(iec61850_context_id))
       {
#ifdef REG_TEST
            if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
            {
                printf("IEC61850-reload mempool-before: %zu %zu %zu\n", iec61850_mempool->max_memory, iec61850_mempool->used_memory, iec61850_mempool->free_memory);
            }
#endif
           //if it is being resized then change the mepool size
            iec61850_config_t *default_config = (iec61850_config_t*)sfPolicyUserDataGetDefault(iec61850_context_id);
            if (default_config == NULL)//shouldn't be possible
                return false;
            max_sessions = default_config->memcap / sizeof(iec61850_session_data_t);

            maxwork = mempool_prune_freelist(iec61850_mempool, max_sessions * sizeof(iec61850_session_data_t), maxwork);
            if (maxwork)
                mempool_setObjectSize(iec61850_mempool, max_sessions, sizeof(iec61850_session_data_t));

#ifdef REG_TEST
        if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
        {
            printf("IEC61850-reload mempool-after: %zu %zu %zu\n", iec61850_mempool->max_memory, iec61850_mempool->used_memory, iec61850_mempool->free_memory);
        }
#endif
       }
       else
       {
           //otherwise make sure that the mempool is empty and then delete the mempool
            maxwork = mempool_prune_freelist(iec61850_mempool, 0, maxwork);
            if (maxwork)
            {
#ifdef REG_TEST
                if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
                {
                    printf("IEC61850-reload before-destroy: %zu %zu %zu\n", iec61850_mempool->max_memory, iec61850_mempool->used_memory, iec61850_mempool->free_memory);
                }
#endif
#ifdef REG_TEST
                int retDestroy =
#endif
                mempool_destroy(iec61850_mempool);
                iec61850_mempool = NULL;
                ada_delete(ada);
                ada = NULL;
#ifdef REG_TEST
                if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
                {
                    printf("IEC61850-reload after-destroy: %d %p %p\n", retDestroy, iec61850_mempool, ada);
                }
#endif
            }
       }

       return maxwork;
    }

    return false;
}
#endif



static void IEC61850RegisterPortsWithSession( struct _SnortConfig *sc, iec61850_config_t *policy )
{

    uint32_t port;

        for ( port = 0; port < MAX_PORTS; port++ )
        {
            if( isPortEnabled( policy->ports, port ) )
                _dpd.sessionAPI->enable_preproc_for_port( sc, PP_IEC61850, PROTO_BIT__TCP | PROTO_BIT__UDP, port );
        }

}

#ifdef REG_TEST
static inline void PrintIEC61850Size(void)
{
    _dpd.logMsg("\nIEC61850 Session Size: %lu\n", (long unsigned int)sizeof(iec61850_session_data_t));
}
#endif

/* Allocate memory for preprocessor config, parse the args, set up callbacks */
static void IEC61850Init(struct _SnortConfig *sc, char *argp)
{
    iec61850_config_t *iec61850_policy = NULL;

    if (iec61850_context_id == NULL)
    	IEC61850OneTimeInit(sc);

    iec61850_policy = IEC61850PerPolicyInit(sc, iec61850_context_id);

    ParseIEC61850Args(sc, iec61850_policy, argp);

#ifdef REG_TEST
    PrintIEC61850Size();
#endif


    PrintIEC61850Config(iec61850_policy);

    IEC61850InitializeMempool(iec61850_context_id);

    IEC61850RegisterPortsWithSession( sc, iec61850_policy );

    IEC61850RegisterPerPolicyCallbacks(sc, iec61850_policy);

#ifdef DUMP_BUFFER
        dumpBufferInit();
#endif
}

static inline void IEC61850OneTimeInit(struct _SnortConfig *sc)
{
    /* context creation & error checking */
    iec61850_context_id = sfPolicyConfigCreate();
    if (iec61850_context_id == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory for "
                                        "IEC61850 config.\n");
    }

    if (_dpd.streamAPI == NULL)
    {
        DynamicPreprocessorFatalMessage("SetupIEC61850(): The Stream preprocessor "
                                        "must be enabled.\n");
    }

    /* callback registration */
    _dpd.addPreprocConfCheck(sc, IEC61850CheckConfig);
    _dpd.addPreprocExit(IEC61850CleanExit, NULL, PRIORITY_LAST, PP_IEC61850);

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("iec61850", (void *)&iec61850PerfStats, 0, _dpd.totalPerfStats, NULL);
#endif

    /* Set up target-based app id */
#ifdef TARGET_BASED
    iec61850_app_id = _dpd.findProtocolReference("iec61850");
    if (iec61850_app_id == SFTARGET_UNKNOWN_PROTOCOL)
    	iec61850_app_id = _dpd.addProtocolReference("iec61850");
    // register with session to handle application
    _dpd.sessionAPI->register_service_handler( PP_IEC61850, iec61850_app_id );
#endif
}

/* Responsible for allocating a IEC61850 policy. Never returns NULL. */
static inline iec61850_config_t * IEC61850PerPolicyInit(struct _SnortConfig *sc, tSfPolicyUserContextId context_id)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);
    iec61850_config_t *iec61850_policy = NULL;

    /* Check for existing policy & bail if found */
    sfPolicyUserPolicySet(context_id, policy_id);
    iec61850_policy = (iec61850_config_t *)sfPolicyUserDataGetCurrent(context_id);
    if (iec61850_policy != NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d): IEC61850 preprocessor can only be "
                "configured once.\n", *_dpd.config_file, *_dpd.config_line);
    }

    /* Allocate new policy */
    iec61850_policy = (iec61850_config_t *)calloc(1, sizeof(iec61850_config_t));
    if (!iec61850_policy)
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory for "
                                        "iec61850 preprocessor configuration.\n");
    }

    sfPolicyUserDataSetCurrent(context_id, iec61850_policy);

    return iec61850_policy;
}

static boolean IEC61850GlobalIsEnabled(tSfPolicyUserContextId context_id)
{
    return sfPolicyUserDataIterate(NULL, context_id, IEC61850IsEnabled) != 0;
}

static void IEC61850InitializeMempool(tSfPolicyUserContextId context_id)
{
    unsigned int max_sessions;
    iec61850_config_t *default_config = (iec61850_config_t*)sfPolicyUserDataGetDefault(context_id);
    if (default_config && IEC61850GlobalIsEnabled(context_id))
    {
#ifdef SNORT_RELOAD
#ifdef REG_TEST
        if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
        {
            printf("IEC61850-reload init-before: %p %p\n", iec61850_mempool, ada);
        }

#endif
#endif
        if (iec61850_mempool == NULL)
        {
            max_sessions = default_config->memcap / sizeof(iec61850_session_data_t);

            iec61850_mempool = (MemPool *)malloc(sizeof(MemPool));
            if (!iec61850_mempool)
            {
                DynamicPreprocessorFatalMessage("IEC61850InitializeMempool: "
                        "Unable to allocate memory for iec61850 mempool\n");
            }
            //mempool is set to 0 in init
            if (mempool_init(iec61850_mempool, max_sessions, sizeof(iec61850_session_data_t)))
            {
                DynamicPreprocessorFatalMessage("Unable to allocate IEC61850 mempool.\n");
            }
        }

#ifdef SNORT_RELOAD
        if (ada == NULL)
        {
            ada = ada_init(IEC61850MemInUse, PP_IEC61850, (size_t) default_config->memcap);
            if (ada == NULL)
                DynamicPreprocessorFatalMessage("Unable to allocate IEC61850 ada.\n");
        }

#ifdef REG_TEST
        if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
        {
            printf("IEC61850-reload init-after: %p %p\n", iec61850_mempool, ada);
        }

#endif
#endif
    }
}

static void IEC61850RegisterPerPolicyCallbacks(struct _SnortConfig *sc, iec61850_config_t *iec61850_policy)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);

    /* Callbacks should be avoided if the preproc is disabled. */
    if (iec61850_policy->disabled)
        return;

    _dpd.addPreproc(sc, ProcessIEC61850, PRIORITY_APPLICATION, PP_IEC61850, PROTO_BIT__TCP|PROTO_BIT__UDP);
    _addPortsToStreamFilter(sc, iec61850_policy, policy_id);
#ifdef TARGET_BASED
    _addServicesToStreamFilter(sc, policy_id);
    IEC61850AddServiceToPaf(sc, iec61850_app_id, policy_id);
#endif
    IEC61850AddPortsToPaf(sc, iec61850_policy, policy_id);
//
//    _dpd.preprocOptRegister(sc, DNP3_FUNC_NAME, DNP3FuncInit, DNP3FuncEval, free, NULL, NULL, NULL, NULL);
//    _dpd.preprocOptRegister(sc, DNP3_OBJ_NAME, DNP3ObjInit, DNP3ObjEval, free, NULL, NULL, NULL, NULL);
//    _dpd.preprocOptRegister(sc, DNP3_IND_NAME, DNP3IndInit, DNP3IndEval, free, NULL, NULL, NULL, NULL);
//    _dpd.preprocOptRegister(sc, DNP3_DATA_NAME, DNP3DataInit, DNP3DataEval, free, NULL, NULL, NULL, NULL);
}

static void ParseSinglePort(iec61850_config_t *config, char *token)
{
    /* single port number */
    char *endptr;
    unsigned long portnum = _dpd.SnortStrtoul(token, &endptr, 10);

    if ((*endptr != '\0') || (portnum >= MAX_PORTS))
    {
        DynamicPreprocessorFatalMessage("%s(%d): Bad iec61850 port number: %s\n"
                      "Port number must be an integer between 0 and 65535.\n",
                      *_dpd.config_file, *_dpd.config_line, token);
    }

    /* Good port number! */
    config->ports[PORT_INDEX(portnum)] |= CONV_PORT(portnum);
}

static void ParseIEC61850Args(struct _SnortConfig *sc, iec61850_config_t *config, char *args)
{
    char *saveptr;
    char *token;
    int index = 0;
    /* Set defaults */
    config->memcap = IEC61850_DEFAULT_MEMCAP;
    config->ports[PORT_INDEX(IEC61850_PORT)] |= CONV_PORT(IEC61850_PORT);


    /* No arguments? Stick with defaults. */
    if (args == NULL)
        return;

    token = strtok_r(args, " ,", &saveptr);
    while (token != NULL)
    {
        if (strcmp(token, IEC61850_PORTS_KEYWORD) == 0)
        {
            unsigned nPorts = 0;

            /* Un-set the default port */
            config->ports[PORT_INDEX(IEC61850_PORT)] = 0;

            /* Parse ports */
            token = strtok_r(NULL, " ,", &saveptr);

            if (token == NULL)
            {
                DynamicPreprocessorFatalMessage("%s(%d): Missing argument for "
                    "IEC61850 preprocessor 'ports' option.\n",
                    *_dpd.config_file, *_dpd.config_line);
            }

            if (isdigit(token[0]))
            {
                ParseSinglePort(config, token);
                nPorts++;
            }
            else if (*token == '{')
            {
                /* list of ports */
                token = strtok_r(NULL, " ,", &saveptr);
                while (token != NULL && *token != '}')
                {
                    ParseSinglePort(config, token);
                    nPorts++;
                    token = strtok_r(NULL, " ,", &saveptr);
                }
            }

            else
            {
                nPorts = 0;
            }
            if ( nPorts == 0 )
            {
                DynamicPreprocessorFatalMessage("%s(%d): Bad IEC61850 'ports' argument: '%s'\n"
                              "Argument to IEC61850 'ports' must be an integer, or a list "
                              "enclosed in { } braces.\n",
                              *_dpd.config_file, *_dpd.config_line, token);
            }
        }
        else if (strcmp(token, IEC61850_MEMCAP_KEYWORD) == 0)
        {
            uint32_t memcap;
            char *endptr;

            /* Parse memcap */
            token = strtok_r(NULL, " ", &saveptr);

            /* In a multiple policy scenario, the memcap from the default policy
               overrides the memcap in any targeted policies. */
            if (_dpd.getParserPolicy(sc) != _dpd.getDefaultPolicy())
            {
                iec61850_config_t *default_config =
                    (iec61850_config_t *)sfPolicyUserDataGet(iec61850_context_id,
                                                         _dpd.getDefaultPolicy());

                if (!default_config || default_config->memcap == 0)
                {
                    DynamicPreprocessorFatalMessage("%s(%d): IEC61850 'memcap' must be "
                        "configured in the default config.\n",
                        *_dpd.config_file, *_dpd.config_line);
                }

                config->memcap = default_config->memcap;
            }
            else
            {
                if (token == NULL)
                {
                    DynamicPreprocessorFatalMessage("%s(%d): Missing argument for IEC61850 "
                        "preprocessor 'memcap' option.\n",
                        *_dpd.config_file, *_dpd.config_line);
                }

                memcap = _dpd.SnortStrtoul(token, &endptr, 10);

                if ((token[0] == '-') || (*endptr != '\0') ||
                    (memcap < MIN_IEC61850_MEMCAP) || (memcap > MAX_IEC61850_MEMCAP))
                {
                    DynamicPreprocessorFatalMessage("%s(%d): Bad IEC61850 'memcap' argument: %s\n"
                              "Argument to IEC61850 'memcap' must be an integer between "
                              "%d and %d.\n", *_dpd.config_file, *_dpd.config_line,
                              token, MIN_IEC61850_MEMCAP, MAX_IEC61850_MEMCAP);
                }

                config->memcap = memcap;
            }
        }

        else if (strcmp(token, IEC61850_DISABLED_KEYWORD) == 0)
        {
            /* TODO: if disabled, check that no other stuff is turned on except memcap */
            config->disabled = 1;
        }
        else if (strcmp(token, "change") == 0)
		{
        	int count =0;

        	//add the the objects to be modified
        	while(count<3 ) {
        	token = strtok_r(NULL, " ,", &saveptr);

        	 if (token == NULL)
        	             {
        	                 DynamicPreprocessorFatalMessage("%s(%d): Missing argument for "
        	                     "IEC61850 preprocessor 'change' option.\n",
        	                     *_dpd.config_file, *_dpd.config_line);
        	             }
        	 else{
        		 switch(count){
        		 	 	 	 	 case(0):
								    if((config->values_to_alter[index]).domainIDAndItemID)
									g_string_free((config->values_to_alter[index]).domainIDAndItemID,1);
        		 	 	 	 	 	(config->values_to_alter[index]).domainIDAndItemID = g_string_new(token);
        		 	 	 	 	(config->values_to_alter[index]).domainIDAndItemID =g_string_erase((config->values_to_alter[index]).domainIDAndItemID,0,1);
        		 	 	 	 (config->values_to_alter[index]).domainIDAndItemID =g_string_erase((config->values_to_alter[index]).domainIDAndItemID,(config->values_to_alter[index]).domainIDAndItemID->len-1,1);

        		 	 	 	 	break;
        						 case(1):
									if((config->values_to_alter[index]).structure)
									g_string_free((config->values_to_alter[index]).structure,1);
		        		 	 	 	(config->values_to_alter[index]).structure = g_string_new(token);
		        		 	 	 	(config->values_to_alter[index]).structure =g_string_erase((config->values_to_alter[index]).structure,0,1);
		        		 	 	 	(config->values_to_alter[index]).structure =g_string_erase((config->values_to_alter[index]).structure,(config->values_to_alter[index]).structure->len-1,1);
		        		 	 	 	char delim = '-';
		        		 	 	 	char *string = (char *)(config->values_to_alter[index]).structure->str;
		        		 	 	 	char *tokenizedStr = strtok(string,&delim);
		        		 	 	 	int i=1;
		        		 	 	 	while(tokenizedStr!=NULL)
		        		 	 	 	{
		        		 	 	 		(config->values_to_alter[index]).intStruct[i] = strtol(tokenizedStr,NULL,10);
		        		 	 	 		tokenizedStr = strtok(NULL,&delim);
		        		 	 	 		i++;
		        		 	 	 	}
		        		 	 	 	break;
		   						 case(2):
									if((config->values_to_alter[index]).newVal)
										g_string_free((config->values_to_alter[index]).newVal,1);
		   						 	 (config->values_to_alter[index]).newVal = g_string_new(token);
		   						 	(config->values_to_alter[index]).newVal =g_string_erase((config->values_to_alter[index]).newVal,0,1);
		   						 	(config->values_to_alter[index]).newVal =g_string_erase((config->values_to_alter[index]).newVal,(config->values_to_alter[index]).newVal->len-1,1);
		   						 	 break;

        						 default:
        							 break;


        	 }
        		 count++;
        	 }
        	}

        	index++;
        	config->numAlteredVal = index;
		}

        else
        {
            DynamicPreprocessorFatalMessage("%s(%d): Failed to parse iec61850 argument: "
                "%s\n", *_dpd.config_file, *_dpd.config_line,  token);
        }
        token = strtok_r(NULL, " ,", &saveptr);
    }
}

/* Print a IEC61850 config */
static void PrintIEC61850Config(iec61850_config_t *config)
{
    int index, newline = 1;

    if (config == NULL)
        return;

    _dpd.logMsg("IEC61850 config: \n");

    if (config->disabled)
        _dpd.logMsg("    IEC61850: INACTIVE\n");

    _dpd.logMsg("    Memcap: %d\n", config->memcap);


    _dpd.logMsg("    Ports:\n");

    /* Loop through port array & print, 5 ports per line */
    for (index = 0; index < MAX_PORTS; index++)
    {
        if (config->ports[PORT_INDEX(index)] & CONV_PORT(index))
        {
            _dpd.logMsg("\t%d", index);
            if ( !((newline++) % 5) )
            {
                _dpd.logMsg("\n");
            }
        }
    }
    _dpd.logMsg("\n");
}





/* Main runtime entry point */
static void ProcessIEC61850(void *ipacketp, void *contextp)
{
    SFSnortPacket *packetp = (SFSnortPacket *)ipacketp;
    MemBucket *tmp_bucket = NULL;
    iec61850_session_data_t *sessp = NULL;
    PROFILE_VARS;

    // preconditions - what we registered for work only on tcp
  //  assert((IsTCP(packetp)) &&
    //    packetp->payload && packetp->payload_size);

    /* If TCP, require that PAF flushes full PDUs first. */


    PREPROC_PROFILE_START(iec61850PerfStats);

    /* When pipelined IEC61850 PDUs appear in a single TCP segment or UDP packet,
       the detection engine caches the results of the rule options after
       evaluating on the first PDU. Setting this flag stops the caching. */
    packetp->flags |= FLAG_ALLOW_MULTIPLE_DETECT;

    /* Fetch me a preprocessor config to use with this VLAN/subnet/etc.! */
    iec61850_eval_config = sfPolicyUserDataGetCurrent(iec61850_context_id);

    /* Look for a previously-allocated session data. */
    tmp_bucket = _dpd.sessionAPI->get_application_data(packetp->stream_session, PP_IEC61850);

    if (tmp_bucket == NULL)
    {
        /* No existing session. Check those ports. */
        if (IEC61850PortCheck(iec61850_eval_config, packetp) != IEC61850_OK)
        {
            PREPROC_PROFILE_END(iec61850PerfStats);
            return;
        }

        /* Create session data and attach it to the Stream session */
        tmp_bucket = IEC61850CreateSessionData(packetp);
        sessp = (iec61850_session_data_t *) tmp_bucket->data;
        sessp->requestList = NULL;
        sessp->request_rdata = g_new0(iec61850_reassembly_data_t,1);
        sessp->responce_rdata = g_new0(iec61850_reassembly_data_t,1);
       // sessp->common_rdata = g_new0(iec61850_reassembly_data_t,1);
        sessp->request_rdata->buffer = g_new0(char,1500);
        sessp->request_rdata->buflen = 0;
        sessp->request_rdata->maxLen = 1500;
        sessp->responce_rdata->buffer = g_new0(char,1500);
        sessp->responce_rdata->buflen = 0;
        sessp->responce_rdata->maxLen = 1500;
        sessp->hashTable = g_hash_table_new_full(g_int_hash, g_int_equal,NULL,NULL);
        sessp->request_rdata->state = IEC61850_REASSEMBLY_STATE__IDLE;
        sessp->responce_rdata->state = IEC61850_REASSEMBLY_STATE__IDLE;
      //  sessp->common_rdata->buffer = g_new0(char,1500);
       // sessp->common_rdata->buflen = 0;
       // sessp->common_rdata->maxLen = 1500;

        if (tmp_bucket == NULL)
        {
            PREPROC_PROFILE_END(iec61850PerfStats);
            return;
        }
    }
    else
    sessp = (iec61850_session_data_t *) tmp_bucket->data;



//    /* Set reassembly direction */
//       if (*(packetp->payload +20) == 0xa1)
//           sessp->direction = RESPONSE_PDU; //mean a request packet
//       else
//           sessp->direction = REQUEST_PDU; //mean a response packet
    	guint length;
        /* Single PDU. PAF already split them up into separate pseudo-packets. */
        IEC61850FullReassembly(iec61850_eval_config, sessp, packetp,(uint8_t *)packetp->payload, packetp->payload_size);




    /* That's the end! */
    PREPROC_PROFILE_END(iec61850PerfStats);
}

/* Check ports & services */
static int IEC61850PortCheck(iec61850_config_t *config, SFSnortPacket *packet)
{
#ifdef TARGET_BASED
    int16_t app_id = _dpd.sessionAPI->get_application_protocol_id(packet->stream_session);

    /* call to get_application_protocol_id gave an error */
    if (app_id == SFTARGET_UNKNOWN_PROTOCOL)
        return IEC61850_FAIL;

    /* this is positively identified as something non-iec61850 */
    if (app_id && (app_id != iec61850_app_id))
        return IEC61850_FAIL;

    /* this is identified as iec61850 */
    if (app_id == iec61850_app_id)
        return IEC61850_OK;

    /* fall back to port check */
#endif

    if (config->ports[PORT_INDEX(packet->src_port)] & CONV_PORT(packet->src_port))
        return IEC61850_OK;

    if (config->ports[PORT_INDEX(packet->dst_port)] & CONV_PORT(packet->dst_port))
        return IEC61850_OK;

    return IEC61850_FAIL;
}




static MemBucket * IEC61850CreateSessionData(SFSnortPacket *packet)
{
    MemBucket *tmp_bucket = NULL;
    iec61850_session_data_t *data = NULL;

    /* Sanity Check */
    if (!packet || !packet->stream_session)
        return NULL;

    /* data = (iec61850_session_data_t *)calloc(1, sizeof(iec61850_session_data_t)); */

    tmp_bucket = mempool_alloc(iec61850_mempool);
    if (!tmp_bucket)
    {
        /* Mempool was full, don't process this session. */
        static unsigned int times_mempool_alloc_failed = 0;

        /* Print a message, but only every 1000 times.
                      Don't want to flood the log if there's a lot of IEC61850 traffic. */
        if (times_mempool_alloc_failed % 1000 == 0)
        {
            _dpd.logMsg("WARNING: IEC61850 memcap exceeded.\n");
        }
        times_mempool_alloc_failed++;

        return NULL;
    }

    data = (iec61850_session_data_t *)tmp_bucket->data;


    if (!data)
        return NULL;
    data->requestList=NULL;
    data->request_rdata=NULL;
    data->responce_rdata=NULL;

    /* Attach to Stream session */
    _dpd.sessionAPI->set_application_data(packet->stream_session, PP_IEC61850,
        tmp_bucket, FreeIEC61850Data);
#ifdef SNORT_RELOAD
    ada_add(ada, tmp_bucket, packet->stream_session);
#endif

    /* Not sure when this reference counting stuff got added to the old preprocs */
    data->policy_id = _dpd.getNapRuntimePolicy();
    data->context_id = iec61850_context_id;
    ((iec61850_config_t *)sfPolicyUserDataGetCurrent(iec61850_context_id))->ref_count++;

    return tmp_bucket;
}


/* Reload functions */
#ifdef SNORT_RELOAD
/* Almost like IEC61850Init, but not quite. */
static void IEC61850Reload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId iec61850_swap_context_id = (tSfPolicyUserContextId)*new_config;
    iec61850_config_t *iec61850_policy = NULL;

    if (iec61850_swap_context_id == NULL)
    {
        iec61850_swap_context_id = sfPolicyConfigCreate();
        if (iec61850_swap_context_id == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate memory "
                                            "for IEC61850 config.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            DynamicPreprocessorFatalMessage("SetupIEC61850(): The Stream preprocessor "
                                            "must be enabled.\n");
        }
        *new_config = (void *)iec61850_swap_context_id;
    }

    iec61850_policy = IEC61850PerPolicyInit(sc, iec61850_swap_context_id);

    ParseIEC61850Args(sc, iec61850_policy, args);

    IEC61850InitializeMempool(iec61850_swap_context_id);

    PrintIEC61850Config(iec61850_policy);

    IEC61850RegisterPortsWithSession( sc, iec61850_policy );

    IEC61850RegisterPerPolicyCallbacks(sc, iec61850_policy);
}

/* Check that Stream is still running, and that the memcap didn't change. */
static int IEC61850ReloadVerify(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId iec61850_swap_context_id = (tSfPolicyUserContextId)swap_config;
    iec61850_config_t *current_default_config, *new_default_config;

    if ((iec61850_context_id == NULL) || (iec61850_swap_context_id == NULL))
        return 0;

    current_default_config =
        (iec61850_config_t *)sfPolicyUserDataGet(iec61850_context_id, _dpd.getDefaultPolicy());

    new_default_config =
        (iec61850_config_t *)sfPolicyUserDataGet(iec61850_swap_context_id, _dpd.getDefaultPolicy());

    /* Sanity check. Shouldn't be possible. */
    if (current_default_config == NULL)
        return 0;

    if (new_default_config == NULL)
    {
        _dpd.errMsg("IEC61850 reload: Changing the IEC61850 configuration "
            "requires a restart.\n");
        return -1;
    }

    //is IEC61850 enabled?
    bool wasEnabled = sfPolicyUserDataIterate(sc, iec61850_context_id, IEC61850IsEnabled) != 0;
    bool isEnabled  = sfPolicyUserDataIterate(sc, iec61850_swap_context_id, IEC61850IsEnabled) != 0;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);
    if (wasEnabled && isEnabled)
    {
        if (new_default_config->memcap < current_default_config->memcap)
        {
            ada_set_new_cap(ada, (size_t) new_default_config->memcap);
            _dpd.reloadAdjustRegister(sc, "IEC61850", policy_id, IEC61850ReloadAdjustFunc, (void *) ada, NULL);
        }
        else if (new_default_config->memcap > current_default_config->memcap)
        {
            unsigned int max_sessions = new_default_config->memcap / sizeof(iec61850_session_data_t);
#ifdef REG_TEST
            if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
            {
                printf("IEC61850-reload mempool-before: %zu %zu %zu\n", iec61850_mempool->max_memory, iec61850_mempool->used_memory, iec61850_mempool->free_memory);
            }
#endif
            mempool_setObjectSize(iec61850_mempool, max_sessions, sizeof(iec61850_session_data_t));
#ifdef REG_TEST
            if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
            {
                printf("IEC61850-reload mempool-after: %zu %zu %zu\n", iec61850_mempool->max_memory, iec61850_mempool->used_memory, iec61850_mempool->free_memory);
            }
#endif
        }
    }
    else if (wasEnabled)
    {
        ada_set_new_cap(ada, 0);
        _dpd.reloadAdjustRegister(sc, "IEC61850", policy_id, IEC61850ReloadAdjustFunc, (void *) ada, NULL);
    }


    /* Did stream5 get turned off? */
    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("SetupIEC61850(): The Stream preprocessor must be enabled.\n");
        return -1;
    }

    return 0;
}

static int IEC61850FreeUnusedConfigPolicy(
    tSfPolicyUserContextId context_id,
    tSfPolicyId policy_id,
    void *data
    )
{
    iec61850_config_t *iec61850_config = (iec61850_config_t *)data;

    /* do any housekeeping before freeing iec61850 config */
    if (iec61850_config->ref_count == 0)
    {
        sfPolicyUserDataClear(context_id, policy_id);
        free(iec61850_config);
    }

    return 0;
}

static void * IEC61850ReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId iec61850_swap_context_id = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_context_id = iec61850_context_id;

    if (iec61850_swap_context_id == NULL)
        return NULL;

    iec61850_context_id = iec61850_swap_context_id;

    sfPolicyUserDataFreeIterate(old_context_id, IEC61850FreeUnusedConfigPolicy);

    if (sfPolicyUserPolicyGetActive(old_context_id) == 0)
    {
        /* No more outstanding configs - free the config array */
        return (void *)old_context_id;
    }

    return NULL;
}

static void IEC61850ReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    IEC61850FreeConfig( (tSfPolicyUserContextId)data );
}
#endif

/* Stream filter functions */
static void _addPortsToStreamFilter(struct _SnortConfig *sc, iec61850_config_t *config, tSfPolicyId policy_id)
{
    if (config == NULL)
        return;

    if (_dpd.streamAPI)
    {
        uint32_t portNum;

        for (portNum = 0; portNum < MAX_PORTS; portNum++)
        {
            if(config->ports[(portNum/8)] & (1<<(portNum%8)))
            {
                //Add port the port
                _dpd.streamAPI->set_port_filter_status(
                    sc, IPPROTO_TCP, (uint16_t)portNum, PORT_MONITOR_SESSION, policy_id, 1);
                _dpd.streamAPI->set_port_filter_status(
                    sc, IPPROTO_UDP, (uint16_t)portNum, PORT_MONITOR_SESSION, policy_id, 1);
            }
        }
    }

}

#ifdef TARGET_BASED
static void _addServicesToStreamFilter(struct _SnortConfig *sc, tSfPolicyId policy_id)
{
    _dpd.streamAPI->set_service_filter_status(sc, iec61850_app_id, PORT_MONITOR_SESSION, policy_id, 1);
}
#endif

static int IEC61850FreeConfigPolicy(
    tSfPolicyUserContextId context_id,
    tSfPolicyId policy_id,
    void *data
    )
{
    iec61850_config_t *iec61850_config = (iec61850_config_t *)data;

    /* do any housekeeping before freeing iec61850_config */

    sfPolicyUserDataClear(context_id, policy_id);
    free(iec61850_config);
    return 0;
}

static void IEC61850FreeConfig(tSfPolicyUserContextId context_id)
{
    if (context_id == NULL)
        return;

    sfPolicyUserDataFreeIterate(context_id, IEC61850FreeConfigPolicy);
    sfPolicyConfigDelete(context_id);
}

static int IEC61850IsEnabled(struct _SnortConfig *sc, tSfPolicyUserContextId context_id,
            tSfPolicyId policy_id, void *data)
{
	iec61850_config_t *config = (iec61850_config_t *)data;

    if ((data == NULL) || config->disabled)
        return 0;

    return 1;
}

/* Check an individual policy */
static int IEC61850CheckPolicyConfig(
    struct _SnortConfig *sc,
    tSfPolicyUserContextId context_id,
    tSfPolicyId policy_id,
    void *data
    )
{
	iec61850_config_t *config = (iec61850_config_t *)data;

    _dpd.setParserPolicy(sc, policy_id);

    /* In a multiple-policy setting, the preprocessor can be turned on in
       a "disabled" state. In this case, we don't require Stream. */
    if (config->disabled)
        return 0;

    /* Otherwise, require Stream. */
    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("ERROR: IEC61850CheckPolicyConfig(): "
            "The Stream preprocessor must be enabled.\n");
        return -1;
    }
    return 0;
}

/* Check configs & set up mempool.
   Mempool stuff is in this function because we want to parse & check *ALL*
   of the configs before allocating a mempool. */
static int IEC61850CheckConfig(struct _SnortConfig *sc)
{
    int rval;

    /* Get default configuration */
    iec61850_config_t *default_config =
        (iec61850_config_t *)sfPolicyUserDataGetDefault(iec61850_context_id);

    if ( !default_config )
    {
        _dpd.errMsg(
            "ERROR: preprocessor iec61850 must be configured in the default policy.\n");
        return -1;
    }
    /* Check all individual configurations */
    if ((rval = sfPolicyUserDataIterate(sc, iec61850_context_id, IEC61850CheckPolicyConfig)))
        return rval;

    return 0;
}

static void IEC61850CleanExit(int signal, void *data)
{
    if (iec61850_context_id != NULL)
    {
        IEC61850FreeConfig(iec61850_context_id);
        iec61850_context_id = NULL;
    }

    if ((iec61850_mempool) && (mempool_destroy(iec61850_mempool) == 0))
    {
        free(iec61850_mempool);
        iec61850_mempool = 0;
    }

#ifdef SNORT_RELOAD
    ada_delete(ada);
    ada = NULL;
#endif
}

static void FreeIEC61850Data(void *bucket)
{
    MemBucket *tmp_bucket = (MemBucket *)bucket;
    iec61850_session_data_t *session;
    iec61850_config_t *config = NULL;

    if ((tmp_bucket == NULL) || (tmp_bucket->data == NULL))
        return;

    session = tmp_bucket->data;

    if (session->context_id != NULL)
    {
        config = (iec61850_config_t *)sfPolicyUserDataGet(session->context_id, session->policy_id);
    }

    if (config != NULL)
    {
        config->ref_count--;
        if ((config->ref_count == 0) &&
            (session->context_id != iec61850_context_id))
        {
            sfPolicyUserDataClear(session->context_id, session->policy_id);
            free(config);

            if (sfPolicyUserPolicyGetActive(session->context_id) == 0)
            {
                /* No more outstanding configs - free the config array */
                IEC61850FreeConfig(session->context_id);
            }
        }
    }

#ifdef SNORT_RELOAD
    ada_appdata_freed(ada, bucket);//iff tmp_bucket/bucket is freed
#endif
    mempool_free(iec61850_mempool, tmp_bucket);
}

static size_t IEC61850MemInUse()
{
    return iec61850_mempool->used_memory;
}

