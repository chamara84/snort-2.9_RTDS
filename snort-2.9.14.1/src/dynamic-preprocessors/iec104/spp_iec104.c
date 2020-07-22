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
 * Dynamic preprocessor for the IEC104 protocol
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
#include "spp_iec104.h"


#include "iec104_paf.h"
#include "iec104_reassembly.h"


#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats iec104PerfStats;
#endif

#ifdef DUMP_BUFFER
#include "iec104_buffer_dump.h"
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
const char *PREPROC_NAME = "SF_IEC104";

#define SetupIEC104 DYNAMIC_PREPROC_SETUP

/* Preprocessor config objects */
static tSfPolicyUserContextId iec104_context_id = NULL;
static iec104_config_t *iec104_eval_config = NULL;

static MemPool *iec104_mempool = NULL;


/* Target-based app ID */
#ifdef TARGET_BASED
int16_t iec104_app_id = SFTARGET_UNKNOWN_PROTOCOL;
#endif

/* Prototypes */
static void IEC104Init(struct _SnortConfig *, char *);
static inline void IEC104OneTimeInit(struct _SnortConfig *);
static inline iec104_config_t *IEC104PerPolicyInit(struct _SnortConfig *, tSfPolicyUserContextId);
static void IEC104RegisterPerPolicyCallbacks(struct _SnortConfig *, iec104_config_t *);
static boolean IEC104GlobalIsEnabled(tSfPolicyUserContextId context_id);
static void IEC104InitializeMempool(tSfPolicyUserContextId context_id);
static int IEC104IsEnabled(struct _SnortConfig *sc, tSfPolicyUserContextId context_id,
            tSfPolicyId policy_id, void *data);

static void ProcessIEC104(void *, void *);

#ifdef SNORT_RELOAD
static void IEC104Reload(struct _SnortConfig *, char *, void **);
static int IEC104ReloadVerify(struct _SnortConfig *, void *);
static void * IEC104ReloadSwap(struct _SnortConfig *, void *);
static void IEC104ReloadSwapFree(void *);
//static boolean IEC104ReloadAdjustFunc(bool idle, tSfPolicyId raPolicyId, void *userData);
#endif


static void _addPortsToStreamFilter(struct _SnortConfig *, iec104_config_t *, tSfPolicyId);
#ifdef TARGET_BASED
static void _addServicesToStreamFilter(struct _SnortConfig *, tSfPolicyId);
#endif

static void IEC104FreeConfig(tSfPolicyUserContextId context_id);
static void FreeIEC104Data(void *);
static int IEC104CheckConfig(struct _SnortConfig *);
static void IEC104CleanExit(int, void *);

static void ParseIEC104Args(struct _SnortConfig *, iec104_config_t *, char *);
static void PrintIEC104Config(iec104_config_t *config);

static int IEC104PortCheck(iec104_config_t *config, SFSnortPacket *packet);
static MemBucket * IEC104CreateSessionData(SFSnortPacket *);

static size_t IEC104MemInUse();

/* Default memcap is defined as MAX_TCP_SESSIONS * .05 * 20 bytes */
#define IEC104_DEFAULT_MEMCAP (256 * 1024)

/* Register init callback */
void SetupIEC104(void)
{
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("iec104", IEC104Init);
#else
    _dpd.registerPreproc("iec104", IEC104Init, IEC104Reload,
    		IEC104ReloadVerify, IEC104ReloadSwap, IEC104ReloadSwapFree);
#endif
#ifdef DUMP_BUFFER
    _dpd.registerBufferTracer(getIEC104Buffers, IEC104_BUFFER_DUMP_FUNC);
#endif
}

#ifdef SNORT_RELOAD
static bool IEC104ReloadAdjustFunc(bool idle, tSfPolicyId raPolicyId, void *userData)
{
    unsigned int max_sessions;
    unsigned maxwork = idle ? 512 : 32;

    if (ada_reload_adjust_func(idle, raPolicyId, userData))
    {
       //check if mempool is being deleted or just resized
       if (IEC104GlobalIsEnabled(iec104_context_id))
       {
#ifdef REG_TEST
            if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
            {
                printf("IEC104-reload mempool-before: %zu %zu %zu\n", iec104_mempool->max_memory, iec104_mempool->used_memory, iec104_mempool->free_memory);
            }
#endif
           //if it is being resized then change the mepool size
            iec104_config_t *default_config = (iec104_config_t*)sfPolicyUserDataGetDefault(iec104_context_id);
            if (default_config == NULL)//shouldn't be possible
                return false;
            max_sessions = default_config->memcap / sizeof(iec104_session_data_t);

            maxwork = mempool_prune_freelist(iec104_mempool, max_sessions * sizeof(iec104_session_data_t), maxwork);
            if (maxwork)
                mempool_setObjectSize(iec104_mempool, max_sessions, sizeof(iec104_session_data_t));

#ifdef REG_TEST
        if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
        {
            printf("IEC104-reload mempool-after: %zu %zu %zu\n", iec104_mempool->max_memory, iec104_mempool->used_memory, iec104_mempool->free_memory);
        }
#endif
       }
       else
       {
           //otherwise make sure that the mempool is empty and then delete the mempool
            maxwork = mempool_prune_freelist(iec104_mempool, 0, maxwork);
            if (maxwork)
            {
#ifdef REG_TEST
                if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
                {
                    printf("IEC104-reload before-destroy: %zu %zu %zu\n", iec104_mempool->max_memory, iec104_mempool->used_memory, iec104_mempool->free_memory);
                }
#endif
#ifdef REG_TEST
                int retDestroy =
#endif
                mempool_destroy(iec104_mempool);
                iec104_mempool = NULL;
                ada_delete(ada);
                ada = NULL;
#ifdef REG_TEST
                if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
                {
                    printf("IEC104-reload after-destroy: %d %p %p\n", retDestroy, iec104_mempool, ada);
                }
#endif
            }
       }

       return maxwork;
    }

    return false;
}
#endif



static void IEC104RegisterPortsWithSession( struct _SnortConfig *sc, iec104_config_t *policy )
{
    uint32_t port;

    for ( port = 0; port < MAX_PORTS; port++ )
    {
        if( isPortEnabled( policy->ports, port ) )
            _dpd.sessionAPI->enable_preproc_for_port( sc, PP_IEC104, PROTO_BIT__TCP | PROTO_BIT__UDP, port );
    }
}

#ifdef REG_TEST
static inline void PrintIEC104Size(void)
{
    _dpd.logMsg("\nIEC104 Session Size: %lu\n", (long unsigned int)sizeof(iec104_session_data_t));
}
#endif

/* Allocate memory for preprocessor config, parse the args, set up callbacks */
static void IEC104Init(struct _SnortConfig *sc, char *argp)
{
    iec104_config_t *iec104_policy = NULL;

    if (iec104_context_id == NULL)
    	IEC104OneTimeInit(sc);

    iec104_policy = IEC104PerPolicyInit(sc, iec104_context_id);

    ParseIEC104Args(sc, iec104_policy, argp);

#ifdef REG_TEST
    PrintIEC104Size();
#endif

    PrintIEC104Config(iec104_policy);

    IEC104InitializeMempool(iec104_context_id);

    IEC104RegisterPortsWithSession( sc, iec104_policy );

    IEC104RegisterPerPolicyCallbacks(sc, iec104_policy);

#ifdef DUMP_BUFFER
        dumpBufferInit();
#endif
}

static inline void IEC104OneTimeInit(struct _SnortConfig *sc)
{
    /* context creation & error checking */
    iec104_context_id = sfPolicyConfigCreate();
    if (iec104_context_id == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory for "
                                        "IEC104 config.\n");
    }

    if (_dpd.streamAPI == NULL)
    {
        DynamicPreprocessorFatalMessage("SetupIEC104(): The Stream preprocessor "
                                        "must be enabled.\n");
    }

    /* callback registration */
    _dpd.addPreprocConfCheck(sc, IEC104CheckConfig);
    _dpd.addPreprocExit(IEC104CleanExit, NULL, PRIORITY_LAST, PP_IEC104);

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("iec104", (void *)&iec104PerfStats, 0, _dpd.totalPerfStats, NULL);
#endif

    /* Set up target-based app id */
#ifdef TARGET_BASED
    iec104_app_id = _dpd.findProtocolReference("iec104");
    if (iec104_app_id == SFTARGET_UNKNOWN_PROTOCOL)
    	iec104_app_id = _dpd.addProtocolReference("iec104");
    // register with session to handle application
    _dpd.sessionAPI->register_service_handler( PP_IEC104, iec104_app_id );
#endif
}

/* Responsible for allocating a IEC104 policy. Never returns NULL. */
static inline iec104_config_t * IEC104PerPolicyInit(struct _SnortConfig *sc, tSfPolicyUserContextId context_id)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);
    iec104_config_t *iec104_policy = NULL;

    /* Check for existing policy & bail if found */
    sfPolicyUserPolicySet(context_id, policy_id);
    iec104_policy = (iec104_config_t *)sfPolicyUserDataGetCurrent(context_id);
    if (iec104_policy != NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d): IEC104 preprocessor can only be "
                "configured once.\n", *_dpd.config_file, *_dpd.config_line);
    }

    /* Allocate new policy */
    iec104_policy = (iec104_config_t *)calloc(1, sizeof(iec104_config_t));
    if (!iec104_policy)
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory for "
                                        "iec104 preprocessor configuration.\n");
    }

    sfPolicyUserDataSetCurrent(context_id, iec104_policy);

    return iec104_policy;
}

static boolean IEC104GlobalIsEnabled(tSfPolicyUserContextId context_id)
{
    return sfPolicyUserDataIterate(NULL, context_id, IEC104IsEnabled) != 0;
}

static void IEC104InitializeMempool(tSfPolicyUserContextId context_id)
{
    unsigned int max_sessions;
    iec104_config_t *default_config = (iec104_config_t*)sfPolicyUserDataGetDefault(context_id);
    if (default_config && IEC104GlobalIsEnabled(context_id))
    {
#ifdef SNORT_RELOAD
#ifdef REG_TEST
        if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
        {
            printf("IEC104-reload init-before: %p %p\n", iec104_mempool, ada);
        }

#endif
#endif
        if (iec104_mempool == NULL)
        {
            max_sessions = default_config->memcap / sizeof(iec104_session_data_t);

            iec104_mempool = (MemPool *)malloc(sizeof(MemPool));
            if (!iec104_mempool)
            {
                DynamicPreprocessorFatalMessage("IEC104InitializeMempool: "
                        "Unable to allocate memory for iec104 mempool\n");
            }
            //mempool is set to 0 in init
            if (mempool_init(iec104_mempool, max_sessions, sizeof(iec104_session_data_t)))
            {
                DynamicPreprocessorFatalMessage("Unable to allocate IEC104 mempool.\n");
            }
        }

#ifdef SNORT_RELOAD
        if (ada == NULL)
        {
            ada = ada_init(IEC104MemInUse, PP_IEC104, (size_t) default_config->memcap);
            if (ada == NULL)
                DynamicPreprocessorFatalMessage("Unable to allocate IEC104 ada.\n");
        }

#ifdef REG_TEST
        if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
        {
            printf("IEC104-reload init-after: %p %p\n", iec104_mempool, ada);
        }

#endif
#endif
    }
}

static void IEC104RegisterPerPolicyCallbacks(struct _SnortConfig *sc, iec104_config_t *iec104_policy)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);

    /* Callbacks should be avoided if the preproc is disabled. */
    if (iec104_policy->disabled)
        return;

    _dpd.addPreproc(sc, ProcessIEC104, PRIORITY_APPLICATION, PP_IEC104, PROTO_BIT__TCP|PROTO_BIT__UDP);
    _addPortsToStreamFilter(sc, iec104_policy, policy_id);
#ifdef TARGET_BASED
    _addServicesToStreamFilter(sc, policy_id);
    IEC104AddServiceToPaf(sc, iec104_app_id, policy_id);
#endif
    IEC104AddPortsToPaf(sc, iec104_policy, policy_id);
//
//    _dpd.preprocOptRegister(sc, DNP3_FUNC_NAME, DNP3FuncInit, DNP3FuncEval, free, NULL, NULL, NULL, NULL);
//    _dpd.preprocOptRegister(sc, DNP3_OBJ_NAME, DNP3ObjInit, DNP3ObjEval, free, NULL, NULL, NULL, NULL);
//    _dpd.preprocOptRegister(sc, DNP3_IND_NAME, DNP3IndInit, DNP3IndEval, free, NULL, NULL, NULL, NULL);
//    _dpd.preprocOptRegister(sc, DNP3_DATA_NAME, DNP3DataInit, DNP3DataEval, free, NULL, NULL, NULL, NULL);
}

static void ParseSinglePort(iec104_config_t *config, char *token)
{
    /* single port number */
    char *endptr;
    unsigned long portnum = _dpd.SnortStrtoul(token, &endptr, 10);

    if ((*endptr != '\0') || (portnum >= MAX_PORTS))
    {
        DynamicPreprocessorFatalMessage("%s(%d): Bad iec104 port number: %s\n"
                      "Port number must be an integer between 0 and 65535.\n",
                      *_dpd.config_file, *_dpd.config_line, token);
    }

    /* Good port number! */
    config->ports[PORT_INDEX(portnum)] |= CONV_PORT(portnum);
}

static void ParseIEC104Args(struct _SnortConfig *sc, iec104_config_t *config, char *args)
{
    char *saveptr;
    char *token;
    int index = 0;
    /* Set defaults */
    config->memcap = IEC104_DEFAULT_MEMCAP;
    config->ports[PORT_INDEX(IEC104_PORT)] |= CONV_PORT(IEC104_PORT);
    config->check_crc = 0;

    /* No arguments? Stick with defaults. */
    if (args == NULL)
        return;

    token = strtok_r(args, " ,", &saveptr);
    while (token != NULL)
    {
        if (strcmp(token, IEC104_PORTS_KEYWORD) == 0)
        {
            unsigned nPorts = 0;

            /* Un-set the default port */
            config->ports[PORT_INDEX(IEC104_PORT)] = 0;

            /* Parse ports */
            token = strtok_r(NULL, " ,", &saveptr);

            if (token == NULL)
            {
                DynamicPreprocessorFatalMessage("%s(%d): Missing argument for "
                    "IEC104 preprocessor 'ports' option.\n",
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
                DynamicPreprocessorFatalMessage("%s(%d): Bad IEC104 'ports' argument: '%s'\n"
                              "Argument to IEC104 'ports' must be an integer, or a list "
                              "enclosed in { } braces.\n",
                              *_dpd.config_file, *_dpd.config_line, token);
            }
        }
        else if (strcmp(token, IEC104_MEMCAP_KEYWORD) == 0)
        {
            uint32_t memcap;
            char *endptr;

            /* Parse memcap */
            token = strtok_r(NULL, " ", &saveptr);

            /* In a multiple policy scenario, the memcap from the default policy
               overrides the memcap in any targeted policies. */
            if (_dpd.getParserPolicy(sc) != _dpd.getDefaultPolicy())
            {
                iec104_config_t *default_config =
                    (iec104_config_t *)sfPolicyUserDataGet(iec104_context_id,
                                                         _dpd.getDefaultPolicy());

                if (!default_config || default_config->memcap == 0)
                {
                    DynamicPreprocessorFatalMessage("%s(%d): IEC104 'memcap' must be "
                        "configured in the default config.\n",
                        *_dpd.config_file, *_dpd.config_line);
                }

                config->memcap = default_config->memcap;
            }
            else
            {
                if (token == NULL)
                {
                    DynamicPreprocessorFatalMessage("%s(%d): Missing argument for IEC104 "
                        "preprocessor 'memcap' option.\n",
                        *_dpd.config_file, *_dpd.config_line);
                }

                memcap = _dpd.SnortStrtoul(token, &endptr, 10);

                if ((token[0] == '-') || (*endptr != '\0') ||
                    (memcap < MIN_IEC104_MEMCAP) || (memcap > MAX_IEC104_MEMCAP))
                {
                    DynamicPreprocessorFatalMessage("%s(%d): Bad IEC104 'memcap' argument: %s\n"
                              "Argument to IEC104 'memcap' must be an integer between "
                              "%d and %d.\n", *_dpd.config_file, *_dpd.config_line,
                              token, MIN_IEC104_MEMCAP, MAX_IEC104_MEMCAP);
                }

                config->memcap = memcap;
            }
        }
        else if (strcmp(token, IEC104_CHECK_CRC_KEYWORD) == 0)
        {
            /* Parse check_crc */
            config->check_crc = 1;
        }
        else if (strcmp(token, IEC104_DISABLED_KEYWORD) == 0)
        {
            /* TODO: if disabled, check that no other stuff is turned on except memcap */
            config->disabled = 1;
        }
        else if (strcmp(token, "change") == 0)
		{
        	int count =0;

        	//add the the objects to be modified
        	while(count<4 ) {
        	token = strtok_r(NULL, " ,", &saveptr);

        	 if (token == NULL)
        	             {
        	                 DynamicPreprocessorFatalMessage("%s(%d): Missing argument for "
        	                     "IEC104 preprocessor 'change' option.\n",
        	                     *_dpd.config_file, *_dpd.config_line);
        	             }
        	 else{
        		 switch(count){
        		 	 	 	 	 case(0): (config->values_to_alter[index]).typeID = strtol(token,NULL,10);
        		         		 	 break;
        						 case(1): (config->values_to_alter[index]).asduAddress = strtol(token,NULL,10);
        						 	 break;
        						 case(2): (config->values_to_alter[index]).infObjAddress = strtol(token,NULL,10);
        						 	 break;

        						 case(3):
        								 if((config->values_to_alter[index]).typeID==M_ME_NC_1 || (config->values_to_alter[index]).typeID==M_ME_TC_1)
        								 {
        									 (config->values_to_alter[index]).floating_point_val =strtof(token,NULL);
        								 }
        								 else
        								 {
        									 (config->values_to_alter[index]).integer_value =strtol(token,NULL,10);

        								 }
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
            DynamicPreprocessorFatalMessage("%s(%d): Failed to parse iec104 argument: "
                "%s\n", *_dpd.config_file, *_dpd.config_line,  token);
        }
        token = strtok_r(NULL, " ,", &saveptr);
    }
}

/* Print a IEC104 config */
static void PrintIEC104Config(iec104_config_t *config)
{
    int index, newline = 1;

    if (config == NULL)
        return;

    _dpd.logMsg("IEC104 config: \n");

    if (config->disabled)
        _dpd.logMsg("    IEC104: INACTIVE\n");

    _dpd.logMsg("    Memcap: %d\n", config->memcap);
    _dpd.logMsg("    Check Link-Layer CRCs: %s\n",
            config->check_crc ?
            "ENABLED":"DISABLED");

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

//static int IEC104ProcessUDP(iec104_config_t *iec104_eval_config,
//		iec104_session_data_t *sessp, SFSnortPacket *packetp)
//{
//    /* Possibly multiple PDUs in this UDP payload.
//       Split up and process individually. */
//
//    uint16_t bytes_processed = 0;
//    int truncated_pdu = 0;
//
//    while (bytes_processed < packetp->payload_size)
//    {
//        uint8_t *pdu_start;
//        uint16_t user_data, num_crcs, pdu_length;
//        dnp3_link_header_t *link;
//
//        pdu_start = (uint8_t *)(packetp->payload + bytes_processed);
//        link = (dnp3_link_header_t *)pdu_start;
//
//        /*Stop if the start bytes are not 0x0564 */
//        if ((packetp->payload_size < bytes_processed + 2)
//                || (link->start != IEC104_START_BYTES))
//            break;
//
//        /* Alert and stop if there's not enough data to read a length */
//        if ((packetp->payload_size - bytes_processed < (int)sizeof(dnp3_link_header_t)) ||
//                (link->len < DNP3_HEADER_REMAINDER_LEN))
//        {
//            truncated_pdu = 1;
//            break;
//        }
//
//        /* Calculate the actual length of data to inspect */
//        user_data = link->len - DNP3_HEADER_REMAINDER_LEN;
//        num_crcs = 1 + (user_data/DNP3_CHUNK_SIZE) + (user_data % DNP3_CHUNK_SIZE? 1 : 0);
//        pdu_length = DNP3_MIN_LEN + link->len + (DNP3_CRC_SIZE*num_crcs);
//
//        if (bytes_processed + pdu_length > packetp->payload_size)
//        {
//            truncated_pdu = 1;
//            break;
//        }
//
//        DNP3FullReassembly(dnp3_eval_config, sessp, packetp, pdu_start,
//                           pdu_length);
//
//        bytes_processed += pdu_length;
//    }
//
//    if (truncated_pdu)
//    {
//        _dpd.alertAdd(GENERATOR_SPP_DNP3, DNP3_DROPPED_FRAME, 1, 0, 3,
//                        DNP3_DROPPED_FRAME_STR, 0);
//    }
//
//    /* All detection was done when DNP3FullReassembly() called Detect()
//       on the reassembled PDUs. Clear the flag to avoid double alerts
//       on the last PDU. */
//    if (bytes_processed)
//        _dpd.DetectReset((uint8_t *)packetp->payload, packetp->payload_size);
//
//    return DNP3_OK;
//}


static guint iec104ObjectHash(gconstpointer dataObject)
{
	iec104_Object_header_t *objHeader = (iec104_Object_header_t *)dataObject;
	return objHeader->informationObjAddress;
}



static gboolean iec104ObjectEqual(gconstpointer dataObject1,gconstpointer dataObject2)
{
return	((iec104_Object_header_t *)dataObject1)->informationObjAddress == ((iec104_Object_header_t *)dataObject2)->informationObjAddress;
}
static void valueDestroyFunc(gconstpointer dataObject)
{
	g_free(dataObject);
}



/* Main runtime entry point */
static void ProcessIEC104(void *ipacketp, void *contextp)
{
    SFSnortPacket *packetp = (SFSnortPacket *)ipacketp;
    MemBucket *tmp_bucket = NULL;
    iec104_session_data_t *sessp = NULL;
    PROFILE_VARS;

    // preconditions - what we registered for work only on tcp
    assert((IsTCP(packetp)) &&
        packetp->payload && packetp->payload_size);

    /* If TCP, require that PAF flushes full PDUs first. */
    if (packetp->tcp_header && !PacketHasFullPDU(packetp))
        return;

    PREPROC_PROFILE_START(iec104PerfStats);

    /* When pipelined IEC104 PDUs appear in a single TCP segment or UDP packet,
       the detection engine caches the results of the rule options after
       evaluating on the first PDU. Setting this flag stops the caching. */
    packetp->flags |= FLAG_ALLOW_MULTIPLE_DETECT;

    /* Fetch me a preprocessor config to use with this VLAN/subnet/etc.! */
    iec104_eval_config = sfPolicyUserDataGetCurrent(iec104_context_id);

    /* Look for a previously-allocated session data. */
    tmp_bucket = _dpd.sessionAPI->get_application_data(packetp->stream_session, PP_IEC104);

    if (tmp_bucket == NULL)
    {
        /* No existing session. Check those ports. */
        if (IEC104PortCheck(iec104_eval_config, packetp) != IEC104_OK)
        {
            PREPROC_PROFILE_END(iec104PerfStats);
            return;
        }

        /* Create session data and attach it to the Stream session */
        tmp_bucket = IEC104CreateSessionData(packetp);

        if (tmp_bucket == NULL)
        {
            PREPROC_PROFILE_END(iec104PerfStats);
            return;
        }
    }

    sessp = (iec104_session_data_t *) tmp_bucket->data;


    sessp->hash = g_hash_table_new_full(iec104ObjectHash, iec104ObjectEqual,NULL,NULL);
    /* Do preprocessor-specific detection stuff here */
    if (packetp->tcp_header)
    {
//    	if(sessp->direction == DNP3_SERVER)
//    	{
//    		(sessp->server_rdata).;
//    	}
    	guint length;
        /* Single PDU. PAF already split them up into separate pseudo-packets. */
        IEC104FullReassembly(iec104_eval_config, sessp, packetp,(uint8_t *)packetp->payload, packetp->payload_size);


        g_hash_table_destroy (sessp->hash);
        /*Add code to modify the content here
         *
         *
         *
         */
    }
//    else if (packetp->udp_header)
//    {
//        DNP3ProcessUDP(dnp3_eval_config, sessp, packetp);
//    }

    /* That's the end! */
    PREPROC_PROFILE_END(iec104PerfStats);
}

/* Check ports & services */
static int IEC104PortCheck(iec104_config_t *config, SFSnortPacket *packet)
{
#ifdef TARGET_BASED
    int16_t app_id = _dpd.sessionAPI->get_application_protocol_id(packet->stream_session);

    /* call to get_application_protocol_id gave an error */
    if (app_id == SFTARGET_UNKNOWN_PROTOCOL)
        return IEC104_FAIL;

    /* this is positively identified as something non-iec104 */
    if (app_id && (app_id != iec104_app_id))
        return IEC104_FAIL;

    /* this is identified as iec104 */
    if (app_id == iec104_app_id)
        return IEC104_OK;

    /* fall back to port check */
#endif

    if (config->ports[PORT_INDEX(packet->src_port)] & CONV_PORT(packet->src_port))
        return IEC104_OK;

    if (config->ports[PORT_INDEX(packet->dst_port)] & CONV_PORT(packet->dst_port))
        return IEC104_OK;

    return IEC104_FAIL;
}




static MemBucket * IEC104CreateSessionData(SFSnortPacket *packet)
{
    MemBucket *tmp_bucket = NULL;
    iec104_session_data_t *data = NULL;

    /* Sanity Check */
    if (!packet || !packet->stream_session)
        return NULL;

    /* data = (iec104_session_data_t *)calloc(1, sizeof(iec104_session_data_t)); */

    tmp_bucket = mempool_alloc(iec104_mempool);
    if (!tmp_bucket)
    {
        /* Mempool was full, don't process this session. */
        static unsigned int times_mempool_alloc_failed = 0;

        /* Print a message, but only every 1000 times.
                      Don't want to flood the log if there's a lot of IEC104 traffic. */
        if (times_mempool_alloc_failed % 1000 == 0)
        {
            _dpd.logMsg("WARNING: IEC104 memcap exceeded.\n");
        }
        times_mempool_alloc_failed++;

        return NULL;
    }

    data = (iec104_session_data_t *)tmp_bucket->data;

    if (!data)
        return NULL;

    /* Attach to Stream session */
    _dpd.sessionAPI->set_application_data(packet->stream_session, PP_IEC104,
        tmp_bucket, FreeIEC104Data);
#ifdef SNORT_RELOAD
    ada_add(ada, tmp_bucket, packet->stream_session);
#endif

    /* Not sure when this reference counting stuff got added to the old preprocs */
    data->policy_id = _dpd.getNapRuntimePolicy();
    data->context_id = iec104_context_id;
    ((iec104_config_t *)sfPolicyUserDataGetCurrent(iec104_context_id))->ref_count++;

    return tmp_bucket;
}


/* Reload functions */
#ifdef SNORT_RELOAD
/* Almost like IEC104Init, but not quite. */
static void IEC104Reload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId iec104_swap_context_id = (tSfPolicyUserContextId)*new_config;
    iec104_config_t *iec104_policy = NULL;

    if (iec104_swap_context_id == NULL)
    {
        iec104_swap_context_id = sfPolicyConfigCreate();
        if (iec104_swap_context_id == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate memory "
                                            "for IEC104 config.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            DynamicPreprocessorFatalMessage("SetupIEC104(): The Stream preprocessor "
                                            "must be enabled.\n");
        }
        *new_config = (void *)iec104_swap_context_id;
    }

    iec104_policy = IEC104PerPolicyInit(sc, iec104_swap_context_id);

    ParseIEC104Args(sc, iec104_policy, args);

    IEC104InitializeMempool(iec104_swap_context_id);

    PrintIEC104Config(iec104_policy);

    IEC104RegisterPortsWithSession( sc, iec104_policy );

    IEC104RegisterPerPolicyCallbacks(sc, iec104_policy);
}

/* Check that Stream is still running, and that the memcap didn't change. */
static int IEC104ReloadVerify(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId iec104_swap_context_id = (tSfPolicyUserContextId)swap_config;
    iec104_config_t *current_default_config, *new_default_config;

    if ((iec104_context_id == NULL) || (iec104_swap_context_id == NULL))
        return 0;

    current_default_config =
        (iec104_config_t *)sfPolicyUserDataGet(iec104_context_id, _dpd.getDefaultPolicy());

    new_default_config =
        (iec104_config_t *)sfPolicyUserDataGet(iec104_swap_context_id, _dpd.getDefaultPolicy());

    /* Sanity check. Shouldn't be possible. */
    if (current_default_config == NULL)
        return 0;

    if (new_default_config == NULL)
    {
        _dpd.errMsg("IEC104 reload: Changing the IEC104 configuration "
            "requires a restart.\n");
        return -1;
    }

    //is IEC104 enabled?
    bool wasEnabled = sfPolicyUserDataIterate(sc, iec104_context_id, IEC104IsEnabled) != 0;
    bool isEnabled  = sfPolicyUserDataIterate(sc, iec104_swap_context_id, IEC104IsEnabled) != 0;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);
    if (wasEnabled && isEnabled)
    {
        if (new_default_config->memcap < current_default_config->memcap)
        {
            ada_set_new_cap(ada, (size_t) new_default_config->memcap);
            _dpd.reloadAdjustRegister(sc, "IEC104", policy_id, IEC104ReloadAdjustFunc, (void *) ada, NULL);
        }
        else if (new_default_config->memcap > current_default_config->memcap)
        {
            unsigned int max_sessions = new_default_config->memcap / sizeof(iec104_session_data_t);
#ifdef REG_TEST
            if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
            {
                printf("IEC104-reload mempool-before: %zu %zu %zu\n", iec104_mempool->max_memory, iec104_mempool->used_memory, iec104_mempool->free_memory);
            }
#endif
            mempool_setObjectSize(iec104_mempool, max_sessions, sizeof(iec104_session_data_t));
#ifdef REG_TEST
            if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
            {
                printf("IEC104-reload mempool-after: %zu %zu %zu\n", iec104_mempool->max_memory, iec104_mempool->used_memory, iec104_mempool->free_memory);
            }
#endif
        }
    }
    else if (wasEnabled)
    {
        ada_set_new_cap(ada, 0);
        _dpd.reloadAdjustRegister(sc, "IEC104", policy_id, IEC104ReloadAdjustFunc, (void *) ada, NULL);
    }


    /* Did stream5 get turned off? */
    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("SetupIEC104(): The Stream preprocessor must be enabled.\n");
        return -1;
    }

    return 0;
}

static int IEC104FreeUnusedConfigPolicy(
    tSfPolicyUserContextId context_id,
    tSfPolicyId policy_id,
    void *data
    )
{
    iec104_config_t *iec104_config = (iec104_config_t *)data;

    /* do any housekeeping before freeing iec104 config */
    if (iec104_config->ref_count == 0)
    {
        sfPolicyUserDataClear(context_id, policy_id);
        free(iec104_config);
    }

    return 0;
}

static void * IEC104ReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId iec104_swap_context_id = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_context_id = iec104_context_id;

    if (iec104_swap_context_id == NULL)
        return NULL;

    iec104_context_id = iec104_swap_context_id;

    sfPolicyUserDataFreeIterate(old_context_id, IEC104FreeUnusedConfigPolicy);

    if (sfPolicyUserPolicyGetActive(old_context_id) == 0)
    {
        /* No more outstanding configs - free the config array */
        return (void *)old_context_id;
    }

    return NULL;
}

static void IEC104ReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    IEC104FreeConfig( (tSfPolicyUserContextId)data );
}
#endif

/* Stream filter functions */
static void _addPortsToStreamFilter(struct _SnortConfig *sc, iec104_config_t *config, tSfPolicyId policy_id)
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
    _dpd.streamAPI->set_service_filter_status(sc, iec104_app_id, PORT_MONITOR_SESSION, policy_id, 1);
}
#endif

static int IEC104FreeConfigPolicy(
    tSfPolicyUserContextId context_id,
    tSfPolicyId policy_id,
    void *data
    )
{
    iec104_config_t *iec104_config = (iec104_config_t *)data;

    /* do any housekeeping before freeing iec104_config */

    sfPolicyUserDataClear(context_id, policy_id);
    free(iec104_config);
    return 0;
}

static void IEC104FreeConfig(tSfPolicyUserContextId context_id)
{
    if (context_id == NULL)
        return;

    sfPolicyUserDataFreeIterate(context_id, IEC104FreeConfigPolicy);
    sfPolicyConfigDelete(context_id);
}

static int IEC104IsEnabled(struct _SnortConfig *sc, tSfPolicyUserContextId context_id,
            tSfPolicyId policy_id, void *data)
{
	iec104_config_t *config = (iec104_config_t *)data;

    if ((data == NULL) || config->disabled)
        return 0;

    return 1;
}

/* Check an individual policy */
static int IEC104CheckPolicyConfig(
    struct _SnortConfig *sc,
    tSfPolicyUserContextId context_id,
    tSfPolicyId policy_id,
    void *data
    )
{
	iec104_config_t *config = (iec104_config_t *)data;

    _dpd.setParserPolicy(sc, policy_id);

    /* In a multiple-policy setting, the preprocessor can be turned on in
       a "disabled" state. In this case, we don't require Stream. */
    if (config->disabled)
        return 0;

    /* Otherwise, require Stream. */
    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("ERROR: IEC104CheckPolicyConfig(): "
            "The Stream preprocessor must be enabled.\n");
        return -1;
    }
    return 0;
}

/* Check configs & set up mempool.
   Mempool stuff is in this function because we want to parse & check *ALL*
   of the configs before allocating a mempool. */
static int IEC104CheckConfig(struct _SnortConfig *sc)
{
    int rval;

    /* Get default configuration */
    iec104_config_t *default_config =
        (iec104_config_t *)sfPolicyUserDataGetDefault(iec104_context_id);

    if ( !default_config )
    {
        _dpd.errMsg(
            "ERROR: preprocessor iec104 must be configured in the default policy.\n");
        return -1;
    }
    /* Check all individual configurations */
    if ((rval = sfPolicyUserDataIterate(sc, iec104_context_id, IEC104CheckPolicyConfig)))
        return rval;

    return 0;
}

static void IEC104CleanExit(int signal, void *data)
{
    if (iec104_context_id != NULL)
    {
        IEC104FreeConfig(iec104_context_id);
        iec104_context_id = NULL;
    }

    if ((iec104_mempool) && (mempool_destroy(iec104_mempool) == 0))
    {
        free(iec104_mempool);
        iec104_mempool = 0;
    }

#ifdef SNORT_RELOAD
    ada_delete(ada);
    ada = NULL;
#endif
}

static void FreeIEC104Data(void *bucket)
{
    MemBucket *tmp_bucket = (MemBucket *)bucket;
    iec104_session_data_t *session;
    iec104_config_t *config = NULL;

    if ((tmp_bucket == NULL) || (tmp_bucket->data == NULL))
        return;

    session = tmp_bucket->data;

    if (session->context_id != NULL)
    {
        config = (iec104_config_t *)sfPolicyUserDataGet(session->context_id, session->policy_id);
    }

    if (config != NULL)
    {
        config->ref_count--;
        if ((config->ref_count == 0) &&
            (session->context_id != iec104_context_id))
        {
            sfPolicyUserDataClear(session->context_id, session->policy_id);
            free(config);

            if (sfPolicyUserPolicyGetActive(session->context_id) == 0)
            {
                /* No more outstanding configs - free the config array */
                IEC104FreeConfig(session->context_id);
            }
        }
    }

#ifdef SNORT_RELOAD
    ada_appdata_freed(ada, bucket);//iff tmp_bucket/bucket is freed
#endif
    mempool_free(iec104_mempool, tmp_bucket);
}

static size_t IEC104MemInUse()
{
    return iec104_mempool->used_memory;
}

