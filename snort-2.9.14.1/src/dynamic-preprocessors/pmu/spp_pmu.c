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
 * Author: Ryan Jordan
 *
 * Dynamic preprocessor for the PMU protocol
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

#include "preprocids.h"
#include "spp_pmu.h"
#include "../pmu/spp_pmu.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats pmuPerfStats;
#endif

#include "sf_types.h"

#include "pmu_decode.h"
#include "pmu_paf.h"
#include "mempool.h"

#ifdef SNORT_RELOAD
#include "appdata_adjuster.h"
static APPDATA_ADJUSTER *ada;
#endif

#ifdef DUMP_BUFFER
#include "pmu_buffer_dump.h"
#endif
const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 2;
const int BUILD_VERSION = 1;
const char *PREPROC_NAME = "SF_PMU";

#define SetupPMU DYNAMIC_PREPROC_SETUP

/* Preprocessor config objects */
static tSfPolicyUserContextId pmu_context_id = NULL;
static pmu_config_t *pmu_eval_config = NULL;

/*memory pool */

static MemPool *pmu_mempool = NULL;

/* Target-based app ID */
#ifdef TARGET_BASED
int16_t pmu_app_id = SFTARGET_UNKNOWN_PROTOCOL;
#endif

/* Prototypes */
static void PMUInit(struct _SnortConfig *, char *);
static inline void PMUOneTimeInit(struct _SnortConfig *);
static inline pmu_config_t * PMUPerPolicyInit(struct _SnortConfig *, tSfPolicyUserContextId);

static void ProcessPMU(void *, void *);

#ifdef SNORT_RELOAD
static void PMUReload(struct _SnortConfig *, char *, void **);
static int PMUReloadVerify(struct _SnortConfig *, void *);
static void * PMUReloadSwap(struct _SnortConfig *, void *);
static void PMUReloadSwapFree(void *);
#endif

static void registerPortsForDispatch( struct _SnortConfig *sc, pmu_config_t *policy );
static void registerPortsForReassembly( pmu_config_t *policy, int direction );
static void _addPortsToStreamFilter(struct _SnortConfig *, pmu_config_t *, tSfPolicyId);
#ifdef TARGET_BASED
static void _addServicesToStreamFilter(struct _SnortConfig *, tSfPolicyId);
#endif

static void PMUFreeConfig(tSfPolicyUserContextId context_id);
static void FreePMUData(void *);
static int PMUCheckConfig(struct _SnortConfig *);
static void PMUCleanExit(int, void *);
static size_t PMUMemInUse();
static void ParsePMUArgs(struct _SnortConfig *sc,pmu_config_t *config, char *args);
static void PMUPrintConfig(pmu_config_t *config);
static void PMUInitializeMempool(tSfPolicyUserContextId context_id);
static int PMUPortCheck(pmu_config_t *config, SFSnortPacket *packet);
static MemBucket * PMUCreateSessionData(SFSnortPacket *);
static bool PMUGlobalIsEnabled(tSfPolicyUserContextId context_id);
static int PMUIsEnabled(struct _SnortConfig *sc, tSfPolicyUserContextId context_id,
            tSfPolicyId policy_id, void *data);
/* Register init callback */
void SetupPMU(void)
{
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("pmu", PMUInit);
#else
    //_dpd.registerPreproc("pmu", PMUInit);
    _dpd.registerPreproc("pmu", PMUInit, PMUReload,
                         PMUReloadVerify, PMUReloadSwap,
                  PMUReloadSwapFree);
#endif
#ifdef DUMP_BUFFER
    _dpd.registerBufferTracer(getPMUBuffers, PMU_BUFFER_DUMP_FUNC);
#endif
}

#ifdef REG_TEST
static inline void PrintPMUSize(void)
{
    _dpd.logMsg("\nPMU Session Size: %lu\n", (long unsigned int)sizeof(pmu_session_data_t));
}
#endif

/* Allocate memory for preprocessor config, parse the args, set up callbacks */
static void PMUInit(struct _SnortConfig *sc, char *argp)
{
    pmu_config_t *pmu_policy = NULL;

#ifdef REG_TEST
    PrintPMUSize();
#endif

    if (pmu_context_id == NULL)
    {
        PMUOneTimeInit(sc);
    }

    pmu_policy = PMUPerPolicyInit(sc, pmu_context_id);

    ParsePMUArgs(sc,pmu_policy, argp);

    /* Can't add ports until they've been parsed... */
    PMUAddPortsToPaf(sc, pmu_policy, _dpd.getParserPolicy(sc));
#ifdef TARGET_BASED
    PMUAddServiceToPaf(sc, pmu_app_id, _dpd.getParserPolicy(sc));
#endif


    PMUInitializeMempool(pmu_context_id);
    PMUPrintConfig(pmu_policy);

    // register ports with session and stream
        registerPortsForDispatch( sc, pmu_policy );
        registerPortsForReassembly( pmu_policy, SSN_DIR_FROM_SERVER | SSN_DIR_FROM_CLIENT );
#ifdef DUMP_BUFFER
        dumpBufferInit();
#endif
}

static inline void PMUOneTimeInit(struct _SnortConfig *sc)
{
    /* context creation & error checking */
    pmu_context_id = sfPolicyConfigCreate();
    if (pmu_context_id == NULL)
    {
        _dpd.fatalMsg("%s(%d) Failed to allocate memory for "
                      "PMU config.\n", *_dpd.config_file, *_dpd.config_line);
    }

    if (_dpd.streamAPI == NULL)
    {
        _dpd.fatalMsg("%s(%d) SetupPMU(): The Stream preprocessor "
                      "must be enabled.\n", *_dpd.config_file, *_dpd.config_line);
    }

    /* callback registration */
    _dpd.addPreprocConfCheck(sc, PMUCheckConfig);
    _dpd.addPreprocExit(PMUCleanExit, NULL, PRIORITY_LAST, PP_PMU);

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("pmu", (void *)&pmuPerfStats, 0, _dpd.totalPerfStats, NULL);
#endif

    /* Set up target-based app id */
#ifdef TARGET_BASED
    pmu_app_id = _dpd.findProtocolReference("pmu");
    if (pmu_app_id == SFTARGET_UNKNOWN_PROTOCOL)
        pmu_app_id = _dpd.addProtocolReference("pmu");

    // register with session to handle applications
    _dpd.sessionAPI->register_service_handler( PP_PMU, pmu_app_id );

#endif
}

/* Responsible for allocating a PMU policy. Never returns NULL. */
static inline pmu_config_t * PMUPerPolicyInit(struct _SnortConfig *sc, tSfPolicyUserContextId context_id)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);
    pmu_config_t *pmu_policy = NULL;

    /* Check for existing policy & bail if found */
    sfPolicyUserPolicySet(context_id, policy_id);
    pmu_policy = (pmu_config_t *)sfPolicyUserDataGetCurrent(context_id);
    if (pmu_policy != NULL)
    {
        _dpd.fatalMsg("%s(%d) PMU preprocessor can only be "
                      "configured once.\n", *_dpd.config_file, *_dpd.config_line);
    }

    /* Allocate new policy */
    pmu_policy = (pmu_config_t *)calloc(1, sizeof(pmu_config_t));
    if (!pmu_policy)
    {
        _dpd.fatalMsg("%s(%d) Could not allocate memory for "
                      "pmu preprocessor configuration.\n"
                      , *_dpd.config_file, *_dpd.config_line);
    }

    sfPolicyUserDataSetCurrent(context_id, pmu_policy);

    /* Register callbacks that are done for each policy */
    _dpd.addPreproc(sc, ProcessPMU, PRIORITY_APPLICATION, PP_PMU, PROTO_BIT__TCP);
   _addPortsToStreamFilter(sc, pmu_policy, policy_id);
#ifdef TARGET_BASED
    _addServicesToStreamFilter(sc, policy_id);
#endif

    /* Add preprocessor rule options here */
    /* _dpd.preprocOptRegister("foo_bar", FOO_init, FOO_rule_eval, free, NULL, NULL, NULL, NULL); */
//    _dpd.preprocOptRegister(sc, "pmu_func", PMUFuncInit, PMURuleEval, free, NULL, NULL, NULL, NULL);
//    _dpd.preprocOptRegister(sc, "pmu_unit", PMUUnitInit, PMURuleEval, free, NULL, NULL, NULL, NULL);
//    _dpd.preprocOptRegister(sc, "pmu_data", PMUDataInit, PMURuleEval, free, NULL, NULL, NULL, NULL);

    return pmu_policy;
}

static void ParseSinglePort(pmu_config_t *config, char *token)
{
    /* single port number */
    char *endptr;
    unsigned long portnum = _dpd.SnortStrtoul(token, &endptr, 10);

    if ((*endptr != '\0') || (portnum >= MAX_PORTS))
    {
        _dpd.fatalMsg("%s(%d) Bad pmu port number: %s\n"
                      "Port number must be an integer between 0 and 65535.\n",
                      *_dpd.config_file, *_dpd.config_line, token);
    }

    /* Good port number! */
    config->ports[PORT_INDEX(portnum)] |= CONV_PORT(portnum);
}

static void ParsePMUArgs(struct _SnortConfig *sc,pmu_config_t *config, char *args)
{
    char *saveptr;
    char *token;
    int index = 0;
    /* Set default port */
    config->ports[PORT_INDEX(PMU_PORT)] |= CONV_PORT(PMU_PORT);

    /* No args? Stick to the default. */
    if (args == NULL)
        return;

    token = strtok_r(args, " ", &saveptr);
    while (token != NULL)
    {
        if (strcmp(token, "ports") == 0)
        {
            unsigned nPorts = 0;

            /* Un-set the default port */
            config->ports[PORT_INDEX(PMU_PORT)] = 0;

            /* Parse ports */
            token = strtok_r(NULL, " ", &saveptr);

            if (token == NULL)
            {
                _dpd.fatalMsg("%s(%d) Missing argument for PMU preprocessor "
                              "'ports' option.\n", *_dpd.config_file, *_dpd.config_line);
            }

            if (isdigit(token[0]))
            {
                ParseSinglePort(config, token);
                nPorts++;
            }

            else if (*token == '{')
            {
                /* list of ports */
                token = strtok_r(NULL, " ", &saveptr);
                while (token != NULL && *token != '}')
                {
                    ParseSinglePort(config, token);
                    nPorts++;
                    token = strtok_r(NULL, " ", &saveptr);
                }
            }

            else
            {
                nPorts = 0;
            }
            if ( nPorts == 0 )
            {
                _dpd.fatalMsg("%s(%d) Bad PMU 'ports' argument: '%s'\n"
                              "Argument to PMU 'ports' must be an integer, or a list "
                              "enclosed in { } braces.\n", *_dpd.config_file, *_dpd.config_line, token);
            }
        }

        else if (strcmp(token, PMU_MEMCAP_KEYWORD) == 0)
                {
                    uint32_t memcap;
                    char *endptr;

                    /* Parse memcap */
                    token = strtok_r(NULL, " ", &saveptr);

                    /* In a multiple policy scenario, the memcap from the default policy
                       overrides the memcap in any targeted policies. */
                    if (_dpd.getParserPolicy(sc) != _dpd.getDefaultPolicy())
                    {
                        pmu_config_t *default_config =
                            (pmu_config_t *)sfPolicyUserDataGet(pmu_context_id,
                                                                 _dpd.getDefaultPolicy());

                        if (!default_config || default_config->memcap == 0)
                        {
                            DynamicPreprocessorFatalMessage("%s(%d): PMU 'memcap' must be "
                                "configured in the default config.\n",
                                *_dpd.config_file, *_dpd.config_line);
                        }

                        config->memcap = default_config->memcap;
                    }
                    else
                                {
                                    if (token == NULL)
                                    {
                                        DynamicPreprocessorFatalMessage("%s(%d): Missing argument for PMU "
                                            "preprocessor 'memcap' option.\n",
                                            *_dpd.config_file, *_dpd.config_line);
                                    }

                                    memcap = _dpd.SnortStrtoul(token, &endptr, 10);

                                    if ((token[0] == '-') || (*endptr != '\0') ||
                                        (memcap < MIN_PMU_MEMCAP) || (memcap > MAX_PMU_MEMCAP))
                                    {
                                        DynamicPreprocessorFatalMessage("%s(%d): Bad PMU 'memcap' argument: %s\n"
                                                  "Argument to PMU 'memcap' must be an integer between "
                                                  "%d and %d.\n", *_dpd.config_file, *_dpd.config_line,
                                                  token, MIN_PMU_MEMCAP, MAX_PMU_MEMCAP);
                                    }

                                    config->memcap = memcap;
                                }
                }
        /*
         * adding code to get the value modification details from the snort.conf
         */
        else if(strcmp(token, "change") == 0)
        {

        	int count =0;
        	char *tempVal;
        	//add the the objects to be modified
        	while(count<5) {
        	token = strtok_r(NULL, " ,", &saveptr);

        	 if (token == NULL)
        	             {
        	                 DynamicPreprocessorFatalMessage("%s(%d): Missing argument for "
        	                     "PMU preprocessor 'change' option.\n",
        	                     *_dpd.config_file, *_dpd.config_line);
        	             }
        	 else{
        		 switch(count){
        		 	 	 	 	 case(0):
        		 	 	 	 			if((config->values_to_alter[index]).pmuName)
        		 	 	 	 				g_string_free((config->values_to_alter[index]).pmuName,1);
        		 	 	 	 			(config->values_to_alter[index]).pmuName = g_string_new(token);
        		 	 	 	 	 break;


        		 	 	 	 	 case(1): (config->values_to_alter[index]).type = strtol(token,NULL,10);
        						 	 break;
        						 case(2):
										 //g_string_free((config->values_to_alter[index]).identifier,1);
										tempVal = token;
        						 //memcpy(tempVal,token,strlen(token));
											for (; *tempVal; ++tempVal)
											{
													if (*tempVal == '_')
															*tempVal = ' ';
											}

											if( (config->values_to_alter[index]).identifier)
												g_string_free( (config->values_to_alter[index]).identifier,1);
        								 (config->values_to_alter[index]).identifier = g_string_new(token);

        						 	 break;
        						 case(3): //treat digital values separate
								if((config->values_to_alter[index]).type!=2)
								{
        						(config->values_to_alter[index]).real_value = strtof(token,NULL);
								}
								else if((config->values_to_alter[index]).type==2)
								{
									(config->values_to_alter[index]).digValue = strtol(token,NULL,16);
								}
        						 if((config->values_to_alter[index]).type!=0) //check if not phasor
										count =5;
        						 	 break;
        						 case(4):

											(config->values_to_alter[index]).imaginary_value = strtof(token,NULL);

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
            _dpd.fatalMsg("%s(%d) Failed to parse pmu argument: %s\n",
                          *_dpd.config_file, *_dpd.config_line, token);
        }

        token = strtok_r(NULL, " ", &saveptr);
    }

}


static bool PMUGlobalIsEnabled(tSfPolicyUserContextId context_id)
{
    return sfPolicyUserDataIterate(NULL, context_id, PMUIsEnabled) != 0;
}
static void PMUInitializeMempool(tSfPolicyUserContextId context_id)
{
    unsigned int max_sessions;
    pmu_config_t *default_config = (pmu_config_t*)sfPolicyUserDataGetDefault(context_id);
    if (default_config && PMUGlobalIsEnabled(context_id))
    {
#ifdef SNORT_RELOAD
#ifdef REG_TEST
        if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
        {
            printf("pmu-reload init-before: %p %p\n", pmu_mempool, ada);
        }

#endif
#endif
        if (pmu_mempool == NULL)
        {
            max_sessions = default_config->memcap / sizeof(pmu_session_data_t);

            pmu_mempool = (MemPool *)malloc(sizeof(MemPool));
            if (!pmu_mempool)
            {
                DynamicPreprocessorFatalMessage("PMUInitializeMempool: "
                        "Unable to allocate memory for dnp3 mempool\n");
            }
            //mempool is set to 0 in init
            if (mempool_init(pmu_mempool, max_sessions, sizeof(pmu_session_data_t)))
            {
                DynamicPreprocessorFatalMessage("Unable to allocate PMU mempool.\n");
            }
        }

#ifdef SNORT_RELOAD
        if (ada == NULL)
        {
            ada = ada_init(PMUMemInUse, PP_PMU, (size_t) default_config->memcap);
            if (ada == NULL)
                DynamicPreprocessorFatalMessage("Unable to allocate PMU data.\n");
        }

#ifdef REG_TEST
        if (REG_TEST_FLAG_RELOAD & getRegTestFlags())
        {
            printf("PMU-reload init-after: %p %p\n", pmu_mempool, ada);
        }

#endif
#endif
    }
}

/* Print a PMU config */
static void PMUPrintConfig(pmu_config_t *config)
{
    int index;
    int newline = 1;

    if (config == NULL)
        return;

    _dpd.logMsg("PMU config: \n");
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
    _dpd.logMsg("    change values:\n");
    for (index = 0; index < config->numAlteredVal; index++)
    {
    	 _dpd.logMsg("change %d %d \n", config->values_to_alter[index].type, config->values_to_alter[index].identifier);
    }
    _dpd.logMsg("\n");
}

/* Main runtime entry point */
static void ProcessPMU(void *ipacketp, void *contextp)
{
    SFSnortPacket *packetp = (SFSnortPacket *)ipacketp;
    MemBucket *tmp_bucket = NULL;
    pmu_session_data_t *sessp = NULL;
    PROFILE_VARS;
    // preconditions - what we registered for
    assert(IsTCP(packetp) && packetp->payload && packetp->payload_size);

    PREPROC_PROFILE_START(pmuPerfStats);

    /* Fetch me a preprocessor config to use with this VLAN/subnet/etc.! */
    pmu_eval_config = sfPolicyUserDataGetCurrent(pmu_context_id);

    /* Look for a previously-allocated session data. */
    tmp_bucket = _dpd.sessionAPI->get_application_data(packetp->stream_session, PP_PMU);

    if (tmp_bucket == NULL)
        {
            /* No existing session. Check those ports. */
            if (PMUPortCheck(pmu_eval_config, packetp) != PMU_OK)
            {
                PREPROC_PROFILE_END(pmuPerfStats);
                return;
            }

            /* Create session data and attach it to the Stream session */
            tmp_bucket = PMUCreateSessionData(packetp);

            if (tmp_bucket == NULL)
            {
                PREPROC_PROFILE_END(pmuPerfStats);
                return;
            }
        }

    sessp = (pmu_session_data_t *) tmp_bucket->data;

if(sessp==NULL)
	return;



    /* When pipelined PMU PDUs appear in a single TCP segment, the
       detection engine caches the results of the rule options after
       evaluating on the first PDU. Setting this flag stops the caching. */
    packetp->flags |= FLAG_ALLOW_MULTIPLE_DETECT;

    /* Do preprocessor-specific detection stuff here */
    if (PMUDecode(sessp,pmu_eval_config, packetp) == PMU_FAIL)
    {

    }

    /* That's the end! */
    PREPROC_PROFILE_END(pmuPerfStats);
}

/* Check ports & services */
static int PMUPortCheck(pmu_config_t *config, SFSnortPacket *packet)
{
#ifdef TARGET_BASED
    int16_t app_id = _dpd.sessionAPI->get_application_protocol_id(packet->stream_session);

    /* call to get_application_protocol_id gave an error */
    if (app_id == SFTARGET_UNKNOWN_PROTOCOL)
        return PMU_FAIL;

    /* this is positively identified as something non-pmu */
    if (app_id && (app_id != pmu_app_id))
        return PMU_FAIL;

    /* this is identified as pmu */
    if (app_id == pmu_app_id)
        return PMU_OK;

    /* fall back to port check */
#endif

    if (config->ports[PORT_INDEX(packet->src_port)] & CONV_PORT(packet->src_port))
        return PMU_OK;

    if (config->ports[PORT_INDEX(packet->dst_port)] & CONV_PORT(packet->dst_port))
        return PMU_OK;

    return PMU_FAIL;
}

static MemBucket * PMUCreateSessionData(SFSnortPacket *packet)
{
    pmu_session_data_t *data = NULL;
    MemBucket *tmp_bucket = NULL;
    /* Sanity Check */
    if (!packet || !packet->stream_session)
        return NULL;

    //data = (pmu_session_data_t *)calloc(1, sizeof(pmu_session_data_t));
    tmp_bucket = mempool_alloc(pmu_mempool);

    if (!tmp_bucket)
        {
            /* Mempool was full, don't process this session. */
            static unsigned int times_mempool_alloc_failed = 0;

            /* Print a message, but only every 1000 times.
                          Don't want to flood the log if there's a lot of PMU traffic. */
            if (times_mempool_alloc_failed % 1000 == 0)
            {
                _dpd.logMsg("WARNING: PMU memcap exceeded.\n");
            }
            times_mempool_alloc_failed++;

            return NULL;
        }


    data = (pmu_session_data_t *)tmp_bucket->data;

    if (!data)

        return NULL;

    /* Attach to Stream session */
    data->pmuConfig2.PMUs = NULL;
    data->partialData = 0;
    data->FrameData =  NULL;
    data->Sync.FrameType = 5;
    data->pmuRefTable = g_hash_table_new_full(g_str_hash, g_str_equal,free,free);
    _dpd.sessionAPI->set_application_data(packet->stream_session, PP_PMU,
    		tmp_bucket, FreePMUData);
#ifdef SNORT_RELOAD
    ada_add(ada, tmp_bucket, packet->stream_session);
#endif
    /* Not sure when this reference counting stuff got added to the old preprocs */
    data->policy_id = _dpd.getNapRuntimePolicy();
    data->context_id = pmu_context_id;
    ((pmu_config_t *)sfPolicyUserDataGetCurrent(pmu_context_id))->ref_count++;

    return tmp_bucket;
}


/* Reload functions */
#ifdef SNORT_RELOAD
/* Almost like PMUInit, but not quite. */
static void PMUReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId pmu_swap_context_id = (tSfPolicyUserContextId)*new_config;
    pmu_config_t *pmu_policy = NULL;

    if (pmu_swap_context_id == NULL)
    {
        pmu_swap_context_id = sfPolicyConfigCreate();
        if (pmu_swap_context_id == NULL)
        {
            _dpd.fatalMsg("Failed to allocate memory "
                                            "for PMU config.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            _dpd.fatalMsg("SetupPMU(): The Stream preprocessor "
                                            "must be enabled.\n");
        }
        *new_config = (void *)pmu_swap_context_id;
    }

    pmu_policy = PMUPerPolicyInit(sc, pmu_swap_context_id);

    ParsePMUArgs(sc,pmu_policy, args);
    PMUInitializeMempool(pmu_swap_context_id);
    /* Can't add ports until they've been parsed... */
    PMUAddPortsToPaf(sc, pmu_policy, _dpd.getParserPolicy(sc));

    PMUPrintConfig(pmu_policy);
    // register ports with session and stream
        registerPortsForDispatch( sc, pmu_policy );
        registerPortsForReassembly( pmu_policy, SSN_DIR_FROM_SERVER | SSN_DIR_FROM_CLIENT );
}

static int PMUReloadVerify(struct _SnortConfig *sc, void *swap_config)
{
    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("SetupPMU(): The Stream preprocessor must be enabled.\n");
        return -1;
    }

    return 0;
}

static int PMUFreeUnusedConfigPolicy(
    tSfPolicyUserContextId context_id,
    tSfPolicyId policy_id,
    void *data
    )
{
    pmu_config_t *pmu_config = (pmu_config_t *)data;

    /* do any housekeeping before freeing pmu config */
    if (pmu_config->ref_count == 0)
    {
        sfPolicyUserDataClear(context_id, policy_id);
        free(pmu_config);
    }

    return 0;
}

static void * PMUReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId pmu_swap_context_id = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_context_id = pmu_context_id;

    if (pmu_swap_context_id == NULL)
        return NULL;

    pmu_context_id = pmu_swap_context_id;

    sfPolicyUserDataFreeIterate(old_context_id, PMUFreeUnusedConfigPolicy);

    if (sfPolicyUserPolicyGetActive(old_context_id) == 0)
    {
        /* No more outstanding configs - free the config array */
        return (void *)old_context_id;
    }

    return NULL;
}

static void PMUReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    PMUFreeConfig( (tSfPolicyUserContextId)data );
}
#endif

static void registerPortsForDispatch( struct _SnortConfig *sc, pmu_config_t *policy )
{
    uint32_t port;

    for ( port = 0; port < MAX_PORTS; port++ )
    {
        if( isPortEnabled( policy->ports, port ) )
            _dpd.sessionAPI->enable_preproc_for_port( sc, PP_PMU, PROTO_BIT__TCP, port );
    }
}

static void registerPortsForReassembly( pmu_config_t *policy, int direction )
{
    uint32_t port;

    for ( port = 0; port < MAX_PORTS; port++ )
    {
        if( isPortEnabled( policy->ports, port ) )
            _dpd.streamAPI->register_reassembly_port( NULL, port, direction );
    }
}

/* Stream filter functions */
static void _addPortsToStreamFilter(struct _SnortConfig *sc, pmu_config_t *config, tSfPolicyId policy_id)
{
    if (config == NULL)
        return;

    if (_dpd.streamAPI)
    {
        int portNum;

        for (portNum = 0; portNum < MAX_PORTS; portNum++)
        {
            if(config->ports[(portNum/8)] & (1<<(portNum%8)))
            {
                //Add port the port
                _dpd.streamAPI->set_port_filter_status( sc, IPPROTO_TCP, (uint16_t)portNum,
                                                        PORT_MONITOR_SESSION, policy_id, 1 );
            }
        }
    }

}

#ifdef TARGET_BASED
static void _addServicesToStreamFilter(struct _SnortConfig *sc, tSfPolicyId policy_id)
{
    _dpd.streamAPI->set_service_filter_status(sc, pmu_app_id, PORT_MONITOR_SESSION, policy_id, 1);
}
#endif

static int PMUFreeConfigPolicy(
    tSfPolicyUserContextId context_id,
    tSfPolicyId policy_id,
    void *data
    )
{
    pmu_config_t *pmu_config = (pmu_config_t *)data;

    /* do any housekeeping before freeing pmu_config */

    sfPolicyUserDataClear(context_id, policy_id);
    free(pmu_config);
    return 0;
}

static int PMUIsEnabled(struct _SnortConfig *sc, tSfPolicyUserContextId context_id,
            tSfPolicyId policy_id, void *data)
{
    pmu_config_t *config = (pmu_config_t *)data;

    if ((data == NULL) || config->disabled)
        return 0;

    return 1;
}

static void PMUFreeConfig(tSfPolicyUserContextId context_id)
{
    if (context_id == NULL)
        return;

    sfPolicyUserDataFreeIterate(context_id, PMUFreeConfigPolicy);
    sfPolicyConfigDelete(context_id);
}

static int PMUCheckPolicyConfig(
    struct _SnortConfig *sc,
    tSfPolicyUserContextId context_id,
    tSfPolicyId policy_id,
    void *data
    )
{
    _dpd.setParserPolicy(sc, policy_id);

    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("%s(%d) PMUCheckPolicyConfig(): The Stream preprocessor "
                      "must be enabled.\n", *_dpd.config_file, *_dpd.config_line);
        return -1;
    }
    return 0;
}

static int PMUCheckConfig(struct _SnortConfig *sc)
{
    int rval;

    if ((rval = sfPolicyUserDataIterate(sc, pmu_context_id, PMUCheckPolicyConfig)))
        return rval;

    return 0;
}

static void PMUCleanExit(int signal, void *data)
{
    if (pmu_context_id != NULL)
    {
        PMUFreeConfig(pmu_context_id);
        pmu_context_id = NULL;
    }
}

static void FreePMUData(void *bucket)
{

	MemBucket *tmp_bucket = (MemBucket *)bucket;
    pmu_session_data_t *session ;
    pmu_config_t *config = NULL;


    if ((tmp_bucket == NULL) || (tmp_bucket->data == NULL))
            return;

        session = tmp_bucket->data;




    if (session->context_id != NULL)
    {
        config = (pmu_config_t *)sfPolicyUserDataGet(session->context_id, session->policy_id);
    }

    if (config != NULL)
    {
        config->ref_count--;
        if ((config->ref_count == 0) &&
            (session->context_id != pmu_context_id))
        {
            sfPolicyUserDataClear(session->context_id, session->policy_id);
            free(config);

            if (sfPolicyUserPolicyGetActive(session->context_id) == 0)
            {
                /* No more outstanding configs - free the config array */
                PMUFreeConfig(session->context_id);
            }
        }
    }
#ifdef SNORT_RELOAD
    ada_appdata_freed(ada, bucket);//iff tmp_bucket/bucket is freed
#endif
    mempool_free(pmu_mempool, tmp_bucket);
}


static size_t PMUMemInUse()
{
    return pmu_mempool->used_memory;
}
