/*
 * dpx.c
 *
 * Copyright (C) 2010-2011 Sourcefire,Inc
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

//-------------------------------------------------------------------------
// @file    dpx.c
// @author  Russ Combs <rcombs@sourcefire.com>
//-------------------------------------------------------------------------

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "sf_types.h"
#include "snort_debug.h"
#include "preprocids.h"
#include "sf_preproc_info.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preproc_lib.h"
#include "sf_dynamic_preprocessor.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#define PP_DPX 10000

#define DPX_KEY PREPROC_NAME

#define DPX_GID 256

#define DPX_SRC_SID 1
#define DPX_DST_SID 2

#define DPX_SRC_STR DPX_KEY ": tcp src port match"
#define DPX_DST_STR DPX_KEY ": tcp dst port match"

#ifdef DEBUG
#define DEBUG_DPX DEBUG_PP_EXP
#endif

//-------------------------------------------------------------------------

typedef struct
{
    uint16_t portToCheck;

} DPX_Config;

// each context has an instance of DPX_Config for each policy
tSfPolicyUserContextId curr_data = NULL;  // current context

extern DynamicPreprocessorData _dpd;

static void DPX_Init(struct _SnortConfig*, char*);
static void DPX_Term(int, void*);
static void DPX_Delete(void*);
static void DPX_Process(void*, void*);

#ifdef SNORT_RELOAD
static void DPX_Reload(struct _SnortConfig*, char*, void**);
static int DPX_Verify(struct _SnortConfig*, void*);
static void* DPX_Swap(struct _SnortConfig*, void*);
#endif

//-------------------------------------------------------------------------
// policy instance ctor / dtor

static DPX_Config* DPX_Parse (tSfPolicyId pid, char* args)
{
    char* arg;
    const char* delim = " \t\n\r";
    DPX_Config* config = calloc(1, sizeof(*config));

    if ( !config )
        _dpd.fatalMsg("pod[%u](%s:%d): allocation failed.\n",
            pid, *_dpd.config_file, *_dpd.config_line);

    arg = strtok(args, delim);

    if ( arg && !strcasecmp("port", arg) )
    {
        unsigned long port;
        char* argEnd;
        arg = strtok(NULL, delim);

        if ( !arg )
        {
            _dpd.fatalMsg("pod[%u](%s:%d): missing port #\n",
                pid, *_dpd.config_file, *_dpd.config_line);
        }

        port = strtol(arg, &argEnd, 10);

        if ( *argEnd || port > 65535 )
        {
            _dpd.fatalMsg("pod[%u](%s:%d): invalid port %s\n",
                pid, *_dpd.config_file, *_dpd.config_line, arg);
        }
        config->portToCheck = (uint16_t)port;

        DEBUG_WRAP(DebugMessage(DEBUG_DPX, "pod[%u](%s:%d): port = %d\n",
            pid, *_dpd.config_file, *_dpd.config_line, config->portToCheck);)
    }
    else
    {
        _dpd.fatalMsg("pod[%u](%s:%d): invalid argument (%s)\n",
            pid, *_dpd.config_file, *_dpd.config_line, arg?arg:"");
    }

    return config;
}

static int DPX_Free (
    tSfPolicyUserContextId config, tSfPolicyId pid, void* data)
{
    DPX_Config* policy_config = (DPX_Config*)data;

    sfPolicyUserDataClear(config, pid);
    free(policy_config);

    DEBUG_WRAP(DebugMessage(DEBUG_DPX, "pod[%u]: freed\n", pid);)
    return 0;
}

//-------------------------------------------------------------------------
// policies are allocated one at a time
// and deleted all at once on reload / shutdown

static tSfPolicyUserContextId DPX_New (
    struct _SnortConfig* sc,
    tSfPolicyUserContextId data,
    char* args, const char* s)
{
    DPX_Config* config;
    tSfPolicyId pid = _dpd.getParserPolicy(sc);

    if ( !data )
    {
        // allocate the context on 1st policy instance
        data = sfPolicyConfigCreate();

        if ( !data )
            _dpd.fatalMsg("ERROR - " "pod[%u]: policy creation failed.\n",
                pid);

        DEBUG_WRAP(DebugMessage(DEBUG_DPX, "alloced = %p\n", data);)
    }

    config = DPX_Parse(pid, args);
    sfPolicyUserPolicySet(data, pid);
    sfPolicyUserDataSetCurrent(data, config);

    DEBUG_WRAP(DebugMessage(DEBUG_DPX, "pod[%u]: %s\n", pid, s);)
    return data;
}

static void DPX_Delete (void* data)
{
    tSfPolicyUserContextId config = (tSfPolicyUserContextId)data;

    if ( !data )
        return;

    sfPolicyUserDataFreeIterate(config, DPX_Free);
    sfPolicyConfigDelete(config);

    DEBUG_WRAP(DebugMessage(DEBUG_DPX, "deleted = %p\n", config);)
}

//-------------------------------------------------------------------------
// startup and shutdown

// register the preproc when snort starts
void DPX_Setup (void)
{
#ifndef SNORT_RELOAD
    _dpd.registerPreproc(DPX_KEY, DPX_Init);
#else
    _dpd.registerPreproc(
        DPX_KEY, DPX_Init, DPX_Reload,
        DPX_Verify, DPX_Swap, DPX_Delete);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_DPX, "registered\n");)
}

// these are called per policy
static void DPX_Init (struct _SnortConfig* sc, char* args)
{
    curr_data = DPX_New(sc, curr_data, args, "initialized");

    _dpd.addPreproc(sc, DPX_Process, PRIORITY_TRANSPORT, PP_DPX,
        PROTO_BIT__TCP | PROTO_BIT__UDP);

    _dpd.addPreprocExit(DPX_Term, NULL, PRIORITY_TRANSPORT, PP_DPX);
}

static void DPX_Term (int signal, void* pv)
{
    DPX_Delete(curr_data);
    curr_data = NULL;
}

//-------------------------------------------------------------------------
// reload stuff

#ifdef SNORT_RELOAD
static void DPX_Reload (
    struct _SnortConfig* sc, char* args, void** pswap)
{
    tSfPolicyUserContextId swap_data = NULL;
    swap_data = DPX_New(sc, swap_data, args, "reloaded");
    *pswap = swap_data;
}

static int DPX_Verify(struct _SnortConfig* sc, void* swap_data)
{
    return ( swap_data != NULL );
}

static void* DPX_Swap (struct _SnortConfig* sc, void* swap_data)
{
    tSfPolicyUserContextId old_data = curr_data;

    if ( !swap_data )
        return NULL;

    curr_data = swap_data;
    swap_data = NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_DPX, "swapped = %p\n", curr_data);)

    return old_data;
}
#endif

//-------------------------------------------------------------------------
// packet processing stuff

static void DPX_Process (void* pkt, void* context)
{
    SFSnortPacket* p = (SFSnortPacket*)pkt;
    tSfPolicyId pid = _dpd.getNapRuntimePolicy();
    DPX_Config* config;

    sfPolicyUserPolicySet(curr_data, pid);
    config = (DPX_Config*)sfPolicyUserDataGetCurrent(curr_data);

    if ( !config )
        return;

    if ( !p->ip4_header || !p->tcp_header )
    {
        /* Not for me, return */
        return;
    }
    DEBUG_WRAP(DebugMessage(DEBUG_DPX, "pod[%u]: src = %d, dst = %d\n",
        pid, p->src_port, p->dst_port);)

    if ( p->src_port == config->portToCheck )
    {
        /* Source port matched, log alert */
        _dpd.alertAdd(DPX_GID, DPX_SRC_SID,
                      1, 0, 3, DPX_SRC_STR, 0);
        return;
    }

    if ( p->dst_port == config->portToCheck )
    {
        /* Destination port matched, log alert */
        _dpd.alertAdd(DPX_GID, DPX_DST_SID,
                      1, 0, 3, DPX_DST_STR, 0);
        return;
    }
}

