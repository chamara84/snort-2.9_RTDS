/*
 **
 **  memory_stats.c
 **
 **  Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
 **  Author(s):   Puneeth Kumar C V <puneetku@cisco.com>
 **
 **  This program is free software; you can redistribute it and/or modify
 **  it under the terms of the GNU General Public License Version 2 as
 **  published by the Free Software Foundation.  You may not use, modify or
 **  distribute this program under any other version of the GNU General
 **  Public License.
 **
 **  This program is distributed in the hope that it will be useful,
 **  but WITHOUT ANY WARRANTY; without even the implied warranty of
 **  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 **  GNU General Public License for more details.
 **
 **  You should have received a copy of the GNU General Public License
 **  along with this program; if not, write to the Free Software
 **  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>

#include "snort.h"
#include "preprocids.h"
#include "memory_stats.h"

static MemoryStatsDisplayFunc MemStatsDisplayCallback[PP_MAX] = {0};
static PreprocMemInfo *preproc_mem_info[PP_MAX] = {0};

static int PopulateMemStatsBuff(char *buffer, uint32_t preproc_id)
{
    return snprintf(buffer, CS_STATS_BUF_SIZE, "\n   Heap Memory:\n"
                "                   Session: %14zu bytes\n"
                "             Configuration: %14zu bytes\n"
                "             --------------         ------------\n"
                "              Total Memory: %14zu bytes\n"
                "              No of allocs: %14d times\n"
                "               IP sessions: %14d times\n"
                "----------------------------------------------------\n"
                , preproc_mem_info[preproc_id]->session_memory.used_memory
                , preproc_mem_info[preproc_id]->cfg_memory.used_memory
                , preproc_mem_info[preproc_id]->session_memory.used_memory +
                                           preproc_mem_info[preproc_id]->cfg_memory.used_memory
                , preproc_mem_info[preproc_id]->session_memory.num_of_alloc +
                                           preproc_mem_info[preproc_id]->cfg_memory.num_of_alloc
                , preproc_mem_info[preproc_id]->session_memory.num_of_free +
                                           preproc_mem_info[preproc_id]->cfg_memory.num_of_free);
}

static inline void PreprocDisplaystats(char *buffer, uint32_t preproc_id)
{
    int len = 0;
    if (!(preproc_id != PP_ALL && preproc_id >= PP_MAX))
    {
         if ( (preproc_id != PP_ALL) && (MemStatsDisplayCallback[preproc_id] != 0 && preproc_mem_info[preproc_id] != NULL) )
         {
             len += MemStatsDisplayCallback[preproc_id](buffer);
             len += PopulateMemStatsBuff(buffer + len, preproc_id);
         }
         else
             for (preproc_id = PP_BO; preproc_id < PP_MAX; preproc_id++)
                if(MemStatsDisplayCallback[preproc_id] != 0 && preproc_mem_info[preproc_id] != NULL)
                {
                   len += MemStatsDisplayCallback[preproc_id](buffer + len);
                   len += PopulateMemStatsBuff(buffer + len, preproc_id);
                }
    }
    else
    {
        snprintf(buffer, CS_STATS_BUF_SIZE, "\nInvalid preprocessor.\n");   
    }
}

void MemoryPostFunction(uint16_t type, void *old_context, struct _THREAD_ELEMENT *te, ControlDataSendFunc f)
{
    char *buffer = (char*) calloc(MEM_STATS_BUF_SIZE + 1, 1);
    uint32_t preproc_id;
    
    if(old_context)
    {
        preproc_id = *((uint32_t *) old_context);
        PreprocDisplaystats(buffer, preproc_id); 

        if(-1 == f(te, (const uint8_t *)buffer, strlen(buffer)))
            LogMessage("Unable to send data to the frontend\n");
    }  
}

int MemoryControlFunction(uint16_t type, void *new_context, void **old_context)
{
    if(new_context)
        *old_context = new_context;
    else    
        LogMessage("\nnew_context is NULL\n");
    return 0;
}

int MemoryPreFunction(uint16_t type, const uint8_t *data, uint32_t length,
                        void **new_context, char *statusBuf, int statusBuf_len)
{
    if(data)
        *new_context = (void*) data;
    else
         LogMessage("\ndata is NULL\n"); 
    return 0; 
}

int RegisterMemoryStatsFunction(uint preproc, char* preproc_name, MemoryStatsDisplayFunc cb)
{
    if (preproc >= PP_MAX)
    {
        return -1;
    }

    MemStatsDisplayCallback[preproc] = cb;
    
    if (preproc_mem_info[preproc] == NULL)
    {
        preproc_mem_info[preproc] = (PreprocMemInfo *)SnortAlloc(sizeof(PreprocMemInfo));    
        preproc_mem_info[preproc]->preproc_name = preproc_name;
    }
 
    return 0;
}

void* SnortPreprocAlloc (int num, unsigned long size, uint32_t preproc, bool cfg)
{
    void *pv = calloc(num, size);

    if ( pv )
    {
        if (preproc_mem_info[preproc] == 0)
        {
            LogMessage("Memory stats information for preprocessor is NULL");
            return pv;
        }

        if (cfg)
        {
            preproc_mem_info[preproc]->cfg_memory.used_memory += size;
            preproc_mem_info[preproc]->cfg_memory.num_of_alloc++;
        }
        else
        {
            preproc_mem_info[preproc]->session_memory.used_memory += size;
            preproc_mem_info[preproc]->session_memory.num_of_alloc++;
        }
    }
   
    else
    { 
        FatalError("Unable to allocate memory!  (%lu requested)\n", size);
    }

    return pv;
}

void SnortPreprocFree (void *ptr, uint32_t size, uint32_t preproc, bool cfg)
{
    if( ptr )
    {
        free(ptr);
        ptr = NULL;
    }

    if (preproc_mem_info[preproc] == NULL)
    {
        LogMessage("Memory stats information for preprocessor is NULL");
        return;
    }
    if (cfg)
    {
        preproc_mem_info[preproc]->cfg_memory.used_memory -= size;
        preproc_mem_info[preproc]->cfg_memory.num_of_free++;
    }
    else
    {
        preproc_mem_info[preproc]->session_memory.used_memory -= size;
        preproc_mem_info[preproc]->session_memory.num_of_free++;
    } 
}

void MemoryStatsFree ()
{
    int i;
    for (i = 0;i < PP_MAX;i++)
    {
       if (preproc_mem_info[i])
       {
          free( preproc_mem_info[i]);
          preproc_mem_info[i] = NULL;
       }
    }
}
