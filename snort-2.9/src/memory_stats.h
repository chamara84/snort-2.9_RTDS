/*
 **
 **  memory_stats.h
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
#ifndef __MEMORY_STATS_H__
#define __MEMORY_STATS_H__

#include "sf_types.h"
#include "control/sfcontrol.h"

typedef struct _PreprocMemNumAlloc {
    uint32_t num_of_alloc;
    uint32_t num_of_free;
    size_t   used_memory;
} PreprocMemNumAlloc;

typedef struct _PreprocMemInfo {
   PreprocMemNumAlloc session_memory;
   PreprocMemNumAlloc cfg_memory;
   char *preproc_name;
} PreprocMemInfo;

typedef int (*MemoryStatsDisplayFunc)(char *buffer);

void MemoryPostFunction(uint16_t type, void *old_context, struct _THREAD_ELEMENT *te, ControlDataSendFunc f);

int MemoryControlFunction(uint16_t type, void *new_context, void **old_context);

int MemoryPreFunction(uint16_t type, const uint8_t *data, uint32_t length,
                        void **new_context, char *statusBuf, int statusBuf_len);
int RegisterMemoryStatsFunction(uint preproc, char *preproc_name, MemoryStatsDisplayFunc cb);

void* SnortPreprocAlloc (int num, unsigned long size, uint32_t preproc, bool data);

void SnortPreprocFree (void *ptr, uint32_t size, uint32_t preproc, bool data);

void MemoryStatsFree();
#endif
