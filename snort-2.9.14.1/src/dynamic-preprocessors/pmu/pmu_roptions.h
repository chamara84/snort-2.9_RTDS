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
 * Rule options for pmu preprocessor.
 *
 */

#ifndef PMU_ROPTIONS_H
#define PMU_ROPTIONS_H

#include <stdint.h>

#define PMU_FUNC_NAME "pmu_func"
#define PMU_UNIT_NAME "pmu_unit"
#define PMU_DATA_NAME "pmu_data"

/* Data types */
typedef enum _pmu_option_type_t
{
    PMU_FUNC = 0,
    PMU_UNIT,
    PMU_DATA
} pmu_option_type_t;

typedef struct _pmu_option_data_t
{
    pmu_option_type_t type;
    uint16_t arg;
} pmu_option_data_t;

typedef struct _pmu_func_map_t
{
    char *name;
    uint8_t func;
} pmu_func_map_t;

int PMUFuncInit(struct _SnortConfig *sc, char *name, char *params, void **data);
int PMUUnitInit(struct _SnortConfig *sc, char *name, char *params, void **data);
int PMUDataInit(struct _SnortConfig *sc, char *name, char *params, void **data);

int PMURuleEval(void *raw_packet, const uint8_t **cursor, void *data);

#endif /* PMU_ROPTIONS_H */
