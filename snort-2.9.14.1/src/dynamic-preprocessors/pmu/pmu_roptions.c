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
 * Rule options for PMU preprocessor
 *
 */

#include "pmu_roptions.h"

#include <string.h>

#include "sf_types.h"
#include "sf_snort_plugin_api.h"
#include "sf_dynamic_preprocessor.h"
#include "spp_pmu.h"
#include "pmu_decode.h"
#include "pmu_paf.h"

/* Mapping of name -> function code for 'pmu_func' option. */
static pmu_func_map_t func_map[] =
{
    {"read_coils", 1},
    {"read_discrete_inputs", 2},
    {"read_holding_registers", 3},
    {"read_input_registers", 4},
    {"write_single_coil", 5},
    {"write_single_register", 6},
    {"read_exception_status", 7},
    {"diagnostics", 8},
    {"get_comm_event_counter", 11},
    {"get_comm_event_log", 12},
    {"write_multiple_coils", 15},
    {"write_multiple_registers", 16},
    {"report_slave_id", 17},
    {"read_file_record", 20},
    {"write_file_record", 21},
    {"mask_write_register", 22},
    {"read_write_multiple_registers", 23},
    {"read_fifo_queue", 24},
    {"encapsulated_interface_transport", 43}
};

int PMUFuncInit(struct _SnortConfig *sc, char *name, char *params, void **data)
{
    char *endptr;
    pmu_option_data_t *pmu_data;
    unsigned int func_code = 0;

    if (name == NULL || data == NULL)
        return 0;

    if (strcmp(name, PMU_FUNC_NAME) != 0)
        return 0;

    if (params == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d): No argument given for PMU_func. "
            "PMU_func requires a number between 0 and 255, or a valid function "
            "name.\n", *_dpd.config_file, *_dpd.config_line);
    }

    pmu_data = (pmu_option_data_t *)calloc(1, sizeof(pmu_option_data_t));
    if (pmu_data == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) Failed to allocate memory for "
            "pmu_func data structure.\n", __FILE__, __LINE__);
    }

    /* Parsing time */
    if (isdigit(params[0]))
    {
        /* Function code given as integer */
        func_code = _dpd.SnortStrtoul(params, &endptr, 10);
        if ((func_code > 255) || (*endptr != '\0'))
        {
            DynamicPreprocessorFatalMessage("%s(%d): pmu_func requires a "
                "number between 0 and 255, or a valid function name.\n",
                *_dpd.config_file, *_dpd.config_line);
        }
    }
    else
    {
        /* Check the argument against the map in pmu_roptions.h */
        size_t i;
        int parse_success = 0;
        for (i = 0; i < (sizeof(func_map) / sizeof(pmu_func_map_t)); i++)
        {
            if (strcmp(params, func_map[i].name) == 0)
            {
                parse_success = 1;
                func_code = func_map[i].func;
                break;
            }
        }

        if (!parse_success)
        {
            DynamicPreprocessorFatalMessage("%s(%d): pmu_func requires a "
                "number between 0 and 255, or a valid function name.\n",
                *_dpd.config_file, *_dpd.config_line);
        }
    }

    pmu_data->type = PMU_FUNC;
    pmu_data->arg = (uint8_t) func_code;

    *data = (void *)pmu_data;

    return 1;
}

int PMUUnitInit(struct _SnortConfig *sc, char *name, char *params, void **data)
{
    char *endptr;
    pmu_option_data_t *pmu_data;
    unsigned int unit_code;

    if (name == NULL || data == NULL)
        return 0;

    if (strcmp(name, PMU_UNIT_NAME) != 0)
        return 0;

    if (params == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d): No argument given for pmu_unit. "
            "pmu_unit requires a number between 0 and 255.\n",
            *_dpd.config_file, *_dpd.config_line);
    }

    pmu_data = (pmu_option_data_t *)calloc(1, sizeof(pmu_option_data_t));
    if (pmu_data == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) Failed to allocate memory for "
            "pmu_unit data structure.\n", __FILE__, __LINE__);
    }

    /* Parsing time */
    unit_code = _dpd.SnortStrtoul(params, &endptr, 10);
    if ((unit_code > 255) || (*endptr != '\0'))
    {
        DynamicPreprocessorFatalMessage("%s(%d): pmu_unit requires a "
            "number between 0 and 255.\n",
            *_dpd.config_file, *_dpd.config_line);
    }

    pmu_data->type = PMU_UNIT;
    pmu_data->arg = (uint8_t) unit_code;

    *data = (void *)pmu_data;

    return 1;
}

int PMUDataInit(struct _SnortConfig *sc, char *name, char *params, void **data)
{
    pmu_option_data_t *pmu_data;

    if (strcmp(name, PMU_DATA_NAME) != 0)
        return 0;

    /* Nothing to parse. */
    if (params)
    {
        DynamicPreprocessorFatalMessage("%s(%d): pmu_data does not take "
            "any arguments.\n", *_dpd.config_file, *_dpd.config_line);
    }

    pmu_data = (pmu_option_data_t *)calloc(1, sizeof(pmu_option_data_t));
    if (pmu_data == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) Failed to allocate memory for "
            "pmu_data data structure.\n", __FILE__, __LINE__);
    }

    pmu_data->type = PMU_DATA;
    pmu_data->arg = 0;

    *data = (void *)pmu_data;

    return 1;
}

/* PMU rule evaluation callback. */
int PMURuleEval(void *raw_packet, const uint8_t **cursor, void *data)
{
    SFSnortPacket *packet = (SFSnortPacket *)raw_packet;
    pmu_option_data_t *rule_data = (pmu_option_data_t *)data;
    pmu_session_data_t *session_data;

    /* The preprocessor only evaluates PAF-flushed PDUs. If the rule options
       don't check for this, they'll fire on stale session data when the
       original packet goes through before flushing. */
    if (!PacketHasFullPDU(packet) && PMUIsPafActive(packet))
        return RULE_NOMATCH;

    session_data = (pmu_session_data_t *)
        _dpd.sessionAPI->get_application_data(packet->stream_session, PP_PMU);

    if ((packet->payload_size == 0 ) || (session_data == NULL))
    {
        return RULE_NOMATCH;
    }


    switch (rule_data->type)
    {
        case PMU_FUNC:
            if (session_data->func == rule_data->arg)
                return RULE_MATCH;
            break;

        case PMU_UNIT:
            if (session_data->unit == rule_data->arg)
                return RULE_MATCH;
            break;

        case PMU_DATA:
            /* XXX: If a PDU contains only the MBAP + Function, should this
               option fail or set the cursor to the end of the payload? */
            if (packet->payload_size < PMU_MIN_LEN)
                return RULE_NOMATCH;

            /* PMU data is always directly after the function code. */
            *cursor = (const uint8_t *) (packet->payload + PMU_MIN_LEN);
            _dpd.SetAltDetect((uint8_t *)*cursor, (uint16_t)(packet->payload_size - PMU_MIN_LEN));

            return RULE_MATCH;
    }

    return RULE_NOMATCH;
}


