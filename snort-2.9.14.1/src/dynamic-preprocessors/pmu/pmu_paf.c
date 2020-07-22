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
 * Protocol-Aware Flushing (PAF) code for the PMU preprocessor.
 *
 */

#include "pmu_paf.h"

#include "spp_pmu.h"
#include "pmu_decode.h"
#include "sf_dynamic_preprocessor.h"

/* Defines */
#define PMU_MIN_HDR_LEN 2        /* Enough for Unit ID + Function */
#define PMU_MAX_HDR_LEN 254      /* Max PDU size is 260, 6 bytes already seen */


int PMUPafRegisterPort (struct _SnortConfig *sc, uint16_t port, tSfPolicyId policy_id)
{
    if (!_dpd.isPafEnabled())
        return 0;

    _dpd.streamAPI->register_paf_port(sc, policy_id, port, 0, PMUPaf, true);
    _dpd.streamAPI->register_paf_port(sc, policy_id, port, 1, PMUPaf, true);

    return 0;
}

#ifdef TARGET_BASED
int PMUAddServiceToPaf (struct _SnortConfig *sc, uint16_t service, tSfPolicyId policy_id)
{
    if (!_dpd.isPafEnabled())
        return 0;

    _dpd.streamAPI->register_paf_service(sc, policy_id, service, 0, PMUPaf, true);
    _dpd.streamAPI->register_paf_service(sc, policy_id, service, 1, PMUPaf, true);

    return 0;
}
#endif

/* Function: PMUPaf()

   Purpose: PMU/TCP PAF callback.
            Statefully inspects PMU traffic from the start of a session,
            Reads up until the length octet is found, then sets a flush point.

   Arguments:
     void * - stream5 session pointer
     void ** - PMU state tracking structure
     const uint8_t * - payload data to inspect
     uint32_t - length of payload data
     uint32_t - flags to check whether client or server
     uint32_t * - pointer to set flush point
     uint32_t * - pointer to set header flush point

   Returns:
    PAF_Status - PAF_FLUSH if flush point found, PAF_SEARCH otherwise
*/

PAF_Status PMUPaf(void *ssn, void **user, const uint8_t *data,
                     uint32_t len, uint64_t *flags, uint32_t *fp, uint32_t *fp_eoh)
{
    PMU_paf_data_t *pafdata = *(PMU_paf_data_t **)user;
    uint32_t bytes_processed = 0;

    /* Allocate state object if it doesn't exist yet. */
    if (pafdata == NULL)
    {
        pafdata = calloc(1, sizeof(PMU_paf_data_t));
        if (pafdata == NULL)
            return PAF_ABORT;

        *user = pafdata;
    }

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
    {
        switch (pafdata->state)
        {
            /* Skip the Transaction & Protocol IDs */
            case PMU_PAF_STATE__TRANS_ID_1:
            case PMU_PAF_STATE__TRANS_ID_2:
            case PMU_PAF_STATE__PROTO_ID_1:
            case PMU_PAF_STATE__PROTO_ID_2:
                pafdata->state++;
                break;

            /* Read length 1 byte at a time, in case a TCP segment is sent
             * with only 5 bytes from the MBAP header */
            case PMU_PAF_STATE__LENGTH_1:
                pafdata->PMU_length |= ( *(data + bytes_processed) << 8 );
                pafdata->state++;
                break;

            case PMU_PAF_STATE__LENGTH_2:
                pafdata->PMU_length |= *(data + bytes_processed);
                pafdata->state++;
                break;

            case PMU_PAF_STATE__SET_FLUSH:
                if ((pafdata->PMU_length < PMU_MIN_HDR_LEN) ||
                    (pafdata->PMU_length > PMU_MAX_HDR_LEN))
                {
                    _dpd.alertAdd(GENERATOR_SPP_PMU, PMU_BAD_LENGTH, 1, 0, 3,
                                  PMU_BAD_LENGTH_STR, 0);
                }

                *fp = pafdata->PMU_length + bytes_processed;
                pafdata->state = PMU_PAF_STATE__TRANS_ID_1;
                pafdata->PMU_length = 0;
                return PAF_FLUSH;
        }

        bytes_processed++;
    }

    return PAF_SEARCH;
}

/* Take a PMU config + Snort policy, iterate through ports, register PAF callback */
void PMUAddPortsToPaf(struct _SnortConfig *sc, pmu_config_t *config, tSfPolicyId policy_id)
{
    unsigned int i;

    for (i = 0; i < MAX_PORTS; i++)
    {
        if (config->ports[PORT_INDEX(i)] & CONV_PORT(i))
        {
            PMUPafRegisterPort(sc, (uint16_t) i, policy_id);
        }
    }
}
