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

#ifndef PMU_PAF__H
#define PMU_PAF__H

#include "spp_pmu.h"
#include "stream_api.h"

typedef enum _PMU_paf_state
{
    PMU_PAF_STATE__TRANS_ID_1 = 0,
    PMU_PAF_STATE__TRANS_ID_2,
    PMU_PAF_STATE__PROTO_ID_1,
    PMU_PAF_STATE__PROTO_ID_2,
    PMU_PAF_STATE__LENGTH_1,
    PMU_PAF_STATE__LENGTH_2,
    PMU_PAF_STATE__SET_FLUSH
} PMU_paf_state_t;

typedef struct _PMU_paf_data
{
    PMU_paf_state_t state;
    uint16_t PMU_length;
} PMU_paf_data_t;

void PMUAddPortsToPaf(struct _SnortConfig *sc, pmu_config_t *config, tSfPolicyId policy_id);
int PMUPafRegisterPort(struct _SnortConfig *sc, uint16_t port, tSfPolicyId policy_id);
int PMUAddServiceToPaf(struct _SnortConfig *sc, uint16_t service, tSfPolicyId policy_id);
PAF_Status PMUPaf(void *ssn, void **user, const uint8_t *data,
                     uint32_t len, uint64_t *flags, uint32_t *fp, uint32_t *fp_eoh);
static inline bool PMUIsPafActive(const SFSnortPacket *p)
{
    bool to_server = (p->flags & FLAG_FROM_CLIENT)? true:false;
    if ((p->stream_session_ptr)
            && _dpd.streamAPI->is_paf_active(p->stream_session_ptr, to_server))
        return true;

    return false;
}
#endif /* PMU_PAF__H */
