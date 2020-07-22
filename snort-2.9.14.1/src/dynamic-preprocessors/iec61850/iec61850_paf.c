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
 * Protocol Aware Flushing (PAF) code for IEC61850 preprocessor.
 *
 */

#include "iec61850_paf.h"

#include "sf_dynamic_preprocessor.h"

#include "spp_iec61850.h"

/* Forward declarations */
static PAF_Status IEC61850Paf(void *ssn, void **user, const uint8_t *data,
                   uint32_t len, uint64_t *flags, uint32_t *fp, uint32_t *fp_eoh);

/* State-tracking structs */
typedef enum _iec61850_paf_state
{
	IEC61850_PAF_STATE__START = 0,
	IEC61850_PAF_STATE__LENGTH,
	IEC61850_PAF_STATE__SET_FLUSH
} iec61850_paf_state_t;

typedef struct _iec61850_paf_data
{
	iec61850_paf_state_t state;
    uint8_t iec61850_length;
    uint16_t real_length;
} iec61850_paf_data_t;

static uint8_t iec61850_paf_id = 0;

static int IEC61850PafRegisterPort (struct _SnortConfig *sc, uint16_t port, tSfPolicyId policy_id)
{
    if (!_dpd.isPafEnabled())
        return 0;

    iec61850_paf_id = _dpd.streamAPI->register_paf_port(sc, policy_id, port, 0, IEC61850Paf, true);
    iec61850_paf_id = _dpd.streamAPI->register_paf_port(sc, policy_id, port, 1, IEC61850Paf, true);

    return 0;
}

#ifdef TARGET_BASED
int IEC61850AddServiceToPaf (struct _SnortConfig *sc, uint16_t service, tSfPolicyId policy_id)
{
    if (!_dpd.isPafEnabled())
        return 0;

    iec61850_paf_id = _dpd.streamAPI->register_paf_service(sc, policy_id, service, 0, IEC61850Paf, true);
    iec61850_paf_id = _dpd.streamAPI->register_paf_service(sc, policy_id, service, 1, IEC61850Paf, true);

    return 0;
}
#endif

/* Function: IEC61850Paf()

   Purpose: IEC61850 PAF callback.
            Statefully inspects IEC61850 traffic from the start of a session,
            Reads up until the length octet is found, then sets a flush point.
            The flushed PDU is a IEC61850 Link Layer frame, the preprocessor
            handles reassembly of frames into Application Layer messages.

   Arguments:
     void * - stream5 session pointer
     void ** - IEC61850 state tracking structure
     const uint8_t * - payload data to inspect
     uint32_t - length of payload data
     uint32_t * - pointer to set flush point
     uint32_t * - pointer to set header flush point

   Returns:
    PAF_Status - PAF_FLUSH if flush point found, PAF_SEARCH otherwise
*/

static PAF_Status IEC61850Paf(void *ssn, void **user, const uint8_t *data,
                     uint32_t len, uint64_t *flags, uint32_t *fp, uint32_t *fp_eoh)
{
    iec61850_paf_data_t *pafdata = *(iec61850_paf_data_t **)user;
    uint8_t bytes_processed = 0;

    /* Allocate state object if it doesn't exist yet. */
    if (pafdata == NULL)
    {
        pafdata = calloc(1, sizeof(iec61850_paf_data_t));
        if (pafdata == NULL)
            return PAF_ABORT;

        *user = pafdata;
    }

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
    {
    	uint16_t length;


        switch (pafdata->state)
        {
            /* Check the Start bytes. If they are not \x05\x64, don't advance state.
               Could be out of sync, junk data between frames, mid-stream pickup, etc. */
            case IEC61850_PAF_STATE__START:
                if (((uint8_t) *(data + bytes_processed)) == 0x03) //TPKT version
                    pafdata->state++;
                else
                    return PAF_ABORT;
                break;



            /* Read the length. */
            case IEC61850_PAF_STATE__LENGTH:

            	memcpy(&length,(data+2),2);
                pafdata->iec61850_length = length;







                pafdata->real_length = pafdata->iec61850_length;

                pafdata->state++;
                break;

            /* Set the flush point. */
            case IEC61850_PAF_STATE__SET_FLUSH:
                *fp = pafdata->real_length ;
                pafdata->state = IEC61850_PAF_STATE__START;
                return PAF_FLUSH;
        }

        bytes_processed++;
    }

    return PAF_SEARCH;
}

/* Take a IEC61850 config + Snort policy, iterate through ports, register PAF callback. */
int IEC61850AddPortsToPaf(struct _SnortConfig *sc, iec61850_config_t *config, tSfPolicyId policy_id)
{
    unsigned int i;

    for (i = 0; i < MAX_PORTS; i++)
    {
        if (config->ports[PORT_INDEX(i)] & CONV_PORT(i))
        {
            IEC61850PafRegisterPort(sc, (uint16_t) i, policy_id);
        }
    }

    return IEC61850_OK;
}
