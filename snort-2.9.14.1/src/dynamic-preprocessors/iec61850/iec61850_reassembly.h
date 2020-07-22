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
 * Dynamic preprocessor for the DNP3 protocol
 *
 */

#ifndef IEC61850_REASSEMBLY__H
#define IEC61850_REASSEMBLY__H

#include "sf_types.h"
#include "sf_snort_packet.h"
#include "spp_iec61850.h"


int IEC61850FullReassembly(iec61850_config_t *config, iec61850_session_data_t *session, SFSnortPacket *packet, uint8_t *pdu_start, uint16_t pdu_length);
static int
BerDecoder_decodeLength(uint8_t* buffer, int* length, int bufPos, int maxBufPos);
static int32_t
BerDecoder_decodeInt32(uint8_t* buffer, int intlen, int bufPos);
static bool
BerDecoder_decodeBoolean(uint8_t* buffer, int bufPos);
static double
BerDecoder_decodeDouble(uint8_t* buffer, int bufPos);

#endif /* IEC61850_REASSEMBLY__H */
