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
 * Protocol Aware Flushing (PAF) code for IEC104 preprocessor.
 *
 */

#ifndef IEC104_PAF__H
#define IEC104_PAF__H

#include "spp_iec104.h"
#include "stream_api.h"

int IEC104AddPortsToPaf(struct _SnortConfig *sc, iec104_config_t *config, tSfPolicyId policy_id);
int IEC104AddServiceToPaf(struct _SnortConfig *sc, uint16_t service, tSfPolicyId policy_id);

#endif /* IEC104_PAF__H */
