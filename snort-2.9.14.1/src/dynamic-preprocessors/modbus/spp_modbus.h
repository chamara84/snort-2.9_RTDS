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
 * Dynamic preprocessor for the Modbus protocol
 *
 */

#ifndef SPP_MODBUS_H
#define SPP_MODBUS_H

#include "sf_types.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#define MAX_PORTS 65536

/* Default MODBUS port */
#define MODBUS_PORT 502

/* Convert port value into an index for the modbus_config->ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

/* Session data flags */
#define MODBUS_FUNC_RULE_FIRED  0x0001
#define MODBUS_UNIT_RULE_FIRED  0x0002
#define MODBUS_DATA_RULE_FIRED  0x0004


typedef struct _modbus_alter_values //structure introduced to keep the obj, variance, identifier , newvalue data
{
	uint8_t type;
	uint16_t identifier;
	uint16_t integer_value;
	uint16_t old_value;
	bool done;

}modbus_alter_values_t;

/* Modbus preprocessor configuration */
typedef struct _modbus_config
{
    uint8_t ports[MAX_PORTS/8];

    int ref_count;
    modbus_alter_values_t values_to_alter[50];
    uint16_t numAlteredVal;
    uint32_t memcap;
    int disabled;
} modbus_config_t;

typedef struct _modbus_request
{	uint16_t transactionID;
	uint8_t unitID;
	uint8_t function;
	uint16_t address;
	uint16_t quantity;
}modbus_request_t;


/* Modbus session data */
typedef struct _modbus_session_data
{
    uint8_t func;
    uint8_t unit;
    uint16_t flags;
    modbus_request_t request_data; //used to map the indices of coils and registers this information is not available in the responce
    tSfPolicyId policy_id;
    tSfPolicyUserContextId context_id;
} modbus_session_data_t;


#define MODBUS_PORTS_KEYWORD    "ports"
#define MODBUS_MEMCAP_KEYWORD   "memcap"
/* Memcap limits. */
#define MIN_MODBUS_MEMCAP 4144
#define MAX_MODBUS_MEMCAP (100 * 1024 * 1024)

#define MODBUS_OK 1
#define MODBUS_FAIL (-1)

#endif /* SPP_MODBUS_H */
