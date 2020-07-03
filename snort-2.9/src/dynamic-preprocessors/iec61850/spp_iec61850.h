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
 * Dynamic preprocessor for the IEC-61850 protocol
 *
 */

#ifndef SPP_IEC61850_H
#define SPP_IEC61850_H

#include "config.h"
#include "sf_types.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
#include<stdint.h>
#include <glib.h>

/* GIDs, SIDs, Messages */
#define GENERATOR_SPP_IEC61850  145

#define IEC61850_BAD_CRC                    1
#define IEC61850_DROPPED_FRAME              2
#define IEC61850_DROPPED_SEGMENT            3
#define IEC61850_REASSEMBLY_BUFFER_CLEARED  4
#define IEC61850_RESERVED_ADDRESS           5
#define IEC61850_RESERVED_FUNCTION          6

#define IEC61850_PORTS_KEYWORD      "ports"
#define IEC61850_CHECK_CRC_KEYWORD  "check_crc"
#define IEC61850_MEMCAP_KEYWORD     "memcap"
#define IEC61850_DISABLED_KEYWORD   "disabled"


#define TPKT_HEADER_LENGTH 4
#define COTP_HEADER_LENGTH 3
#define ISO8327_HEADER_LENGTH 2
#define ISO8823_HEADER_LENGTH 7 //this is the fixed length for MMS data <120 Bytes

#define IEC61850_DROPPED_FRAME_STR "(spp_iec61850): IEC61850 Link-Layer Frame was dropped."
#define IEC61850_DROPPED_SEGMENT_STR "(spp_iec61850): IEC61850 Transport-Layer Segment was dropped during reassembly."
#define IEC61850_REASSEMBLY_BUFFER_CLEARED_STR "(spp_iec61850): IEC61850 Reassembly Buffer was cleared without reassembling a complete message."


#define MAX_PORTS 65536

/* Default IEC61850 port */
#define IEC61850_PORT 102

/* Memcap limits. */
#define MIN_IEC61850_MEMCAP 4144
#define MAX_IEC61850_MEMCAP (100 * 1024 * 1024)

/* Convert port value into an index for the dnp3_config->ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)




/* Session data flags */

/* IEC61850 minimum length: TPKT (4 octets) + COTP (3 octet) + 2*ISO8327 (4 octets) + ISO8823 (7 octets)*/
#define IEC61850_MIN_LEN 18


typedef enum _iec61850_reassembly_state_t
{
	IEC61850_REASSEMBLY_STATE__IDLE = 0,
	IEC61850_REASSEMBLY_STATE__ASSEMBLY,
	IEC61850_REASSEMBLY_STATE__DONE
} iec61850_reassembly_state_t;


// whether request or response
#define REQUEST_PDU 0
#define  RESPONSE_PDU 1

typedef enum _mmsPduType
{
	CONFIRMED_REQUEST_PDU=0,
	CONFIRMED_RESPONSE_PDU,
	CONFIRMED_ERROR_PDU,
	UNCONFIRMED_PDU,
	REJECT_PDU,
	CANCEL_REQUEST_PDU,
	CANCEL_RESPONSE_PDU,
	CANCEL_ERROR_PDU,
	INITIATE_REQUEST_PDU,
	INITIATE_RESPONSE_PDU,
	INITIATE_ERROR_PDU,
	CONCLUDE_REQUEST_PDU,
	CONCLUDE_RESPONSE_PDU,
	CONCLUDE_ERROR_PDU
}mmsPduType;
typedef struct _iec61850_reassembly_data_t
{
    char * buffer;
    uint16_t buflen;
    uint16_t maxLen;
    uint32_t segment;
    uint16_t currentPacketStarts;
    uint16_t mmsDataStart;
    iec61850_reassembly_state_t state;

} iec61850_reassembly_data_t;

typedef struct _iec61850_alter_values //structure introduced to keep the obj, variance, identifier , newvalue data
{
	GString * domainIDAndItemID;
	GString *structure;  // structure is a comma separated number format "first_level_node_number, 2nd_level_num,etc"
	uint16_t intStruct[10];
	GString *newVal;  //all the values for the dataModel in TLV format
	boolean done;

}iec61850_alter_values;
/* IEC61850 preprocessor configuration */
typedef struct _iec61850_config
{
    uint32_t memcap;
    uint8_t  ports[MAX_PORTS/8];
    int disabled;
    int ref_count;
    iec61850_alter_values values_to_alter[50];
    int numAlteredVal;
} iec61850_config_t;

/* IE61850 session data */


/* IEC61850 header structures */



typedef struct _COTP_header_t
{
	uint8_t length;
	uint8_t pdu_type;
	uint8_t TPDU_number;
	boolean isLastDataUnit;
}COTP_header_t;



typedef struct _iec61850_session_data
{
	uint8_t direction;

	 /* Reassembly stuff */
	iec61850_reassembly_data_t* request_rdata;
	iec61850_reassembly_data_t* responce_rdata;
	GNode * dataModel;
	GSList * requestList;
	iec61850_reassembly_data_t* common_rdata;
	GHashTable * hashTable;
    tSfPolicyId policy_id;
    tSfPolicyUserContextId context_id;
} iec61850_session_data_t;







typedef struct _mms_request_header_t
{
    uint32_t invokeID;
    uint8_t requestType; //There are 14  request types in mms
    uint8_t extendedObjClass;
    uint8_t typeOfextendedObjClass;
    GString * objectScope;
    uint8_t typeOfObjScope;
} iec61850_Object_header_t;

typedef struct _mms_read_request_t
		{
			int invokeID;
			int rootChild;
			GSList *domainIDAndItemID;


		}mms_read_request_t;

#define IEC61850_OK 1
#define IEC61850_FAIL (-1)



#endif /* SPP_IEC61850_H */
