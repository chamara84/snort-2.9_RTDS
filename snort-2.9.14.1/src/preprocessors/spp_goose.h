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
 * E-mail: chamara@rtds.com
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
#include "glib.h"


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


#define IEC61850_START_BYTES 0x68

#define IEC61850_DROPPED_FRAME_STR "(spp_iec61850): IEC61850 Link-Layer Frame was dropped."
#define IEC61850_DROPPED_SEGMENT_STR "(spp_iec61850): IEC61850 Transport-Layer Segment was dropped during reassembly."
#define IEC61850_REASSEMBLY_BUFFER_CLEARED_STR "(spp_iec61850): IEC61850 Reassembly Buffer was cleared without reassembling a complete message."


#define MAX_PORTS 65536

/* Default IEC103 port */
#define IEC61850_PORT 2404

/* Memcap limits. */
#define MIN_IEC61850_MEMCAP 4144
#define MAX_IEC61850_MEMCAP (100 * 1024 * 1024)

/* Convert port value into an index for the dnp3_config->ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

/* Packet Type */
#define IEC61850_I 0
#define IEC61850_U 1
#define IEC61850_S 2

#define IEC61850_START_BYTE 0x68
/* Session data flags */

/* IEC61850 minimum length: start (1 octets) + len (1 octet) + control field (4 octets)*/
#define IEC61850_MIN_LEN 6
#define IEC60870_5_61850_MAX_ASDU_LENGTH 1500
#define IEC60870_5_61850_APCI_LENGTH 10

/**
 * \brief Message type IDs
 */



typedef struct _iec61850_reassembly_data_t
{
    char buffer[IEC60870_5_61850_MAX_ASDU_LENGTH];
    uint16_t buflen;
    uint8_t last_seq;
    uint8_t typeID;
    uint8_t numObj;
    uint8_t orgAddress;
    uint16_t asduAddress;
    uint32_t startingAddress;

} iec61850_reassembly_data_t;

typedef struct _iec61850_alter_values //structure introduced to keep the obj, variance, identifier , newvalue data
{
	GString * gocbRef;
	GString * datSet;
	uint16_t dataItemNo;
	float floating_point_val;
	uint64_t integer_value;
	GString *newVal;
	boolean done;

}iec61850_alter_values;
/* IEC61850 preprocessor configuration */
typedef struct _iec61850_config
{
    uint32_t memcap;
    uint8_t  ports[MAX_PORTS/8];
    uint8_t  check_crc;
    int disabled;
    GString * interface;
    int ref_count;
    iec61850_alter_values values_to_alter[50];
    int numAlteredVal;
} IEC61850Config,iec61850_config_t;

/* IE61850 session data */


/* IEC61850 header structures */
typedef struct _iec61850_header_t
{
    uint16_t appID;
    uint16_t len;
    uint16_t reserved_1;
    uint16_t reserved_2;

} iec61850_header_t;


typedef struct _iec61850_asdu_header_t
{

	GString * gocbRef;   //ASN Tag 0x80
	uint32_t timeToLive; //ASN Tag 0x81
	GString * datSet; //ASN Tag 0x82
	GString * goID; //ASN Tag 0x83
	struct timeval t; //ASN Tag 0x84
    uint32_t stNum; //ASN Tag 0x85
    uint32_t sqNum; //ASN Tag 0x86
    boolean simulation; //ASN Tag 0x87
    uint32_t confRev; //ASN Tag 0x88
    boolean ndsCom; //ASN Tag 0x89
    uint32_t numDataSetEntries; //ASN Tag 0x8a

} iec61850_asdu_header_t;


typedef struct _frame_identifier_t
{
//GString * gocbref;
uint32_t sqNum;
uint32_t stNum;
struct timeval tv;
}frame_identifier_t;



typedef struct _iec61850_Object_header_t
{
    uint32_t dataNum;
    uint8_t informationElements[11]; //how to know the length of information based on the type in ASDU header
    uint8_t infElementBytesUsed;
    uint16_t dataOffsetFromStart; //
    uint8_t type;
} iec61850_Object_header_t;



#define IEC61850_OK 1
#define IEC61850_FAIL (-1)

//**************PROTOTYPES*****************

static guint iec61850ObjectHash(gconstpointer dataObject);
static gboolean iec61850ObjectEqual(gconstpointer dataObject1,gconstpointer dataObject2);
static void valueDestroyFunc(gconstpointer dataObject);
static void keyDestroyFunc(gconstpointer dataObject);

#endif /* SPP_IEC103_H */
