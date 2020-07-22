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

#ifndef SPP_SV_H
#define SPP_SV_H

#include "config.h"
#include "sf_types.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
#include<stdint.h>
#include "glib.h"


/* GIDs, SIDs, Messages */
#define GENERATOR_SPP_SV  145

#define SV_BAD_CRC                    1
#define SV_DROPPED_FRAME              2
#define SV_DROPPED_SEGMENT            3
#define SV_REASSEMBLY_BUFFER_CLEARED  4
#define SV_RESERVED_ADDRESS           5
#define SV_RESERVED_FUNCTION          6

#define SV_PORTS_KEYWORD      "ports"
#define SV_CHECK_CRC_KEYWORD  "check_crc"
#define SV_MEMCAP_KEYWORD     "memcap"
#define SV_DISABLED_KEYWORD   "disabled"


#define SV_START_BYTES 0x68

#define SV_DROPPED_FRAME_STR "(spp_sv): SV Link-Layer Frame was dropped."
#define SV_DROPPED_SEGMENT_STR "(spp_sv): SV Transport-Layer Segment was dropped during reassembly."
#define SV_REASSEMBLY_BUFFER_CLEARED_STR "(spp_sv): SV Reassembly Buffer was cleared without reassembling a complete message."


#define MAX_PORTS 65536

/* Default IEC103 port */
#define SV_PORT 2404

/* Memcap limits. */
#define MIN_SV_MEMCAP 4144
#define MAX_SV_MEMCAP (100 * 1024 * 1024)

/* Convert port value into an index for the dnp3_config->ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

/* Packet Type */
#define SV_I 0
#define SV_U 1
#define SV_S 2

#define SV_START_BYTE 0x68
/* Session data flags */

/* SV minimum length: start (1 octets) + len (1 octet) + control field (4 octets)*/
#define SV_MIN_LEN 6
#define SV_MAX_ASDU_LENGTH 1500
#define SV_APCI_LENGTH 10

/**
 * \brief Message type IDs
 */



typedef struct _sv_reassembly_data_t
{
    char buffer[SV_MAX_ASDU_LENGTH];
    uint16_t buflen;
    uint8_t last_seq;
    uint8_t typeID;
    uint8_t numObj;
    uint8_t orgAddress;
    uint16_t asduAddress;
    uint32_t startingAddress;

} sv_reassembly_data_t;

typedef struct _sv_alter_values //structure introduced to keep the obj, variance, identifier , newvalue data
{
	GString * svID;
	GString * datSet;
	uint16_t asduNo;
	float floating_point_val;
	uint64_t integer_value;
	GString *newVal;
	boolean done;
	uint8_t type;

}sv_alter_values;
/* SV preprocessor configuration */
typedef struct _sv_config
{
    uint32_t memcap;
    uint8_t  ports[MAX_PORTS/8];
    uint8_t  check_crc;
    int disabled;

    int ref_count;
    sv_alter_values values_to_alter[50];
    int numAlteredVal;
    GString * interface;
} SVConfig,sv_config_t;

/* IE61850 session data */


/* SV header structures */
typedef struct _sv_header_t
{
    uint16_t appID;
    uint16_t len;
    uint16_t reserved_1;
    uint16_t reserved_2;

} sv_header_t;


typedef struct _sv_asdu_header_t
{

	GString * svID;   //ASN Tag 0x80
	GString * datSet; //ASN Tag 0x81
	uint16_t smpCnt; //ASN Tag 0x82
	uint32_t confRev; //ASN Tag 0x83
	struct timeval refrTm; //ASN Tag 0x84
    uint8_t smpSynch; //ASN Tag 0x85
    uint16_t smpRate; //ASN Tag 0x86
    GString * dataBuffer; //ASN Tag 0x87
    uint16_t smpMod; //ASN Tag 0x88
    int dataBufferLength;
    uint16_t offset;

} sv_asdu_header_t;


typedef struct _sv_frame_identifier_t
{
//GString * gocbref;
uint32_t phsor1;

}sv_frame_identifier_t;



typedef struct _sv_Object_header_t
{
    uint32_t dataNum;
    uint8_t informationElements[11]; //how to know the length of information based on the type in ASDU header
    uint8_t infElementBytesUsed;
    uint16_t dataOffsetFromStart; //
    uint8_t type;
} sv_Object_header_t;



#define SV_OK 1
#define SV_FAIL (-1)

//**************PROTOTYPES*****************

static guint svObjectHash(gconstpointer dataObject);
static gboolean svObjectEqual(gconstpointer dataObject1,gconstpointer dataObject2);
static void valueDestroyFunc(gconstpointer dataObject);
static void keyDestroyFunc(gconstpointer dataObject);

#endif /* SPP_IEC103_H */
