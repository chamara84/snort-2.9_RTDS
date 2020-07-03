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
 * Dynamic preprocessor for the IEC-104 protocol
 *
 */

#ifndef SPP_IEC104_H
#define SPP_IEC104_H

#include "config.h"
#include "sf_types.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
#include<stdint.h>
#include <glib.h>

/* GIDs, SIDs, Messages */
#define GENERATOR_SPP_IEC104  145

#define IEC104_BAD_CRC                    1
#define IEC104_DROPPED_FRAME              2
#define IEC104_DROPPED_SEGMENT            3
#define IEC104_REASSEMBLY_BUFFER_CLEARED  4
#define IEC104_RESERVED_ADDRESS           5
#define IEC104_RESERVED_FUNCTION          6

#define IEC104_PORTS_KEYWORD      "ports"
#define IEC104_CHECK_CRC_KEYWORD  "check_crc"
#define IEC104_MEMCAP_KEYWORD     "memcap"
#define IEC104_DISABLED_KEYWORD   "disabled"


#define IEC104_START_BYTES 0x68

#define IEC104_DROPPED_FRAME_STR "(spp_iec104): IEC104 Link-Layer Frame was dropped."
#define IEC104_DROPPED_SEGMENT_STR "(spp_iec104): IEC104 Transport-Layer Segment was dropped during reassembly."
#define IEC104_REASSEMBLY_BUFFER_CLEARED_STR "(spp_iec104): IEC104 Reassembly Buffer was cleared without reassembling a complete message."


#define MAX_PORTS 65536

/* Default IEC103 port */
#define IEC104_PORT 2404

/* Memcap limits. */
#define MIN_IEC104_MEMCAP 4144
#define MAX_IEC104_MEMCAP (100 * 1024 * 1024)

/* Convert port value into an index for the dnp3_config->ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

/* Packet Type */
#define IEC104_I 0
#define IEC104_U 1
#define IEC104_S 2

#define IEC104_START_BYTE 0x68
/* Session data flags */

/* IEC104 minimum length: start (1 octets) + len (1 octet) + control field (4 octets)*/
#define IEC104_MIN_LEN 6
#define IEC60870_5_104_MAX_ASDU_LENGTH 249
#define IEC60870_5_104_APCI_LENGTH 6

/**
 * \brief Message type IDs
 */
typedef enum {
    M_SP_NA_1 = 1,
    M_SP_TA_1 = 2,
    M_DP_NA_1 = 3,
    M_DP_TA_1 = 4,
    M_ST_NA_1 = 5,
    M_ST_TA_1 = 6,
    M_BO_NA_1 = 7,
    M_BO_TA_1 = 8,
    M_ME_NA_1 = 9,
    M_ME_TA_1 = 10,
    M_ME_NB_1 = 11,
    M_ME_TB_1 = 12,
    M_ME_NC_1 = 13,
    M_ME_TC_1 = 14,
    M_IT_NA_1 = 15,
    M_IT_TA_1 = 16,
    M_EP_TA_1 = 17,
    M_EP_TB_1 = 18,
    M_EP_TC_1 = 19,
    M_PS_NA_1 = 20,
    M_ME_ND_1 = 21,
    M_SP_TB_1 = 30,
    M_DP_TB_1 = 31,
    M_ST_TB_1 = 32,
    M_BO_TB_1 = 33,
    M_ME_TD_1 = 34,
    M_ME_TE_1 = 35,
    M_ME_TF_1 = 36,
    M_IT_TB_1 = 37,
    M_EP_TD_1 = 38,
    M_EP_TE_1 = 39,
    M_EP_TF_1 = 40,
    S_IT_TC_1 = 41,
    C_SC_NA_1 = 45,
    C_DC_NA_1 = 46,
    C_RC_NA_1 = 47,
    C_SE_NA_1 = 48,
    C_SE_NB_1 = 49,
    C_SE_NC_1 = 50,
    C_BO_NA_1 = 51,
    C_SC_TA_1 = 58,
    C_DC_TA_1 = 59,
    C_RC_TA_1 = 60,
    C_SE_TA_1 = 61,
    C_SE_TB_1 = 62,
    C_SE_TC_1 = 63,
    C_BO_TA_1 = 64,
    M_EI_NA_1 = 70,
    S_CH_NA_1 = 81,
    S_RP_NA_1 = 82,
    S_AR_NA_1 = 83,
    S_KR_NA_1 = 84,
    S_KS_NA_1 = 85,
    S_KC_NA_1 = 86,
    S_ER_NA_1 = 87,
    S_US_NA_1 = 90,
    S_UQ_NA_1 = 91,
    S_UR_NA_1 = 92,
    S_UK_NA_1 = 93,
    S_UA_NA_1 = 94,
    S_UC_NA_1 = 95,
    C_IC_NA_1 = 100,
    C_CI_NA_1 = 101,
    C_RD_NA_1 = 102,
    C_CS_NA_1 = 103,
    C_TS_NA_1 = 104,
    C_RP_NA_1 = 105,
    C_CD_NA_1 = 106,
    C_TS_TA_1 = 107,
    P_ME_NA_1 = 110,
    P_ME_NB_1 = 111,
    P_ME_NC_1 = 112,
    P_AC_NA_1 = 113,
    F_FR_NA_1 = 120,
    F_SR_NA_1 = 121,
    F_SC_NA_1 = 122,
    F_LS_NA_1 = 123,
    F_AF_NA_1 = 124,
    F_SG_NA_1 = 125,
    F_DR_TA_1 = 126,
    F_SC_NB_1 = 127
} IEC104_TypeID;


typedef enum {
    CS101_COT_PERIODIC = 1,
    CS101_COT_BACKGROUND_SCAN = 2,
    CS101_COT_SPONTANEOUS = 3,
    CS101_COT_INITIALIZED = 4,
    CS101_COT_REQUEST = 5,
    CS101_COT_ACTIVATION = 6,
    CS101_COT_ACTIVATION_CON = 7,
    CS101_COT_DEACTIVATION = 8,
    CS101_COT_DEACTIVATION_CON = 9,
    CS101_COT_ACTIVATION_TERMINATION = 10,
    CS101_COT_RETURN_INFO_REMOTE = 11,
    CS101_COT_RETURN_INFO_LOCAL = 12,
    CS101_COT_FILE_TRANSFER = 13,
    CS101_COT_AUTHENTICATION = 14,
    CS101_COT_MAINTENANCE_OF_AUTH_SESSION_KEY = 15,
    CS101_COT_MAINTENANCE_OF_USER_ROLE_AND_UPDATE_KEY = 16,
    CS101_COT_INTERROGATED_BY_STATION = 20,
    CS101_COT_INTERROGATED_BY_GROUP_1 = 21,
    CS101_COT_INTERROGATED_BY_GROUP_2 = 22,
    CS101_COT_INTERROGATED_BY_GROUP_3 = 23,
    CS101_COT_INTERROGATED_BY_GROUP_4 = 24,
    CS101_COT_INTERROGATED_BY_GROUP_5 = 25,
    CS101_COT_INTERROGATED_BY_GROUP_6 = 26,
    CS101_COT_INTERROGATED_BY_GROUP_7 = 27,
    CS101_COT_INTERROGATED_BY_GROUP_8 = 28,
    CS101_COT_INTERROGATED_BY_GROUP_9 = 29,
    CS101_COT_INTERROGATED_BY_GROUP_10 = 30,
    CS101_COT_INTERROGATED_BY_GROUP_11 = 31,
    CS101_COT_INTERROGATED_BY_GROUP_12 = 32,
    CS101_COT_INTERROGATED_BY_GROUP_13 = 33,
    CS101_COT_INTERROGATED_BY_GROUP_14 = 34,
    CS101_COT_INTERROGATED_BY_GROUP_15 = 35,
    CS101_COT_INTERROGATED_BY_GROUP_16 = 36,
    CS101_COT_REQUESTED_BY_GENERAL_COUNTER = 37,
    CS101_COT_REQUESTED_BY_GROUP_1_COUNTER = 38,
    CS101_COT_REQUESTED_BY_GROUP_2_COUNTER = 39,
    CS101_COT_REQUESTED_BY_GROUP_3_COUNTER = 40,
    CS101_COT_REQUESTED_BY_GROUP_4_COUNTER = 41,
    CS101_COT_UNKNOWN_TYPE_ID = 44,
    CS101_COT_UNKNOWN_COT = 45,
    CS101_COT_UNKNOWN_CA = 46,
    CS101_COT_UNKNOWN_IOA = 47
} IEC104_CauseOfTransmission;

//information element lengths

#define SIQ_LEN 1
#define DIQ_LEN 1
#define BSI_LEN 4
#define SCD_LEN 4
#define QDS_LEN 1
#define SEP_LEN 1
#define VTI_LEN 1
#define NVA_LEN 2
#define SVA_LEN 2
#define IEEE754_LEN 4
#define BCR_LEN 5
#define CP56Time_LEN 7
#define CP24Time_LEN 3
#define CP16Time_LEN 2
#define SPE_LEN 1
#define OCI_LEN 1
#define QDP_LEN 1


//length of different ASDU type objects
#define LEN_M_SP_NA_1  SIQ_LEN
#define LEN_M_SP_TA_1  SIQ_LEN+CP24Time_LEN
#define LEN_M_DP_NA_1  DIQ_LEN
#define LEN_M_DP_TA_1  DIQ_LEN+CP24Time_LEN
#define LEN_M_ST_NA_1  VTI_LEN+QDS_LEN
#define LEN_M_ST_TA_1  VTI_LEN+QDS_LEN+CP24Time_LEN
#define LEN_M_BO_NA_1  BSI_LEN+QDS_LEN
#define LEN_M_BO_TA_1  BSI_LEN+QDS_LEN+CP24Time_LEN
#define LEN_M_ME_NA_1  NVA_LEN+QDS_LEN
#define LEN_M_ME_TA_1  NVA_LEN+QDS_LEN+CP24Time_LEN
#define LEN_M_ME_NB_1  SVA_LEN+QDS_LEN
#define LEN_M_ME_TB_1  SVA_LEN+QDS_LEN+CP24Time_LEN
#define LEN_M_ME_NC_1  IEEE754_LEN+QDS_LEN
#define LEN_M_ME_TC_1  IEEE754_LEN+QDS_LEN+CP24Time_LEN
#define LEN_M_IT_NA_1  BCR_LEN
#define LEN_M_IT_TA_1  BCR_LEN+CP24Time_LEN
#define LEN_M_EP_TA_1  CP16Time_LEN+CP24Time_LEN
#define LEN_M_EP_TB_1  SEP_LEN+QDP_LEN+CP16Time_LEN+CP24Time_LEN
#define LEN_M_EP_TC_1  OCI_LEN+QDP_LEN+CP16Time_LEN+CP24Time_LEN
#define LEN_M_PS_NA_1  SCD_LEN+QDS_LEN
#define LEN_M_ME_ND_1 NVA_LEN
//#define LEN_M_SP_TB_1
//#define LEN_M_DP_TB_1
//#define LEN_M_ST_TB_1
//#define LEN_M_BO_TB_1
//#define LEN_M_ME_TD_1
//#define LEN_M_ME_TE_1
//#define LEN_M_ME_TF_1
//#define LEN_M_IT_TB_1
//#define LEN_M_EP_TD_1
//#define LEN_M_EP_TE_1
//#define LEN_M_EP_TF_1
//#define LEN_S_IT_TC_1
//#define LEN_C_SC_NA_1
//#define LEN_C_DC_NA_1
//#define LEN_C_RC_NA_1
//#define LEN_C_SE_NA_1
//#define LEN_C_SE_NB_1
//#define LEN_C_SE_NC_1
//#define LEN_C_BO_NA_1
//#define LEN_C_SC_TA_1
//#define LEN_C_DC_TA_1
//#define LEN_C_RC_TA_1
//#define LEN_C_SE_TA_1
//#define LEN_C_SE_TB_1
//#define LEN_C_SE_TC_1
//#define LEN_C_BO_TA_1
//#define LEN_M_EI_NA_1
//#define LEN_S_CH_NA_1
//#define LEN_S_RP_NA_1
//#define LEN_S_AR_NA_1
//#define LEN_S_KR_NA_1
//#define LEN_S_KS_NA_1
//#define LEN_S_KC_NA_1
//#define LEN_S_ER_NA_1
//#define LEN_S_US_NA_1
//#define LEN_S_UQ_NA_1
//#define LEN_S_UR_NA_1
//#define LEN_S_UK_NA_1
//#define LEN_S_UA_NA_1
//#define LEN_S_UC_NA_1
//#define LEN_C_IC_NA_1
//#define LEN_C_CI_NA_1
//#define LEN_C_RD_NA_1
//#define LEN_C_CS_NA_1
//#define LEN_C_TS_NA_1
//#define LEN_C_RP_NA_1
//#define LEN_C_CD_NA_1
//#define LEN_C_TS_TA_1
//#define LEN_P_ME_NA_1
//#define LEN_P_ME_NB_1
//#define LEN_P_ME_NC_1
//#define LEN_P_AC_NA_1
//#define LEN_F_FR_NA_1
//#define LEN_F_SR_NA_1
//#define LEN_F_SC_NA_1
//#define LEN_F_LS_NA_1
//#define LEN_F_AF_NA_1
//#define LEN_F_SG_NA_1
//#define LEN_F_DR_TA_1
//#define LEN_F_SC_NB_1



typedef enum _iec104_reassembly_state_t
{
	IEC104_REASSEMBLY_STATE__IDLE = 0,
	IEC104_REASSEMBLY_STATE__ASSEMBLY,
	IEC104_REASSEMBLY_STATE__DONE
} iec104_reassembly_state_t;

typedef struct _iec104_reassembly_data_t
{
    char buffer[IEC60870_5_104_MAX_ASDU_LENGTH];
    uint16_t buflen;
    uint8_t last_seq;
    uint8_t typeID;
    uint8_t numObj;
    uint8_t orgAddress;
    uint16_t asduAddress;
    uint32_t startingAddress;

} iec104_reassembly_data_t;

typedef struct _iec104_alter_values //structure introduced to keep the obj, variance, identifier , newvalue data
{
	uint8_t typeID;
	uint16_t asduAddress;
	uint32_t infObjAddress;
	float floating_point_val;
	uint64_t integer_value;
	boolean done;

}iec104_alter_values;
/* IEC104 preprocessor configuration */
typedef struct _iec104_config
{
    uint32_t memcap;
    uint8_t  ports[MAX_PORTS/8];
    uint8_t  check_crc;
    int disabled;

    int ref_count;
    iec104_alter_values values_to_alter[50];
    int numAlteredVal;
} iec104_config_t;

/* IE104 session data */


/* IEC104 header structures */
typedef struct _iec104_header_t
{
    uint8_t start;
    uint8_t len;
    uint8_t format; //whether I, S or U
    uint16_t sendSeqNo;
    uint16_t recvSeqNo;
    uint8_t testFrame;
    uint8_t stopDataTransmission;
    uint8_t startDataTransmission;
} iec104_header_t;


typedef struct _iec104_asdu_header_t
{
	IEC104_TypeID type;
    uint8_t sq;
    uint8_t numObjects;
    boolean testBit;
    boolean positiveOrNegative;
    IEC104_CauseOfTransmission cot; //the two most significant bits of cot are test bit and P/N bit
    uint8_t orgAddress;
    uint16_t asduAddress;
} iec104_asdu_header_t;

typedef struct _iec104_session_data
{

	iec104_header_t apci;
	iec104_asdu_header_t asdu_header;
    /* Reassembly stuff */
	GHashTable *hash;

    tSfPolicyId policy_id;
    tSfPolicyUserContextId context_id;
} iec104_session_data_t;







typedef struct _iec104_Object_header_t
{
    uint32_t informationObjAddress;
    uint8_t informationElements[10]; //how to know the length of information based on the type in ASDU header
    uint8_t infElementBytesUsed;
    uint16_t dataOffsetFromStart; //
} iec104_Object_header_t;



#define IEC104_OK 1
#define IEC104_FAIL (-1)



#endif /* SPP_IEC103_H */
