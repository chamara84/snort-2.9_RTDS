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
 * Dynamic preprocessor for the PMU protocol
 *
 */

#ifndef SPP_PMU_H
#define SPP_PMU_H

#include "sf_types.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
#include <glib.h>
#include <glib/gprintf.h>

#define MAX_PORTS 65536

/* Default PMU port */
#define PMU_PORT 4712

/* Convert port value into an index for the pmu_config->ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

/* Session data flags */
#define PMU_FUNC_RULE_FIRED  0x0001
#define PMU_UNIT_RULE_FIRED  0x0002
#define PMU_DATA_RULE_FIRED  0x0004


typedef struct _pmu_alter_values //structure introduced to keep the obj, variance, identifier , newvalue data
{
	GString * pmuName;
	uint8_t type;
	GString * identifier;
	float real_value;
	float imaginary_value;
	uint16_t digValue;
	bool done;

}pmu_alter_values_t;

/* PMU preprocessor configuration */
typedef struct _pmu_config
{
    uint8_t ports[MAX_PORTS/8];

    int ref_count;
    pmu_alter_values_t values_to_alter[50];
    uint16_t numAlteredVal;
    uint32_t memcap;
    int disabled;
} pmu_config_t;




typedef struct
	{
	uint32_t FractionOfSecond;
			uint8_t TimeQuality;


	}C37118FracSec;

typedef enum
	{
		DATA_FRAME = 0,
		HEADER_FRAME = 1,
		CONFIGURATION_FRAME_1 = 2,
		CONFIGURATION_FRAME_2 = 3,
		CONFIGURATION_FRAME_3 = 5,
		COMMAND_FRAME = 4
	}C37118HdrFrameType;


typedef struct
		{

			uint8_t Type; // 0=Volt, 1=Current;
			uint32_t PhasorScalar;
		}C37118PhasorUnit;



typedef	struct
		{

			// 0 = Single point on wave
			// 1 = RMS of analog input
			// 2 = peak of analog input
			// 5-64 = reserved
			int Type_X;
			int32_t AnalogScalar;
		}C37118AnalogUnit;





typedef	struct
		{

			uint16_t DigNormalStatus;
			uint16_t DigValidInputs;
		}C37118DigitalUnit;



		typedef enum
		{
			PHC0_ZERO_SEQUENCE = 0,
			PHC1_POSITIVE_SEQUENCE = 1,
			PHC2_NEGATIVE_SEQUENCE= 2,
			PHC3_RESERVED = 3,
			PHC4_PHASE_A = 4,
			PHC5_PHASE_B = 5,
			PHC6_PHASE_C = 6,
			PHC7_RESERVED = 7
		}PhasorComponentCodeEnum;

typedef struct
			{
				bool Bit0_0xPhasorFormatRect_1xMagnitudeAndAngle;
				bool Bit1_0xPhasorsIsInt_1xPhasorFloat;
				bool Bit2_0xAnalogIsInt_1xAnalogIsFloat;
				bool Bit3_0xFreqIsInt_1xFreqIsFloat;
			}C37118PmuFormat;

typedef	struct
				{
					bool Bit0_1xFreqIs50_0xFreqIs60;


				}C37118NomFreq;
typedef	struct
		{
			GString *StationName ;

			uint16_t IdCode;
			C37118PmuFormat DataFormat;
			GSList *phasorChnNames ;
			GSList * analogChnNames;
			GSList * digitalChnNames;
			GSList * PhasorUnit; // accepts a pointer to C37118PhasorUnit
			GSList * AnalogUnit;// accepts a pointer to C37118AnalogUnit
			GSList * DigitalUnit; // 16 chn names per unit accepts a pointer to C37118DigitalUnit
			C37118NomFreq NomFreqCode;
			uint16_t ConfChangeCnt;
			uint16_t numPhasors;
			uint16_t numAnalog;
			uint16_t numDigital;
		}C37118PmuConfiguration;


typedef struct
			{
				uint8_t Flags;
				uint32_t TimeBase;
			}C37118TimeBase;

typedef struct
				{


					int16_t m_datarateRaw;
				}C37118DataRate;

typedef struct
			{

				C37118TimeBase TimeBase;
				GSList * PMUs; //accepts pointer to C37118PmuConfiguration
				C37118DataRate DataRate;
				uint16_t NumPMU;
				uint16_t FooterCrc16;
			}C37118PdcConfiguration;

typedef struct C37118SyncField
	{
	char LeadIn; // Should be 0xAA
			C37118HdrFrameType FrameType;
			char Version;

	}C37118SyncField;


typedef struct
	{
		C37118SyncField Sync;
		uint16_t FrameSize;
		uint16_t IdCode;
		uint32_t SOC;
		C37118FracSec FracSec;
	}C37118FrameHeader;


/* PMU session data */
typedef struct _pmu_session_data
{
	C37118SyncField Sync;
	uint16_t FrameSize;
	uint16_t IdCode;
	uint32_t SOC;
	C37118FracSec FracSec;
	C37118PdcConfiguration pmuConfig2;
	boolean partialData; //if 1 on going construction, if 0 newFrame, if 2 fullFrame
	GString *FrameData;
    tSfPolicyId policy_id;
    boolean capturedConfig2;
    tSfPolicyUserContextId context_id;
    GHashTable * pmuRefTable; //this table returns the offset of the message for a given pmu_nameValue_name pair concatenated
} pmu_session_data_t;


#define PMU_PORTS_KEYWORD    "ports"
#define PMU_MEMCAP_KEYWORD   "memcap"
/* Memcap limits. */
#define MIN_PMU_MEMCAP 4144
#define MAX_PMU_MEMCAP (100 * 1024 * 1024)

#define PMU_OK 1
#define PMU_FAIL (-1)

#endif /* SPP_PMU_H */
