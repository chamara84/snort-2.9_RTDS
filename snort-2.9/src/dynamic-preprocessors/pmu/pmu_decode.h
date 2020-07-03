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

#ifndef PMU_DECODE_H
#define PMU_DECODE_H

#include <stdint.h>
#include <string.h>
#include <complex.h>
#include <math.h>
#include <stdint.h>
#include <glib.h>
#include <glib/gslist.h>
#include <glib/gprintf.h>
#include "sf_snort_plugin_api.h"
#include "spp_pmu.h"


/* Need 8 bytes for PMU frame header */
#define PMU_MIN_LEN 14

/* GIDs, SIDs, and Strings */
#define GENERATOR_SPP_PMU 144

#define PMU_BAD_LENGTH 1
#define PMU_BAD_PROTO_ID 2
#define PMU_RESERVED_FUNCTION 3
#define PMU_MISSED_TRANSACTION 4

#define PMU_BAD_LENGTH_STR "(spp_pmu): Length in PMU MBAP header does not match the length needed for the given PMU function."
#define PMU_BAD_PROTO_ID_STR "(spp_pmu): PMU protocol ID is non-zero."
#define PMU_RESERVED_FUNCTION_STR "(spp_pmu): Reserved PMU function code in use."

int PMUDecode(pmu_session_data_t *session, pmu_config_t *config, SFSnortPacket *packet);
static char *trimwhitespace(char *str);



////typedef enum { false, true } bool;
//
//

//
//
//	static struct C37118FracSec Create( uint32_t fracSec, int leapSecOffset, bool leapSecPending, int cloclErrorLevel );
//	static void GetParsedQuality( int* outLeapSecOffset, bool* outLeapSecPending, float* outTimeClockMaxErrorSec, bool* outIsRealiable );
//
//	struct C37118NomFreq
//	{
//		bool Bit0_1xFreqIs50_0xFreqIs60;
//
//
//	};
//
//
//	struct C37118TimeBase
//	{
//		uint8_t Flags;
//		uint32_t TimeBase;
//	};
//
//	struct C37118PmuFormat
//	{
//		bool Bit0_0xPhasorFormatRect_1xMagnitudeAndAngle;
//		bool Bit1_0xPhasorsIsInt_1xPhasorFloat;
//		bool Bit2_0xAnalogIsInt_1xAnalogIsFloat;
//		bool Bit3_0xFreqIsInt_1xFreqIsFloat;
//	};
//
//	struct C37118PhasorUnit
//	{
//
//		uint8_t Type; // 0=Volt, 1=Current;
//		uint32_t PhasorScalar;
//	};
//
//
//
//	struct C37118AnalogUnit
//	{
//
//		// 0 = Single point on wave
//		// 1 = RMS of analog input
//		// 2 = peak of analog input
//		// 5-64 = reserved
//		int Type_X;
//		int32_t AnalogScalar;
//	};
//
//
//
//
//
//	struct C37118DigitalUnit
//	{
//
//
//
//
//		uint16_t DigNormalStatus;
//		uint16_t DigValidInputs;
//	};
//
//
//
//	typedef enum
//	{
//		PHC0_ZERO_SEQUENCE = 0,
//		PHC1_POSITIVE_SEQUENCE = 1,
//		PHC2_NEGATIVE_SEQUENCE= 2,
//		PHC3_RESERVED = 3,
//		PHC4_PHASE_A = 4,
//		PHC5_PHASE_B = 5,
//		PHC6_PHASE_C = 6,
//		PHC7_RESERVED = 7
//	}PhasorComponentCodeEnum;
//
//	struct C37118PhasorScale_Ver3
//	{
//
//
//		// Group 1
//		uint16_t PhasorBits; // Skip impl for now..
//		uint8_t VoltOrCurrent; // 0 = voltage, 1 = current
//		PhasorComponentCodeEnum PhasorComponentCode;
//
//		// Group 2+3
//		float ScaleFactorOne_Y; // Scales primary volt/amperes
//		float ScaleFactorTwo_Angle; // Scales phasor angle adjustment
//	};
//
//
//
//
//
//
//
//	struct C37118AnalogScale_Ver3
//	{
//
//
//		float Scale;
//		float Offset;
//	};
//
//
//
//	struct C37118PmuConfiguration
//	{
//		GString *StationName ;
//
//		uint16_t IdCode;
//		struct C37118PmuFormat DataFormat;
//		GSList *phasorChnNames ;
//		GSList * analogChnNames;
//		GSList * digitalChnNames;
//		GSList * PhasorUnit; // accepts a pointer to C37118PhasorUnit
//		GSList * AnalogUnit;// accepts a pointer to C37118AnalogUnit
//		GSList * DigitalUnit; // 16 chn names per unit accepts a pointer to C37118DigitalUnit
//		struct C37118NomFreq NomFreqCode;
//		uint16_t ConfChangeCnt;
//	};



//	struct C37118DataRate
//	{
//
//
//		int16_t m_datarateRaw;
//	};
//	static struct C37118DataRate CreateByRawC37118Format( int16_t datarateRaw );
//	static struct C37118DataRate CreateByFramesPerSecond( float datarateRaw );
//
//	static int16_t RawDataRate() ;
//	static float FramesPerSecond();
//
//
//	struct C37118PdcConfiguration
//	{
//				struct C37118FrameHeader HeaderCommon;
//				struct C37118TimeBase TimeBase;
//		GSList * PMUs; //accepts pointer to C37118PmuConfiguration
//		struct C37118DataRate DataRate;
//		uint16_t FooterCrc16;
//	};
//
//	struct C37118PmuConfiguration_Ver3
//	{
//		GString *StationName ;
//		uint16_t IdCode;
//		char GlobalPmuId[16];
//		struct C37118PmuFormat DataFormat;
//		GSList *phasorChnNames;
//		GSList * analogChnNames;
//		GSList * digitalChnNames;
//		GSList * PhasorUnit; // accepts a pointer to C37118PhasorUnit
//		GSList * AnalogUnit;// accepts a pointer to C37118AnalogUnit
//		GSList * DigitalUnit; // 16 chn names per unit accepts a pointer to C37118DigitalUnit
//		float POS_LAT;
//		float POS_LON;
//		float POS_ELEV;
//		unsigned char ServiceClass;
//		int32_t PhasorMeasurementWindow;
//		int32_t PhasorMeasurementGroupDelayMs;
//		struct C37118NomFreq NomFreqCode;
//		uint16_t ConfChangeCnt;
//	};
//
//	struct C37118ContIdx
//	{
//
//		uint16_t m_raw;
//	};
//
//
//
//
//
//
//			static struct C37118ContIdx * CreateByC37118Raw( uint16_t rawValue );
//			static struct C37118ContIdx * CreateAsFrameInSequence( int frameIdx, int numFrames );
//
//			static int GetCurrentFrameIndex(struct C37118ContIdx *);
//			static bool IsLastFrame(struct C37118ContIdx *);
//			static uint16_t GetRawC37118Value(struct C37118ContIdx *);
//
//
//
//
//	struct C37118PdcConfiguration_Ver3
//	{
//		struct C37118FrameHeader HeaderCommon;
//		struct C37118ContIdx ContinuationIndex;
//		struct C37118TimeBase TimeBase;
//		GSList * PMUs; // accepts a pointer to C37118PmuConfiguration_Ver3
//		struct C37118DataRate DataRate;
//		uint16_t FooterCrc16;
//	};
//
//	struct C37118PmuDataFrameStat
//	{
//
//		uint16_t m_raw;
//	};
//
//
//
//	static uint16_t ToRaw(struct C37118PmuDataFrameStat*);
//
//			 // Getters..
//			 static uint8_t getDataError(struct C37118PmuDataFrameStat*);
//			 static bool getPmuSyncFlag(struct C37118PmuDataFrameStat*);
//			 static bool getDataSortingFlag(struct C37118PmuDataFrameStat*);
//			 static bool getPmuTriggerFlag(struct C37118PmuDataFrameStat*);
//			 static bool getConfigChangeFlag(struct C37118PmuDataFrameStat*);
//			 static bool getDataModifiedFlag(struct C37118PmuDataFrameStat*);
//			 static uint8_t getTimeQualityCode(struct C37118PmuDataFrameStat*);
//			 static uint8_t getUnlockTimeCode(struct C37118PmuDataFrameStat*);
//			 static uint8_t getTriggerReasonCode(struct C37118PmuDataFrameStat*);
//
//			 // Setters
//			 static void setDataErrorCode(uint8_t errCode,struct C37118PmuDataFrameStat*);
//			 static void setPmuSyncFlag(bool isset,struct C37118PmuDataFrameStat*);
//			 static void setDataSortingFlag(bool isset,struct C37118PmuDataFrameStat*);
//			 static void setPmuTriggerFlag(bool isset,struct C37118PmuDataFrameStat*);
//			 static void setConfigChangeFlag(bool isset,struct C37118PmuDataFrameStat*);
//			 static void setDataModifiedFlag(bool isset,struct C37118PmuDataFrameStat*);
//			 static void setTimeQualityCode(uint8_t code,struct C37118PmuDataFrameStat*);
//			 static void setUnlockTimeCode(uint8_t code,struct C37118PmuDataFrameStat*);
//			 static void setTriggerReasonCode(uint8_t code,struct C37118PmuDataFrameStat*);
//
//
//	struct C37118PmuDataFramePhasorRealImag
//	{
//
//
//		float Real;
//		float Imag;
//	};
//
//
//
//	static struct C37118PmuDataFramePhasorRealImag* CreateByRealImag(int16_t real, int16_t imag);
//	static struct C37118PmuDataFramePhasorRealImag* CreateByRealImagf(float real, float imag);
//	static struct C37118PmuDataFramePhasorRealImag* CreateByPolarMag(uint16_t magnitude, int16_t angleRad); // angle assumed to be in "radians * 10^4"
//	static struct C37118PmuDataFramePhasorRealImag* CreateByPolarMagf(float magnitude, float angleRad);
//
//	static void getRealImagAsFloat(float* refReal, float* refImag,struct C37118PmuDataFramePhasorRealImag* pmuDataFrame);
//	static void getRealImagAsInt16(int16_t* refReal, int16_t* refImag,struct C37118PmuDataFramePhasorRealImag* pmuDataFrame);
//	static void getMagAngleAsFloat(float* mag, float* angle,struct C37118PmuDataFramePhasorRealImag* pmuDataFrame);
//	static void getMagAngleAsInt16(uint16_t* mag, int16_t* angle,struct C37118PmuDataFramePhasorRealImag* pmuDataFrame);
//
//
//
//
//	struct C37118PmuDataFrameAnalog
//	{
//
//				float Value;
//	};
//
//	static struct C37118PmuDataFrameAnalog* CreateByInt16(int16_t value);
//	static struct C37118PmuDataFrameAnalog* CreateByFloat(float value);
//
//	static float getValueAsFloat(struct C37118PmuDataFrameAnalog * pmuAnlgDataFrame);
//	static int16_t getValueAsInt16(struct C37118PmuDataFrameAnalog * pmuAnlgDataFrame);
//
//	struct C37118PmuDataFrameDigitalHelper
//	{
//		GSList * m_digValues;
//	};
//
//	static struct C37118PmuDataFrameDigitalHelper* CreateByBoolArray(GSList* digBits); //Arg:linked list of booleans
//			static struct C37118PmuDataFrameDigitalHelper* CreateByUint16Arr(GSList * digWordArray); //Arg: linked list of uint_16
//			static void PushDigWord( uint16_t word, struct C37118PmuDataFrameDigitalHelper* pmuDataFrameDigHelper);
//			static void PushDigValue( bool bit, struct C37118PmuDataFrameDigitalHelper* pmuDataFrameDigHelper );
//
//			static GSList*  ToBoolArray(struct C37118PmuDataFrameDigitalHelper* pmuDataFrameDigHelper);
//			static GSList* ToDigWord(struct C37118PmuDataFrameDigitalHelper* pmuDataFrameDigHelper);
//
//
//
//	struct C37118PmuDataFrame
//	{
//		struct C37118PmuDataFrameStat Stat;
//		GSList * PhasorValues ; //takes pointers to C37118PmuDataFramePhasorRealImag
//		float Frequency;
//		float DeltaFrequency;
//		GSList* AnalogValues; //takes pointers to C37118PmuDataFrameAnalog
//		GSList* DigitalValues ; //takes pointers to bool
//	};
//
//	struct C37118PdcDataFrame
//	{
//		struct C37118FrameHeader HeaderCommon;
//		GSList* pmuDataFrame ; //takes pointers to C37118PmuDataFrame
//		uint16_t CRC16;
//	};
//
//
//	typedef enum
//	{
//		KILL_RTD = 1,
//		START_RTD = 2,
//		SEND_HDR_FRAME = 3,
//		SEND_CFG1_FRAME = 4,
//		SEND_CFG2_FRAME = 5,
//		SEND_CFG3_FRAME = 6
//	}C37118CmdType;
//
//	struct C37118CommandFrame
//	{
//		struct C37118FrameHeader Header;
//		C37118CmdType CmdType;
//		uint16_t CRC16;
//	};
//
//
//	struct C37118PdcHeaderFrame
//	{
//		struct C37118FrameHeader Header;
//		GString* HeaderMessage;
//		uint16_t FooterCrc16;
//	};
//
//
//	struct C37118PmuDataDecodeInfo
//	{
//		int numPhasors;
//		int numAnalogs;
//		int numDigitals;
//		struct C37118PmuFormat DataFormat;
//	};
//
//	struct C37118PdcDataDecodeInfo
//	{
//		struct C37118TimeBase timebase;
//		GSList* PMUs; // accepts pointers to C37118PmuDataDecodeInfo
//	};
//
//
//
//		static void WriteConfigurationFrame(char* data, const struct C37118PdcConfiguration* pdcconfig, int* offset);
//		static void WriteConfigurationFrame_Ver3( char* data, const struct C37118PdcConfiguration_Ver3* pdcConfg, int* offset);
//		static void WriteFrameHeader(char* data, const struct C37118FrameHeader* frameHeader, int* offset);
//		static void WriteDataFrame(char* data, const struct C37118PdcDataDecodeInfo* config, const struct C37118PdcDataFrame* dataFrame, int* offset);
//		static void WriteHeaderFrame(char* data, const struct C37118PdcHeaderFrame* headerFrame, int* offset);
//		static void WriteCommandFrame(char* data, const struct C37118CommandFrame* cmdFrame, int* offset);
//
//		static void WriteSyncField(char* data,const struct C37118SyncField* syncField, int* offset);
//		static void WriteFracSecField(char* data, const struct C37118FracSec* fracSecField, int* offset);
//		static void WriteNomFreqField(char* data, const struct C37118NomFreq* nomFreqField, int* offset);
//		static void WriteTimeBaseField(char* data,  const struct C37118TimeBase* timeBaseField , int* offset);
//		static void WriteC37118PmuFormat(char* data, const struct C37118PmuFormat* pmuFormat, int* offset );
//		static void WriteC37118PhasorUnit(char* data,const struct C37118PhasorUnit* pmuFormat , int* offset);
//		static void WriteC37118AnalogUnit(char* data,  const struct C37118AnalogUnit* pmuFormat, int* offset );
//		static void WriteC37118DigitalUnit(char* data, const struct C37118DigitalUnit* pmuFormat, int* offset );
//		static void WriteC37118PhasorScale_Ver3(char* data, const struct C37118PhasorScale_Ver3* phScale, int* offset);
//		static void WriteC37118AnalogScale_Ver3(char* data, const struct C37118AnalogScale_Ver3* phScale, int* offset);
//
//
//		static struct C37118PdcConfiguration ReadConfigurationFrame(char* data, int length);
//		static struct C37118PdcConfiguration_Ver3 ReadConfigurationFrame_Ver3(char* data, int length);
//		static struct C37118FrameHeader ReadFrameHeader(char* data, int length, int* offset);
//		static struct C37118PdcDataFrame ReadDataFrame(char* data, int length, const struct C37118PdcDataDecodeInfo* config, int* offset);
//		static struct C37118PdcHeaderFrame ReadHeaderFrame(char* data, int length, int* offset);
//		static struct C37118CommandFrame ReadCommandFrame(char* data, int bufferSize, int* offset);
//
//		static struct C37118SyncField ReadSyncField(char* data, int* offset);
//		static struct C37118FracSec ReadFracSecField(char* data,int* offset);
//		static struct C37118NomFreq ReadNomFreqField(char* data, int* offset);
//		static struct C37118TimeBase ReadTimeBaseField(char* data,int* offset);
//		static struct C37118PmuFormat ReadC37118PmuFormat(char* data, int* offset );
//		static struct C37118PhasorUnit ReadC37118PhasorUnit(char* data,int* offset);
//		static struct C37118AnalogUnit ReadC37118AnalogUnit(char* data, int* offset );
//		static struct C37118DigitalUnit ReadC37118DigitalUnit(char* data,int* offset );
//		static struct C37118PhasorScale_Ver3 ReadC37118PhasorScale_Ver3(char* data, int* offset);
//		static struct C37118AnalogScale_Ver3 ReadC37118AnalogScale_Ver3(char* data, int* offset);
//
//		// Helper functions
//		static struct C37118PdcDataDecodeInfo CreateDecodeInfoByPdcConfig(const struct C37118PdcConfiguration * pdccfg) ;
//		static struct C37118PdcDataDecodeInfo CreateDecodeInfoByPdcConfigVer3(const struct C37118PdcConfiguration_Ver3 * pdccfg);
//		static struct C37118PdcConfiguration DowngradePdcConfig(const struct C37118PdcConfiguration_Ver3* pdccfg);
//		static struct C37118PmuConfiguration DowngradePmuConfig(const struct C37118PmuConfiguration_Ver3* pdccfg);

//		static uint16_t CalcCrc16(char* data, int length);





#endif /* PMU_DECODE_H */
