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
 *
 *
 *
 * Author: Chamara Devanarayana based on Prof. Luigi Vanfretti's repo on PMU https://github.com/ALSETLab/S3DK-STRONGgrid
 *
 * Dynamic preprocessor for the PMU protocol C37.118.2-2011
 *
 */

#include "pmu_decode.h"

#include <string.h>
/* PMU Function Codes */




/******************************************************************************/
static unsigned short CalcCrc16(char* data, int length)
		{
		  unsigned short crc = 0xFFFF; /*0xFFFF -> 0x0 -> 0xFFFF;*/
		  unsigned short temp;
		  unsigned short quick;
		  unsigned int crcIdx;
		  unsigned char *bufPtr = (unsigned char *)data;

		  for(crcIdx = 0; crcIdx < length ;crcIdx++){
		    temp = (crc >> 8) ^ bufPtr[crcIdx];
		    crc <<= 8;
		    quick = temp ^ (temp >> 4);
		    crc ^= quick;
		    quick <<= 5;
		    crc ^= quick;
		    quick <<= 7;
		    crc ^= quick;
		  }
		  return crc;
		}

static char *trimwhitespace(char *str)
{
  char *end;

  // Trim leading space
  while(isspace((unsigned char)*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace((unsigned char)*end)) end--;

  // Write new null terminator character
  end[1] = '\0';

  return str;
}


static int modifyData(pmu_config_t *config, pmu_session_data_t *session, SFSnortPacket *packet)
{
	int modified = 0;
	int pmuNumber =0;
	int phasorNumber = 0;
	int analogNumber = 0;
	int digitalNumber = 0;
	int startingIndex = 0;
	int numPhasors, numAnalog, numDigital;
	int bytesToSkip=16;
	int bytesPerPhasor=4;
	int bytesPerAnalog=4;
	int bytesPerDigital=4;
	int bytesPerFrequency=4;
	GString * phasorName=g_new0(GString,1);
	GString * analogName=g_new0(GString,1);
	GString * digitalName=g_new0(GString,1);
	int* pktOffset = g_new0(uint32_t,2);

	GString *PMUName  =g_new0(GString,1);
	unsigned short crc;
	float temp=0;
	uint32_t a=0;
	uint32_t b = 0;
	uint16_t aShort= 0;
	uint16_t bShort = 0;
	char tempArray[33];
	uint8_t  tempValueToCopy[4];
	double realValue, imaginaryValue;
	if(session->FrameData->len >= packet->payload_size){
		for(int index =0;index<config->numAlteredVal;index++)
			{
				memset(tempArray,NULL,33);
				GString *PMUId = config->values_to_alter[index].pmuName;
				memcpy(tempArray,trimwhitespace(PMUId->str),strlen(trimwhitespace(PMUId->str)));
				GString *Id = config->values_to_alter[index].identifier;
				strcat(tempArray,trimwhitespace(Id->str));


				pktOffset = g_hash_table_lookup(session->pmuRefTable,tempArray);
				startingIndex = *pktOffset-(session->FrameData->len-packet->payload_size);    // buflen is the length of data in the current packet

				if(config->values_to_alter[index].type == 0){
															if(startingIndex<0 && abs(startingIndex)>=(*(pktOffset+1))/2)
															{

																_dpd.logMsg("you have missed the point\n");
																//you have missed the point
																continue;
															}

															else if(startingIndex<0 && abs(startingIndex)<(*(pktOffset+1))/2)
															{
																_dpd.logMsg("the data is split between two packets\n");
																//the data is split between two packets


															}

															else if(startingIndex > packet->payload_size)
															{
																_dpd.logMsg("the data is in a future packet\n");
																continue;

															}
															else{
																_dpd.logMsg("the data is in the current packet\n");
																//entire data is in the current packet
															}
//TODO: need to change the modification to match the data type
															temp = config->values_to_alter[index].real_value;

															a = *((uint32_t*)&temp ); // reinterpret as uint32
															b = htonl(a);			 // switch endianness: host-to-net
															temp = *((float*)&b);
										memcpy((packet->payload+startingIndex),&temp,(*(pktOffset+1))/2);
										temp = config->values_to_alter[index].imaginary_value;
										 a = *((uint32_t*)&temp ); // reinterpret as uint32
																	 b = htonl(a);			 // switch endianness: host-to-net
																	temp = *((float*)&b);

										memcpy((packet->payload+startingIndex+(*(pktOffset+1))/2),&temp,(*(pktOffset+1))/2);

										modified = 1;


			}
				else if(config->values_to_alter[index].type == 1){
																			if(startingIndex<0 && abs(startingIndex)>=(*(pktOffset+1)))
																			{

																				_dpd.logMsg("you have missed the point\n");
																				//you have missed the point
																				continue;
																			}

																			else if(startingIndex<0 && abs(startingIndex)<(*(pktOffset+1)))
																			{
																				_dpd.logMsg("the data is split between two packets\n");
																				//the data is split between two packets


																			}

																			else if(startingIndex > packet->payload_size)
																			{
																				_dpd.logMsg("the data is in a future packet\n");
																				continue;

																			}
																			else{
																				_dpd.logMsg("the data is in the current packet\n");
																				//entire data is in the current packet
																			}
				//TODO: need to change the modification to match the data type
																			temp = config->values_to_alter[index].real_value;

																			a = *((uint32_t*)&temp ); // reinterpret as uint32
																			b = htonl(a);			 // switch endianness: host-to-net
																			temp = *((float*)&b);
														memcpy((packet->payload+startingIndex),&temp,(*(pktOffset+1)));


														modified = 1;


							}

				else if(config->values_to_alter[index].type == 2){
																							if(startingIndex<0 && abs(startingIndex)>=(*(pktOffset+1)))
																							{

																								_dpd.logMsg("you have missed the point\n");
																								//you have missed the point
																								continue;
																							}

																							else if(startingIndex<0 && abs(startingIndex)<(*(pktOffset+1)))
																							{
																								_dpd.logMsg("the data is split between two packets\n");
																								//the data is split between two packets


																							}

																							else if(startingIndex > packet->payload_size)
																							{
																								_dpd.logMsg("the data is in a future packet\n");
																								continue;

																							}
																							else{
																								_dpd.logMsg("the data is in the current packet\n");
																								//entire data is in the current packet
																							}
								//TODO: need to change the modification to match the data type
																							aShort = config->values_to_alter[index].digValue;


																							bShort = htons(aShort);			 // switch endianness: host-to-net

																		memcpy((packet->payload+startingIndex),&bShort ,(*(pktOffset+1)));


																		modified = 1;


											}


				if(modified)
				{
					crc = CalcCrc16(packet->payload, packet->payload_size-2);
															crc = htons(crc);
															memcpy((packet->payload+packet->payload_size-2),&crc,2);
				}
			}
//	for(int index =0;index<config->numAlteredVal;index++)
//	{
//		GString *PMUId = config->values_to_alter[index].pmuName;
//		GString *Id = config->values_to_alter[index].identifier;
//		uint8_t type = config->values_to_alter[index].type;
//		C37118PmuConfiguration *pmuIntest = (C37118PmuConfiguration *)session->pmuConfig2.PMUs->data;
//			GSList *nextPMU = (C37118PmuConfiguration *)session->pmuConfig2.PMUs->next;
//			bytesToSkip=16;
//			pmuNumber = 0;
//		while(pmuIntest){
//			numPhasors = pmuIntest->numPhasors;
//						numAnalog = pmuIntest->numAnalog;
//						numDigital = pmuIntest->numDigital;
//
//						if(pmuIntest->DataFormat.Bit1_0xPhasorsIsInt_1xPhasorFloat)
//														{
//															bytesPerPhasor=8;
//														}
//						if(pmuIntest->DataFormat.Bit2_0xAnalogIsInt_1xAnalogIsFloat)
//																				{
//																					bytesPerAnalog=8;
//																				}
//						if(pmuIntest->DataFormat.Bit3_0xFreqIsInt_1xFreqIsFloat)
//																									{
//																										bytesPerFrequency=8;
//																									}
//
//			PMUName = g_string_overwrite_len(PMUName, 0,pmuIntest->StationName->str,((GString *)pmuIntest->StationName)->len);
//
//			PMUName = g_string_truncate(PMUName,PMUId->len);
//			if(!g_string_equal(PMUId,PMUName) )
//			{
//				if(nextPMU!=NULL){
//							pmuNumber++;
//							pmuIntest = (C37118PmuConfiguration *)nextPMU->data;
//							nextPMU = (C37118PmuConfiguration *)nextPMU ->next;
//							}
//
//
//							else
//								pmuIntest = NULL;
//
//				bytesToSkip+=2+numPhasors*bytesPerPhasor+bytesPerFrequency+numAnalog*bytesPerAnalog+numDigital*2;
//				phasorNumber = 0;
//				continue;
//
//				//need to find the offset of the phasor data for subsequent PMUs
//			}
//			GSList * nextPhasor = pmuIntest->phasorChnNames->next;
//            if(pmuIntest->phasorChnNames->data)
//			phasorName = g_string_overwrite_len(phasorName, 0,((GString *)pmuIntest->phasorChnNames->data)->str,((GString *)pmuIntest->phasorChnNames->data)->len);
//            if(pmuIntest->analogChnNames && pmuIntest->analogChnNames->data)
//			analogName = g_string_overwrite_len(analogName, 0,((GString *)pmuIntest->analogChnNames->data)->str,((GString *)pmuIntest->analogChnNames->data)->len);
//            if(pmuIntest->digitalChnNames && pmuIntest->digitalChnNames->data)
//			digitalName = g_string_overwrite_len(digitalName, 0,((GString *)pmuIntest->digitalChnNames->data)->str,((GString *)pmuIntest->digitalChnNames->data)->len);
//			// phasor values
//			if(config->values_to_alter[index].type == 0){
//
//			while(phasorName)
//			{
//				phasorName = g_string_truncate(phasorName,Id->len);
//				if(g_string_equal(Id,phasorName) )
//				{
//					bytesToSkip+=phasorNumber*bytesPerPhasor;
//					_dpd.logMsg("PMU %d bytes to skip :%d\n",pmuNumber,bytesToSkip);
//					if(bytesPerPhasor==8)
//					{
//						temp = config->values_to_alter[index].real_value;
//
//						uint32_t a = *((uint32_t*)&temp ); // reinterpret as uint32
//							uint32_t b = htonl(a);			 // switch endianness: host-to-net
//							temp = *((float*)&b);
//
//							// should calculate the offset of the packet taking the multi fragment message to account
//
//
//
//							startingIndex = bytesToSkip-(session->FrameData->len-packet->payload_size);    // buflen is the length of data in the current packet
//											if(startingIndex<0 && abs(startingIndex)>=(bytesPerPhasor))
//											{
//
//												_dpd.logMsg("you have missed the point\n");
//												//you have missed the point
//												continue;
//											}
//
//											else if(startingIndex<0 && abs(startingIndex)<(bytesPerPhasor))
//											{
//												_dpd.logMsg("the data is split between two packets\n");
//												//the data is split between two packets
//
//
//											}
//
//											else if(startingIndex > packet->payload_size)
//											{
//												_dpd.logMsg("the data is in a future packet\n");
//												continue;
//
//											}
//											else{
//												_dpd.logMsg("the data is in the current packet\n");
//												//entire data is in the current packet
//											}
//
//						memcpy((packet->payload+startingIndex),&temp,4);
//						temp = config->values_to_alter[index].imaginary_value;
//						 a = *((uint32_t*)&temp ); // reinterpret as uint32
//													 b = htonl(a);			 // switch endianness: host-to-net
//													temp = *((float*)&b);
//
//						memcpy((packet->payload+startingIndex+4),&temp,4);
//						crc = CalcCrc16(packet->payload, packet->payload_size-2);
//						crc = htons(crc);
//						memcpy((packet->payload+packet->payload_size-2),&crc,2);
//						modified = 1;
//						break;
//					}
//					//write a function to modify the packet data
//
//
//				}
//				phasorNumber++;
//				if(nextPhasor){
//					phasorName = g_string_overwrite_len(phasorName, 0,((GString *)nextPhasor->data)->str,((GString *)nextPhasor->data)->len);
//
//				nextPhasor = nextPhasor->next;
//				}
//				else
//					phasorName = NULL;
//			}
//
//			}
//
//			//analog values
//
//
//			if(config->values_to_alter[index].type == 1){
//
//			while(analogName)
//			{
//				analogName = g_string_truncate(analogName,Id->len);
//				if(g_string_equal(Id,analogName) )
//				{
//					bytesToSkip+=analogNumber*bytesPerPhasor;
//					_dpd.logMsg("PMU %d bytes to skip :%d\n",pmuNumber,bytesToSkip);
//					if(bytesPerPhasor==8)
//					{
//						temp = config->values_to_alter[index].real_value;
//
//						uint32_t a = *((uint32_t*)&temp ); // reinterpret as uint32
//							uint32_t b = htonl(a);			 // switch endianness: host-to-net
//							temp = *((float*)&b);
//
//							// should calculate the offset of the packet taking the multi fragment message to account
//
//
//
//							startingIndex = bytesToSkip-(session->FrameData->len-packet->payload_size);    // buflen is the length of data in the current packet
//											if(startingIndex<0 && abs(startingIndex)>=(bytesPerPhasor))
//											{
//
//												_dpd.logMsg("you have missed the point\n");
//												//you have missed the point
//												continue;
//											}
//
//											else if(startingIndex<0 && abs(startingIndex)<(bytesPerPhasor))
//											{
//												_dpd.logMsg("the data is split between two packets\n");
//												//the data is split between two packets
//
//
//											}
//
//											else if(startingIndex > packet->payload_size)
//											{
//												_dpd.logMsg("the data is in a future packet\n");
//												continue;
//
//											}
//											else{
//												_dpd.logMsg("the data is in the current packet\n");
//												//entire data is in the current packet
//											}
//
//						memcpy((packet->payload+startingIndex),&temp,4);
//						temp = config->values_to_alter[index].imaginary_value;
//						 a = *((uint32_t*)&temp ); // reinterpret as uint32
//													 b = htonl(a);			 // switch endianness: host-to-net
//													temp = *((float*)&b);
//
//						memcpy((packet->payload+startingIndex+4),&temp,4);
//						crc = CalcCrc16(packet->payload, packet->payload_size-2);
//						crc = htons(crc);
//						memcpy((packet->payload+packet->payload_size-2),&crc,2);
//						modified = 1;
//						break;
//					}
//					//write a function to modify the packet data
//
//
//				}
//				phasorNumber++;
//				if(nextPhasor){
//					phasorName = g_string_overwrite_len(phasorName, 0,((GString *)nextPhasor->data)->str,((GString *)nextPhasor->data)->len);
//
//				nextPhasor = nextPhasor->next;
//				}
//				else
//					phasorName = NULL;
//			}
//
//			}
//
//			if(nextPMU!=NULL){
//			pmuNumber++;
//			pmuIntest = (C37118PmuConfiguration *)nextPMU->data;
//			nextPMU = (C37118PmuConfiguration *)nextPMU ->next;
//			}
//
//
//			else
//				pmuIntest = NULL;
//		}
//	}
	}


return modified;
}

static int extractFrameHdr(pmu_session_data_t *session,const gchar *data,int length, int *offsetOrg)
{
	int offset = *offsetOrg;
	offset = 0;
	session->Sync.LeadIn = *(data+offset);
	offset++;
	uint8_t rawVerType = *(data+offset);
	session->Sync.Version = rawVerType & 0xF;
	session->Sync.FrameType = (C37118HdrFrameType)((rawVerType & 0x70) >> 4);
	offset++;
	memcpy(&(session->FrameSize),(data+offset),2);
	session->FrameSize = ntohs(session->FrameSize);
	offset+=2;
	memcpy(&(session->IdCode),(data+offset),2);
	session->IdCode = ntohs(session->IdCode);
	offset+=2;
	memcpy(&(session->SOC),(data+offset),4);
	session->SOC = ntohl(session->SOC);
	offset+=4;

	uint32_t raw;
	memcpy(&raw,(data+offset),4);
	raw = ntohl(raw);
	session->FracSec.TimeQuality = (raw & 0xFF000000) >> 24;
	session->FracSec.FractionOfSecond = (raw & 0x00FFFFFF);
	offset+=4;
	*offsetOrg = offset;


return 0;
}

//this function should save the configuration data and build a hash table to have PMU_NAMEValueName as the key and the offset of data in the message



static int extractConfig2Data(pmu_session_data_t *session,const gchar *data,int length, int *offsetOrg)
{
	uint32_t raw;
	int offset = *offsetOrg;
	int offsetDataFrame = 14;
	int sizeOfPhasor = 4;
	int sizeOfAnalog = 2;
	int sizeOfFreq = 4;
	uint32_t * tempPointer;
	_dpd.logMsg("init offset:%d\n",offset);
	memcpy(&raw,(data+offset),4);
	session->pmuConfig2.TimeBase.Flags = (raw & 0xFF000000) >> 24;
	session->pmuConfig2.TimeBase.TimeBase = (raw & 0x00FFFFFF);
	offset+=4;
	memcpy(&(session->pmuConfig2.NumPMU),(data+offset),2);
	session->pmuConfig2.NumPMU = ntohs(session->pmuConfig2.NumPMU);
	GSList *tmp;
	GString * tempString = NULL;
	while (session->pmuConfig2.PMUs != NULL)
	    { //free up if existing
	       tmp = session->pmuConfig2.PMUs;
	       session->pmuConfig2.PMUs = session->pmuConfig2.PMUs->next;
	       free(tmp);
	    }
	g_slist_free (session->pmuConfig2.PMUs);
	session->pmuConfig2.PMUs = NULL;
	offset+=2;
	// Read STN
	for( int ipmu = 0; ipmu < session->pmuConfig2.NumPMU; ++ipmu )
	{	 sizeOfPhasor = 4;
	 	 sizeOfAnalog = 2;
	 	sizeOfFreq = 4;
	 	offsetDataFrame+=2;
		_dpd.logMsg("PMU %d offset:%d\n",ipmu,offset);
		C37118PmuConfiguration* pmuCfg = g_new0(C37118PmuConfiguration,1);
       char string[17];
       memset(string,NULL,17);
		// Read STN
       memcpy(string,(data+offset),16);

    	   pmuCfg->StationName = g_string_new_len(string,16);


       offset+=16;

	// Read IDCODE
       memcpy(&pmuCfg->IdCode,(data+offset),2);
       pmuCfg->IdCode = ntohs(pmuCfg->IdCode);
       offset+=2;

		// Read FORMAT

	uint16_t rawformat=0;
	memcpy(&rawformat,(data+offset),2);
	rawformat =  ntohs(rawformat);
	pmuCfg->DataFormat.Bit0_0xPhasorFormatRect_1xMagnitudeAndAngle	= (rawformat & (1 << 0)) != 0;
	pmuCfg->DataFormat.Bit1_0xPhasorsIsInt_1xPhasorFloat				= (rawformat & (1 << 1)) != 0;
	if(pmuCfg->DataFormat.Bit1_0xPhasorsIsInt_1xPhasorFloat)
		sizeOfPhasor=8;
	pmuCfg->DataFormat.Bit2_0xAnalogIsInt_1xAnalogIsFloat				= (rawformat & (1 << 2)) != 0;
	if (pmuCfg->DataFormat.Bit2_0xAnalogIsInt_1xAnalogIsFloat)
		sizeOfAnalog = 4;
	pmuCfg->DataFormat.Bit3_0xFreqIsInt_1xFreqIsFloat					= (rawformat & (1 << 3)) != 0;

	if(pmuCfg->DataFormat.Bit3_0xFreqIsInt_1xFreqIsFloat)
		sizeOfFreq = 8;
	offset+=2;
		// Read PHNMR / ANNMR / DGNMR

	memcpy(&rawformat,(data+offset),2);
	pmuCfg->numPhasors =   ntohs(rawformat);
	offset+=2;

	memcpy(&rawformat,(data+offset),2);
	pmuCfg->numAnalog =   ntohs(rawformat);
	offset+=2;



		memcpy(&rawformat,(data+offset),2);
		pmuCfg->numDigital =   ntohs(rawformat);
			offset+=2;

	// Read CHNAM - phasors


				pmuCfg->phasorChnNames=NULL;
				pmuCfg->digitalChnNames = NULL;
				pmuCfg->analogChnNames = NULL;
		for( int i = 0; i < pmuCfg->numPhasors; ++i ){
			memcpy(string,(data+offset),16);
            offset+=16;
            pmuCfg->phasorChnNames = g_slist_append (pmuCfg->phasorChnNames, g_string_new_len(string,16));
            tempString = g_string_new(trimwhitespace(pmuCfg->StationName->str));
            tempString = g_string_append_len(tempString,trimwhitespace(string),16);

            uint32_t *offsetAndSizeOfData = (uint32_t *)malloc(sizeof(uint32_t)*2);
            		            *offsetAndSizeOfData = offsetDataFrame;
            		            tempPointer = offsetAndSizeOfData;
            		            offsetAndSizeOfData++;
            		            *offsetAndSizeOfData = sizeOfPhasor;
            		                        g_hash_table_insert(session->pmuRefTable,strdup(tempString->str),tempPointer);
            _dpd.logMsg("Key %.*s offset:%d size of one point %d\n",tempString->len,tempString->str,*tempPointer,*offsetAndSizeOfData);
            offsetDataFrame+=sizeOfPhasor;
            g_string_free(tempString,TRUE);
		}
		offsetDataFrame+=sizeOfFreq;
		// Read CHNAM - analog
	for( int i = 0; i < pmuCfg->numAnalog; ++i ){

		memcpy(string,(data+offset),16);
		            offset+=16;
		            pmuCfg->analogChnNames = g_slist_append (pmuCfg->analogChnNames, g_string_new_len(string,16));
		            tempString = g_string_new(trimwhitespace(pmuCfg->StationName->str));
		            tempString = g_string_append_len(tempString,trimwhitespace(string),16);
		            uint32_t *offsetAndSizeOfData = (uint32_t *)malloc(sizeof(uint32_t)*2);
		                        		            *offsetAndSizeOfData = offsetDataFrame;
		                        		            tempPointer = offsetAndSizeOfData;
		                        		            offsetAndSizeOfData++;
		            *offsetAndSizeOfData = sizeOfAnalog;
		                        g_hash_table_insert(session->pmuRefTable,strdup(tempString->str),tempPointer);
		                        _dpd.logMsg("Key %.*s offset:%d size of one point %d\n",tempString->len,tempString->str,*tempPointer,*offsetAndSizeOfData);
		                        offsetDataFrame+=sizeOfAnalog;
		                        g_string_free(tempString,TRUE);

	}
		// Read CHNAM - dig chns
		for( int i = 0; i < pmuCfg->numDigital * 16; ++i ){
			memcpy(string,(data+offset),16);
			offset+=16;
			pmuCfg->digitalChnNames = g_slist_append (pmuCfg->digitalChnNames, g_string_new_len(string,16));
			tempString = g_string_new(trimwhitespace(pmuCfg->StationName->str));
			tempString = g_string_append_len(tempString,trimwhitespace(string),16);
			uint32_t *offsetAndSizeOfData = (uint32_t *)malloc(sizeof(uint32_t)*2);
					                        		            *offsetAndSizeOfData = offsetDataFrame;
					                        		            tempPointer = offsetAndSizeOfData;
					                        		            offsetAndSizeOfData++;
					            *offsetAndSizeOfData = 2;
					                        g_hash_table_insert(session->pmuRefTable,strdup(tempString->str),tempPointer);
					                        _dpd.logMsg("Key %.*s offset:%d size of one point %d\n",tempString->len,tempString->str,*tempPointer++,*offsetAndSizeOfData);
					                        if(i!=0 && i%15==0)
					                        	offsetDataFrame+=2;
					                        g_string_free(tempString,TRUE);
		}
		// Read PHUNIT
		pmuCfg->PhasorUnit = NULL;
		for( int i = 0; i < pmuCfg->numPhasors; ++i )
		{
			uint32_t raw;
			C37118PhasorUnit * phunit = g_new0(C37118PhasorUnit,1);;
			memcpy(&raw,(data+offset),4);
			offset+=4;
			raw = ntohl(raw);
			phunit->Type = (raw & 0xFF000000) >> 24;
			phunit->PhasorScalar = (raw & 0x00FFFFFF);

			pmuCfg->PhasorUnit = g_slist_append(pmuCfg->PhasorUnit,phunit);
		}
		// Read ANUNIT
		pmuCfg->AnalogUnit = NULL;
		for( int i = 0; i < pmuCfg->numAnalog; ++i )
		{
			uint32_t raw;
			C37118AnalogUnit anunit;
			memcpy(&raw,(data+offset),4);
			offset+=4;
			raw = ntohl(raw);
			anunit.Type_X = (raw & 0xFF000000) >> 24;
			anunit.AnalogScalar = (raw & 0x00FFFFFF); // TODO: REVIEW - UNSIGNED / SIGNED
			pmuCfg->AnalogUnit =NULL;
			pmuCfg->AnalogUnit = g_slist_append(pmuCfg->AnalogUnit,&anunit);
		}


		// Read DIGUINT
		pmuCfg->DigitalUnit = NULL;
		for( int i = 0; i < pmuCfg->numDigital; ++i )
		{
			uint16_t raw;
			C37118DigitalUnit digUnit;
			memcpy(&raw,(data+offset),2);
			offset+=2;
			raw = ntohs(raw);

			digUnit.DigNormalStatus = raw;
			memcpy(&raw,(data+offset),2);
			offset+=2;
			raw = ntohs(raw);

			digUnit.DigValidInputs = raw;
			pmuCfg->DigitalUnit = g_slist_append(pmuCfg->DigitalUnit,&digUnit);
		}


		// Read FNOM

		uint16_t raw;
		memcpy(&raw,(data+offset),2);
		offset+=2;
		raw = ntohs(raw);
		pmuCfg->NomFreqCode.Bit0_1xFreqIs50_0xFreqIs60 = raw & 0x1;


		// Read CFGCNT
		memcpy(&raw,(data+offset),2);
		offset+=2;
		raw = ntohs(raw);
		pmuCfg->ConfChangeCnt = raw;

		// Add PMU to the list
		session->pmuConfig2.PMUs=g_slist_append(session->pmuConfig2.PMUs,pmuCfg);
		_dpd.logMsg("End PMU %d offset:%d\n",ipmu,offset);
	}

	// Read DATA_RATE
	memcpy(&raw,(data+offset),2);
	offset+=2;
	raw = ntohs(raw);
	session->pmuConfig2.DataRate.m_datarateRaw = raw;
	memcpy(&raw,(data+offset),2);
	offset+=2;
	raw = ntohs(raw);
	// Read CRC16
	session->pmuConfig2.FooterCrc16 = raw;
	*offsetOrg = offset;

	session->capturedConfig2 = 1;
return 0;
}




int PMUDecode(pmu_session_data_t *session,pmu_config_t *config, SFSnortPacket *packet)
{




    if(*(packet->payload)!=0xaa && session->partialData!=1) //1 is for on going construction
    	return 0 ;


    int offset = 0;

    if(session->partialData==0 && *(packet->payload)==0xaa)
    {
    	memcpy(&(session->FrameSize),(packet->payload +2),2);
    	    session->FrameSize = ntohs(session->FrameSize);

    session->FrameData = g_string_new_len(packet->payload,packet->payload_size);
    if(session->FrameSize>packet->payload_size)
    {

    	session->partialData=1;
    }
    else
    	session->partialData=3;

    }

    else if(session->partialData==1 && *(packet->payload)!=0xaa )
    {

    	session->FrameData =g_string_append_len(session->FrameData,packet->payload,packet->payload_size);
    	if(session->FrameSize<=session->FrameData->len)
    	    {

    	    	session->partialData=3;
    	    }
    }

    else if((session->partialData==3 || session->partialData==1) && *(packet->payload)==0xaa)
        {
        	session->FrameData =g_string_free(session->FrameData,1);
        	session->FrameData =NULL;
        	memcpy(&(session->FrameSize),(packet->payload +2),2);
        	    session->FrameSize = ntohs(session->FrameSize);


        	        session->FrameData = g_string_new_len(packet->payload,packet->payload_size);

        	if(session->FrameSize>session->FrameData->len)
        	    {

        	    	session->partialData=1;
        	    }
        	else
        		session->partialData=3;
        }
    else
    {
    	if(session->FrameData!=NULL)
    	session->FrameData =g_string_free(session->FrameData,1);
    	session->partialData=0;
    	_dpd.logMsg("Wrong condition\n");
    	return 0;
    }



    /* Lay the header struct over the payload */
    if(session->FrameData->len>=PMU_MIN_LEN)
    {
    	offset = 0;
       extractFrameHdr(session,session->FrameData->str,session->FrameData->len, &offset);

   switch( session->Sync.FrameType)
   {
   case(DATA_FRAME):
		/*
		         * Add code here to modify the data
		         */
		    if(session->capturedConfig2){
		        if(modifyData(config, session, packet))
		        {
		        	packet->flags|=0x00400000;
		        //	_dpd.logMsg("Got to Modify Data\n");
		        }
		    }
	  _dpd.logMsg("Got a Data frame\n");
   break;
   case(CONFIGURATION_FRAME_2):

		if(session->partialData==3)
		{
		   if(session->pmuConfig2.PMUs)
		   {
			   //should free individual memory
		g_slist_free(session->pmuConfig2.PMUs);
		session->pmuConfig2.PMUs =  NULL;
		   }
		extractConfig2Data(session,session->FrameData->str,session->FrameData->len, &offset);
		if(session->FrameData!=NULL)
		    	session->FrameData =g_string_free(session->FrameData,1);
		    	session->partialData=0;
		}
		 _dpd.logMsg("Got a Config 2 frame\n");
		   break;
   case(COMMAND_FRAME):
		if(session->partialData==3)
				{


				if(session->FrameData!=NULL)
				    	session->FrameData =g_string_free(session->FrameData,1);
				    	session->partialData=0;
				}
   		 _dpd.logMsg("Got a command frame\n");
   		   break;
   default:
	   break;
   }


    }

    return PMU_OK;
}
