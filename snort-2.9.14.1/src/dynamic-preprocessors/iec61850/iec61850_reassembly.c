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
 *
 * Dynamic preprocessor for the IEC61850 protocol
 *
 */

#include "iec61850_reassembly.h"

#include <string.h>
#include <stdint.h>

#include "sf_types.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_packet.h"
#include "snort_bounds.h"
#include "glib.h"

#include "spp_iec61850.h"

#ifdef DUMP_BUFFER
#include "iec61850_buffer_dump.h"
#endif



/* Append a IEC61850 Transport segment to the reassembly buffer.

   Returns:
    IEC61850_OK:    Segment queued successfully.
    IEC61850_FAIL:  Data copy failed. Segment did not fit in reassembly buffer.
 */
static int IEC61850QueueSegment(iec61850_reassembly_data_t *rdata, char *buf, uint16_t buflen)
{
	if (rdata == NULL || buf == NULL)
		return IEC61850_FAIL;

	/* the first four bytes has the TPKT header, The next 3 bytes has the COTP check to see if the payload continues in the next segment
	 * the first of the 3 bytes is the length, the second identifies the PDU type 0x0f is DT Data.
	 * the last byte is important the MS Bit indicates if this is the last of the segments. the rest indicates the segment number starting at 0x00
	 */

	/* Set the initial memory to 1500 bytes. */

if(rdata->buflen+buflen>rdata->maxLen)
{
	rdata->buffer = g_realloc(rdata->buffer,rdata->maxLen+1500);
	rdata->maxLen +=1500;
}
	memcpy((rdata->buffer + rdata->buflen), buf, (size_t) buflen);
	rdata->buflen += buflen;
	return IEC61850_OK;
}

/* Reset a IEC61850 reassembly buffer */
static void IEC61850ReassemblyReset(iec61850_reassembly_data_t *rdata)
{
	rdata->buflen = 0;
	g_free(rdata->buffer);
	rdata->buffer = g_new0(char,1500);
	rdata->maxLen =1500;
	rdata->currentPacketStarts = 0;
	rdata->segment = 1;
	rdata->state=IEC61850_REASSEMBLY_STATE__IDLE;

}
//M_SP_NA_1 = 1,
//   M_SP_TA_1 = 2,
//   M_DP_NA_1 = 3,
//   M_DP_TA_1 = 4,
//   M_ST_NA_1 = 5,
//   M_ST_TA_1 = 6,
//   M_BO_NA_1 = 7,
//   M_BO_TA_1 = 8,
//   M_ME_NA_1 = 9,
//   M_ME_TA_1 = 10,malloc
//   M_ME_NB_1 = 11,
//   M_ME_TB_1 = 12,
//   M_ME_NC_1 = 13,
//   M_ME_TC_1 = 14,
//   M_IT_NA_1 = 15,
//   M_IT_TA_1 = 16,
//   M_EP_TA_1 = 17,
//   M_EP_TB_1 = 18,
//   M_EP_TC_1 = 19,
//   M_PS_NA_1 = 20,
//   M_ME_ND_1 = 21,



static int modifyData(iec61850_config_t *config, iec61850_session_data_t *session,uint8_t * pdu_start, uint16_t pdu_length)
{
int modified = 0;
mms_read_request_t * listOfDataIDsMMSReqs;
GSList * listOfDataIDs =NULL;
GSList *tempIDs = NULL;
iec61850_reassembly_data_t *rdata;
rdata = session->responce_rdata;

//need to lookup for the invokeID and process up to the place where the Actual data is.


	int length = 0;
	char * domainID=NULL;
	char * itemID=NULL;

	uint16_t offset = rdata->mmsDataStart;

	int32_t invokeID=0;
	char tempReq = 0xa0;
	char tempResp = 0xa1;
	char tempStruct = 0xa2;
	char tempRead = 0xa4;
	char tempInt =0x02;
	char tempSeq = 0x30;
	char tempStr = 0x1a;
	if(rdata)
	{
		if(strncmp(rdata->buffer+offset,&tempReq,1)!=0) //the ASN1-type tag
			return IEC61850_FAIL;
		offset++;
		offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
		if(strncmp(rdata->buffer+offset,&tempResp,1)!=0) // check if it is a response
					return IEC61850_FAIL;
		offset++;
		offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
		if(strncmp(rdata->buffer+offset,&tempInt,1)==0)
		{
			offset++;
			offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
			invokeID = BerDecoder_decodeInt32(rdata->buffer, length, offset);
			offset+=length;
		}

	}
if(g_hash_table_size (session->hashTable)>0)
{
 listOfDataIDsMMSReqs=(mms_read_request_t *)g_hash_table_lookup(session->hashTable,&invokeID);
listOfDataIDs =  listOfDataIDsMMSReqs->domainIDAndItemID;
}
if(!listOfDataIDs)
{
	IEC61850ReassemblyReset(rdata);
	return modified;
}

for(int index = 0 ; index<config->numAlteredVal;index++)
	{
	tempIDs = listOfDataIDs;

		while(tempIDs!=NULL)
		{
			if(g_string_equal((GString *)(tempIDs->data),config->values_to_alter[index].domainIDAndItemID))
			{
				//modify the data
				_dpd.logMsg("Name Tag: %s\n",((GString *)(tempIDs->data))->str);


				//modify
				if(strncmp(rdata->buffer+offset,&tempRead,1)!=0)
						{

							IEC61850ReassemblyReset(rdata);
							return IEC61850_OK;
						}

						offset++; //read request
						offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
						//offset points to AccessResult field indicates whether the operation was successful or not
						if(strncmp(rdata->buffer+offset,&tempResp,1)!=0)
								{
									//Access was unsuccessful
									IEC61850ReassemblyReset(rdata);
									return IEC61850_OK;
								}
						offset++;
						offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);

						//TODO: Will be a structure or data here where the data is. Should put the data in tree format
						if(strncmp(rdata->buffer+offset,&tempStruct,1)==0) //the root of tree
						{  //is a structure
							offset++;
							offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);

							int level = 0;
							int child = 1;
							//now read the nth level of the variable tree checking if the second parameter in the change string matches
							while(offset<rdata->buflen){
								if(strncmp(rdata->buffer+offset,&tempStruct,1)==0) //Start of level level+1 nodes
								{
									offset++;
									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
									if(config->values_to_alter[index].intStruct[level]==child)
									{
										level++;
										child = 1;


										// set the offset to jump to the next struct inside the current struct
									}
									else
									{
										//goto the next child
										child++;
										offset+=length;
										//set the offset to jump to the next struct
									}



								}


						else
						{
							int dataOffsetFromStart = 0;
							uint8_t switchVal;
							memcpy(&switchVal,rdata->buffer+offset,1);
							switch(switchVal)
							{
							case(0x83):

								modified=1;
								offset++;
								offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
								if(offset>0)
								{
									dataOffsetFromStart = offset - rdata->currentPacketStarts;
									dataOffsetFromStart+=7;

									int8_t tempBoolVal = strtol(config->values_to_alter[index].newVal->str,NULL,10);
									memcpy(pdu_start+dataOffsetFromStart,&tempBoolVal ,length);

								}

								break;

							case(0x85):

								modified=1;
								offset++;
								offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
								if(offset>0)
								{
									dataOffsetFromStart = offset - rdata->currentPacketStarts;
									dataOffsetFromStart+=7;
									int64_t tempIntVal = strtoll(config->values_to_alter[index].newVal->str,NULL,10);
									char * tempCharVal = malloc(sizeof(int64_t));
									memcpy(tempCharVal,&tempIntVal,sizeof(int64_t));

									memcpy(pdu_start+dataOffsetFromStart,tempCharVal ,length);

									free(tempCharVal);
								}
								break;



							case(0x86):

								modified=1;
								offset++;
								offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
								if(offset>0)
								{
									dataOffsetFromStart = offset - rdata->currentPacketStarts;
									dataOffsetFromStart+=7;
									uint64_t tempUIntVal = strtoull(config->values_to_alter[index].newVal->str,NULL,10);
									char * tempCharVal = malloc(sizeof(uint64_t));
									memcpy(tempCharVal,&tempUIntVal,sizeof(uint64_t));

									memcpy(pdu_start+dataOffsetFromStart,tempCharVal ,length);

									free(tempCharVal);
								}
								break;


							case(0x87):

								modified=1;
								offset++;
								offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
								if(offset>0)
								{
									dataOffsetFromStart = offset - rdata->currentPacketStarts;
									dataOffsetFromStart+=7;
									uint8_t additionalBits = length - 4;
									float tempDoubleVal = strtof(config->values_to_alter[index].newVal->str,NULL);
									int32_t * tempCharVal = malloc(4);
									memcpy(tempCharVal,&tempDoubleVal,sizeof(float));
									*tempCharVal = htonl(*tempCharVal);
									memcpy(pdu_start+dataOffsetFromStart+additionalBits,tempCharVal,length);

									free(tempCharVal);
								}
								break;



							case(0x84):

								modified=1;
								offset++;
								offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
								if(offset>0)
								{
									dataOffsetFromStart = offset - rdata->currentPacketStarts;
									dataOffsetFromStart+=7;
									uint16_t tempCodemEnumVal = strtol(config->values_to_alter[index].newVal->str,NULL,16);
									tempCodemEnumVal = ntohs(tempCodemEnumVal);
									char * tempCharVal = malloc(sizeof(uint16_t));
									memset(tempCharVal,0,2);
									memcpy(tempCharVal,&tempCodemEnumVal,sizeof(uint16_t));

									memcpy(pdu_start+dataOffsetFromStart,tempCharVal ,length);

									free(tempCharVal);
								}
								break;


							case(0x89):

								modified=1;
								offset++;
								offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
								if(offset>0)
								{
									dataOffsetFromStart = offset - rdata->currentPacketStarts;
									dataOffsetFromStart+=7;
									memcpy(pdu_start+dataOffsetFromStart,config->values_to_alter[index].newVal->str ,length);
								}
								break;

							case(0x8a):

								modified=1;
								offset++;
								offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
								if(offset>0)
								{
									dataOffsetFromStart = offset - rdata->currentPacketStarts;
									dataOffsetFromStart+=7;
									memcpy(pdu_start+dataOffsetFromStart,config->values_to_alter[index].newVal->str ,length);


								}
								break;
							case(0x91):

								modified=1;
								offset++;
								offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
								if(offset>0)
								{
									dataOffsetFromStart = offset - rdata->currentPacketStarts;
									dataOffsetFromStart+=7;
									uint64_t tempUIntVal = strtoull(config->values_to_alter[index].newVal->str,NULL,10);
									char * tempCharVal = malloc(sizeof(uint64_t));
									memcpy(tempCharVal,&tempUIntVal,sizeof(uint64_t));

									memcpy(pdu_start+dataOffsetFromStart,tempCharVal ,length);

									free(tempCharVal);
								}
								break;

							default:
								offset++;
								offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
								break;
							//data is here
							}
						}
					}

					IEC61850ReassemblyReset(rdata);

				//
				//
			}
						else
						{
							int level = 0;
							int child = 1;
							boolean done = FALSE;
							while(offset<rdata->buflen && !done){
															if(strncmp(rdata->buffer+offset,&tempStruct,1)!=0) //Start of level level+1 nodes
															{

																if(config->values_to_alter[index].intStruct[level]==child)
																{
																	//modify the child node
																	int dataOffsetFromStart = 0;
																								uint8_t switchVal;
																								memcpy(&switchVal,rdata->buffer+offset,1);
																	switch(switchVal)
																								{
																								case(0x83):

																									modified=1;
																									offset++;
																									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																									if(offset>0)
																									{
																										dataOffsetFromStart = offset - rdata->currentPacketStarts;
																										dataOffsetFromStart+=7;

																										int8_t tempBoolVal = strtol(config->values_to_alter[index].newVal->str,NULL,10);
																										memcpy(pdu_start+dataOffsetFromStart,&tempBoolVal ,length);
																										done=TRUE;
																									}

																									break;

																								case(0x85):

																									modified=1;
																									offset++;
																									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																									if(offset>0)
																									{
																										dataOffsetFromStart = offset - rdata->currentPacketStarts;
																										dataOffsetFromStart+=7;
																										int64_t tempIntVal = strtoll(config->values_to_alter[index].newVal->str,NULL,10);
																										char * tempCharVal = malloc(sizeof(int64_t));
																										memcpy(tempCharVal,&tempIntVal,sizeof(int64_t));

																										memcpy(pdu_start+dataOffsetFromStart,tempCharVal ,length);
																										done=TRUE;
																										free(tempCharVal);
																									}
																									break;



																								case(0x86):

																									modified=1;
																									offset++;
																									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																									if(offset>0)
																									{
																										dataOffsetFromStart = offset - rdata->currentPacketStarts;
																										dataOffsetFromStart+=7;
																										uint64_t tempUIntVal = strtoull(config->values_to_alter[index].newVal->str,NULL,10);
																										char * tempCharVal = malloc(sizeof(uint64_t));
																										memcpy(tempCharVal,&tempUIntVal,sizeof(uint64_t));

																										memcpy(pdu_start+dataOffsetFromStart,tempCharVal ,length);
																										done=TRUE;
																										free(tempCharVal);
																									}
																									break;


																								case(0x87):

																									modified=1;
																									offset++;
																									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																									if(offset>0)
																									{
																										dataOffsetFromStart = offset - rdata->currentPacketStarts;
																										dataOffsetFromStart+=7;
																										uint8_t additionalBits = length - 4;
																										float tempDoubleVal = strtof(config->values_to_alter[index].newVal->str,NULL);
																										int32_t * tempCharVal = malloc(4);
																										memcpy(tempCharVal,&tempDoubleVal,sizeof(float));
																										*tempCharVal = htonl(*tempCharVal);
																										memcpy(pdu_start+dataOffsetFromStart+additionalBits,tempCharVal,length);
																										done=TRUE;
																										free(tempCharVal);
																									}
																									break;



																								case(0x84):

																									modified=1;
																									offset++;
																									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																									if(offset>0)
																									{
																										dataOffsetFromStart = offset - rdata->currentPacketStarts;
																										dataOffsetFromStart+=7;
																										uint16_t tempCodemEnumVal = strtol(config->values_to_alter[index].newVal->str,NULL,16);
																										tempCodemEnumVal = ntohs(tempCodemEnumVal);
																										char * tempCharVal = malloc(sizeof(uint16_t));
																										memset(tempCharVal,0,2);
																										memcpy(tempCharVal,&tempCodemEnumVal,sizeof(uint16_t));

																										memcpy(pdu_start+dataOffsetFromStart,tempCharVal ,length);
																										done=TRUE;
																										free(tempCharVal);
																									}
																									break;


																								case(0x89):

																									modified=1;
																									offset++;
																									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																									if(offset>0)
																									{
																										dataOffsetFromStart = offset - rdata->currentPacketStarts;
																										dataOffsetFromStart+=7;
																										memcpy(pdu_start+dataOffsetFromStart,config->values_to_alter[index].newVal->str ,length);
																										done=TRUE;
																									}
																									break;

																								case(0x8a):

																									modified=1;
																									offset++;
																									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																									if(offset>0)
																									{
																										dataOffsetFromStart = offset - rdata->currentPacketStarts;
																										dataOffsetFromStart+=7;
																										memcpy(pdu_start+dataOffsetFromStart,config->values_to_alter[index].newVal->str ,length);

																										done=TRUE;
																									}
																									break;
																								case(0x91):

																									modified=1;
																									offset++;
																									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																									if(offset>0)
																									{
																										dataOffsetFromStart = offset - rdata->currentPacketStarts;
																										dataOffsetFromStart+=7;
																										uint64_t tempUIntVal = strtoull(config->values_to_alter[index].newVal->str,NULL,10);
																										char * tempCharVal = malloc(sizeof(uint64_t));
																										memcpy(tempCharVal,&tempUIntVal,sizeof(uint64_t));

																										memcpy(pdu_start+dataOffsetFromStart,tempCharVal ,length);
																										done=TRUE;
																										free(tempCharVal);
																									}
																									break;

																								default:
																									offset++;
																									offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																									break;
																								//data is here
																								}


																}
																else
																{
																	//goto the next child
																	offset++;
																	offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
																	child++;
																	offset+=length;
																	//set the offset to jump to the next struct
																}



															}}
						}

		}
			tempIDs = tempIDs->next;
	}
	}

	g_hash_table_remove(session->hashTable,&invokeID);
	return modified;
}
static int copyReassemblyData(iec61850_reassembly_data_t *rdataDest, iec61850_reassembly_data_t *rdataSrc)
{
	if(rdataDest->maxLen<rdataSrc->maxLen)
		rdataDest->buffer = g_realloc(rdataDest->buffer,rdataSrc->buflen+1);
	rdataDest->buffer = memcpy(rdataDest->buffer,rdataSrc->buffer,rdataSrc->maxLen);
	rdataDest->buflen = rdataSrc->buflen;
	rdataDest->maxLen = rdataSrc->maxLen;
	rdataDest->state = rdataSrc->state;
	rdataDest->mmsDataStart = rdataSrc->mmsDataStart;

	if(rdataDest->buffer)
		return IEC61850_OK;

	return IEC61850_FAIL;

}

static int IEC61850ReassembleTransport(iec61850_reassembly_data_t *rdata, char *buf, uint16_t buflen)
{
	COTP_header_t trans_header;


	if (rdata == NULL || buf == NULL || buflen < sizeof(COTP_header_t)+15)
	{
		return IEC61850_FAIL;
	}

	/*find the length of the packet
	 * if less than 145 the header length will be fixed else the ISO 8823 header length varies*/

	uint16_t lengthTPKT,lengthCPC_PPDU;


	memcpy(&lengthTPKT,buf+2,2);


	buf+=TPKT_HEADER_LENGTH; //skip the tpkt header
    buflen -= TPKT_HEADER_LENGTH;
	trans_header.length = *buf;
	trans_header.pdu_type = *(buf+1);
	if(trans_header.pdu_type!=0xf0)
		return IEC61850_FAIL;
	trans_header.TPDU_number = *(buf+2) & 0x7f;
	trans_header.isLastDataUnit = ((*(buf+2) & 0x80)==0x80);

	buf += trans_header.length+1;  // at this point the buffer only has application data
	buflen -= (trans_header.length+1);
	_dpd.logMsg("Is Last TPDU: %x \n",(*(buf+2) & 0x80));

	//should combine the multiple fragments before checking for the


					/* If the previously-existing state was DONE, we need to reset it back
       to IDLE. */
	if (rdata->state == IEC61850_REASSEMBLY_STATE__DONE)
	{

		IEC61850ReassemblyReset(rdata);
	}
	switch (rdata->state)
	{
	case IEC61850_REASSEMBLY_STATE__IDLE:
		/* Discard any non-first segment. */
		if ( trans_header.TPDU_number != 0 )
			return IEC61850_FAIL;

		/* Reset the buffer & queue the first segment */
		IEC61850ReassemblyReset(rdata);

		_dpd.logMsg("Queue segment at Idle \n");
		IEC61850QueueSegment(rdata, buf, buflen);


		if ( trans_header.isLastDataUnit )
		{
			rdata->state = IEC61850_REASSEMBLY_STATE__DONE;
			_dpd.logMsg("Last Data unit at idle \n");
		}else
			rdata->state = IEC61850_REASSEMBLY_STATE__ASSEMBLY;

		break;

	case IEC61850_REASSEMBLY_STATE__ASSEMBLY:
		/* Reset if tpdu num is 0x00. */
		if ( trans_header.TPDU_number ==0x00 )
		{
			_dpd.logMsg("Queue segment at Assembly \n");
			rdata->segment++;
			rdata->currentPacketStarts = rdata->buflen;
			IEC61850QueueSegment(rdata, buf, buflen);

			if (trans_header.isLastDataUnit )
				rdata->state = IEC61850_REASSEMBLY_STATE__DONE;
			else
							rdata->state = IEC61850_REASSEMBLY_STATE__ASSEMBLY;


		}

		break;

	case IEC61850_REASSEMBLY_STATE__DONE:
		//Now process the ISO8823 header
		_dpd.logMsg("Queue segment done \n");
		break;
	}

	/* Set the Alt Decode buffer. This must be done during preprocessing
       in order to stop the Fast Pattern matcher from using raw packet data
       to evaluate the longest content in a rule. */
	if (rdata->state == IEC61850_REASSEMBLY_STATE__DONE)
	{
		_dpd.logMsg("Queue segment done \n");
		char *completeBuff = rdata->buffer;
		uint16_t completeBufLen = rdata->buflen;
		int offset = 0;
		completeBuff += (2*ISO8327_HEADER_LENGTH);  // at this point the buffer only has application data
		completeBufLen -= (2*ISO8327_HEADER_LENGTH);

				if(lengthTPKT<145)
				{
					completeBuff += ISO8823_HEADER_LENGTH;  // at this point the buffer only has application data
					completeBufLen -=ISO8823_HEADER_LENGTH;
					rdata->mmsDataStart =ISO8823_HEADER_LENGTH+2*ISO8327_HEADER_LENGTH;
				}
				else
				{
					if(completeBuff[offset++]==0x61) //CPC-type PPDU
					{
						//run through packet and find the offset at the end
						offset = BerDecoder_decodeLength(completeBuff,&lengthCPC_PPDU,offset,completeBufLen);
						 _dpd.logMsg("PDV-list: |%x| \n", completeBuff[offset]);
						offset++;
						offset = BerDecoder_decodeLength(completeBuff,&lengthCPC_PPDU,offset,completeBufLen);
						 _dpd.logMsg("Presentation context Tag: |%x| \n", completeBuff[offset]);
						offset+=3;
						completeBuff+=offset;
											completeBufLen-=offset;
										rdata->mmsDataStart =  offset+2*ISO8327_HEADER_LENGTH;

					}
					else{
						IEC61850ReassemblyReset(rdata);
								return IEC61850_FAIL;

					}//process the ISO8823 header for length


				}


				uint32_t length = 0;
				offset = 0;
				char tempReq = 0xa0;
				char tempResp = 0xa1;
				_dpd.logMsg("ASN1-type tag: |%x| \n", completeBuff[0]);
				if(strncmp(completeBuff,&tempReq,1)==0) //the ASN1-type tag
				{
					offset++;
						offset = BerDecoder_decodeLength(completeBuff,&length, offset, completeBufLen);


						if(strncmp(completeBuff+offset,&tempReq,1)==0) // check if it is a request
						{


							_dpd.logMsg("Request: |%x| \n", completeBuff[offset]);

									return IEC61850_OK;
						}
						else if (strncmp(completeBuff+offset,&tempResp,1)==0)
						{

							_dpd.logMsg("Response: |%x| \n", completeBuff[offset]);

									return IEC61850_OK;
						}//response
						else
							return IEC61850_FAIL;


				}
//		uint8_t *alt_buf = _dpd.altBuffer->data;
//		uint16_t alt_len = sizeof(_dpd.altBuffer->data);
//		int ret;
//
//		ret = SafeMemcpy((void *)alt_buf,
//				(const void *)rdata->buffer,
//				(size_t)rdata->buflen,
//				(const void *)alt_buf,
//				(const void *)(alt_buf + alt_len));
//
//		if (ret == SAFEMEM_SUCCESS)
//			_dpd.SetAltDecode(alt_len);



	}

	return IEC61850_OK;
}

static int
BerDecoder_decodeLength(uint8_t* buffer, int* length, int bufPos, int maxBufPos)
{
    if (bufPos >= maxBufPos)
        return -1;

    uint8_t len1 = buffer[bufPos++];


    if (len1 & 0x80) {
        int lenLength = len1 & 0x7f;

        if (lenLength == 0) { /* indefinite length form */
            *length = -1;
        }
        else {
            *length = 0;

            int i;
            for (i = 0; i < lenLength; i++) {
                if (bufPos >= maxBufPos)
                    return -1;

                *length <<= 8;
                *length += buffer[bufPos++];

            }
        }

    }
    else {
        *length = len1;
    }

    if (*length < 0)
        return -1;



    return bufPos;
}


static char*
BerDecoder_decodeString(uint8_t* buffer, int strlen, int bufPos, int maxBufPos)
{
    char* string = (char*) malloc(strlen + 1);
    memcpy(string, buffer + bufPos, strlen);
    string[strlen] = 0;

    return string;
}

static uint32_t
BerDecoder_decodeUint32(uint8_t* buffer, int intLen, int bufPos)
{
    uint32_t value = 0;

    int i;
    for (i = 0; i < intLen; i++) {
        value <<= 8;
        value += buffer[bufPos + i];
    }

    return value;
}

static int32_t
BerDecoder_decodeInt32(uint8_t* buffer, int intlen, int bufPos)
{
    int32_t value;
    int i;

    bool isNegative = ((buffer[bufPos] & 0x80) == 0x80);

    if (isNegative)
        value = -1;
    else
        value = 0;

    for (i = 0; i < intlen; i++) {
        value <<= 8;
        value += buffer[bufPos + i];
    }

    return value;
}

static float
BerDecoder_decodeFloat(uint8_t* buffer, int bufPos)
{
    float value;
    uint8_t* valueBuf = (uint8_t*) &value;

    int i;

    bufPos += 1; /* skip exponentWidth field */

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    for (i = 3; i >= 0; i--) {
        valueBuf[i] = buffer[bufPos++];
    }
#else
    for (i = 0; i < 4; i++) {
        valueBuf[i] = buffer[bufPos++];
    }
#endif

    return value;
}

static double
BerDecoder_decodeDouble(uint8_t* buffer, int bufPos)
{
    double value;
    uint8_t* valueBuf = (uint8_t*) &value;

    int i;

    bufPos += 1; /* skip exponentWidth field */

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    for (i = 7; i >= 0; i--) {
        valueBuf[i] = buffer[bufPos++];
    }
#else
    for (i = 0; i < 8; i++) {
        valueBuf[i] = buffer[bufPos++];
    }
#endif

    return value;
}

static bool
BerDecoder_decodeBoolean(uint8_t* buffer, int bufPos) {
    if (buffer[bufPos] != 0)
        return true;
    else
        return false;
}


static int IEC61850SaveRequestData(iec61850_session_data_t *session,iec61850_config_t *config)
{
	iec61850_reassembly_data_t *rdata;

	int length = 0;
	char * domainID=NULL;
	char * itemID=NULL;
	rdata = session->request_rdata;
	uint16_t offset = rdata->mmsDataStart; //TODO: on Monday
	mms_read_request_t *readReqData = g_new0(mms_read_request_t,1);
	readReqData->domainIDAndItemID=NULL;
	readReqData->invokeID=0;
	readReqData->rootChild = 0;
	char tempReq = 0xa0;
	char tempResp = 0xa1;
	char tempRead = 0xa4;
	char tempInt =0x02;
	char tempSeq = 0x30;
	char tempStr = 0x1a;
	if(rdata)
	{
		if(strncmp(rdata->buffer+offset,&tempReq,1)!=0) //the ASN1-type tag
			return IEC61850_FAIL;
		offset++;
		offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
		if(strncmp(rdata->buffer+offset,&tempReq,1)!=0) // check if it is a request
					return IEC61850_FAIL;
		offset++;
		offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
		if(strncmp(rdata->buffer+offset,&tempInt,1)==0)
		{
			offset++;
			offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
			readReqData->invokeID = BerDecoder_decodeInt32(rdata->buffer, length, offset);
			offset+=length;
		}

		if(strncmp(rdata->buffer+offset,&tempRead,1)!=0)
		{
			g_free(readReqData);
			IEC61850ReassemblyReset(rdata);
			return IEC61850_OK;
		}

		offset++; //read request
		offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
		//offset points to specificationWithResult field do not need that
		offset++;
		offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
		offset+=length;
		//points to variable access specification
		if(strncmp(rdata->buffer+offset,&tempResp,1)==0)
		{
			offset++;
			offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
			if(strncmp(rdata->buffer+offset,&tempReq,1)==0) //listOfVariable
			{
				offset++;
				offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);


				while(offset<rdata->buflen){
				if(strncmp(rdata->buffer+offset,&tempSeq,1)==0) //Start of sequence
				{   readReqData->rootChild++;
					offset++;
					offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);

					if(strncmp(rdata->buffer+offset,&tempReq,1)==0) //name
									{
										offset++;
										offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);

										if(strncmp(rdata->buffer+offset,&tempResp,1)==0) //domain specific
										{
											offset++;
											offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
											if(strncmp(rdata->buffer+offset,&tempStr,1)==0) //identifier domainID
											{   int lenDomainAndItem = 0;
												offset++;
												offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
												 domainID = BerDecoder_decodeString(rdata->buffer, length, offset, rdata->buflen);
												 offset+=length;
												 lenDomainAndItem+=length;
												 GString *domainAndItemId = g_string_new_len(domainID,lenDomainAndItem);
												 domainAndItemId = g_string_append_c (domainAndItemId,'$');
												 if(strncmp(rdata->buffer+offset,&tempStr,1)==0) //identifier domainID
												 {
													 offset++;
													 offset = BerDecoder_decodeLength(rdata->buffer,&length, offset, rdata->buflen);
													 itemID = BerDecoder_decodeString(rdata->buffer, length, offset, rdata->buflen);
													 offset+=length;
													// lenDomainAndItem+=length;

													 g_string_insert(domainAndItemId,
															 lenDomainAndItem+1,itemID);
													 lenDomainAndItem+=length;
													 boolean isPresent = FALSE;
													 _dpd.logMsg("InvokeID : %d Domain$ItemID: %s \n", readReqData->invokeID,domainAndItemId->str);
													 for(int i=0;i<config->numAlteredVal;i++)
													 {
														 if(g_string_equal(config->values_to_alter[i].domainIDAndItemID,domainAndItemId)) // checking if we want to keep track of this request
														 {

															 readReqData->domainIDAndItemID =g_slist_append(readReqData->domainIDAndItemID,domainAndItemId);
															 isPresent = TRUE;
															 _dpd.logMsg("InvokeID : %d Domain$ItemID: %s => Present \n", readReqData->invokeID,readReqData->domainIDAndItemID->data);
															 config->values_to_alter[i].intStruct[0]=readReqData->rootChild;
															 break;
														 }
												 }
													 if(!isPresent)
														 g_string_free(domainAndItemId,TRUE);
												 }
											}
										}
									}

				}

				}
				if(readReqData->domainIDAndItemID)
				{
				session->requestList = g_slist_append(session->requestList,readReqData);
				 g_hash_table_insert(session->hashTable,&(readReqData->invokeID),readReqData);
				}

				else
					g_free(readReqData);

			}
		}
	}

	IEC61850ReassemblyReset(rdata);
	return IEC61850_OK;
}

/* Main IEC61850 Reassembly function. Moved here to avoid circular dependency between
   spp_iec61850 and iec61850_reassembly. */
int IEC61850FullReassembly(iec61850_config_t *config, iec61850_session_data_t *session, SFSnortPacket *packet, uint8_t *pdu_start, uint16_t pdu_length)
{

	iec61850_reassembly_data_t *rdata;
if(packet->dst_port == 102)
{
	session->direction=REQUEST_PDU;
	rdata = session->request_rdata;
}
else{
	session->direction=RESPONSE_PDU;
	rdata = session->responce_rdata;
}
	uint16_t offset = 0;

		if (IEC61850ReassembleTransport(rdata, pdu_start, pdu_length) == IEC61850_FAIL)
			return IEC61850_FAIL;


		if(session->direction==REQUEST_PDU && session->request_rdata->state == IEC61850_REASSEMBLY_STATE__DONE)
				{
			IEC61850SaveRequestData(session,config);
				}


		else if(session->direction==RESPONSE_PDU)
		{

			if(modifyData(config, session,pdu_start, pdu_length))
				packet->flags|=FLAG_MODIFIED;

		}
		/* Step 4: Decode Application-Layer  */
//		if (rdata->state == IEC61850_REASSEMBLY_STATE__DONE)
//		{
//			int ret = IEC61850ProcessApplication(session);
//
//
//
//			/* To support multiple PDUs in UDP, we're going to call Detect()
//	           on each individual PDU. The AltDecode buffer was set earlier. */
//			if ((ret == IEC61850_OK) && (packet->udp_header))
//				_dpd.detect(packet);
//			else
//				return ret;
//		}

		return IEC61850_OK;
}

