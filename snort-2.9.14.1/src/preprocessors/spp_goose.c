/* $Id$ */
/*
** Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2004-2013 Sourcefire, Inc.
** Copyright (C) 2001-2004 Jeff Nathan <jeff@snort.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* Snort GOOSE Preprocessor Plugin
 *   by Chamara Devanarayana <chamara@rtds.com> based on libiec61850-1.4.0 https://github.com/mz-automation/libiec61850
 *   Version 0.1.0
 *
 * Purpose:
 *
 * This preprocessor decodes GOOSE  packets and is able to modify the data
 *
 *
 *
 */

/*  I N C L U D E S  ************************************************/
#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef WIN32
# include <sys/time.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#else
# include <time.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "generators.h"
#include "log.h"
#include "detect.h"
#include "decode.h"
#include "encode.h"
#include "event.h"
#include "plugbase.h"
#include "parser.h"
#include "mstring.h"
#include "snort_debug.h"
#include "util.h"
#include "event_queue.h"

#include "snort.h"
#include "profiler.h"
#include "sfPolicy.h"
#include "session_api.h"
#include "spp_goose.h"
#include "glib.h"
/*  D E F I N E S  **************************************************/



/*  D A T A   S T R U C T U R E S  **********************************/



/*  G L O B A L S  **************************************************/
static tSfPolicyUserContextId iec61850_config = NULL;

GHashTable * gooseRefTable;

#ifdef PERF_PROFILING
PreprocStats arpPerfStats;
#endif


/*  P R O T O T Y P E S  ********************************************/
static void IEC61850Init(struct _SnortConfig *, char *args);

static void ParseIEC61850Args(IEC61850Config *, char *);


static void IEC61850CleanExit(int signal, void *unused);

static void IEC61850FullReassembly(Packet *p, void *context);

static void IEC61850FreeConfig(tSfPolicyUserContextId config);



#ifdef SNORT_RELOAD
static void IEC61850Reload(struct _SnortConfig *, char *, void **);
static void * IEC61850ReloadSwap(struct _SnortConfig *, void *);
static void IEC61850ReloadSwapFree(void *);
#endif


void SetupIEC61850(void)
{
#ifndef SNORT_RELOAD
    RegisterPreprocessor("goose", IEC61850Init);

#else
    RegisterPreprocessor("goose", IEC61850Init, IEC61850Reload, NULL,IEC61850ReloadSwap,IEC61850ReloadSwapFree);

#endif

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,
            "Preprocessor: IEC61850 is setup...\n"););
}



static void IEC61850Init(struct _SnortConfig *sc, char *args)
{
    int policy_id = (int)getParserPolicy(sc);
    IEC61850Config *pDefaultPolicyConfig = NULL;
    IEC61850Config *pCurrentPolicyConfig = NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,
            "Preprocessor: IEC61850 Initialized\n"););

    if (iec61850_config == NULL)
    {
    	iec61850_config = sfPolicyConfigCreate();

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("goose", &arpPerfStats, 0, &totalPerfStats, NULL);
#endif

        AddFuncToPreprocCleanExitList(IEC61850CleanExit, NULL, PRIORITY_LAST, PP_GOOSE);
    }

    sfPolicyUserPolicySet (iec61850_config, policy_id);
    pDefaultPolicyConfig = (IEC61850Config *)sfPolicyUserDataGetDefault(iec61850_config);
    pCurrentPolicyConfig = (IEC61850Config *)sfPolicyUserDataGetCurrent(iec61850_config);

    if ((policy_id != 0) && (pDefaultPolicyConfig == NULL))
    {
        ParseError("IEC61850 configuration: Must configure default policy "
                   "if other policies are to be configured.");
    }

    if (pCurrentPolicyConfig)
    {
        ParseError("IEC61850 can only be configured once.\n");
    }

    pCurrentPolicyConfig = (IEC61850Config *)SnortAlloc(sizeof(IEC61850Config));
    if (!pCurrentPolicyConfig)
    {
        ParseError("IEC61850 preprocessor: memory allocate failed.\n");
    }

    sfPolicyUserDataSetCurrent(iec61850_config, pCurrentPolicyConfig);
    /* Add IEC61850 to the preprocessor function list */
    AddFuncToPreprocList(sc, IEC61850FullReassembly, PRIORITY_NETWORK, PP_GOOSE, PROTO_BIT__GOOSE);
    session_api->enable_preproc_all_ports( sc, PP_GOOSE, PROTO_BIT__GOOSE );



    /* Parse the goose arguments from snort.conf */
    ParseIEC61850Args(pCurrentPolicyConfig, args);
    Active_Open(pCurrentPolicyConfig->interface->str);  //open the ethernet interface for active responce
    gooseRefTable = g_hash_table_new_full(iec61850ObjectHash, iec61850ObjectEqual,keyDestroyFunc,valueDestroyFunc);
}


/**
 * Parse arguments passed to the goose keyword.
 *
 * @param args preprocessor argument string
 *
 * @return void function
 */
static void ParseIEC61850Args(IEC61850Config *config, char *args)
{
    if ((config == NULL) || (args == NULL))
        return;

    char *saveptr;
        char *token;
        int index = 0;
    token = strtok_r(args, " ,", &saveptr);
        while (token != NULL)
        {

        	if (strcmp(token, "interface") == 0)  // add the interface name to the config
        	{
        		token = strtok_r(NULL, " ,", &saveptr);
        		config->interface = g_string_new(token);
        	}
        	else if (strcmp(token, "change") == 0)
    		{
            	int count =0;

            	//add the the objects to be modified
            	while(count<4 ) {
            	token = strtok_r(NULL, " ,", &saveptr);

            	 if (token == NULL)
            	             {
            		 ParseError("Missing argument for "
            	                     "IEC61850 preprocessor 'change' option.\n");

            	             }
            	 else{
            		 switch(count){
            		 	 	 	 	 case(0):
    								    if((config->values_to_alter[index]).gocbRef)
    									g_string_free((config->values_to_alter[index]).gocbRef,1);
            		 	 	 	 	 	(config->values_to_alter[index]).gocbRef = g_string_new(token+1);
            		 	 	 	 	 	g_string_truncate((config->values_to_alter[index]).gocbRef,(config->values_to_alter[index]).gocbRef->len-1);
            		 	 	 	 	 	break;
            						 case(1):
    									if((config->values_to_alter[index]).datSet)
    									g_string_free((config->values_to_alter[index]).datSet,1);
    		        		 	 	 	(config->values_to_alter[index]).datSet = g_string_new(token+1);
    		        		 	 	  	g_string_truncate((config->values_to_alter[index]).datSet,(config->values_to_alter[index]).datSet->len-1);
    		        		 	 	 	break;
    		   						 case(2):
    		   								 (config->values_to_alter[index]).dataItemNo = strtol(token,NULL,10);
            						 	 break;

            						 case(3):
    										if((config->values_to_alter[index]).newVal)
    											g_string_free((config->values_to_alter[index]).newVal,1);
    				        		 	 	 	(config->values_to_alter[index]).newVal = g_string_new(token);
    				        		 	 	 	break;
            						 	 break;
            						 default:
            							 break;


            	 }
            		 count++;
            	 }
            	}

            	index++;
            	config->numAlteredVal = index;
    		}

    token = strtok_r(NULL, " ,", &saveptr);
}
}


static guint iec61850ObjectHash(gconstpointer dataObject)
{
	//const GString *objHeader = ((frame_identifier_t *)dataObject)->gocbref;

	return g_int_hash(dataObject);
}



static gboolean iec61850ObjectEqual(gconstpointer dataObject1,gconstpointer dataObject2)
{
return	g_int_equal(dataObject1, dataObject2);
}



static void valueDestroyFunc(gconstpointer dataObject)
{

	g_free(dataObject);
}

static void keyDestroyFunc(gconstpointer dataObject)
{

	free(dataObject);
}




static int modifyData(uint8_t * pdu_start, uint16_t pdu_length,GList *dataSet, iec61850_asdu_header_t* pdu)
{
int modified = 0;
IEC61850Config* aconfig=NULL;
iec61850_Object_header_t* dataEnty=NULL;
sfPolicyUserPolicySet (iec61850_config, getNapRuntimePolicy());
   aconfig = (IEC61850Config *)sfPolicyUserDataGetCurrent(iec61850_config);


for(int index = 0 ; index<aconfig->numAlteredVal;index++)
	{

		if(g_string_equal(pdu->gocbRef,aconfig->values_to_alter[index].gocbRef) && g_string_equal(pdu->datSet,aconfig->values_to_alter[index].datSet))
				            		 {
									dataEnty=(iec61850_Object_header_t*)g_slist_nth_data(dataSet,aconfig->values_to_alter[index].dataItemNo);

									if(dataEnty==NULL)
									{
										return modified;
									}

									switch(dataEnty->type)
									{
									case(0x83):
										{
											modified=1;
											int8_t tempBoolVal = strtol(aconfig->values_to_alter[index].newVal->str,NULL,10);
											memcpy(pdu_start+dataEnty->dataOffsetFromStart,&tempBoolVal ,dataEnty->infElementBytesUsed);


											break;
										}
									case(0x85):
											{
													modified=1;
													int64_t tempIntVal = strtoll(aconfig->values_to_alter[index].newVal->str,NULL,10);
													char * tempCharVal = malloc(sizeof(int64_t));
													memcpy(tempCharVal,&tempIntVal,sizeof(int64_t));

													memcpy(pdu_start+dataEnty->dataOffsetFromStart,tempCharVal ,dataEnty->infElementBytesUsed);

													free(tempCharVal);
													break;
											}


									case(0x86):
											{
											modified=1;
									uint64_t tempUIntVal = strtoull(aconfig->values_to_alter[index].newVal->str,NULL,10);
									char * tempCharVal = malloc(sizeof(uint64_t));
									memcpy(tempCharVal,&tempUIntVal,sizeof(uint64_t));

									memcpy(pdu_start+dataEnty->dataOffsetFromStart,tempCharVal ,dataEnty->infElementBytesUsed);

									free(tempCharVal);
									break;
											}

									case(0x87):
											{
																						modified=1;
									uint8_t additionalBits = dataEnty->infElementBytesUsed - 4;
									float tempDoubleVal = strtof(aconfig->values_to_alter[index].newVal->str,NULL);
									int32_t * tempCharVal = malloc(4);
									memcpy(tempCharVal,&tempDoubleVal,sizeof(float));
                                    *tempCharVal = htonl(*tempCharVal);
									memcpy(pdu_start+dataEnty->dataOffsetFromStart+additionalBits,tempCharVal,dataEnty->infElementBytesUsed);

									free(tempCharVal);
									break;
											}

									case(0x84):
										{
										modified=1;
										uint16_t tempCodemEnumVal = strtol(aconfig->values_to_alter[index].newVal->str,NULL,16);
										tempCodemEnumVal = ntohs(tempCodemEnumVal);
										char * tempCharVal = malloc(sizeof(uint16_t));
										memset(tempCharVal,0,2);
										memcpy(tempCharVal,&tempCodemEnumVal,sizeof(uint16_t));

										memcpy(pdu_start+dataEnty->dataOffsetFromStart,tempCharVal ,dataEnty->infElementBytesUsed);

										free(tempCharVal);
										break;
										}

									case(0x89):
										{
										modified=1;
										memcpy(pdu_start+dataEnty->dataOffsetFromStart,aconfig->values_to_alter[index].newVal->str ,dataEnty->infElementBytesUsed);

										break;
										}
									case(0x8a):
										{
										modified=1;
										memcpy(pdu_start+dataEnty->dataOffsetFromStart,aconfig->values_to_alter[index].newVal->str ,dataEnty->infElementBytesUsed);
										break;
										}
									case(0x91):
										{
										modified=1;
										uint64_t tempUIntVal = strtoull(aconfig->values_to_alter[index].newVal->str,NULL,10);
										char * tempCharVal = malloc(sizeof(uint64_t));
										memcpy(tempCharVal,&tempUIntVal,sizeof(uint64_t));

										memcpy(pdu_start+dataEnty->dataOffsetFromStart,tempCharVal ,dataEnty->infElementBytesUsed);

										free(tempCharVal);
										break;
										}









				            		 }


	}
	}
	return modified;
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

    if (bufPos + (*length) > maxBufPos)
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




static void IEC61850FullReassembly(Packet *packet, void* context)
{


	int offset = 0;
	int stuffUp = 0;
	int dosAttack = 0;
	uint16_t offsetStNum = 0;
	uint16_t offsetTime = 0;
	int elementLengthStNum = 0;
	iec61850_header_t gooseHeader;
	iec61850_asdu_header_t* pdu = g_new0(iec61850_asdu_header_t,1);
	pdu->datSet=NULL;
	pdu->goID=NULL;
	pdu->gocbRef=NULL;
	GSList * dataSet = NULL;
	 int dataOffset = 1;
	 uint64_t timeval = 0;
	 uint16_t dataLength = 0;
	 iec61850_Object_header_t* data =NULL;
	  	 iec61850_Object_header_t* dataTemp=NULL;
	  	 uint8_t * stNumPt = malloc(4);
	  	frame_identifier_t* frameID = g_new0(frame_identifier_t,1);
 char nullCharactor = '\0';
	 int modify = 0;


	if (packet->dsize < (sizeof(iec61850_header_t) ))
		return ;

	if ( packet->dsize > IEC60870_5_61850_MAX_ASDU_LENGTH + IEC60870_5_61850_APCI_LENGTH )

		return ;
	uint8_t *lengthData = malloc(1);
	//memset(lengthData,100,1);
	gooseHeader.appID = packet->data[offset++]*0x100;
	gooseHeader.appID += packet->data[offset++];
	gooseHeader.len= packet->data[offset++]*0x100;
	gooseHeader.len += packet->data[offset];
	//memcpy(packet->data+offset,lengthData,1);
	offset++;
	gooseHeader.reserved_1 = packet->data[offset++]*0x100;
	gooseHeader.reserved_1 += packet->data[offset++];
	gooseHeader.reserved_2 = packet->data[offset++]*0x100;
	gooseHeader.reserved_2 += packet->data[offset++];


	 if (packet->data[offset++] == 0x61)
	 {
		 int gooseLength;
		 int bytesInLength;
		 int tempOffset;
		 offset = BerDecoder_decodeLength(packet->data, &gooseLength, offset, gooseHeader.len);
		         if (offset < 0) {

		             return ;
		         }

		         int gooseEnd = offset + gooseLength;

		         while (offset < gooseEnd) {
		             int elementLength;

		             uint8_t tag = packet->data[offset++];
		             offset = BerDecoder_decodeLength(packet->data, &elementLength, offset, gooseHeader.len);
		             if (offset < 0) {

		                 return;
		             }



		             switch (tag)
		             {
		             case 0x80: /* gocbRef */
		            	 pdu->gocbRef = g_string_new_len( (packet->data+offset),elementLength);
		            	 //frameID->gocbref=g_string_new_len( (packet->data+offset),elementLength);
		                 break;

		             case 0x81: /* timeAllowedToLive */

		            	 pdu->timeToLive = BerDecoder_decodeUint32(packet->data, elementLength, offset);


		                 break;

		             case 0x82:
		            	 pdu->datSet = g_string_new_len( (packet->data+offset),elementLength);

		            	 IEC61850Config* aconfig=NULL;
		            	 sfPolicyUserPolicySet (iec61850_config, getNapRuntimePolicy());
		            	 aconfig = (IEC61850Config *)sfPolicyUserDataGetCurrent(iec61850_config);


		            	 for(int index = 0 ; index<aconfig->numAlteredVal;index++)
		            	 {
		            		 if(g_string_equal(pdu->gocbRef,aconfig->values_to_alter[index].gocbRef) && g_string_equal(pdu->datSet,aconfig->values_to_alter[index].datSet))
		            		 {

		            			 modify = 1;
		            			 break;
		            		 }

//		            		 else
//		            			 return;


		            	 }

		            	 if(modify==0)
		            	 {
		            		 if(pdu->gocbRef)
		            		 g_string_free(pdu->gocbRef,TRUE);
		            		 if(pdu->datSet)
		            		 g_string_free(pdu->datSet,TRUE);
		            		 if(pdu)
		            		 g_free(pdu);
		            		 return;
		            	 }


		                 break;

		             case 0x83:
		            	 pdu->goID = g_string_new_len( (packet->data+offset),elementLength);
		                 break;

		             case 0x84:

		                 memcpy(&(pdu->t.tv_sec), packet->data + offset,elementLength/2);
		                 memcpy(&(pdu->t.tv_usec), packet->data + offset+4,4);
		                 //timeval = ntohll(timeval);
		                 offsetTime = offset;
		                 uint32_t fraction = ntohl(pdu->t.tv_usec)*0x100;






		                 break;

		             case 0x85:
		            	 pdu->stNum = BerDecoder_decodeUint32(packet->data, elementLength, offset);
		            	 frameID->stNum = pdu->stNum;
		            	 elementLengthStNum = elementLength;
		            	 offsetStNum = offset;

		                 break;

		             case 0x86:
		            	 pdu->sqNum = BerDecoder_decodeUint32(packet->data, elementLength, offset);
		            	 frameID->sqNum = pdu->sqNum;
		            	 gchar *orig_Key;
		            	 frame_identifier_t* tempFrameID;
		            	 char * tempLookup =strdup(pdu->gocbRef->str);
		            	 strcat(tempLookup,&nullCharactor);
		            	 tempFrameID = g_hash_table_lookup (gooseRefTable,
		            			 tempLookup);
		            	 if(!tempFrameID || (tempFrameID && (frameID->sqNum == 0 && frameID->stNum<=tempFrameID->stNum)))
		            	 		            	 { //we are seeing the gocbRev for the first time or it is a new status by the Org publisher


		            		 if(tempFrameID && tempFrameID->stNum==frameID->stNum && tempFrameID->sqNum==frameID->sqNum)
		            			 return;

		            		 if(!dosAttack){
		            		 if(!tempFrameID)          		 // we need to send a fake new status
		            	 			  pdu->stNum ++;
		            	 		  else
		            	 			 pdu->stNum = tempFrameID->stNum+1;
		            		 }

		            		 else
		            		 {
		            			 switch(elementLengthStNum)
		            			 {
		            			 case 1:
		            				 pdu->stNum = 127;
		            				 uint8_t val = ( uint8_t)pdu->stNum;
		            				 frameID->stNum = pdu->stNum;
		            				 memcpy(stNumPt,&val,1);
		            				 break;
		            			 case 2:
		            				 pdu->stNum = 65535;
		            				 uint16_t val16 = ( uint16_t)pdu->stNum;
		            				 memcpy(stNumPt,&val16,2);
		            				 frameID->stNum = pdu->stNum;
		            				 break;

		            			 case 4:
		            				 pdu->stNum = 4294967295;
		            				 uint32_t val32 = ( uint32_t)pdu->stNum;
		            				 frameID->stNum = pdu->stNum;
		            				 memcpy(stNumPt,&val32,4);
		            				 break;



		            			 }
		            		 }
		            		 struct timeval tv;
		            		 		                 gettimeofday(&tv,NULL);
		            		 		                 time_t curtime;
		            		 		                 char buffer[80];
		            		 		                 curtime=tv.tv_sec;
		            		 		                 uint32_t curTimeInc = curtime;
		            		 		                 curTimeInc = htonl(curTimeInc);
		            		 		                 memcpy(packet->data + offsetTime,&curTimeInc,4);
		            		 		                 curtime=tv.tv_usec;
		            		 		                 curTimeInc = curtime;
		            		 		                 curTimeInc = htonl(curTimeInc);
		            		 		                 memcpy(packet->data + offsetTime+4,&curTimeInc,4);
		            		 		                memcpy(&(frameID->tv),&tv,sizeof(tv));
		            		 switch(elementLengthStNum)
		            				            	 {
		            				            	 case 1:
		            				            		 pdu->stNum = (pdu->stNum)%(256);
		            				            		 uint8_t val = ( uint8_t)pdu->stNum;
		            				            		 frameID->stNum = pdu->stNum;
		            				            		 memcpy(stNumPt,&val,1);
		            				            		 break;
		            				            	 case 2:
		            				            		 pdu->stNum = (pdu->stNum)%(65536);
		            				            		 uint16_t val16 = ( uint16_t)pdu->stNum;
		            				            		 		            		 memcpy(stNumPt,&val16,2);
		            				            		 		            		frameID->stNum = pdu->stNum;
		            				            		 break;

		            				            	 case 4:
		            				            	     pdu->stNum = (pdu->stNum)%(4294967296);
		            				            	     uint32_t val32 = ( uint32_t)pdu->stNum;
		            				            	     frameID->stNum = pdu->stNum;
		            				            	     memcpy(stNumPt,&val32,4);
		            				            	     break;



		            				            	 }

		            				            	 memcpy(packet->data+offsetStNum, stNumPt,elementLengthStNum);

		            				            	 if(frameID->sqNum!=0)
		            				            	 {
		            				            		 pdu->sqNum=0;

		            				            		 uint32_t val = 0;
		            				            		 frameID->sqNum = 0;
		            				            		 memcpy(stNumPt,&val,4);
		            				            		 memcpy(packet->data+offset, stNumPt,elementLength);
		            				            	 }


		            	 		            		 char * temp2 = strdup(pdu->gocbRef->str);
		            	 		            		 		            	 strcat(temp2,&nullCharactor);
		            	 		            		 g_hash_table_insert (gooseRefTable,temp2,frameID);

		            	 		            		 LogMessage("KEY: |%s|.SQNum %d StNum %d \n", pdu->gocbRef->str,frameID->sqNum,frameID->stNum);


		            	 		            	 }

		            	 else if(tempFrameID && (frameID->sqNum != 0 && frameID->stNum<tempFrameID->stNum))
		            	 		            	 { //old status by the Org publisher
		            	 		            		 // we need to increase the sqNum saved in hash and send with the old stNum saved

		            		 	 	 	 	 pdu->sqNum=tempFrameID->sqNum+1;
		            		 	 	 	 	pdu->stNum = tempFrameID->stNum;



		            		 	 	 	 switch(elementLengthStNum)
		            		 	 	 	 		            				            	 {
		            		 	 	 	 		            				            	 case 1:
		            		 	 	 	 		            				            		 pdu->stNum = (pdu->stNum)%(256);
		            		 	 	 	 		            				            		 uint8_t val = ( uint8_t)pdu->stNum;
		            		 	 	 	 		            				            		 frameID->stNum = pdu->stNum;
		            		 	 	 	 		            				            		 memcpy(stNumPt,&val,1);
		            		 	 	 	 		            				            		 break;
		            		 	 	 	 		            				            	 case 2:
		            		 	 	 	 		            				            		 pdu->stNum = (pdu->stNum)%(65536);
		            		 	 	 	 		            				            		 uint16_t val16 = ( uint16_t)pdu->stNum;
		            		 	 	 	 		            				            		 val16 = htons(val16);
		            		 	 	 	 		            				            		 memcpy(stNumPt,&val16,2);
		            		 	 	 	 		            				            		 frameID->stNum = pdu->stNum;
		            		 	 	 	 		            				            		 break;

		            		 	 	 	 		            				            	 case 4:
		            		 	 	 	 		            				            	     pdu->stNum = (pdu->stNum)%(4294967296);
		            		 	 	 	 		            				            	     uint32_t val32 = ( uint32_t)pdu->stNum;
		            		 	 	 	 		            				            	     val32 = htonl(val32);
		            		 	 	 	 		            				            	     frameID->stNum = pdu->stNum;
		            		 	 	 	 		            				            	     memcpy(stNumPt,&val32,4);
		            		 	 	 	 		            				            	     break;



		            		 	 	 	 		            				            	 }
		            		 	 	 	 memcpy(packet->data+offsetStNum, stNumPt,elementLengthStNum);

		            		 	 	 	switch(elementLength)
		            		 	 	 			            				            	 {
		            		 	 	 			            				            	 case 1:
		            		 	 	 			            				            		 pdu->sqNum = (pdu->sqNum)%(256);
		            		 	 	 			            				            		 uint8_t val = ( uint8_t)pdu->sqNum;
		            		 	 	 			            				            		 frameID->sqNum = pdu->sqNum;
		            		 	 	 			            				            		 memcpy(stNumPt,&val,1);
		            		 	 	 			            				            		 break;
		            		 	 	 			            				            	 case 2:
		            		 	 	 			            				            		 pdu->sqNum = (pdu->sqNum)%(65536);
		            		 	 	 			            				            		 uint16_t val16 = ( uint16_t)pdu->sqNum;
		            		 	 	 			            				            		val16 = htons(val16);
		            		 	 	 			            				            		 memcpy(stNumPt,&val16,2);
		            		 	 	 			            				            		frameID->sqNum = pdu->sqNum;
		            		 	 	 			            				            		 break;

		            		 	 	 			            				            	 case 4:
		            		 	 	 			            				            	     pdu->sqNum = (pdu->sqNum)%(4294967296);
		            		 	 	 			            				            	     uint32_t val32 = ( uint32_t)pdu->sqNum;
		            		 	 	 			            				            	     val32 =  htonl(val32);
		            		 	 	 			            				            	     frameID->sqNum = pdu->sqNum;
		            		 	 	 			            				            	     memcpy(stNumPt,&val32,4);
		            		 	 	 			            				            	     break;



		            		 	 	 			            				            	 }


		            		 	 	 	 	 memcpy(packet->data+offset, stNumPt,elementLength);


		            		 	 	 	 	time_t curtime;
		            		 	 	 	 			            		 		                 char buffer[80];
		            		 	 	 	 			            		 		                 curtime=tempFrameID->tv.tv_sec;
		            		 	 	 	 			            		 		                 uint32_t curTimeInc = curtime;
		            		 	 	 	 			            		 		                 curTimeInc = htonl(curTimeInc);
		            		 	 	 	 			            		 		                 memcpy(packet->data + offsetTime,&curTimeInc,4);
		            		 	 	 	 			            		 		                 curtime=tempFrameID->tv.tv_usec;
		            		 	 	 	 			            		 		                 curTimeInc = curtime;
		            		 	 	 	 			            		 		                 curTimeInc = htonl(curTimeInc);
		            		 	 	 	 			            		 		                 memcpy(packet->data + offsetTime+4,&curTimeInc,4);
		            		 	 	 	 			            		 		            memcpy(&(frameID->tv),&(tempFrameID->tv),sizeof(tempFrameID->tv));
		            	 		            		 char * temp2 = strdup(pdu->gocbRef->str);
		            	 		            		 		            	 strcat(temp2,&nullCharactor);
		            	 		            		 g_hash_table_insert (gooseRefTable,temp2,frameID);

		            	 		            		LogMessage("No Change KEY: |%s|.SQNum %d StNum %d \n", pdu->gocbRef->str,frameID->sqNum,frameID->stNum);
		            	 		            	 }
		            	 else if(tempFrameID &&  tempFrameID->stNum==frameID->stNum && tempFrameID->sqNum==frameID->sqNum)
		            	 		            	 {
		            	 		            		 //This is a packet that the snort sent
		            	 		            		// LogMessage("KEY: |%s|.SQNum %d \n", pdu->gocbRef->str,tempFrameID->sqNum);
		            	 		            		 char * temp1 = strdup(pdu->gocbRef->str);
		            	 		            	 strcat(temp1,&nullCharactor);
		            	 		            	//	 g_hash_table_insert (gooseRefTable,temp1,frameID); why put old packet information in the hash
		            	 		            	LogMessage("Not Sent KEY: |%s|.SQNum %d StNum %d \n", pdu->gocbRef->str,frameID->sqNum,frameID->stNum);
		            	 		            	 return;
		            	 		            	 }
		            	 else
		            	 {
		            		 LogMessage("No Match KEY: |%s|.SQNum %d:%d StNum %d:%d \n", pdu->gocbRef->str,frameID->sqNum,tempFrameID->sqNum,frameID->stNum,tempFrameID->stNum);
		            		 return;
		            	 }

		                 break;

		             case 0x87:
		            	 pdu->simulation = BerDecoder_decodeBoolean(packet->data, offset);

		                 break;

		             case 0x88:
		            	 pdu->confRev = BerDecoder_decodeUint32(packet->data, elementLength, offset);

		                 break;

		             case 0x89:
		            	 pdu->ndsCom = BerDecoder_decodeBoolean(packet->data, offset);

		                 break;

		             case 0x8a:
		            	 pdu->numDataSetEntries = BerDecoder_decodeUint32(packet->data, elementLength, offset);

		                 break;

		             case 0xab:

		            	  dataOffset = offset;
		            	  dataLength = 0;
		            	 data = g_new0(iec61850_Object_header_t,pdu->numDataSetEntries);
		            	 dataTemp = data;
		                 for(int j=0;j<pdu->numDataSetEntries;j++)
		                 {
		                	 uint8_t dataTag = packet->data[dataOffset++];

		                	 dataOffset = BerDecoder_decodeLength(packet->data, &dataLength, dataOffset, gooseHeader.len);


		                		 dataTemp->dataNum = j;
		                		 dataTemp->dataOffsetFromStart =  dataOffset;
		                		 dataTemp->infElementBytesUsed = dataLength;
		                		 dataTemp->type = dataTag;
		                		 memcpy(dataTemp->informationElements,packet->data+dataOffset,dataLength);




		                	 dataOffset+=dataLength;


		                	 dataSet = g_slist_append(dataSet,dataTemp);
		                	 dataTemp++;



		                 }

		                 break;

		             default:

		                 break;
		             }

		             offset += elementLength;
		         }


		         }




 if(modify==1)
 {
		if(modifyData(packet->data, packet->dsize,dataSet,pdu))
		{
			//packet->packet_flags|=PKT_MODIFIED;

		}

		if(stuffUp==0){
		uint8_t * dataPlusEth= NULL;
		if(packet->vh)
		{
			dataPlusEth = (uint8_t *)malloc(packet->dsize+sizeof(EtherHdr)+sizeof(VlanTagHdr));
					memcpy(dataPlusEth,packet->eh,sizeof(EtherHdr));
		memcpy(dataPlusEth+sizeof(EtherHdr),packet->vh,sizeof(VlanTagHdr));
		memcpy(dataPlusEth+sizeof(EtherHdr)+sizeof(VlanTagHdr),packet->data,packet->dsize);
		Active_SendEth (
				   packet->pkth, !(packet->packet_flags & ENC_FLAG_FWD),dataPlusEth, packet->dsize+sizeof(EtherHdr)+sizeof(VlanTagHdr));

		}
		else
		{
			//memcpy(dataPlusEth+sizeof(EtherHdr),packet->vh,sizeof(VlanTagHdr));
			dataPlusEth = (uint8_t *)malloc(packet->dsize+sizeof(EtherHdr));
			memcpy(dataPlusEth,packet->eh,sizeof(EtherHdr));
			memcpy(dataPlusEth+sizeof(EtherHdr),packet->data,packet->dsize);
			Active_SendEth (
					   packet->pkth, !(packet->packet_flags & ENC_FLAG_FWD),dataPlusEth, packet->dsize+sizeof(EtherHdr));

		}
		}

		else
		{
			uint8_t * dataPlusEth = (uint8_t *)malloc(1500); //packet->dsize+sizeof(EtherHdr)+sizeof(VlanTagHdr)

					memset(dataPlusEth,'$',1500);
					memcpy(dataPlusEth,packet->eh,sizeof(EtherHdr));
					if(packet->vh)
					{
					memcpy(dataPlusEth+sizeof(EtherHdr),packet->vh,sizeof(VlanTagHdr));
					memcpy(dataPlusEth+sizeof(EtherHdr)+sizeof(VlanTagHdr),packet->data,packet->dsize);



					Active_SendEth (
							   packet->pkth, !(packet->packet_flags & ENC_FLAG_FWD),dataPlusEth, 1500);

					}
					else
					{
						//memcpy(dataPlusEth+sizeof(EtherHdr),packet->vh,sizeof(VlanTagHdr));
						memcpy(dataPlusEth+sizeof(EtherHdr),packet->data,packet->dsize);
						Active_SendEth (
								   packet->pkth, !(packet->packet_flags & ENC_FLAG_FWD),dataPlusEth, 1500);

					}
		}
//		struct timespec *requested_time = malloc(sizeof(struct timespec));
//		requested_time->tv_sec = 0;
//		requested_time->tv_nsec =100000;
//		struct timespec *remaining = malloc(sizeof(struct timespec));
//		remaining->tv_nsec = 0;
//		remaining->tv_sec = 0;
		// nanosleep (requested_time, remaining);

 }
 if(pdu->gocbRef)
 g_string_free(pdu->gocbRef,TRUE);
 if(pdu->datSet )
 g_string_free(pdu->datSet,TRUE);
 if(pdu->goID)
 g_string_free(pdu->goID,TRUE);
 if(pdu)
 g_free(pdu);
 if(dataSet)
		 g_slist_free(dataSet);
	return;
}

static void IEC61850CleanExit(int signal, void *unused)
{
    IEC61850FreeConfig(iec61850_config);
    iec61850_config = NULL;
}

static int IEC61850FreeConfigPolicy(tSfPolicyUserContextId config,tSfPolicyId policyId, void* pData )
{
    IEC61850Config *pPolicyConfig = (IEC61850Config *)pData;

    sfPolicyUserDataClear (config, policyId);
    free(pPolicyConfig);
    return 0;
}

static void IEC61850FreeConfig(tSfPolicyUserContextId config)
{

    if (config == NULL)
        return;

    sfPolicyUserDataFreeIterate (config, IEC61850FreeConfigPolicy);
    sfPolicyConfigDelete(config);

}




#ifdef SNORT_RELOAD
static void IEC61850Reload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId iec61850_swap_config = (tSfPolicyUserContextId)*new_config;
    int policy_id = (int)getParserPolicy(sc);
    IEC61850Config *pPolicyConfig;

    if (!iec61850_swap_config)
    {
    	iec61850_swap_config = sfPolicyConfigCreate();
        *new_config = (void *)iec61850_swap_config;
    }

    sfPolicyUserPolicySet (iec61850_swap_config, policy_id);

    pPolicyConfig = (IEC61850Config *)sfPolicyUserDataGetCurrent(iec61850_swap_config);
    if (pPolicyConfig)
    {
        FatalError("IEC61850 can only be configured once.\n");
    }

    pPolicyConfig = (IEC61850Config *)SnortAlloc(sizeof(IEC61850Config));
    if (!pPolicyConfig)
    {
        ParseError("IEC61850 preprocessor: memory allocate failed.\n");
    }
     sfPolicyUserDataSetCurrent(iec61850_swap_config, pPolicyConfig);


    /* Add IEC61850 to the preprocessor function list */
    AddFuncToPreprocList(sc, IEC61850FullReassembly, PRIORITY_NETWORK, PP_GOOSE, PROTO_BIT__GOOSE);
    session_api->enable_preproc_all_ports( sc, PP_GOOSE, PROTO_BIT__GOOSE );



    /* Parse the arpspoof arguments from snort.conf */
    ParseIEC61850Args(pPolicyConfig, args);
    Active_Open (pPolicyConfig->interface->str);

}



static void *IEC61850ReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId iec61850_swap_config = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_config = iec61850_config;

    if (iec61850_swap_config == NULL)
        return NULL;

    iec61850_config = iec61850_swap_config;
    iec61850_swap_config = NULL;

    return (void *)old_config;
}

static void IEC61850ReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    IEC61850FreeConfig((tSfPolicyUserContextId)data);
}
#endif
