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

/* Snort SV Preprocessor Plugin
 *   by Chamara Devanarayana <chamara@rtds.com> based on libiec61850-1.4.0 https://github.com/mz-automation/libiec61850
 *   Version 0.1.0
 *
 * Purpose:
 *
 * This preprocessor decodes SV packets and is able to modify the data
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
#include "spp_sv.h"
#include "glib.h"
/*  D E F I N E S  **************************************************/



/*  D A T A   S T R U C T U R E S  **********************************/



/*  G L O B A L S  **************************************************/
static tSfPolicyUserContextId sv_config = NULL;

GHashTable * svRefTable;

#ifdef PERF_PROFILING
PreprocStats arpPerfStats;
#endif


/*  P R O T O T Y P E S  ********************************************/
static void SVInit(struct _SnortConfig *, char *args);

static void ParseSVArgs(SVConfig *, char *);


static void SVCleanExit(int signal, void *unused);

static void SVFullReassembly(Packet *p, void *context);

static void SVFreeConfig(tSfPolicyUserContextId config);



#ifdef SNORT_RELOAD
static void SVReload(struct _SnortConfig *, char *, void **);
static void * SVReloadSwap(struct _SnortConfig *, void *);
static void SVReloadSwapFree(void *);
#endif


void SetupSV(void)
{
#ifndef SNORT_RELOAD
    RegisterPreprocessor("sample_value", SVInit);

#else
    RegisterPreprocessor("sample_value", SVInit, SVReload, NULL,SVReloadSwap,SVReloadSwapFree);

#endif

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,
            "Preprocessor: SV is setup...\n"););
}



static void SVInit(struct _SnortConfig *sc, char *args)
{
    int policy_id = (int)getParserPolicy(sc);
    SVConfig *pDefaultPolicyConfig = NULL;
    SVConfig *pCurrentPolicyConfig = NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,
            "Preprocessor: SV Initialized\n"););

    if (sv_config == NULL)
    {
    	sv_config = sfPolicyConfigCreate();

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("sample_value", &arpPerfStats, 0, &totalPerfStats, NULL);
#endif

        AddFuncToPreprocCleanExitList(SVCleanExit, NULL, PRIORITY_LAST, PP_SV);
    }

    sfPolicyUserPolicySet (sv_config, policy_id);
    pDefaultPolicyConfig = (SVConfig *)sfPolicyUserDataGetDefault(sv_config);
    pCurrentPolicyConfig = (SVConfig *)sfPolicyUserDataGetCurrent(sv_config);

    if ((policy_id != 0) && (pDefaultPolicyConfig == NULL))
    {
        ParseError("SV configuration: Must configure default policy "
                   "if other policies are to be configured.");
    }

    if (pCurrentPolicyConfig)
    {
        ParseError("SV can only be configured once.\n");
    }

    pCurrentPolicyConfig = (SVConfig *)SnortAlloc(sizeof(SVConfig));
    if (!pCurrentPolicyConfig)
    {
        ParseError("SV preprocessor: memory allocate failed.\n");
    }

    sfPolicyUserDataSetCurrent(sv_config, pCurrentPolicyConfig);
    /* Add SV to the preprocessor function list */
    AddFuncToPreprocList(sc, SVFullReassembly, PRIORITY_NETWORK, PP_SV, PROTO_BIT__SV);
    session_api->enable_preproc_all_ports( sc, PP_SV, PROTO_BIT__SV );



    /* Parse the sv arguments from snort.conf */
    ParseSVArgs(pCurrentPolicyConfig, args);
    Active_Open (pCurrentPolicyConfig->interface->str);
    svRefTable = g_hash_table_new_full(svObjectHash, svObjectEqual,keyDestroyFunc,valueDestroyFunc);
}


/**
 * Parse arguments passed to the sv keyword.
 *
 * @param args preprocessor argument string
 *
 * @return void function
 */
static void ParseSVArgs(SVConfig *config, char *args)
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
            	                     "SV preprocessor 'change' option.\n");

            	             }
            	 else{
            		 switch(count){
            		 	 	 	 	 case(0):
    								    if((config->values_to_alter[index]).svID)
    									g_string_free((config->values_to_alter[index]).svID,1);
            		 	 	 	 	 	(config->values_to_alter[index]).svID = g_string_new(token+1);
            		 	 	 	 	 	g_string_truncate((config->values_to_alter[index]).svID,(config->values_to_alter[index]).svID->len-1);
            		 	 	 	 	 	break;
            						 case(1):
    									if((config->values_to_alter[index]).datSet)
    									g_string_free((config->values_to_alter[index]).datSet,1);
    		        		 	 	 	(config->values_to_alter[index]).datSet = g_string_new(token+1);
    		        		 	 	  	g_string_truncate((config->values_to_alter[index]).datSet,(config->values_to_alter[index]).datSet->len-1);
    		        		 	 	 	break;
    		   						 case(2):
    		   								 (config->values_to_alter[index]).asduNo = strtol(token,NULL,10);
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


static guint svObjectHash(gconstpointer dataObject)
{
	//const GString *objHeader = ((sv_frame_identifier_t *)dataObject)->gocbref;

	return g_int_hash(dataObject);
}



static gboolean svObjectEqual(gconstpointer dataObject1,gconstpointer dataObject2)
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




static int modifyData(uint8_t * pdu_start, uint16_t pdu_length, sv_asdu_header_t* pdu,uint8_t numASDU)
{
int modified = 0;
SVConfig* aconfig=NULL;
sv_Object_header_t* dataEnty=NULL;
sfPolicyUserPolicySet (sv_config, getNapRuntimePolicy());
   aconfig = (SVConfig *)sfPolicyUserDataGetCurrent(sv_config);



for(int index = 0 ; index<aconfig->numAlteredVal;index++)
{
	for(int asduIndex = 0;asduIndex<numASDU;asduIndex++)
	{


		if(g_string_equal(pdu[asduIndex].svID,aconfig->values_to_alter[index].svID) )
				            		 {



													modified=1;
													char nullCharactor = '\0';
													int32_t tempIntVal = strtol(aconfig->values_to_alter[index].newVal->str,NULL,10);
													tempIntVal = htonl(tempIntVal);
													//int32_t tempVal = 0;
													int valNumber = aconfig->values_to_alter[index].asduNo;
													char * tempCharVal = malloc(sizeof(int32_t));
													memcpy(tempCharVal,&tempIntVal,sizeof(int32_t));
													sv_frame_identifier_t* frameID = g_new0(sv_frame_identifier_t,1);
													for(int i=0;i<8;i++)
													{
														//memcpy(&tempVal,pdu_start+pdu[asduIndex].offset+i*8,sizeof(int32_t));
														//memcpy(&tempVal,tempCharVal,4);
														//tempVal*=tempIntVal;
														if(i==valNumber)
															memcpy(pdu_start+pdu[asduIndex].offset+i*8,tempCharVal ,4);
													if(i==0 && asduIndex==0)
													{
														 char * temp1 = strdup(pdu[asduIndex].svID->str);
														 strcat(temp1,&nullCharactor);
														 frameID->phsor1 = tempIntVal;

														 g_hash_table_insert (svRefTable,temp1,frameID);
													}

													}
													free(tempCharVal);




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




static void SVFullReassembly(Packet *packet, void* context)
{


	uint16_t offset = 0;
	sv_header_t svHeader;
	sv_asdu_header_t* pdu = NULL;
	uint8_t noASDU;
	GSList * dataSet = NULL;
	 uint16_t dataOffset = 0;
	 uint64_t timeval = 0;
	 uint16_t dataLength = 0;
	 sv_Object_header_t* data =NULL;
	  	 sv_Object_header_t* dataTemp=NULL;
	  	 uint8_t * smpCntPt = malloc(2);
	  	 memset(smpCntPt,0,2);
	  	sv_frame_identifier_t* frameID = g_new0(sv_frame_identifier_t,1);

	  	SVConfig* aconfig=NULL;
	  			            	 sfPolicyUserPolicySet (sv_config, getNapRuntimePolicy());
	  			            	 aconfig = (SVConfig *)sfPolicyUserDataGetCurrent(sv_config);
 char nullCharactor = '\0';
	 int modify = 0;


	if (packet->dsize < (sizeof(sv_header_t) ))
		return ;

	if ( packet->dsize > SV_MAX_ASDU_LENGTH + SV_APCI_LENGTH )

		return ;
	svHeader.appID = packet->data[offset++]*0x100;
	svHeader.appID += packet->data[offset++];
	svHeader.len = packet->data[offset++]*0x100;
	svHeader.len += packet->data[offset++];
	svHeader.reserved_1 = packet->data[offset++]*0x100;
	svHeader.reserved_1 += packet->data[offset++];
	svHeader.reserved_2 = packet->data[offset++]*0x100;
	svHeader.reserved_2 += packet->data[offset++];


	 if (packet->data[offset] == 0x60)
	 {
		 offset++;
		 int svLength = 0;
		 int bytesInLength = 0;
		 int tempOffset = 0;
		 int elementLength=0;
		  noASDU=0;
		 uint8_t indexASDU = -1;

		 offset = BerDecoder_decodeLength(packet->data, &svLength, offset, svHeader.len);
		         if (offset < 0) {

		             return ;
		         }
		         int svEnd = offset + svLength;


		       if(  packet->data[offset]==0x80)
		       {
		    	   offset++;
		    	   offset = BerDecoder_decodeLength(packet->data, &elementLength, offset, svHeader.len);
		    	   memcpy(&noASDU,(packet->data+offset),elementLength);
		    	   offset += elementLength;
		       }


               if(  packet->data[offset]==0x81)
		       		       {
            	   offset++;
		       		    	   LogMessage("Secure ASDU not processed\n");
		       		    	   return;
		       		       }
		       if(  packet->data[offset]==0xa2)
		    	   offset++;
		       		         		             offset = BerDecoder_decodeLength(packet->data, &elementLength, offset, svHeader.len);


		       if(packet->data[offset++]!=0x30)
		       {

		    	   LogMessage("ASDU data not found\n");
		    	   return;
		       }

		       offset = BerDecoder_decodeLength(packet->data, &elementLength, offset, svHeader.len);
		       pdu = g_new0(sv_asdu_header_t,noASDU);

		    	   while (offset < svEnd) {


		             uint8_t tag = packet->data[offset++];
		             offset = BerDecoder_decodeLength(packet->data, &elementLength, offset, svHeader.len);
		             if (offset < 0) {

		                 return;
		             }



		             switch (tag)
		             {
		             case 0x80: /* SV ID */

		            	 indexASDU++;
		            		 pdu[indexASDU].datSet=NULL;
		            		 	pdu[indexASDU].dataBuffer=NULL;
		            		 	pdu[indexASDU].svID=NULL;

		            	 pdu[indexASDU].svID = g_string_new_len( (packet->data+offset),elementLength);
		            	 for(int index = 0 ; index<aconfig->numAlteredVal;index++)
		            	 {
		            		 if(modify==0 && g_string_equal(pdu[indexASDU].svID,aconfig->values_to_alter[index].svID) )
		            		 {

		            			 modify = 1;
		            			 break;
		            		 }
		            	 }

		            	 if(modify==0)
		            	 {
		            		 for(int indexASDU = 0;indexASDU<noASDU;indexASDU++)
		            		 	{

		            		 if(pdu[indexASDU].svID)
		            			 g_string_free(pdu[indexASDU].svID,TRUE);


		            		 	}
		            		 g_free(pdu);
		            		 return;
		            	 }


		            	 //frameID->gocbref=g_string_new_len( (packet->data+offset),elementLength);
		                 break;

		             case 0x81: /* dataset */

		            	 pdu[indexASDU].datSet =g_string_new_len( (packet->data+offset),elementLength);

		            	 for(int index = 0 ; index<aconfig->numAlteredVal;index++)
		            	 		            	 {
		            	 		            		 if(g_string_equal(pdu[indexASDU].svID,aconfig->values_to_alter[index].svID) && g_string_equal(pdu[indexASDU].datSet,aconfig->values_to_alter[index].datSet))
		            	 		            		 {

		            	 		            			 modify = 1;
		            	 		            			 break;
		            	 		            		 }

		            	 //		            		 else
		            	 //		            			 return;


		            	 		            	 }

		            	 		            	 if(modify==0)
		            	 		            	 {
		            	 		            		for(int asduIndex = 0;asduIndex<noASDU;asduIndex++)
		            	 		            				 	{


		            	 		            				 if(pdu){
		            	 		            				 if(pdu[asduIndex].svID)
		            	 		            				 g_string_free(pdu[asduIndex].svID,TRUE);
		            	 		            				 if(pdu[asduIndex].datSet )
		            	 		            				 g_string_free(pdu[asduIndex].datSet,TRUE);
		            	 		            				 if(pdu[asduIndex].dataBuffer)
		            	 		            				 g_string_free(pdu[asduIndex].dataBuffer,FALSE);

		            	 		            				 }
		            	 		            				 	}
		            	 		            				 if(pdu)
		            	 		            						 g_free(pdu);


		            	 		            		 return;
		            	 		            	 }

		                 break;

		             case 0x82: /* smpCnt */
		            	 pdu[indexASDU].smpCnt = BerDecoder_decodeUint32(packet->data, elementLength, offset);

		            	// frameID->smpCnt = pdu->smpCnt;
		            	 pdu[indexASDU].smpCnt+=1;

		            	 pdu[indexASDU].smpCnt = (pdu[indexASDU].smpCnt)%(4800);
		            	 uint16_t val16 = ( uint16_t)pdu[indexASDU].smpCnt;
		            	 val16 = htons(val16);
		            	 memcpy(smpCntPt,&val16,2);






		            	 memcpy(packet->data+offset, smpCntPt,elementLength);


		                 break;

		             case 0x83:
		            	 pdu[indexASDU].confRev =  BerDecoder_decodeUint32(packet->data, elementLength, offset);
		                 break;

		             case 0x84:

		                 memcpy(&(pdu[indexASDU].refrTm.tv_sec), packet->data + offset,elementLength/2);
		                 memcpy(&(pdu[indexASDU].refrTm.tv_usec), packet->data + offset+4,4);
		                 //timeval = ntohll(timeval);

		                 uint32_t fraction = ntohl(pdu[indexASDU].refrTm.tv_usec)*0x100;


		                 time_t curtime;
		                 char buffer[80];
		                 curtime=ntohl(pdu[indexASDU].refrTm.tv_sec);
		                 uint32_t curTimeInc = curtime+1;
		                 curTimeInc = htonl(curTimeInc);
		                 memcpy(packet->data + offset,&curTimeInc,4);
		                 struct tm *info = localtime(&curtime );
		                 strftime(buffer,80,"%c %Z", info);
		                 uint32_t nanoseconds = (uint32_t)( ((uint64_t)fraction * 1000000000U) / 0x100000000U ) ;



		                 break;

		             case 0x85:
		            	 pdu[indexASDU].smpSynch = BerDecoder_decodeUint32(packet->data, elementLength, offset);




		                 break;

		             case 0x86:
		            	 pdu[indexASDU].smpRate = BerDecoder_decodeUint32(packet->data, elementLength, offset);

		                 break;

		             case 0x87:
		            	 pdu[indexASDU].offset = offset;
		            	 pdu[indexASDU].dataBuffer = g_string_new_len( (packet->data+offset),elementLength);
		            	 pdu[indexASDU].dataBufferLength=elementLength;
		            	 //should know which data there is to decode the data buffer. In 9-2LE there are 10 phasors all are scaled to int32
		            	 int32_t tempPhasor;
		            	 memcpy(&tempPhasor,pdu[indexASDU].dataBuffer->str,4);
		            	 frameID->phsor1 = tempPhasor;
		            	 gchar *orig_Key;
		            	 		            	 		            	 sv_frame_identifier_t* tempFrameID;
		            	 		            	 		            	 char * tempLookup =strdup(pdu[indexASDU].svID->str);
		            	 		            	 		            	 strcat(tempLookup,&nullCharactor);
		            	 		            	 		            	 if(g_slist_length(dataSet)==0)
		            	 		            	 		            	 {
		            	 		            	 		            	 tempFrameID = g_hash_table_lookup (svRefTable,
		            	 		            	 		            			 tempLookup);

		            	 		            	 		            	 if(tempFrameID && tempFrameID->phsor1==frameID->phsor1 )
		            	 		            	 		            	 {
		            	 		            	 		            		LogMessage("Dropped KEY: |%s|.SQNum %d ingress_index %d  egress_index %d\n", pdu[indexASDU].svID->str,pdu[indexASDU].smpCnt,packet->pkth->ingress_index,packet->pkth->egress_index);
		            	 		            	 		            		for(int asduIndex = 0;asduIndex<noASDU;asduIndex++)
		            	 		            	 		            				 	{


		            	 		            	 		            				 if(pdu){
		            	 		            	 		            				 if(pdu[asduIndex].svID)
		            	 		            	 		            				 g_string_free(pdu[asduIndex].svID,TRUE);
		            	 		            	 		            				 if(pdu[asduIndex].datSet )
		            	 		            	 		            				 g_string_free(pdu[asduIndex].datSet,TRUE);
		            	 		            	 		            				 if(pdu[asduIndex].dataBuffer)
		            	 		            	 		            				 g_string_free(pdu[asduIndex].dataBuffer,FALSE);

		            	 		            	 		            				 }
		            	 		            	 		            				 	}
		            	 		            	 		            				 if(pdu)
		            	 		            	 		            						 g_free(pdu);
		            	 		            	 		            	 return ;
		            	 		            	 		            	 }
		            	 		            	 		            	 }


		            	 //		  moved to modify          	 		            	 else
		            	 //		            	 		            	 {
		            	 //		            	 		            		frameID->smpCnt++;
		            	 //		            	 		            		frameID->smpCnt=(frameID->smpCnt)%(4800) ;
		            	 //		            	 		            		 char * temp2 = strdup(pdu->svID->str);
		            	 //		            	 		            		 		            	 strcat(temp2,&nullCharactor);
		            	 //		            	 		            		 g_hash_table_insert (svRefTable,temp2,frameID);
		            	 //
		            	 //
		            	 //		            	 		            	 }
		            	 		            	 		            	LogMessage("Accept KEY: |%s|.SQNum %d ingress_index %d  egress_index %d\n", pdu[indexASDU].svID->str,pdu[indexASDU].smpCnt,packet->pkth->ingress_index,packet->pkth->egress_index);

		                 break;

		             case 0x88:
		             		            	 pdu[indexASDU].smpMod = BerDecoder_decodeUint32(packet->data, elementLength, offset);

		             		                 break;


//		             case 0xab:
//
//		            	  dataOffset = offset;
//		            	  dataLength = 0;
//		            	 data = g_new0(sv_Object_header_t,pdu->numDataSetEntries);
//		            	 dataTemp = data;
//		                 for(int j=0;j<pdu->numDataSetEntries;j++)
//		                 {
//		                	 uint8_t dataTag = packet->data[dataOffset++];
//
//		                	 dataOffset = BerDecoder_decodeLength(packet->data, &dataLength, dataOffset, svHeader.len);
//
//
//		                		 dataTemp->dataNum = j;
//		                		 dataTemp->dataOffsetFromStart =  dataOffset;
//		                		 dataTemp->infElementBytesUsed = dataLength;
//		                		 dataTemp->type = dataTag;
//		                		 memcpy(dataTemp->informationElements,packet->data+dataOffset,dataLength);
//
//
//
//
//		                	 dataOffset+=dataLength;
//
//
//		                	 dataSet = g_slist_append(dataSet,dataTemp);
//		                	 dataTemp++;
//
//
//
//		                 }
//
//		                 break;

		             default:

		                 break;
		             }

		             offset += elementLength;


		         }


		         }




 if(modify==1)
 {
		if(modifyData(packet->data, packet->dsize,pdu,noASDU))
			packet->packet_flags|=PKT_MODIFIED;
		uint8_t * dataPlusEth = (uint8_t *)malloc(packet->dsize+sizeof(EtherHdr));
		memcpy(dataPlusEth,packet->eh,sizeof(EtherHdr));
		memcpy(dataPlusEth+sizeof(EtherHdr),packet->data,packet->dsize);

		Active_SendEth (
		   packet->pkth, !(packet->packet_flags & ENC_FLAG_FWD),dataPlusEth, packet->dsize+sizeof(EtherHdr));
		for(int asduIndex = 0;asduIndex<noASDU;asduIndex++)
		 	{
			LogMessage("In Modify KEY: |%s|.SQNum %d \n", pdu[asduIndex].svID->str,pdu[asduIndex].smpCnt);

		 if(pdu){
		 if(pdu[asduIndex].svID)
		 g_string_free(pdu[asduIndex].svID,TRUE);
		 if(pdu[asduIndex].datSet )
		 g_string_free(pdu[asduIndex].datSet,TRUE);
		 if(pdu[asduIndex].dataBuffer)
		 g_string_free(pdu[asduIndex].dataBuffer,FALSE);

		 }
		 	}
		 if(pdu)
				 g_free(pdu);
 }

	return;
}

static void SVCleanExit(int signal, void *unused)
{
    SVFreeConfig(sv_config);
    sv_config = NULL;
}

static int SVFreeConfigPolicy(tSfPolicyUserContextId config,tSfPolicyId policyId, void* pData )
{
    SVConfig *pPolicyConfig = (SVConfig *)pData;

    sfPolicyUserDataClear (config, policyId);
    free(pPolicyConfig);
    return 0;
}

static void SVFreeConfig(tSfPolicyUserContextId config)
{

    if (config == NULL)
        return;

    sfPolicyUserDataFreeIterate (config, SVFreeConfigPolicy);
    sfPolicyConfigDelete(config);

}




#ifdef SNORT_RELOAD
static void SVReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId sv_swap_config = (tSfPolicyUserContextId)*new_config;
    int policy_id = (int)getParserPolicy(sc);
    SVConfig *pPolicyConfig;

    if (!sv_swap_config)
    {
    	sv_swap_config = sfPolicyConfigCreate();
        *new_config = (void *)sv_swap_config;
    }

    sfPolicyUserPolicySet (sv_swap_config, policy_id);

    pPolicyConfig = (SVConfig *)sfPolicyUserDataGetCurrent(sv_swap_config);
    if (pPolicyConfig)
    {
        FatalError("SV can only be configured once.\n");
    }

    pPolicyConfig = (SVConfig *)SnortAlloc(sizeof(SVConfig));
    if (!pPolicyConfig)
    {
        ParseError("SV preprocessor: memory allocate failed.\n");
    }
     sfPolicyUserDataSetCurrent(sv_swap_config, pPolicyConfig);


    /* Add SV to the preprocessor function list */
    AddFuncToPreprocList(sc, SVFullReassembly, PRIORITY_NETWORK, PP_SV, PROTO_BIT__SV);

    session_api->enable_preproc_all_ports( sc, PP_SV, PROTO_BIT__SV );



       /* Parse the sv arguments from snort.conf */
       ParseSVArgs(pPolicyConfig, args);
       Active_Open (pPolicyConfig->interface->str);




}



static void *SVReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId sv_swap_config = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_config = sv_config;

    if (sv_swap_config == NULL)
        return NULL;

    sv_config = sv_swap_config;
    sv_swap_config = NULL;

    return (void *)old_config;
}

static void SVReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    SVFreeConfig((tSfPolicyUserContextId)data);
}
#endif
