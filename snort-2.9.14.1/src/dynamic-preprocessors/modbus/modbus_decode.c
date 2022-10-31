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
 * Dynamic preprocessor for the Modbus protocol
 *
 */

#include "modbus_decode.h"
#include <string.h>
/* Modbus Function Codes */
#define MODBUS_FUNC_READ_COILS                          0x01
#define MODBUS_FUNC_READ_DISCRETE_INPUTS                0x02
#define MODBUS_FUNC_READ_HOLDING_REGISTERS              0x03
#define MODBUS_FUNC_READ_INPUT_REGISTERS                0x04
#define MODBUS_FUNC_WRITE_SINGLE_COIL                   0x05
#define MODBUS_FUNC_WRITE_SINGLE_REGISTER               0x06
#define MODBUS_FUNC_READ_EXCEPTION_STATUS               0x07
#define MODBUS_FUNC_DIAGNOSTICS                         0x08
#define MODBUS_FUNC_GET_COMM_EVENT_COUNTER              0x0B
#define MODBUS_FUNC_GET_COMM_EVENT_LOG                  0x0C
#define MODBUS_FUNC_WRITE_MULTIPLE_COILS                0x0F
#define MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS            0x10
#define MODBUS_FUNC_REPORT_SLAVE_ID                     0x11
#define MODBUS_FUNC_READ_FILE_RECORD                    0x14
#define MODBUS_FUNC_WRITE_FILE_RECORD                   0x15
#define MODBUS_FUNC_MASK_WRITE_REGISTER                 0x16
#define MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS       0x17
#define MODBUS_FUNC_READ_FIFO_QUEUE                     0x18
#define MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT    0x2B
#define MODBUS_SUB_FUNC_CANOPEN                         0x0D
#define MODBUS_SUB_FUNC_READ_DEVICE_ID                  0x0E

/* Various Modbus lengths */
#define MODBUS_BYTE_COUNT_SIZE 1
#define MODBUS_DOUBLE_BYTE_COUNT_SIZE 2
#define MODBUS_FILE_RECORD_SUB_REQUEST_SIZE 7
#define MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET 5
#define MODBUS_READ_DEVICE_ID_HEADER_LEN 6
#define MODBUS_READ_DEVICE_ID_NUM_OBJ_OFFSET 5

#define MODBUS_EMPTY_DATA_LEN   0
#define MODBUS_FOUR_DATA_BYTES  4
#define MODBUS_BYTE_COUNT_SIZE  1
#define MODBUS_WRITE_MULTIPLE_BYTE_COUNT_OFFSET 4
#define MODBUS_WRITE_MULTIPLE_MIN_SIZE          5
#define MODBUS_MASK_WRITE_REGISTER_SIZE         6
#define MODBUS_READ_WRITE_MULTIPLE_BYTE_COUNT_OFFSET    8
#define MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE             9
#define MODBUS_READ_FIFO_SIZE                           2
#define MODBUS_MEI_MIN_SIZE                             1
#define MODBUS_FUNC_READ_EXCEPTION_RESP_SIZE            1
#define MODBUS_SUB_FUNC_READ_DEVICE_ID_SIZE             3
#define MODBUS_SUB_FUNC_READ_DEVICE_START_LEN           2
#define MODBUS_SUB_FUNC_READ_DEVICE_LENGTH_OFFSET       1

#ifdef DUMP_BUFFER
#include "modbus_buffer_dump.h"
#endif

/* Other defines */
#define MODBUS_PROTOCOL_ID 0

/* Modbus data structures */
typedef struct _modbus_header
{
    /* MBAP Header */
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t length;
    uint8_t  unit_id;

    /* PDU Start */
    uint8_t function_code;
} modbus_header_t;


static void ModbusCheckRequestLengths(modbus_session_data_t *session, SFSnortPacket *packet)
{
    uint16_t modbus_payload_len = packet->payload_size - MODBUS_MIN_LEN;
    uint8_t tmp_count;
    int check_passed = 0;
    modbus_header_t *header;
    	uint16_t start,stop;
    	header = (modbus_header_t *) packet->payload;

    switch (session->func)
    {
        case MODBUS_FUNC_READ_COILS:
        	(session->request_data).function = session->func;
        	        	(session->request_data).transactionID = header->transaction_id;
        	        	(session->request_data).unitID = header->unit_id;
        	        	memcpy(&((session->request_data).address),packet->payload+MODBUS_MIN_LEN,2);
        	        	memcpy(&((session->request_data).quantity),packet->payload+MODBUS_MIN_LEN+2,2);
        	        	(session->request_data).address = ntohs((session->request_data).address);
        	        	(session->request_data).quantity = ntohs((session->request_data).quantity);
        	break;

        case MODBUS_FUNC_READ_DISCRETE_INPUTS:
        	(session->request_data).function = session->func;
        	        	(session->request_data).transactionID = header->transaction_id;
        	        	(session->request_data).unitID = header->unit_id;
        	        	memcpy(&((session->request_data).address),packet->payload+MODBUS_MIN_LEN,2);
        	        	memcpy(&((session->request_data).quantity),packet->payload+MODBUS_MIN_LEN+2,2);
        	        	(session->request_data).address = ntohs((session->request_data).address);
        	        	(session->request_data).quantity = ntohs((session->request_data).quantity);
        	        	break;
        case MODBUS_FUNC_READ_HOLDING_REGISTERS:
        	(session->request_data).function = session->func;
        	(session->request_data).transactionID = header->transaction_id;
        	(session->request_data).unitID = header->unit_id;
        	memcpy(&((session->request_data).address),packet->payload+MODBUS_MIN_LEN,2);
        	memcpy(&((session->request_data).quantity),packet->payload+MODBUS_MIN_LEN+2,2);
        	(session->request_data).address = ntohs((session->request_data).address);
        	(session->request_data).quantity = ntohs((session->request_data).quantity);

        	break;
        case MODBUS_FUNC_READ_INPUT_REGISTERS:
        	(session->request_data).function = session->func;
        	        	(session->request_data).transactionID = header->transaction_id;
        	        	(session->request_data).unitID = header->unit_id;
        	        	memcpy(&((session->request_data).address),packet->payload+MODBUS_MIN_LEN,2);
        	        	memcpy(&((session->request_data).quantity),packet->payload+MODBUS_MIN_LEN+2,2);
        	        	(session->request_data).address = ntohs((session->request_data).address);
        	        	(session->request_data).quantity = ntohs((session->request_data).quantity);
        	        	break;
        case MODBUS_FUNC_WRITE_SINGLE_COIL:
        case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
        case MODBUS_FUNC_DIAGNOSTICS:
            if (modbus_payload_len == MODBUS_FOUR_DATA_BYTES)
                check_passed = 1;
            break;

        case MODBUS_FUNC_READ_EXCEPTION_STATUS:
        case MODBUS_FUNC_GET_COMM_EVENT_COUNTER:
        case MODBUS_FUNC_GET_COMM_EVENT_LOG:
        case MODBUS_FUNC_REPORT_SLAVE_ID:
            if (modbus_payload_len == MODBUS_EMPTY_DATA_LEN)
                check_passed = 1;
            break;
        
        case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
        case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:
            if (modbus_payload_len >= MODBUS_WRITE_MULTIPLE_MIN_SIZE)
            {
                tmp_count = *(packet->payload + MODBUS_MIN_LEN +
                              MODBUS_WRITE_MULTIPLE_BYTE_COUNT_OFFSET);
                if (modbus_payload_len == tmp_count + MODBUS_WRITE_MULTIPLE_MIN_SIZE)
                    check_passed = 1;
            }
            break;

        case MODBUS_FUNC_MASK_WRITE_REGISTER:
            if (modbus_payload_len == MODBUS_MASK_WRITE_REGISTER_SIZE)
                check_passed = 1;
            break;

        case MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS:
            if (modbus_payload_len >= MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE)
            {
                tmp_count = *(packet->payload + MODBUS_MIN_LEN +
                              MODBUS_READ_WRITE_MULTIPLE_BYTE_COUNT_OFFSET);
                if (modbus_payload_len == MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE + tmp_count)
                    check_passed = 1;
            }
            break;


        case MODBUS_FUNC_READ_FIFO_QUEUE:
            if (modbus_payload_len == MODBUS_READ_FIFO_SIZE)
                check_passed = 1;
            break;

        case MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT:
            if (modbus_payload_len >= MODBUS_MEI_MIN_SIZE)
            {
                uint8_t mei_type = *(packet->payload + MODBUS_MIN_LEN);

                /* MEI Type 0x0E is covered under the Modbus spec as
                   "Read Device Identification". Type 0x0D is defined in
                   the spec as "CANopen General Reference Request and Response PDU"
                   and falls outside the scope of the Modbus preprocessor.

                   Other values are reserved.
                */
                if ((mei_type == MODBUS_SUB_FUNC_READ_DEVICE_ID) &&
                    (modbus_payload_len == MODBUS_SUB_FUNC_READ_DEVICE_ID_SIZE))
                    check_passed = 1;
            }
            break;


        case MODBUS_FUNC_READ_FILE_RECORD:
            /* Modbus read file record request contains a byte count, followed
               by a set of 7-byte sub-requests. */
            if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
            {
                tmp_count = *(packet->payload + MODBUS_MIN_LEN);
                if ((tmp_count == modbus_payload_len - MODBUS_BYTE_COUNT_SIZE) &&
                    (tmp_count % MODBUS_FILE_RECORD_SUB_REQUEST_SIZE == 0))
                {
                    check_passed = 1;
                }
            }
            break;

        case MODBUS_FUNC_WRITE_FILE_RECORD:
            /* Modbus write file record request contains a byte count, followed
               by a set of sub-requests that contain a 7-byte header and a
               variable amount of data. */

            if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
            {
                tmp_count = *(packet->payload + MODBUS_MIN_LEN);
                if (tmp_count == modbus_payload_len - MODBUS_BYTE_COUNT_SIZE)
                {
                    uint16_t bytes_processed = 0;

                    while (bytes_processed < (uint16_t)tmp_count)
                    {
                        uint16_t record_length = 0;

                        /* Check space for sub-request header info */
                        if ((modbus_payload_len - bytes_processed) <
                                MODBUS_FILE_RECORD_SUB_REQUEST_SIZE)
                            break;

                        /* Extract record length. */
                        record_length = *(packet->payload + MODBUS_MIN_LEN +
                            MODBUS_BYTE_COUNT_SIZE + bytes_processed +
                            MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET);

                        record_length = record_length << 8;

                        record_length |= *(packet->payload + MODBUS_MIN_LEN +
                            MODBUS_BYTE_COUNT_SIZE + bytes_processed +
                            MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET + 1);

                        /* Jump over record data. */
                        bytes_processed += MODBUS_FILE_RECORD_SUB_REQUEST_SIZE +
                                           2*record_length;

                        if (bytes_processed == (uint16_t)tmp_count)
                            check_passed = 1;
                    }
                }
            }
            break;

        default: /* Don't alert if we couldn't check the length. */
            check_passed = 1;
            break;
    }

    if (!check_passed)
    {
        _dpd.alertAdd(GENERATOR_SPP_MODBUS, MODBUS_BAD_LENGTH, 1, 0, 3,
                      MODBUS_BAD_LENGTH_STR, 0);
    }
}

static void ModbusCheckResponseLengths(modbus_session_data_t *session, SFSnortPacket *packet)
{
    uint16_t modbus_payload_len = packet->payload_size - MODBUS_MIN_LEN;
    uint8_t tmp_count;
    int check_passed = 0;

    switch (session->func)
    {
        case MODBUS_FUNC_READ_COILS:
        case MODBUS_FUNC_READ_DISCRETE_INPUTS:
        case MODBUS_FUNC_GET_COMM_EVENT_LOG:
        case MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS:
            if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
            {
                tmp_count = *(packet->payload + MODBUS_MIN_LEN); /* byte count */
                if (modbus_payload_len == MODBUS_BYTE_COUNT_SIZE + tmp_count)
                    check_passed = 1;
            }
            break;

        case MODBUS_FUNC_READ_HOLDING_REGISTERS:
        case MODBUS_FUNC_READ_INPUT_REGISTERS:
            if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
            {
                tmp_count = *(packet->payload + MODBUS_MIN_LEN);
                if (modbus_payload_len == MODBUS_BYTE_COUNT_SIZE + tmp_count)
                    check_passed = 1;
            }
            break;

        case MODBUS_FUNC_WRITE_SINGLE_COIL:
        case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
        case MODBUS_FUNC_DIAGNOSTICS:
        case MODBUS_FUNC_GET_COMM_EVENT_COUNTER:
        case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
        case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:
            if (modbus_payload_len == MODBUS_FOUR_DATA_BYTES)
                check_passed = 1;
            break;

        case MODBUS_FUNC_READ_EXCEPTION_STATUS:
            if (modbus_payload_len == MODBUS_FUNC_READ_EXCEPTION_RESP_SIZE)
                check_passed = 1;
            break;

        case MODBUS_FUNC_MASK_WRITE_REGISTER:
            if (modbus_payload_len == MODBUS_MASK_WRITE_REGISTER_SIZE)
                check_passed = 1;
            break;

        case MODBUS_FUNC_READ_FIFO_QUEUE:
            if (modbus_payload_len >= MODBUS_DOUBLE_BYTE_COUNT_SIZE)
            {
                uint16_t tmp_count_16;

                /* This function uses a 2-byte byte count!! */
                tmp_count_16 = *(uint16_t *)(packet->payload + MODBUS_MIN_LEN);
                tmp_count_16 = ntohs(tmp_count_16);
                if (modbus_payload_len == MODBUS_DOUBLE_BYTE_COUNT_SIZE + tmp_count_16)
                    check_passed = 1;
            }
            break;

        case MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT:
            if (modbus_payload_len >= MODBUS_READ_DEVICE_ID_HEADER_LEN)
            {
                uint8_t mei_type = *(packet->payload + MODBUS_MIN_LEN);
                uint8_t num_objects = *(packet->payload + MODBUS_MIN_LEN +
                                        MODBUS_READ_DEVICE_ID_NUM_OBJ_OFFSET);
                uint16_t offset;
                uint8_t i;

                /* MEI Type 0x0E is covered under the Modbus spec as
                   "Read Device Identification". Type 0x0D is defined in
                   the spec as "CANopen General Reference Request and Response PDU"
                   and falls outside the scope of the Modbus preprocessor.

                   Other values are reserved.
                */

                if (mei_type == MODBUS_SUB_FUNC_CANOPEN)
                    check_passed = 1;

                if (mei_type != MODBUS_SUB_FUNC_READ_DEVICE_ID)
                    break;

                /* Loop through sub-requests, make sure that the lengths inside
                   don't violate our total Modbus PDU size. */

                offset = MODBUS_READ_DEVICE_ID_HEADER_LEN;
                for (i = 0; i < num_objects; i++)
                {
                    uint8_t sub_request_data_len;

                    /* Sub request starts with 2 bytes, type + len */
                    if (offset + MODBUS_SUB_FUNC_READ_DEVICE_START_LEN > modbus_payload_len)
                        break;

                    /* Length is second byte in sub-request */
                    sub_request_data_len = *(packet->payload + MODBUS_MIN_LEN +
                                            offset + MODBUS_SUB_FUNC_READ_DEVICE_LENGTH_OFFSET);

                    /* Set offset to byte after sub-request */
                    offset += (MODBUS_SUB_FUNC_READ_DEVICE_START_LEN + sub_request_data_len);
                }

                if ((i == num_objects) && (offset == modbus_payload_len))
                    check_passed = 1;
            }
            break;

        /* Cannot check this response, as it is device specific. */
        case MODBUS_FUNC_REPORT_SLAVE_ID:

        /* Cannot check these responses, as their sizes depend on the corresponding
           requests. Can re-visit if we bother with request/response tracking. */
        case MODBUS_FUNC_READ_FILE_RECORD:
        case MODBUS_FUNC_WRITE_FILE_RECORD:

        default: /* Don't alert if we couldn't check the lengths. */
            check_passed = 1;
            break;
    }

    if (!check_passed)
    {
        _dpd.alertAdd(GENERATOR_SPP_MODBUS, MODBUS_BAD_LENGTH, 1, 0, 3,
                      MODBUS_BAD_LENGTH_STR, 0);
    }
}

static void ModbusCheckReservedFuncs(modbus_header_t *header, SFSnortPacket *packet)
{
    switch (header->function_code)
    {
        /* Reserved function codes */
        case MODBUS_FUNC_DIAGNOSTICS:
            /* Only some sub-functions are reserved here. */
            {
                uint16_t sub_func;

                if (packet->payload_size < MODBUS_MIN_LEN+2)
                    break;
                
                sub_func = *((uint16_t *)(packet->payload + MODBUS_MIN_LEN));
                sub_func = ntohs(sub_func);

                if ((sub_func == 19) || (sub_func >= 21))
                {
                    _dpd.alertAdd(GENERATOR_SPP_MODBUS, MODBUS_RESERVED_FUNCTION,
                                  1, 0, 3, MODBUS_RESERVED_FUNCTION_STR, 0);
                }
            }
            break;
        case 0x09:
        case 0x0A:
        case 0x0D:
        case 0x0E:
        case 0x29:
        case 0x2A:
        case 0x5A:
        case 0x5B:
        case 0x7D:
        case 0x7E:
        case 0x7F:
            _dpd.alertAdd(GENERATOR_SPP_MODBUS, MODBUS_RESERVED_FUNCTION, 1, 0, 3,
                          MODBUS_RESERVED_FUNCTION_STR, 0);
            break;
    }
#ifdef DUMP_BUFFER
        dumpBuffer(MODBUS_RESERVED_FUN_DUMP,packet->payload,packet->payload_size);
#endif
}

static int modifyWriteData(modbus_config_t *config, modbus_session_data_t *session, SFSnortPacket *packet)
{
	modbus_header_t *header;
	uint16_t start,stop;
	uint16_t temp;
	uint8_t modified = 0;
	uint16_t tempRegHold=0, tempRegHold2=0;
	uint8_t mask = 0;
	uint16_t n =0;
	uint8_t p=0;
	uint16_t bit_cnt = 0, byte_cnt = 0;
	uint8_t * pdu_start = packet->payload;

	header = (modbus_header_t *) pdu_start;
	if(header->transaction_id!=(session->request_data).transactionID)
	{
		printf("Transaction is missed\n");
		return 0;
	}

	start = (session->request_data).address;
	stop = (session->request_data).address+(session->request_data).quantity-1;

	for(int index = 0 ; index<config->numAlteredVal;index++)
	{
		if((config->values_to_alter[index]).type == header->function_code && ((config->values_to_alter[index]).identifier)>=start && ((config->values_to_alter[index]).identifier)<=stop )
		{
			uint16_t byteNumber;
			switch(header->function_code)
			{



			case MODBUS_FUNC_WRITE_SINGLE_COIL:
				byteNumber = 1;



				memcpy(&n,(pdu_start+MODBUS_MIN_LEN),2); //copy the index
				 n = ntohs(n);
				 if(n==(config->values_to_alter[index]).identifier)
						{
					 uint16_t data = 0;

					 memcpy(&data,(pdu_start+MODBUS_MIN_LEN+2),2); //copy the data
					 (config->values_to_alter[index]).old_value = ntohs(data);
					 if((config->values_to_alter[index]).integer_value == 0)
					 {
						 temp = 0;

					 }
					 else
					 {
						 temp = 0xFF00;
					 }
					 memcpy(pdu_start+MODBUS_MIN_LEN+2,&(temp),2);
					 modified = 1;
					 printf("Modify WriteCoils id=%d value=%d\n",(config->values_to_alter[index]).identifier,temp );
						}


				break;
			case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
				memcpy(&n,(pdu_start+MODBUS_MIN_LEN),2); //copy the index
								 n = ntohs(n);
								 if(n==(config->values_to_alter[index]).identifier)
										{
									 uint16_t data = 0;

									 memcpy(&data,(pdu_start+MODBUS_MIN_LEN+2),2); //copy the data
									 (config->values_to_alter[index]).old_value = ntohs(data);
										 temp = htons((config->values_to_alter[index]).integer_value);


									 memcpy(pdu_start+MODBUS_MIN_LEN+2,&(temp),2);
									 modified = 1;
									 printf("Modify WriteCoils id=%d value=%d\n",(config->values_to_alter[index]).identifier,temp );
										}


								break;

			case MODBUS_FUNC_DIAGNOSTICS:
			case MODBUS_FUNC_GET_COMM_EVENT_COUNTER:
			case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
			{
				memcpy(&n,(pdu_start+MODBUS_MIN_LEN),2); //copy the index
				n = ntohs(n);
				if(n==(config->values_to_alter[index]).identifier)
				{
					uint16_t data = 0;

					memcpy(&bit_cnt,(pdu_start+MODBUS_MIN_LEN+2),2); //copy the data

					bit_cnt = ntohs(bit_cnt);

					memcpy(&byte_cnt,(pdu_start+MODBUS_MIN_LEN+4),1);
					byte_cnt = ntohs(byte_cnt);

					memcpy(&data,(pdu_start+MODBUS_MIN_LEN+5),2);


					(config->values_to_alter[index]).old_value = ntohs(data);
					temp = htons((config->values_to_alter[index]).integer_value);


					memcpy(pdu_start+MODBUS_MIN_LEN+5,&(temp),2);
					modified = 1;
					printf("Modify Multiple Write Coils id=%d value=%d\n",(config->values_to_alter[index]).identifier,temp );
				}


				break;
			}
			case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:


			case MODBUS_FUNC_READ_EXCEPTION_STATUS:


			case MODBUS_FUNC_MASK_WRITE_REGISTER:


			case MODBUS_FUNC_READ_FIFO_QUEUE:


			case MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT:


				/* Cannot check this response, as it is device specific. */
			case MODBUS_FUNC_REPORT_SLAVE_ID:

				/* Cannot check these responses, as their sizes depend on the corresponding
                              requests. Can re-visit if we bother with request/response tracking. */
			case MODBUS_FUNC_READ_FILE_RECORD:
			case MODBUS_FUNC_WRITE_FILE_RECORD:

			default:

				break;
			}
	}
}
return modified;
}

static int modifyData(modbus_config_t *config, modbus_session_data_t *session, SFSnortPacket *packet)
{
	modbus_header_t *header;
	uint16_t start,stop;

	uint16_t temp;
	uint8_t modified = 0;
	int mask;
	uint16_t n;
	int p;
	header = (modbus_header_t *) packet->payload;
	if(header->transaction_id!=(session->request_data).transactionID)
	{
		_dpd.logMsg("Transaction is missed\n");
		return 0;
	}

	start = (session->request_data).address;
	stop = (session->request_data).address+(session->request_data).quantity-1;

	for(int index = 0 ; index<config->numAlteredVal;index++)
	{
		if((config->values_to_alter[index]).type == header->function_code && ((config->values_to_alter[index]).identifier)>=start && ((config->values_to_alter[index]).identifier)<=stop )
		{
			uint16_t byteNumber;
		switch(header->function_code)
		{
		case MODBUS_FUNC_READ_COILS:
			 byteNumber = ((config->values_to_alter[index]).identifier-start+1)/8;
			 byteNumber +=((config->values_to_alter[index]).identifier-start+1)%8==0?0:1;
			 p = ((config->values_to_alter[index]).identifier%8);
			 									mask = 1<<p;

			 									memcpy(&n,(packet->payload+MODBUS_MIN_LEN+byteNumber),1);

			 									temp = ntohs((config->values_to_alter[index]).integer_value);
			 									temp = (n & ~mask)|((temp<<p)& mask);

			memcpy(packet->payload+MODBUS_MIN_LEN+byteNumber,&(temp),1);
			modified = 1;
			_dpd.logMsg("Modify Read Coils id=%d value=%d\n",(config->values_to_alter[index]).identifier,temp );
			_dpd.alertAdd(GENERATOR_SPP_MODBUS, 5, 1, 0, 3,
			                      "Modify READ COILS", 0);
			break;
		case MODBUS_FUNC_READ_DISCRETE_INPUTS:
			 byteNumber = ((config->values_to_alter[index]).identifier-start+1)/8;
						 byteNumber +=((config->values_to_alter[index]).identifier-start+1)%8==0?0:1;
			 p = ((config->values_to_alter[index]).identifier%8);
									 mask = 1<<p;

									memcpy(&n,(packet->payload+MODBUS_MIN_LEN+byteNumber),1);

									temp = ntohs((config->values_to_alter[index]).integer_value);
									temp = (n & ~mask)|((temp<<p)& mask);




						memcpy(packet->payload+MODBUS_MIN_LEN+byteNumber,&(temp),1);
						modified = 1;
						_dpd.logMsg("Modify Read Discrete Inputs id=%d value=%d\n",(config->values_to_alter[index]).identifier,temp);
						break;

		case MODBUS_FUNC_READ_HOLDING_REGISTERS:
			byteNumber= ((config->values_to_alter[index]).identifier-start)*2;
			memcpy(packet->payload+MODBUS_MIN_LEN+1+byteNumber,&((config->values_to_alter[index]).integer_value),2);
			modified = 1;
			break;

        case MODBUS_FUNC_READ_INPUT_REGISTERS:
                        	   byteNumber= ((config->values_to_alter[index]).identifier-start)*2;
                        	   			memcpy(packet->payload+MODBUS_MIN_LEN+1+byteNumber,&((config->values_to_alter[index]).integer_value),2);
                        	   			modified = 1;
                        	   			break;


        case MODBUS_FUNC_WRITE_SINGLE_COIL:
        							byteNumber = 1;



        							memcpy(&n,(packet->payload+MODBUS_MIN_LEN),2); //copy the index
        							 n = ntohs(n);
        							 if(n==(config->values_to_alter[index]).identifier)
        									{
        								 uint16_t data = 0;

        								 memcpy(&data,(packet->payload+MODBUS_MIN_LEN+2),2); //copy the data
        								 if((config->values_to_alter[index]).old_value == 0)
        								 {
        									 temp = 0;

        								 }
        								 else
        								 {
        									 temp = 0xFF00;
        								 }
        								 memcpy(packet->payload+MODBUS_MIN_LEN+2,&(temp),2);
        								 modified = 1;
        								 printf("Modify WriteCoils id=%d value=%d\n",(config->values_to_alter[index]).identifier,temp );
        									}


        							break;
        						case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
        							memcpy(&n,(packet->payload+MODBUS_MIN_LEN),2); //copy the index
        											 n = ntohs(n);
        											 if(n==(config->values_to_alter[index]).identifier)
        													{
        												 uint16_t data = 0;

        												 memcpy(&data,(packet->payload+MODBUS_MIN_LEN+2),2); //copy the data

        													 temp = htons((config->values_to_alter[index]).old_value);


        												 memcpy(packet->payload+MODBUS_MIN_LEN+2,&(temp),2);
        												 modified = 1;
        												 printf("Modify WriteCoils id=%d value=%d\n",(config->values_to_alter[index]).identifier,temp );
        													}


        											break;
                           case MODBUS_FUNC_DIAGNOSTICS:
                           case MODBUS_FUNC_GET_COMM_EVENT_COUNTER:
                           case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
                           case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:


                           case MODBUS_FUNC_READ_EXCEPTION_STATUS:


                           case MODBUS_FUNC_MASK_WRITE_REGISTER:


                           case MODBUS_FUNC_READ_FIFO_QUEUE:


                           case MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT:


                           /* Cannot check this response, as it is device specific. */
                           case MODBUS_FUNC_REPORT_SLAVE_ID:

                           /* Cannot check these responses, as their sizes depend on the corresponding
                              requests. Can re-visit if we bother with request/response tracking. */
                           case MODBUS_FUNC_READ_FILE_RECORD:
                           case MODBUS_FUNC_WRITE_FILE_RECORD:

                           default:

                               break;
                       }
	}
}
return modified;
}

int ModbusDecode(modbus_session_data_t *session,modbus_config_t *config, SFSnortPacket *packet)
{

    modbus_header_t *header;

    if (packet->payload_size < MODBUS_MIN_LEN)
        return MODBUS_FAIL;


    
    /* Lay the header struct over the payload */
    header = (modbus_header_t *) packet->payload;

    /* The protocol ID field should read 0x0000 for Modbus. It allows for
       multiplexing with some other protocols over serial line. */
    if (header->protocol_id != MODBUS_PROTOCOL_ID)
    {
        _dpd.alertAdd(GENERATOR_SPP_MODBUS, MODBUS_BAD_PROTO_ID, 1, 0, 3,
                      MODBUS_BAD_PROTO_ID_STR, 0);
        return MODBUS_FAIL;
    }

    /* Set the session data.
       Normally we'd need to swap byte order, but these are 8-bit fields. */
    session->unit = header->unit_id;
    session->func = header->function_code;

    /* Check for reserved function codes */
    ModbusCheckReservedFuncs(header, packet);

    /* Read the Modbus payload and check lengths against the expected length for
       each function. */
    if (packet->flags & FLAG_FROM_CLIENT)
    {
        ModbusCheckRequestLengths(session, packet);
#ifdef DUMP_BUFFER
        dumpBuffer(MODBUS_CLINET_REQUEST_DUMP,packet->payload,packet->payload_size);
#endif

        if(modifyWriteData(config, session, packet))
                {
                	packet->flags|=FLAG_MODIFIED;
                	_dpd.logMsg("Got to Modify Data\n");
                }
    }
    else
    {
        ModbusCheckResponseLengths(session, packet);
        _dpd.logMsg("Got to Chk Response Length\n");

        /*
         * Add code here to modify the data
         */
        if(modifyData(config, session, packet))
        {
        	packet->flags|=FLAG_MODIFIED;
        	_dpd.logMsg("Got to Modify Data\n");
        }

#ifdef DUMP_BUFFER
        dumpBuffer(MODBUS_SERVER_RESPONSE_DUMP,packet->payload,packet->payload_size);
#endif
    }
    return MODBUS_OK;
}
