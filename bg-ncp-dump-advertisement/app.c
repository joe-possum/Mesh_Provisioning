/***************************************************************************//**
 * @file
 * @brief Event handling and application code for Empty NCP Host application example
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

/* standard library headers */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <mbedtls/md5.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/ccm.h>
#include <assert.h>

/* BG stack headers */
#include "bg_types.h"
#include "gecko_bglib.h"

/* Own header */
#include "app.h"
//#include "dump.h"
#include "cic.h"
#include "provision_transaction.h"
#include "mesh-fault-values.h"
#include "mesh-model-lookup.h"
#include "../protocol.h"
#include "../utility.h"
#include "../encryption.h"

#ifndef DUMP
void dump_event(struct gecko_cmd_packet *);
#endif
int dump_advertisement(uint8 len, uint8*data);
void dump_address(bd_addr address,uint8 type,int8 rssi);
void dump_packet_type(uint8 packet_type);

#define dprintf if(1)printf

// App booted flag
static bool appBooted = false;
static struct {
  uint32 timeout;
  uint8 channel_map;
  uint8 verbose, phy;
  int8 limit, active, replay, log;
  FILE *file;
} config = {
	    .timeout = 0,
	    .active = 0,
	    .channel_map = 7,
	    .verbose = 0,
	    .limit = -127,
	    .phy = le_gap_phy_1m,
	    .file = NULL,
	    .replay = 0,
	    .log = 0,
};

void parse_address(const char *fmt,bd_addr *address) {
  char buf[3];
  int octet;
  for(uint8 i = 0; i < 6; i++) {
    memcpy(buf,&fmt[3*i],2);
    buf[2] = 0;
    sscanf(buf,"%02x",&octet);
    address->addr[5-i] = octet;
  }
}

const char *getAppOptions(void) {
  return "avcm<channel-map>l<rssi-limit>t<timeout>k<xskey>s<save-file>r<replay-file>L<log-file>";
}

void appOption(int option, char *arg) {
  double dv;
  int iv;
  uint8_t key128[16];
  switch(option) {
  case 'a':
    config.active = 1;
    break;
  case 'c':
    config.phy = le_gap_phy_coded;
    break;
  case 'm':
    sscanf(arg,"%d",&iv);
    if((iv & 7)&&!(iv >> 3)) {
      config.channel_map = iv;
    } else {
      fprintf(stderr,"channel map must be 0 - 7\n");
      exit(1);
    }
    break;
  case 'v':
    config.verbose++;
    break;
  case 'l':
    config.limit = atoi(arg);
    break;
  case 't':
    sscanf(arg,"%lf",&dv);
    config.timeout = round(dv*32768);
    break;
  case 'k':
    if(':' == arg[1]) {
      switch(arg[0]) {
      case 'n':
	assert(strlen(arg) > 35);
	assert(':' == arg[34]);
	optarg[34] = 0;
	sscanf(&arg[35],"%i",&iv);
	hex2bin(&arg[2],key128);
	add_netkey(key128,iv);
	return;
	break;
      case 'a':
	assert(strlen(arg) == 34);
	hex2bin(&arg[2],key128);
	add_appkey(key128);
	return;
	break;
      case 'd':
	assert(strlen(arg) > 35);
	assert(':' == arg[34]);
	arg[34] = 0;
	sscanf(&arg[35],"%i",&iv);
	hex2bin(&arg[2],key128);
	add_devkey(key128,iv);
	return;
	break;
      }
    }
    fprintf(stderr,"Usage: ''-k n:<netkey>:<iv>'', ''-k a:<appkey>'', or ''-k d:<devkey>\n");
    exit(1);
    break;
  case 'L':
    config.file = fopen(arg,"w");
    config.log = 1;
    break;
  case 's':
    config.file = fopen(arg,"w");
    break;
  case 'r':
    config.file = fopen(arg,"r");
    config.replay = 1;
    break;
  default:
    fprintf(stderr,"Unhandled option '-%c'\n",option);
    exit(1);
  }
}

void appInit(void) {
  if(config.replay) {
    uint8_t buf[512];
    uint8_t ss = sizeof(struct gecko_msg_le_gap_extended_scan_response_evt_t);
    struct gecko_msg_le_gap_extended_scan_response_evt_t *resp = (struct gecko_msg_le_gap_extended_scan_response_evt_t *)&buf[0];
    while(1) {
      assert(fread(buf,ss,1,config.file));
      assert(fread(buf+ss,resp->data.len,1,config.file));
      dump_address(resp->address,resp->address_type,resp->rssi);
      dump_packet_type(resp->packet_type);
      dump_advertisement(resp->data.len,resp->data.data);
    }
  }
  return;
}

void dump_flags(uint8 flags) {
  printf("Flags: %02x\n",flags);
  if(!config.verbose) return;
  printf("  LE Limited Discoverable Mode: %d\n",flags&1);
  printf("  LE General Discoverable Mode: %d\n",(flags>>1)&1);
  printf("  BR/EDR Not Supported: %d\n",(flags>>2)&1);
  printf("  Simultaneous LE and BR/EDR to Same Device Capable (Controller).: %d\n",(flags>>3)&1);
  printf("  Simultaneous LE and BR/EDR to Same Device Capable (Host).: %d\n",(flags>>4)&1);
  if(flags >> 5) printf("  Reserved bits set: %02x",flags);
}

void dump_list_of_services(uint8 len,uint8*data, uint8 complete, uint16 bits) {
  printf("%somplete List of %d-bit Service Class UUIDs:",(complete)?"C":"Inc",bits);
  if(len & 1) {
    printf("length of %d-bit service UUIDs is odd!\n",bits);
    return;
  }
  uint8 bytes = bits >> 3;
  //printf("len: %d, bits: %d, bytes: %d\n",len,bits,bytes);
  for(int i = 0; i < len; i += bytes) {
    printf(" ");
    for(int j = 0; j < bytes; j++) printf("%02x",data[i+(bytes-1)-j]);
  }
  printf("\n");
}

void dump_incomplete_list_of_16bit_services(uint8 len,uint8*data) {
  dump_list_of_services(len,data,0,16);
}

void dump_complete_list_of_16bit_services(uint8 len,uint8*data) {
  dump_list_of_services(len,data,1,16);
}

void dump_incomplete_list_of_128bit_services(uint8 len,uint8*data) {
  dump_list_of_services(len,data,0,128);
}

void dump_complete_list_of_128bit_services(uint8 len,uint8*data) {
  dump_list_of_services(len,data,1,128);
}

void dump_shortened_local_name(uint8 len, uint8* data) {
  char str[len+1];
  memcpy(str,data,len);
  str[len]= 0;
  printf("Shortened Local Name: '%s'\n",str);
}

void dump_complete_local_name(uint8 len, uint8* data) {
  char str[len+1];
  memcpy(str,data,len);
  str[len]= 0;
  printf("Complete Local Name: '%s'\n",str);
}

void dump_slave_connection_interval_range(uint8 len, uint8* data) {
  uint16 min = data[0] + (data[1] << 8);
  uint16 max = data[2] + (data[3] << 8);
  printf("Slave Connection Interval Range: %02x - %02x (%.1f - %.1f ms)\n",min,max,min*1.25,max*1.25);
}

void dump_service_data_16(uint8 len, uint8* data) {
  printf("Service Data - 16-bit UUID: %02x%02x:",data[1],data[0]);
  for(int i = 2; i < len; i++) {
    printf(" %02x",data[i]);
  }
  printf("\n");
}

void dump_device_address(uint8 len, uint8* data) {
  printf("Device Address: ");
  for(int i = 0; i < len; i++) printf("%s%02x",(i)?":":"",data[7-i]);
  printf(" (%s)\n",(data[1])?"public":"random");
}

void dump_service_data_128(uint8 len, uint8* data) {
  printf("Service Data - 128-bit UUID: ");
  for(int i = 0; i < 16; i++) printf("%02x",data[15-i]);
  printf(":");
  for(int i = 16; i < len; i++) {
    printf(" %02x",data[i]);
  }
  printf("\n");
}

void dump_manufacturer_specific_data(uint8 len,uint8 *data) {
  uint16 id = *(uint16_t*)data;
  printf("Manufacturer Specific Data:\n");
  printf("  Manufacturer Identifier: %04x %s\n",id,get_cic(id));
  printf("  Data:");
  for (int i = 2; i < len; i++) printf(" %02x",data[i]);
  printf("\n");
}

void dump_pbadv(uint8 len, uint8 *data) {
  const char *close_reason[] = {"Success","Timeout","Fail"};
  uint32 link_id = 0;
  for(int i = 0; i < 4; i++) {
    link_id <<= 8;
    link_id += data[i];
  }
  printf("PB-ADV: Link ID:%08x",link_id);
  printf(", Transaction Number:%d, Generic Provisioning PDU:{",data[4]);
  for(int i = 5; i < len; i++) printf(" %02x",data[i]);
  printf(" }\n");
  uint8 segn;
  uint16 total_length;
  switch(data[5]&3){
  case 0:
    segn = data[5]>>2;
    total_length = (data[6]<<8UL)|data[7];
    printf("  Transaction Start: SegN:%d, TotalLength:%d, FCS:%02x\n",segn,total_length,data[8]);
    if(segn > 0) transaction_start(link_id,data[4],total_length,segn,len-9,&data[9]);
    break;
  case 1:
    printf("  Transaction Acknowledgement\n");
    break;
  case 2:
    printf("  Transaction Continuation: SegmentIndex: %d\n",data[5]>>2);
    break;
  case 3:
    printf("  Provisioning Bearer Control: ");
    switch(data[5] >> 2) {
    case 0:
      printf("Link Open UUID:");
      for(int i = 0; i < 16; i++) printf("%02x",data[6+i]);
      printf("\n");
      break;
    case 1:
      printf("Link ACK\n");
      break;
    case 2:
      printf("Link Close: %s\n",(data[6]>2)?"Unrecognized":close_reason[data[6]]);
      break;
    }
    break;
  }
}

void dump_mesh_health_current_status(uint8_t len,uint8_t *parameters) {
  uint8_t testid = parameters[0];
  uint16_t companyid = (parameters[1] << 8) | parameters[2];
  uint8_t *faultArray = &parameters[3];
  len -= 3;
  printf("    Mesh Health Current status: Test ID: %d, Company ID: %04x\n", testid,companyid);
  for(int i = 0; i < len; i++) {
    printf("      %s\n",lookup_fault_value(faultArray[i]));
  }    
}
  
void dump_mesh_unsegmented_access_message(uint8 len, uint8_t *utam, uint16_t src, uint16_t dst) {
  uint32_t opcode = utam[0];
  uint8_t *parameters = &utam[1];
  len --;
  switch(opcode >> 6) {
  case 0:
    break;
  case 1:
    if(0x7f == opcode) printf("RFU opcode");
    break;
  case 2:
    opcode <<= 8;
    opcode |= parameters[0];
    parameters++;
    len --;
    break;
  case 3:
    opcode <<= 8;
    opcode |= parameters[0];
    opcode <<= 8;
    opcode |= parameters[1];
    parameters += 2;
    len -= 2;
    break;
  }
  if((opcode < 0x10000)&&(mesh_model_lookup(opcode))) {
    printf("    %04x -> %04x Model: %s, Message: %s, parameters:%s\n",src, dst, mesh_model_lookup(opcode),mesh_message_lookup(opcode),hex(len,parameters));
    return;
  }
  printf("    Unsegmented Access Message: Opcode:%x, parameters:%s\n",opcode,hex(len,parameters));
  switch(opcode) {
  case 4:
    dump_mesh_health_current_status(len,parameters);
    break;
  }
}

void dump_mesh_message(uint8 len,uint8 *data) {
  decode_network_pdu(len,data);
  return;
}

void dump_secure_network_beacon(uint8 len,const uint8 *data) {
  uint8 key_refresh_flag = data[1]&1;
  uint8 iv_update_flag = (data[1]>>1)&1;
  const uint8 *network_id = &data[2];
  uint32_t iv_index = be2uint32(&data[10]);
  const uint8_t *authentication_value = &data[14];
  printf("Secure Network beacon, Key Refresh Flag:%d, IV Update Flag:%d, Network ID: %s, IV Index: %08x, Authentication Value: %s\n",
	 key_refresh_flag,
	 iv_update_flag,
	 hex(4, network_id),
	 iv_index,
	 hex(8, authentication_value));
}

void dump_mesh_beacon(uint8 len, const uint8 *data) {
  char*RFU = "Reserved for Future Use";
  char *oob_str[16] = {"Other","Electronic/URI","2D machine-readable code","Bar code","NFC","Number","String",RFU,RFU,RFU,RFU,"On box","Inside box","On peice of paper","Indide manual","On device"};
  uint16 oob_info = (data[17]<<8) + data[18];
  bool comma = 0;
  printf("Bluetooth Mesh Beacon:\nBeacon Type: ");
  switch(data[0]) {
  case 0:
    printf("Unprovisioned Device beacon, UUID:");
    for(int i = 0; i < 16; i++) printf("%02x",data[1+i]);
    printf(", OOB Information:");
    for(int i = 0; i < 16; i++) {
      if(oob_info & (1<<i)) {
	printf("%s%s",(comma)?"|":"",oob_str[i]);
	comma=1;
      }
    }
    if(len>19) {
      printf(", URI Hash:");
      for(int i = 0; i < 4; i++) printf("%02x",data[19+i]);
    }
    printf("\n");
    break;
  case 1:
    dump_secure_network_beacon(len,data);
    break;
  default:
    printf("RESERVED\n");
  }
}

int dump_element(uint8 type,uint8 len, uint8*data) {
  switch(type) {
  case 0x01:
    dump_flags(data[0]);
    break;
  case 0x02:
    dump_incomplete_list_of_16bit_services(len,data);
    break;
  case 0x03:
    dump_complete_list_of_16bit_services(len,data);
    break;
  case 0x06:
    dump_incomplete_list_of_128bit_services(len,data);
    break;
  case 0x07:
    dump_complete_list_of_128bit_services(len,data);
    break;
  case 0x08:
    dump_shortened_local_name(len,data);
    break;
  case 0x09:
    dump_complete_local_name(len,data);
    break;
  case 0x0a:
    printf("TX Power Level: %d dBm\n",((int8*)data)[0]);
    break;
  case 0x12:
    dump_slave_connection_interval_range(len,data);
    break;
  case 0x16:
    dump_service_data_16(len,data);
    break;
  case 0x19:
    printf("Appearance:\n");
    break;
  case 0x1b:
    dump_device_address(len,data);
    break;
  case 0x21:
    dump_service_data_128(len,data);
    break;
  case 0x29:
    dump_pbadv(len,data);
    break;
  case 0x2a:
    dump_mesh_message(len,data);
    break;
  case 0x2b:
    dump_mesh_beacon(len,data);
    break;
  case 0xff:
    dump_manufacturer_specific_data(len,data);
    break;
  default:
    printf("Unhandled advertising element: type: %02x, len: %d\n",type,len);
    return 1;
  }
  return 0;
}

int dump_advertisement(uint8 len, uint8*data) {
  uint8 i = 0;
  while(i < len) {
    uint8 elen = data[i++];
    uint8 type = data[i];
    if(dump_element(type,elen-1,&data[i+1])) return 1;
    i += elen;
  }
  return 0;
}

void dump_address(bd_addr address,uint8 type,int8 rssi) {
  const char *ts = "*illegal address type*";
  switch(type) {
  case 0: ts = "public"; break;
  case 1: ts = "random"; break;
  case 255: ts = "anonymous"; break;
  }
  printf("Address: ");
  for(int i = 0; i < 6; i++) printf("%s%02x",(i)?":":"",address.addr[5-i]);
  printf(" %d dBm (%s)\n",rssi,ts);
}

void dump_packet_type(uint8 packet_type) {
  char *cs;
  switch(packet_type & 7) {
  case 0: cs = "Connectable scannable undirected advertising"; break;
  case 1: cs = "Connectable undirected advertising"; break;
  case 2: cs = "Scannable undirected advertising"; break;
  case 3: cs = "Non-connectable non-scannable undirected advertising"; break;
  case 4: cs = "Scan Response"; break;
  }
  printf("Packet type: %s (%s)\n",cs,(packet_type&0x80)?"Extended":"Legacy");
}

uint8 unique[512][16],md5sum[16];
uint16 ucount = 0;


/***********************************************************************************************//**
												  *  \brief  Event handler function.
												  *  \param[in] evt Event pointer.
												  **************************************************************************************************/
void appHandleEvents(struct gecko_cmd_packet *evt)
{
  mbedtls_md5_context ctx;
  if (NULL == evt) {
    return;
  }

  // Do not handle any events until system is booted up properly.
  if ((BGLIB_MSG_ID(evt->header) != gecko_evt_system_boot_id)
      && !appBooted) {
#if defined(DEBUG)
    printf("Event: 0x%04x\n", BGLIB_MSG_ID(evt->header));
#endif
    usleep(50000);
    return;
  }

  /* Handle events */
#ifdef DUMP
  dump_event(evt);
#endif
  switch (BGLIB_MSG_ID(evt->header)) {
  case gecko_evt_system_boot_id:
    appBooted = true;
    mbedtls_md5_init(&ctx);
    ucount = 0;
    gecko_cmd_system_linklayer_configure(3,1,&config.channel_map);
    gecko_cmd_le_gap_set_discovery_extended_scan_response(1);
    gecko_cmd_le_gap_set_discovery_timing(config.phy,1000,1000);
    gecko_cmd_le_gap_set_discovery_type(config.phy,config.active);
    gecko_cmd_le_gap_start_discovery(config.phy,le_gap_discover_observation);
    if(config.timeout) {
      gecko_cmd_hardware_set_soft_timer(config.timeout,0,1);
    }
    break;
  case gecko_evt_hardware_soft_timer_id: /******************************************************************* hardware_soft_timer **/
#define ED evt->data.evt_hardware_soft_timer
    gecko_cmd_le_gap_end_procedure();
    exit(0);
    break;
#undef ED

  case gecko_evt_le_gap_extended_scan_response_id:
#define ED evt->data.evt_le_gap_extended_scan_response
    if(ED.rssi < config.limit) return;
    if(config.log) {
      fwrite(&ED,sizeof(ED),1,config.file);
      fwrite(&ED.data.data[0],ED.data.len,1,config.file);
      fflush(config.file);
    }
    mbedtls_md5_starts_ret(&ctx);
    mbedtls_md5_update_ret(&ctx,&ED.address.addr[0],6);
    mbedtls_md5_update_ret(&ctx,&ED.data.data[0],ED.data.len);
    mbedtls_md5_finish_ret(&ctx,md5sum);
    for(int i = 0; i < ucount; i++)
      if(0 == memcmp(unique[i],md5sum,16)) return;
    memcpy(unique[ucount++],md5sum,16);
    if(config.file && !config.log) {
      fwrite(&ED,sizeof(ED),1,config.file);
      fwrite(&ED.data.data[0],ED.data.len,1,config.file);
      fflush(config.file);
    }
    dump_address(ED.address,ED.address_type,ED.rssi);
    dump_packet_type(ED.packet_type);
    if(config.verbose > 1) dump_event(evt);
    if(dump_advertisement(ED.data.len,ED.data.data) && !(config.verbose > 1)) {
      dump_event(evt);
      exit(1);
    };
    printf("\n");
    break;
#undef ED
  case gecko_evt_le_gap_scan_response_id: /***************************************************************** le_gap_scan_response **/
#define ED evt->data.evt_le_gap_scan_response
    dump_event(evt);
    break;
#undef ED
  default:
    break;
  }
}
