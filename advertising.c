#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "host_gecko.h"
#include <mbedtls/aes.h>
#include <mbedtls/ccm.h>
#include <mbedtls/cmac.h>
#include "utility.h"
#include "cic.h"
#include "mesh-fault-values.h"
#include "mesh-model-lookup.h"
#include "provision_transaction.h"
#include <unistd.h>
#include "protocol.h"
#include "encryption.h"

#define VERBOSE_ADVERTISING 0

void dump_flags(uint8 flags) {
  printf("Flags: %02x\n",flags);
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
  int comma = 0;
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

void cmdline_decrypt(const char *message) {
  fprintf(stderr,"%s(message:%s)\n",__PRETTY_FUNCTION__,message);
  uint8_t pdu[31];
  int n = strlen(message);
  if(n & 1) {
    fprintf(stderr,"Odd hex message length\n");
    exit(1);
  }
  n >>= 1;
  char buf[3];
  buf[2] = 0;
  for(int i = 0; i < n; i++) {
    unsigned int v;
    memcpy(buf,&message[i<<1],2);
    assert(1 == sscanf(buf,"%x",&v));
    pdu[2+i] = v;
  }
  pdu[0] = 1+n;
  pdu[1] = 0x2a;
  dump_advertisement(2+n,pdu);
  exit(0);
}

uint8 unique[512][16],md5sum[16];
uint16 ucount = 0;


int main(int argc, char *argv[]) {
  uint8_t buf[512];
  uint8_t ss = sizeof(struct gecko_msg_le_gap_extended_scan_response_evt_t);
  struct gecko_msg_le_gap_extended_scan_response_evt_t *resp = (struct gecko_msg_le_gap_extended_scan_response_evt_t *)&buf[0];
  int done = 0;
  while(!done) {
    int rc = getopt(argc,argv,"k:");
    switch(rc) {
    case 'k':
      if(':' == optarg[1]) {
	uint8_t key128[16];
	int iv;
	switch(optarg[0]) {
	case 'n':
	  assert(strlen(optarg) > 35);
	  assert(':' == optarg[34]);
	  optarg[34] = 0;
	  sscanf(&optarg[35],"%i",&iv);
	  hex2bin(&optarg[2],key128);
	  add_netkey(key128,iv);
	  break;
	case 'a':
	  //add_appkey(&optarg[2]);
	  break;
	case 'd':
	  assert(34 == strlen(optarg));
	  hex2bin(&optarg[2],key128);
	  add_devkey(key128);
	  break;
	}
      }
      break;
    default:
      done = 1;
      break;
    }
  }
  while(1) {
    assert(fread(buf,ss,1,stdin));
    assert(fread(buf+ss,resp->data.len,1,stdin));
    if(dump_advertisement(resp->data.len,resp->data.data)) {
      return 1;
    }
    fflush(stdout);
  }
}
