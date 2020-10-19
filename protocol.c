#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/ccm.h>
#include <mbedtls/ecdh.h>
#include "provisioner/fcs.h"
#include "k1.h"
#include "s1.h"
#include "confirmation.h"
#include "provisioning-data.h"
#include "encryption.h"
#include "utility.h"
#include "mesh-access-lookup.h"
#include "mesh-model-lookup.h"
#include "segmented-messages.h"

#ifdef TEST_PROTOCOL
#define VERBOSE_PROTOCOL 1
#else
#define VERBOSE_PROTOCOL 0
#endif

#ifndef TEST_PROTOCOL
#ifdef BLUETOOTH_ACTIVE
/* BG stack headers */
#include "bg_types.h"
#include "gecko_bglib.h"
#include "btmesh-proxy/gatt_db.h"
#endif
#endif

static struct config {
  mbedtls_ecdh_context ctx;
  mbedtls_ecp_keypair local_kp;
  mbedtls_ecp_point remote_point;
  uint8_t shared_secret[32];
  uint8_t local_random[16], authvalue[16], remote_random[16], remote_confirmation[16];
#ifndef TEST_PROTOCOL
  uint16_t mtu;
  uint8_t connection;
#endif
} config;

#ifndef TEST_PROTOCOL
void set_mtu(uint16_t mtu) {
  config.mtu = mtu;
}

void set_connection(uint8_t connection) {
  config.connection = connection;
}
#endif

#ifdef TEST_PROTOCOL
void decode_network_pdu(uint8_t len, uint8_t *data);
#endif

void send_proxy_pdu(uint8_t type, uint8_t len, uint8_t *data) {
  printf("send_proxy_pdu(type:%d, data:%s)\n",type,hex(len,data));
#ifdef TEST_PROTOCOL
  printf("SIMULATED OUT: %02x%s\n",type,hex(len,data));
#else
  printf("mtu: %d\n",config.mtu);
  if(len < (config.mtu-3)) {
    uint8_t pdu[1+len];
    pdu[0] = type;
    memcpy(&pdu[1],data,len);
#ifdef BLUETOOTH_ACTIVE
    gecko_cmd_gatt_server_send_characteristic_notification(config.connection,gattdb_provisioning_out,sizeof(pdu),pdu);
#endif
  }
#endif
}

void send_provisioning_pdu(uint8_t type, uint8_t len, uint8_t *data) {
  uint8_t pdu[1+len];
  pdu[0] = type;
  memcpy(&pdu[1],data,len);
  send_proxy_pdu(3,sizeof(pdu),pdu);
}

void send_provisioning_capabilities(uint8_t elements) {
  uint8_t parameters[11] = { elements, 0, 1, };
  confirmation_set_capabilities(sizeof(parameters),parameters);
  send_provisioning_pdu(1,sizeof(parameters),parameters);
}

void send_provisioning_public_key(uint8_t *x, uint8_t *y) {
  uint8_t parameters[64];
  memcpy(parameters,x,32);
  memcpy(parameters+32,y,32);
  confirmation_set_device_public_key(sizeof(parameters),parameters);
  send_provisioning_pdu(3,sizeof(parameters),parameters);
}

void send_provisioning_confirmation(uint8_t len, uint8_t *data) {
  printf("send_provisioning_confirmation()\n");
  send_provisioning_pdu(5,len,data);
}

void send_provisioning_random(uint8_t len, uint8_t *data) {
  printf("send_provisioning_confirmation()\n");
  send_provisioning_pdu(6,len,data);
}

void send_provisioning_complete(void) {
  printf("send_provisioning_confirmation()\n");
  send_provisioning_pdu(8,0,NULL);
}

void decode_provisioning_invite(uint8_t len, uint8_t *data) {
  uint8_t attention_timer_seconds = data[0];
  printf("  Attention Timer: %d seconds\n", attention_timer_seconds);
  confirmation_set_invite(len,data);
  send_provisioning_capabilities(1);
}

void decode_provisioning_start(uint8_t len, uint8_t *data) {
  confirmation_set_start(len,data);
}

void decode_public_key(uint8_t len, uint8_t *data) {
  char xstr[65], ystr[65];
  int rc;
  mbedtls_mpi shared_secret;
  confirmation_set_provisioner_public_key(len,data);
  strncpy(xstr,hex(32,data),64);
  strncpy(ystr,hex(32,data+32),64);
  xstr[64] = ystr[64] = 0;
  mbedtls_ecp_keypair_init(&config.local_kp);
  mbedtls_ecp_point_init(&config.remote_point);
  mbedtls_mpi_init(&shared_secret);
  assert(0 == (rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,&config.local_kp,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_ecp_point_read_string(&config.remote_point, 16, xstr, ystr)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_ecp_check_pubkey(&config.local_kp.grp, &config.remote_point)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_mpi_write_binary(&config.local_kp.Q.X,(unsigned char*)xstr,32)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_mpi_write_binary(&config.local_kp.Q.Y,(unsigned char*)ystr,32)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_ecdh_compute_shared(&config.local_kp.grp, &shared_secret, &config.remote_point, &config.local_kp.d,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_mpi_write_binary(&shared_secret,(unsigned char*)&config.shared_secret,32)) || (-1 == printf("rc = -%x\n",-rc)));
  send_provisioning_public_key((uint8_t*)xstr, (uint8_t*)ystr);
  assert(0 == (rc = mbedtls_mpi_write_binary(&config.local_kp.d,(unsigned char*)xstr,32)) || (-1 == printf("rc = -%x\n",-rc)));
  myrnd(NULL,config.local_random,16);
  memset(config.authvalue, 0, 16);
  printf("Private key: %s\n",hex(32,(uint8_t*)xstr));
  printf("Shared secret: %s\n",hex(32,config.shared_secret));
  confirmation_set_secret(32,config.shared_secret);
  confirmation_set_authvalue(16,config.authvalue);
  uint8_t result[16];
  confirmation(config.local_random,result);
  send_provisioning_confirmation(16,result);
}

void decode_provisioning_confirmation(uint8_t len, uint8_t *data) {
  assert(16 == len);
  memcpy(&config.remote_confirmation,data,len);
}

void decode_provisioning_random(uint8_t len, uint8_t *data) {
  assert(16 == len);
  uint8_t result[16];
  confirmation(data,result);
  if(memcmp(&config.remote_confirmation,result,16)) {
    printf("Confirmation value fails\n");
  } else {
    printf("Confirmation values match\n");
    memcpy(config.remote_random,data,len);
    send_provisioning_random(16,config.local_random);
  }
}

void decode_provisioning_data(uint8_t len, uint8_t *data) { // Mesh Profile 5.4.2.5
#ifndef TEST_PROTOCOL
  uint8_t salt[16];
  struct __attribute__((packed)) {
    uint8_t net_key[16], key_index[2],flags[1], iv_index[4], unicast_address[2];
  } plaintext;
  confirmation_get_salt(salt);
  provisioning_data_init(salt,config.remote_random,config.local_random,config.shared_secret);
  assert(0 == provisioning_data_decrypt((void*)&plaintext,data,data+25));
  printf("    Network Key: %s\n",hex(16,plaintext.net_key));
  printf("      Key Index: %s\n",hex(2,plaintext.key_index));
  printf("          Flags: %s\n",hex(1,plaintext.flags));
  printf("       IV Index: %s\n",hex(4,plaintext.iv_index));
  printf("Unicast Address: %s\n",hex(2,plaintext.unicast_address));
  add_netkey(plaintext.net_key,be2uint32(plaintext.iv_index));
  uint8_t devkey[16];
  provisioning_data_get_salt(salt);
  printf("Calculate device key ... provisioning salt: %s\n",hex(16,salt));
  k1(32,config.shared_secret,salt,4,(uint8_t*)"prdk",devkey);
  add_devkey(devkey,be2uint16(plaintext.unicast_address));
#endif
  send_provisioning_complete();
}

void decode_provisioning_pdu(uint8_t len, uint8_t *data) {
  uint8_t padding = data[0] >> 6;
  uint8_t type = data[0] & 0x3f;
  if(0 != padding) {
    printf("Provisioning PDU padding is non-zero\n");
    //gecko_cmd_system_reset(0);
    exit(1);
  }
  if(type > 9) {
    printf("Provisioning PDU types greater than 9 are reserved for future use\n");
    //gecko_cmd_system_reset(0);
    exit(1);
  }
  char *typestr[10] = { "Provisioning Invite","Provisioning Capabilities","Provisioning Start",
			"Provisioning Public Key","Provisioning Input Complete","Provisioning Confirmation",
			"Provisioning Random","Provisioning Data","Provisioning Complete","Provisioning Failed"};
  printf("Provisioning PDU: %s, data: %s\n",typestr[type],hex(len-1,data+1));
  switch(type) {
  case 0:
    decode_provisioning_invite(len-1,data+1);
    break;
  case 2:
    decode_provisioning_start(len-1,data+1);
    break;
  case 3:
    decode_public_key(len-1,data+1);
    break;
  case 5:
    decode_provisioning_confirmation(len-1,data+1);
    break;
  case 6:
    decode_provisioning_random(len-1,data+1);
    break;
  case 7:
    decode_provisioning_data(len-1,data+1);
    break;
  default:
    printf("UNHANDLED TYPE %d\n",type);
  }
}


void decode_dcd_status(uint8_t len, uint8_t *parameters) {
  struct __attribute__((packed)) dcd {
    uint16_t cid, pid, vid, crpl, features;
  } *p = (struct dcd*)&parameters[1];
  struct __attribute__((packed)) elements {
    uint16_t loc;
    uint8_t nums, numv;
  } *e = (void*)p + 10;
  char *features[4] = {"relay","proxy","friend","low power"};
  printf("  Page:%02x, CID:%04x, PID:%04x, VID:%04x, CRPL:%04x, Features:%04x:",parameters[0],
	 p->cid,p->pid,p->vid,p->crpl,p->features);
  int count = 0;
  for(int i = 0; i < 4; i++) {
    if((1<<i) & p->features) {
      printf("%s%s",(count)?"|":"",features[i]);
      count++;
    }
  }
  printf("\n");
  len--;
  for(int element = 0; len > ((void*)e-(void*)p); element++) {
    printf("    Element %d: Loc:%x\n      NumS:%x: ",element,e->loc,e->nums);
    for(int i = 0; i < e->nums; i++) {
      printf("%s%04x",(i)?",":"",*(uint16_t*)((void*)e + 4 + 2*i));
    }
    printf("\n      NumV:%x\n",e->numv);
    e = (void*)e + 4 + 2*e->nums + 3*e->numv;
  }
}

void decode_access(uint8_t len, uint8_t *data) {
  uint32_t opcode = data[0];
  uint8_t *parameters = data+1;
  len--;
  if(opcode & 0x80) {
    opcode <<= 8;
    opcode |= data[1];
    parameters++;
    len--;
    if(opcode &0x40) {
      opcode <<= 8;
      opcode |= data[2];
      parameters++;
      len--;
    }
  }
  assert(opcode != 0x7f);
  const char *str = mesh_access_lookup(opcode);
  if(NULL == str) str = mesh_model_lookup(opcode);
  printf("Access opcode: %x %s, parameters: %s\n",opcode,str,hex(len,parameters));
  switch(opcode) {
  case 2:
    decode_dcd_status(len,parameters);
    break;
  case 0x8008:
    // TODO send_access("00ff02b0f0341220000300000004000000020003000010");
    break;
  }
}
struct network {
  uint8_t nid;
  uint8_t  ctl, ttl;
  uint32_t seq;
  uint16_t src;
  uint16_t dst;
  uint8_t seg;
};
struct segment_info {
  uint8_t szmic;
  uint16_t seqzero;
  uint8_t sego, segn;
};
struct control_info {
  uint8_t opcode;
};
struct access_info {
  uint8_t akf, aid;
};
struct mesh_message {
  struct network network;
  struct segment_info segment_info;
  union {
    struct control_info control_info;
    struct access_info access_info;
  } lower;
};

int encrypt(uint8_t len, uint8_t *pdu);
uint32_t txseq = 0x10000;
void send_transport_pdu(struct mesh_message *message, uint8_t len, uint8_t *data, uint16_t dst, uint16_t src) {
  uint8_t pdu[31] = {message->network.nid, 0x80|5,};
  memcpy(&pdu[2],beuint24(txseq),3);
  memcpy(&pdu[5],beuint16(src),2);
  memcpy(&pdu[7],beuint16(dst),2);
  memcpy(&pdu[9],data,len);
  encrypt(len+9+8, pdu);
#ifdef TEST_PROTOCOL
  uint8_t dummy[31];
  memcpy(dummy,pdu,len+9+8);
  decode_network_pdu(len+9+8, dummy);
#endif
  send_proxy_pdu(0,len+9+8,pdu);
}

void send_unsegmented_control(struct mesh_message *message, uint8_t opcode, uint8_t len, uint8_t *data, uint16_t dst, uint16_t src) {
  uint8_t pdu[31] = { opcode, };
  memcpy(&pdu[1],data,len);
  send_transport_pdu(message,len+1,pdu,dst,src);
}

void send_segment_acknowledge(struct mesh_message *message) {
  uint16_t seqzero = message->network.seq & ((1 << 13)-1);
  if(message->network.seg) seqzero = message->segment_info.seqzero;
  uint32_t blockack = (1<<(1+message->segment_info.segn))-1;
  printf("BlockAck: %04x--------------------\n",blockack);
  uint8_t pdu[6] = {(seqzero >> 6) & 0x7f, (seqzero << 2), };
  memcpy(&pdu[2],beuint32(blockack),4);
  printf("Segment Ack: %s\n",hex(6,pdu));
  send_unsegmented_control(message,0,6,pdu,message->network.src,message->network.dst);
}

void decode_upper_transport_access_pdu(struct mesh_message *message, uint8_t len, uint8_t *data) {
  uint8_t szmic = (message->network.seg)?message->segment_info.szmic:0;
  uint32_t seq = message->network.seq;
  if(message->network.seg) {
    int delta = (seq & ((1<<13)-1)) - message->segment_info.seqzero;
    seq -= delta;
  }
  len = upper_decrypt(len,data,szmic,seq,message->network.src,message->network.dst,message->network.nid,message->lower.access_info.akf,message->lower.access_info.aid);
  if(!len) {
    struct network *n = &message->network;
    printf("decode_upper_transport_access_pdu(%s)\n",hex(len,data));
    printf("Message info: NID:%02x, CTL:%d, TTL:%x, SEQ:%06x, SRC:%04x, DST:%04x, SEG:%d\n",
	   n->nid,n->ctl,n->ttl,n->seq,n->src,n->dst,n->seg);
    return;
  }
  decode_access(len,data);
}

void decode_upper_transport_control_pdu(struct mesh_message *message, uint8_t len, uint8_t *data) {
  printf("decode_upper_transport_control_pdu(opcode:%x, %s)\n",
	 message->lower.control_info.opcode, hex(len,data));
  assert(message->lower.control_info.opcode > 0);
  assert(message->lower.control_info.opcode < 0xb);
}

void decode_lower_transport_pdu(struct mesh_message *message, uint8_t len, uint8_t *data) {
  struct network *n = &message->network;
  struct segment_info *s = &message->segment_info;
  struct control_info *c = &message->lower.control_info;
  struct access_info *a = &message->lower.access_info;
  struct segment_data sdata = { .src = n->src, };
  struct segmented *rc = NULL;
  printf("decode_lower_transport_pdu(NID:%x, CTL:%d TTL:%d, SEQ:%06x, SRC:%04x, DST:%04x, data:%s)\n",n->nid,n->ctl,n->ttl,n->seq,n->src,n->dst,hex(len,data));
  n->seg = data[0] >> 7;
  if(n->ctl) {
    c->opcode = data[0] & 0x7f;
  } else {
    a->akf = (data[0] >> 6) & 1;
    a->aid = data[0] & 0x3f;
  }
  if(n->seg) {
    s->szmic = data[1] >> 7;
    s->seqzero = ((data[1] & 0x7f) << 6) | (data[2] >> 2);
    s->sego = ((data[2] & 3) << 3) | (data[3] >> 5);
    s->segn = data[3] & 0x1f;
    if(s->segn > 0) {
      sdata.size = 12;
      sdata.len = len - 4;
      sdata.seq = s->seqzero;
      sdata.data = data + 4;
      sdata.offset = s->sego;
      sdata.last = s->segn;
      rc = new_segment(&sdata);
      if(!rc) return;
    }
    send_segment_acknowledge(message);
  }
  if(n->seg) {
    if(n->ctl) {
      s->szmic = 0;
      printf("Segmented Control message:: SZMIC:%d, SeqZero:%x, SegO:%d, SegN:%d, Opcode:%d\n",
	     s->szmic,s->seqzero,s->sego,s->segn,c->opcode);
      if(rc) {
	decode_upper_transport_control_pdu(message, rc->len,rc->data);
	rc->clear(rc);
      } else {
	decode_upper_transport_control_pdu(message,len-4,data+4);	
      }
    } else {
      printf("Segmented Access message:: AKF:%d, AID:%02x\n",a->akf,a->aid);
      if(rc) {
	decode_upper_transport_access_pdu(message, rc->len,rc->data);
	rc->clear(rc);
      } else {
	decode_upper_transport_access_pdu(message,len-4,data+4);	
      }
    }
  } else {
    if(n->ctl) {
      if(0 == c->opcode) {
	assert((len == 7)||(printf("len: %d\n",len) == -1));
	uint8_t obo = data[1] >> 7;
	uint16_t seqzero = ((data[1] & 0x7f) << 5) | (data[2] >> 2);
	uint32_t blockack = be2uint32(&data[3]);
	printf("Segment Acknowledgement: OBO:%d, SeqZero:%x, BlockAck:%08x\n",obo,seqzero,blockack);
	return;
      }
      printf("Unsegmented Control Message:: opcode:%d\n",c->opcode);
      decode_upper_transport_control_pdu(message,len-1,data+1);
    } else {
      printf("Unsegmented Access message:: AKF:%d, AID:%02x\n",a->akf,a->aid);
      decode_upper_transport_access_pdu(message,len-1,data+1);	
    }
  }
}

void decode_network_pdu(uint8_t len, uint8_t *data) {
  //printf("decode_network_pdu(%s)\n",hex(len,data));
  len = decrypt(len,data);
  if(!len) return;
  struct mesh_message info;
  struct network *p = &info.network;
  //printf(" after decryption: %s\n",hex(len,data));
  p->nid = data[0] & 0x7f;
  p->ctl = data[1]>>7, p->ttl = data[1]&0x7f;
  p->seq = be2uint24(&data[2]);
  p->src = be2uint16(&data[5]);
  p->dst = be2uint16(&data[7]);
  decode_lower_transport_pdu(&info,len-9,data+9);
}

void decode_pdu(uint8_t message_type, uint8_t len, uint8_t *data) {
  switch(message_type) {
  case 0:
    decode_network_pdu(len,data);
    break;
  case 1:
    printf("Unhandled beacon\n");
    break;
  case 3:
    decode_provisioning_pdu(len,data);
    break;
  default:
    printf("Unhandled message type, %d\n",message_type);
    //gecko_cmd_system_reset(0);
    exit(1);
  }    
}

void decode_proxy_pdu(uint8_t len, uint8_t *data) {
  uint8_t sar = data[0] >> 6;
  uint8_t message_type = data[0] & 0x3f;
  switch(sar) {
  case 0:
    decode_pdu(message_type,len-1,data+1);
    break;
  default:
    printf("Unhandled sar, %d\n",sar);
    //gecko_cmd_system_reset(0);
    exit(1);
  }
}

#ifdef TEST_PROTOCOL
int main(int argc, char* argv[]) {
  uint8_t netkey[16], devkey[16];
  uint32_t ivi = 0;
  hex2bin("6D36686F8D85DB35D73D8D0AC2C3551A",netkey);
  hex2bin("89875D5D2545A7744C4299C65CE79371",devkey);
  add_netkey(netkey,ivi);
  add_devkey(devkey,0x2008);
  FILE *fh = fopen("gatt-log.txt","r");
  size_t size;
  fseek(fh,0,SEEK_END);
  size = ftell(fh);
  fseek(fh,0,SEEK_SET);
  char *text = malloc(size);
  fread(text,size,1,fh);
  fclose(fh);
  char *sptr = text;
  char *last, *last2;
  uint8_t packet[256];
  do {
    char *line = strtok_r(sptr,"\n",&last);
    sptr = NULL;
    if(!line) break;
    if(line) {
      int c;
      char *t = strtok_r(line,":",&last2);
      //printf("t(characteristic):%s\n",t);
      sscanf(t,"%d",&c);
      t = strtok_r(NULL,":",&last2);
      //printf("t(hexstr):%s\n",t);
      int len = strlen(t) >> 1;
      hex2bin(t,packet);
      if((19 == c)||(25 == c)) {
	printf(" SIMULATED IN: %s\n",hex(len,packet));
      } else {
	printf("OBSERVED OUT: %s\n",hex(len,packet));
      }
      decode_proxy_pdu(len,packet);
    }
  } while(1);
  //printf("%s",text);
}
#endif
