/* standard library headers */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <sys/time.h>
#include <assert.h>

/* BG stack headers */
#include "bg_types.h"
#include "gecko_bglib.h"

/* Own header */
#include "app.h"
#include "dump.h"
#include "support.h"
#include "common.h"

// App booted flag
static bool appBooted = false;
static struct {
  char *name;
  uint32 advertising_interval;
  uint16 connection_interval, mtu; 
  bd_addr remote;
  uint8 advertise, connection;
} config = { .remote = { .addr = {0,0,0,0,0,0}},
	     .connection = 0xff,
	     .advertise = 1,
	     .name = NULL,
	     .advertising_interval = 160, // 100 ms
	     .connection_interval = 80, // 100 ms
	     .mtu = 23,
};
  
const char *getAppOptions(void) {
  return "a<remote-address>n<name>";
}

void appOption(int option, const char *arg) {
  double dv;
  switch(option) {
  case 'a':
    parse_address(arg,&config.remote);
    config.advertise = 0;
    break;
  case 'i':
    sscanf(arg,"%lf",&dv);
    config.advertising_interval = round(dv/0.625);
    config.connection_interval = round(dv/1.25);
    break;
  case 'n':
    config.name = strdup(arg);
    break;
  default:
    fprintf(stderr,"Unhandled option '-%c'\n",option);
    exit(1);
  }
}

void appInit(void) {
  if(config.advertise) return;
  for(int i = 0; i < 6; i++) {
    if(config.remote.addr[i]) return;
  }
  printf("Usage: master [ -a <address> ]\n");
  exit(1);
}

struct links {
  struct links *next;
  uint8 uuid[16];
  uint8 state;
  uint32 linkid;
  uint8_t transaction;
  struct timeval action;
} *links = NULL;
uint8 busy = 0;

void send_pbadv(uint32 linkid,uint8 transaction, uint8 len, uint8 *pdu) {
  uint8 data[31];
  data[0] = 6+len;
  data[1] = 0x29;
  for(int i = 0; i < 4; i++) {
    data[5-i] = linkid & 0xff;
    linkid >>= 8;
  }
  data[6] = transaction;
  memcpy(&data[7],pdu,len);
  gecko_cmd_le_gap_bt5_set_adv_data(0, 0, 7+len, data);
  gecko_cmd_le_gap_set_advertise_timing(0,50,50,0,1);
  gecko_cmd_le_gap_start_advertising(0,le_gap_user_data,le_gap_non_connectable);
}

struct links *get_next(void) {
  struct timeval now, delta;
  gettimeofday(&now,NULL);
  for(struct links *p = links; p; p = p->next) {
    timersub(&now,&p->action,&delta);
    if(delta.tv_sec >= 0) return p;
  }
  return NULL;
}

struct links *find_linkid(const uint32_t linkid) {
  for(struct links *p = links; p; p = p->next) {
    if(linkid == p->linkid) {
      printf("Found %x at %p\n",linkid,p);
      return p;
    }
  }
  return NULL;
}

void send_next(uint8 timeout) {
  uint8 data[31];
  if(timeout) busy = 0;
  if(busy) return;
  struct links *current = get_next();
  if(!current) return;
  struct timeval now, delta;
  gettimeofday(&now,NULL);
  switch(current->state) {
  case 0:
  case 1:
    data[0] = 3;
    memcpy(&data[1],links->uuid,16);
    send_pbadv(current->linkid,0,17,data);
    current->state = 1;
    delta.tv_sec = 5;
    delta.tv_usec = 0;
    timeradd(&now,&delta,&current->action);
    current->state = 1;
    busy = 1;
    break;
  }
}

static char *hex(uint8 len, const uint8_t *in) {
  static char out[4][256];
  static uint8 index;
  index &= 3;
  for(int i = 0; i < len; i++) sprintf(&out[index][i<<1],"%02x",in[i]);
  return &out[index++][0];
}

void provision(uint8 *uuid) {
  for(struct links *p = links; p; p = p->next) {
    if(0 == memcmp(uuid,p->uuid,16)) return;
  }
  printf("Opening link to %s\n",hex(16,uuid));
  struct links *n = malloc(sizeof(struct links));
  n->next = links;
  memcpy(n->uuid,uuid,16);
  n->state = 0;
  n->linkid = rand();
  gettimeofday(&n->action,NULL);
  n->transaction = 0;
  links = n;
  if(!busy) send_next(0);
}

void send_provisioning_bearer_control(uint32_t linkid, uint8 transaction, uint8_t opcode, uint8_t len, uint8_t *data) {
  uint8_t pdu[31];
  pdu[0] = 3 | (opcode << 2);
  memcpy(&pdu[1],data,len);
  send_pbadv(linkid,transaction,len+1,pdu);
}

void send_link_close(uint32_t linkid, uint8_t transaction, uint8_t reason) {
  send_provisioning_bearer_control(linkid,transaction,2,1,&reason);
}

#define RETURN(...) do { printf(__VA_ARGS__); return; } while(0)

void send_transaction_start(uint32 linkid, uint8 transaction, uint8 segn, uint8 len, uint8 *data, uint8 fcs) {
  uint8 pdu[31] = { segn << 2, 0, len, fcs, };
  memcpy(&pdu[4],data,len);
  send_pbadv(linkid,transaction,4+len,pdu);
}

void send_transaction_ack(uint32 linkid, uint8 transaction) {
  uint8 pdu[1] = { 1 };
  send_pbadv(linkid,transaction,1,pdu);
}

void send_provisioning_invite(struct links *p, uint8 duration) {
  printf("send_provisioning_invite(p->linkid: %x, duration: %d)\n",p->linkid,duration);
  uint8 pdu[2] = { 0, duration };
  gettimeofday(&p->action,NULL);
  p->state = 2;
  send_transaction_start(p->linkid, p->transaction, 0, 2, pdu, calculate_fcs(2,pdu));
}

void handle_link_open(struct links *p) {
  printf("Link %d open\n",p->linkid);
  send_provisioning_invite(p,0);
}

void decode_providioning_bearer_control(uint32_t linkid,uint8_t transaction, uint8_t opcode,uint8_t len, uint8_t *data) {
  printf("decode_provisioning_bearer_control(linkid: %x, transaction: %x, opcode: %x, data: %s)\n",linkid,transaction,opcode,hex(len,data));
  struct links *p = find_linkid(linkid);
  switch(opcode) {
  case 0:
    printf("  Link Open\n");
    break;
  case 1:
    if(!p) RETURN("Link Open linkid, %d, not found\n",linkid);
    if(0 != len) RETURN("Link Open len, %d, != 0\n",len);
    if(0 != transaction) RETURN("Link Open transaction, %d, != 0\n",transaction);
    handle_link_open(p);
    break;
  default:
    printf("  Unhandled opcode %x\n",opcode);
    exit(1);
  }
}

void decode_provisioning_capabilities(struct links *p, uint8_t len, uint8_t *data) {
  printf("decode_provisioning_capabilities(p,%s)\n",hex(len,data));
  assert(11 == len);
  uint8 elements = data[0];
  uint16 algorithms = (data[1] << 8) | data[2];
  uint8 pktype = data[3];
  uint8 soobtype = data[4];
  uint8 ooobsize = data[5];
  uint16 ooobaction = (data[6] << 8) | data[7];
  uint8 ioobsize = data[8];
  uint16 ioobaction = (data[9] << 8) | data[10];
  printf("  %d elements\n",elements);
}

void decode_provisioning_pdu(struct links *p, uint8_t len, uint8_t *data) {
  uint8 padding = data[0] >> 6;
  uint8 type = data[0] & 0x3f;
  if(0 != padding) {
    printf("Provisioning PDU padding is non-zero\n");
    gecko_cmd_system_reset(0);
    exit(1);
  }
  if(type > 9) {
    printf("Provisioning PDU types greater than 9 are reserved for future use\n");
    gecko_cmd_system_reset(0);
    exit(1);
  }
  char *typestr[10] = { "Provisioning Invite","Provisioning Capabilities","Provisioning Start",
			"Provisioning Public Key","Provisioning Input Complete","Provisioning Confirmation",
			"Provisioning Random","Provisioning Data","Provisioning Complete","Provisioning Failed"};
  printf("Provisioning PDU: %s, data: %s\n",typestr[type],hex(len-1,data+1));
  switch(type) {
  case 0:
    printf("We do the invites!\n");
    exit(1);
    break;
  case 1:
    decode_provisioning_capabilities(p,len-1,data+1);
    break;
  }    
}

void decode_transaction_start(uint32 linkid,uint8 transaction,uint8 segn,uint8 len,uint8*data) {
  printf("decode_transaction_start(linkid: %x, transaction: %x, segn: %x, data: %s\n",linkid,transaction,segn,hex(len,data));
  struct links *p = find_linkid(linkid);
  if(!p) RETURN("linkid %x not found\n",linkid);
  if(0 == segn) {
    send_transaction_ack(linkid,transaction);
    decode_provisioning_pdu(p,len-3,data+3);
  }
  p->state++;
}

void decode_generic_provisioning_pdu(uint32_t linkid,uint8_t transaction,uint8_t len, uint8_t *data) {
  uint8_t gpcf = data[0] & 3;
  printf("decode_generic_provisioning_pdu(linkid: %x, transaction: %x, data: %s)\n",linkid,transaction,hex(len,data));
  switch(gpcf) {
  case 0:
    decode_transaction_start(linkid,transaction,data[0]>>2,len-1,data+1);
    break;
  case 1:
    printf("Acknowledgement for transaction %x:%x\n",linkid,transaction);
    break;
  case 3:
    decode_providioning_bearer_control(linkid,transaction,data[0]>>2,len-1,data+1);
    break;
  default:
    printf("Unhandled gpcf, %d, , data: %s\n",gpcf, hex(len,data));
  }
}

void decode_pbadv(uint8 len, uint8 *data) {
  uint32_t linkid = 0;
  for(int i = 0; i < 4; i++) {
    linkid <<= 8;
    linkid += data[i];
  }
  uint8_t transaction = data[4];
  printf("decode_pbadv(%s): linkid: %x, transaction %x\n",hex(len,data),linkid,transaction);
  decode_generic_provisioning_pdu(linkid,transaction,len-5,data+5);
}

void process_packet(uint8 len, uint8 *data) {
  switch(data[1]) {
  case 0x2b:
    provision(&data[3]);
    break;
  case 0x29:
    decode_pbadv(len-2,data+2);
    break;
  }
}

/***********************************************************************************************//**
 *  \brief  Event handler function.
 *  \param[in] evt Event pointer.
 **************************************************************************************************/
void appHandleEvents(struct gecko_cmd_packet *evt)
{
  if (NULL == evt) {
    return;
  }

  // Do not handle any events until system is booted up properly.
  if ((BGLIB_MSG_ID(evt->header) != gecko_evt_system_boot_id)
      && !appBooted) {
#if defined(DEBUG)
    printf("Event: 0x%04x\n", BGLIB_MSG_ID(evt->header));
#endif
    millisleep(50);
    return;
  }

  /* Handle events */
#ifdef DUMP
  switch (BGLIB_MSG_ID(evt->header)) {
  case gecko_evt_le_gap_scan_response_id: /***************************************************************** le_gap_scan_response **/
    break;
  default:
    dump_event(evt);
  }
#endif
  switch (BGLIB_MSG_ID(evt->header)) {
  case gecko_evt_system_boot_id: /*********************************************************************************** system_boot **/
#define ED evt->data.evt_system_boot
    appBooted = true;
    gecko_cmd_le_gap_start_discovery(le_gap_phy_1m,le_gap_discover_observation);
    break;
#undef ED

  case gecko_evt_le_gap_scan_response_id: /***************************************************************** le_gap_scan_response **/
#define ED evt->data.evt_le_gap_scan_response
    if(3 != ED.packet_type) break;
    process_packet(ED.data.len, &ED.data.data[0]);
    break;
#undef ED

  case gecko_evt_le_gap_adv_timeout_id: /********************************************************************* le_gap_adv_timeout **/
#define ED evt->data.evt_le_gap_adv_timeout
    send_next(1);
    break;
#undef ED

  default:
    break;
  }
}
