/* standard library headers */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

/* BG stack headers */
#include "bg_types.h"
#include "gecko_bglib.h"

/* Own header */
#include "app.h"
#include "dump.h"
#include "support.h"
#include "common.h"
#include "../btmesh-proxy/gatt_db.h"
#include "../provisioner/fcs.h"
#include <mbedtls/ecdh.h>


// App booted flag
static bool appBooted = false;

struct public_key {
  uint8_t x[32], y[32];
};

static struct {
  uint32 advertising_interval;
  uint16 mtu;
  mbedtls_ecdh_context ctx;
  mbedtls_ecp_keypair local_kp;
  mbedtls_ecp_point remote_point;
  uint8 connection, uuid[16], pk_x[32], pk_y[32];
} config = { .uuid = { 0xc0, 0xff,0xee, 0xc0, 0xff,0xee, 0xc0, 0xff,0xee, 0xc0, 0xff,0xee, 0xde, 0xad, 0xbe, 0xef },
	     .advertising_interval = 0x160,
	     .mtu = 23,
};
  
const char *getAppOptions(void) {
  return "i<adv-interval-ms>";
}

void appOption(int option, const char *arg) {
  double dv;
  switch(option) {
  case 'i':
    sscanf(arg,"%lf",&dv);
    config.advertising_interval = round(dv/0.625);
    break;
  default:
    fprintf(stderr,"Unhandled option '-%c'\n",option);
    exit(1);
  }
}

uint8 unprovisioned_gatt_adv[29] = { 0x02,0x01,0x06,// flags
				     0x03,0x03,0x27,0x18, // Provisioning Service
				     0x15,0x16,0x27,0x18, }; // service data header, 16 bytes of uuid follows

int myrnd(void*ctx, unsigned char *buf, size_t len) {
  for(size_t i = 0; i < len; i++) {
    buf[i] = rand();
  }
  return 0;
}

void appInit(void) {
  memcpy(&unprovisioned_gatt_adv[11],config.uuid,16);
}

static char *hex(uint8 len, const uint8_t *in) {
  static char out[4][256];
  static uint8 index;
  index &= 3;
  for(int i = 0; i < len; i++) sprintf(&out[index][i<<1],"%02x",in[i]);
  return &out[index++][0];
}

void send_proxy_pdu(uint8_t type, uint8_t len, uint8_t *data) {
  if(len < (config.mtu-3)) {
    uint8_t pdu[1+len];
    pdu[0] = type;
    memcpy(&pdu[1],data,len);
    gecko_cmd_gatt_server_send_characteristic_notification(config.connection,gattdb_provisioning_out,sizeof(pdu),pdu);
  }
}

void send_provisioning_pdu(uint8_t type, uint8_t len, uint8_t *data) {
  uint8_t pdu[1+len];
  pdu[0] = type;
  memcpy(&pdu[1],data,len);
  send_proxy_pdu(3,sizeof(pdu),pdu);
}

void send_provisioning_capabilities(uint8_t elements) {
  uint8_t parameters[11] = { elements, 0, 1, };
  send_provisioning_pdu(1,sizeof(parameters),parameters);
}

void send_provisioning_public_key(uint8_t *x, uint8_t *y) {
  uint8_t parameters[64];
  memcpy(parameters,x,32);
  memcpy(parameters+32,y,32);
  send_provisioning_pdu(3,sizeof(parameters),parameters);
}

void decode_provisioning_invite(uint8_t len, uint8_t *data) {
  uint8_t attention_timer_seconds = data[0];
  printf("  Attention Timer: %d seconds\n", attention_timer_seconds);
  send_provisioning_capabilities(1);
}

void decode_public_key(uint8_t len, uint8_t *data) {
  char xstr[65], ystr[65];
  int rc;
  strncpy(xstr,hex(32,data),64);
  strncpy(ystr,hex(32,data+32),64);
  xstr[64] = ystr[64] = 0;
  mbedtls_ecp_keypair_init(&config.local_kp);
  mbedtls_ecp_point_init(&config.remote_point);
  assert(0 == (rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,&config.local_kp,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_ecp_point_read_string(&config.remote_point, 16, xstr, ystr)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_ecp_check_pubkey(&config.local_kp.grp, &config.remote_point)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_mpi_write_binary(&config.local_kp.Q.X,(unsigned char*)xstr,32)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_mpi_write_binary(&config.local_kp.Q.Y,(unsigned char*)ystr,32)) || (-1 == printf("rc = -%x\n",-rc)));
  send_provisioning_public_key((uint8_t*)xstr, (uint8_t*)ystr);
}

void decode_provisioning_pdu(uint8_t len, uint8_t *data) {
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
    decode_provisioning_invite(len-1,data+1);
    break;
  case 3:
    decode_public_key(len-1,data+1);
    break;
  }    
}

void decode_pdu(uint8 message_type, uint8_t len, uint8_t *data) {
  switch(message_type) {
  case 3:
    decode_provisioning_pdu(len,data);
    break;
  default:
    printf("Unhandled message type, %d\n",message_type);
    gecko_cmd_system_reset(0);
    exit(1);
  }    
}

void decode_proxy_pdu(uint8 len, uint8 *data) {
  uint8_t sar = data[0] >> 6;
  uint8_t message_type = data[0] & 0x3f;
  switch(sar) {
  case 0:
    decode_pdu(message_type,len-1,data+1);
    break;
  default:
    printf("Unhandled sar, %d\n",sar);
    gecko_cmd_system_reset(0);
    exit(1);
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
  default:
    dump_event(evt);
  }
#endif
  switch (BGLIB_MSG_ID(evt->header)) {
  case gecko_evt_system_boot_id: /*********************************************************************************** system_boot **/
#define ED evt->data.evt_system_boot
    appBooted = true;
    gecko_cmd_le_gap_bt5_set_adv_data(0,0,sizeof(unprovisioned_gatt_adv),unprovisioned_gatt_adv);
    gecko_cmd_le_gap_set_advertise_timing(0,config.advertising_interval,config.advertising_interval,0,0);
    gecko_cmd_le_gap_start_advertising(0,le_gap_user_data,le_gap_connectable_scannable);
    break;
#undef ED

  case gecko_evt_le_connection_opened_id: /***************************************************************** le_connection_opened **/
#define ED evt->data.evt_le_connection_opened
    config.connection = ED.connection;
    break;
#undef ED

  case gecko_evt_gatt_mtu_exchanged_id: /********************************************************************* gatt_mtu_exchanged **/
#define ED evt->data.evt_gatt_mtu_exchanged
    config.mtu = ED.mtu;
    break;
#undef ED

  case gecko_evt_le_connection_closed_id: /***************************************************************** le_connection_closed **/
#define ED evt->data.evt_le_connection_closed
    exit(1);
    break;
#undef ED

  case gecko_evt_gatt_server_user_write_request_id: /********************************************* gatt_server_user_write_request **/
#define ED evt->data.evt_gatt_server_user_write_request
    switch(ED.characteristic) {
    case gattdb_provisioning_in:
      decode_proxy_pdu(ED.value.len,&ED.value.data[0]);
      break;
    }
    break;
#undef ED

  default:
    break;
  }
}
