/* standard library headers */
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
#include "../k1.h"
#include "../s1.h"
#include "../confirmation.h"
#include "../provisioning-data.h"

// App booted flag
static bool appBooted = false;

static struct {
  uint32 advertising_interval;
  uint16 mtu;
  mbedtls_ecdh_context ctx;
  mbedtls_ecp_keypair local_kp;
  mbedtls_ecp_point remote_point;
  uint8 shared_secret[32];
  uint8_t local_random[16], authvalue[16], remote_random[16], remote_confirmation[16];
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
  printf("Private key: %s\n",hex(32,(uint8*)xstr));
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
  uint8_t salt[16];
  struct __attribute__((packed)) {
    uint8_t net_key[16], key_index[2],flags[1], iv_index[4], unicast_address[2];
  } plaintext;
  confirmation_get_salt(salt);
  provisioning_data_init(salt,config.remote_random,config.local_random,config.shared_secret);
  assert(0 == provisioning_data_decrypt(&plaintext,data,data+25));
  printf("    Network Key: %s\n",hex(16,plaintext.net_key));
  printf("      Key Index: %s\n",hex(2,plaintext.key_index));
  printf("          Flags: %s\n",hex(1,plaintext.flags));
  printf("       IV Index: %s\n",hex(4,plaintext.iv_index));
  printf("Unicast Address: %s\n",hex(2,plaintext.unicast_address));
  send_provisioning_complete();
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
    gecko_cmd_le_gap_start_advertising(0,le_gap_user_data,le_gap_connectable_scannable);
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
