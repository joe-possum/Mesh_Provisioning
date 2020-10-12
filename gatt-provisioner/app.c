/* standard library headers */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>

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
  mbedtls_ecp_keypair local_kp;
  mbedtls_ecp_point remote_point;
  mbedtls_mpi shared_secret;
  uint32 provisioning_service, state;
  uint16 connection_interval, mtu, provisioning_in, provisioning_out; 
  bd_addr remote;
  uint8 connection;
} config = { .remote = { .addr = {0,0,0,0,0,0}},
	     .connection = 0xff,
	     .state = 0,
	     .provisioning_service = 0,
	     .connection_interval = 80, // 100 ms
	     .mtu = 23,
};
  
static char *hex(uint8 len, const uint8_t *in) {
  static char out[4][256];
  static uint8 index;
  index &= 3;
  for(int i = 0; i < len; i++) sprintf(&out[index][i<<1],"%02x",in[i]);
  return &out[index++][0];
}

const char *getAppOptions(void) {
  return "a<remote-address>n<name>";
}

void appOption(int option, const char *arg) {
  double dv;
  switch(option) {
  case 'a':
    parse_address(arg,&config.remote);
    break;
  case 'i':
    sscanf(arg,"%lf",&dv);
    config.connection_interval = round(dv/1.25);
    break;
  default:
    fprintf(stderr,"Unhandled option '-%c'\n",option);
    exit(1);
  }
}

int myrnd(void*ctx, unsigned char *buf, size_t len) {
  for(size_t i = 0; i < len; i++) {
    buf[i] = rand() >> 1;
  }
  return 0;
}

void appInit(void) {
  for(int i = 0; i < 6; i++) {
    if(config.remote.addr[i]) return;
  }
  printf("Usage: master [ -a <address> ]\n");
  exit(1);
}

void send_proxy_pdu(uint8_t type, uint8_t len, uint8_t *data) {
  if(len < (config.mtu-3)) {
    uint8_t pdu[1+len];
    pdu[0] = type;
    memcpy(&pdu[1],data,len);
    gecko_cmd_gatt_write_characteristic_value_without_response(config.connection,config.provisioning_in,sizeof(pdu),pdu);
  }
}

void send_provisioning_pdu(uint8_t type, uint8_t len, uint8_t *data) {
  uint8_t pdu[1+len];
  pdu[0] = type;
  memcpy(&pdu[1],data,len);
  send_proxy_pdu(3,sizeof(pdu),pdu);
}

void send_provisioning_public_key(void) {
  int rc;
  uint8_t parameters[64];
  mbedtls_ecp_keypair_init(&config.local_kp);
  assert(0 == (rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,&config.local_kp,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_mpi_write_binary(&config.local_kp.Q.X,(unsigned char*)parameters,32)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_mpi_write_binary(&config.local_kp.Q.Y,(unsigned char*)parameters+32,32)) || (-1 == printf("rc = -%x\n",-rc)));
  send_provisioning_pdu(3,sizeof(parameters),parameters);
  assert(0 == (rc = mbedtls_mpi_write_binary(&config.local_kp.d,(unsigned char*)parameters,32)) || (-1 == printf("rc = -%x\n",-rc)));
  printf("Private key: %s\n",hex(32,parameters));  
}

void send_provisioning_start(uint8_t algorithm, uint8_t public_key, uint8_t auth_method, uint8_t auth_action, uint8_t auth_size) {
  printf("send_provisioning_start(algorithm: %x, public_key: %x, auth_method: %x, auth_action: %x, auth_size: %x)\n",
	 algorithm, public_key, auth_method, auth_action, auth_size);
  uint8_t parameters[5] = { algorithm, public_key, auth_method, auth_action, auth_size };
  send_provisioning_pdu(2,sizeof(parameters),parameters);  
}

void send_provisioning_invite(uint8 duration) {
  printf("send_provisioning_invite(duration: %d)\n",duration);
  uint8 parameters[1] = { duration };
  send_provisioning_pdu(0,sizeof(parameters),parameters);
}

void decode_public_key(uint8_t len, uint8_t *data) {
  char xstr[65], ystr[65];
  int rc;
  strncpy(xstr,hex(32,data),64);
  strncpy(ystr,hex(32,&data[32]),64);
  xstr[64] = ystr[64] = 0;
  printf("xstr: %s, ystr: %s\n",xstr, ystr);
  mbedtls_ecp_point_init(&config.remote_point);
  mbedtls_mpi_init(&config.shared_secret);
  assert(0 == (rc = mbedtls_ecp_point_read_string(&config.remote_point, 16, xstr, ystr)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_ecp_check_pubkey(&config.local_kp.grp, &config.remote_point)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_ecdh_compute_shared(&config.local_kp.grp,&config.shared_secret,&config.remote_point,&config.local_kp.d,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
  assert(0 == (rc = mbedtls_mpi_write_binary(&config.shared_secret,(unsigned char*)xstr,32)) || (-1 == printf("rc = -%x\n",-rc)));
  printf("Shared secret: %s\n",hex(32,xstr));
}

void decode_provisioning_capabilities(uint8_t len, uint8_t *data) {
  printf("decode_provisioning_capabilities(%s)\n",hex(len,data));
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
  send_provisioning_start(0, 0, 0, 0, 0);
  send_provisioning_public_key();
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
  case 1:
    decode_provisioning_capabilities(len-1,data+1);
    break;
  case 3:
    decode_public_key(len-1,data+1);
    break;
  default:
    printf("type %d not handled\n", type);
  }    
}

/* from fake */
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
/* from fake */
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
    gecko_cmd_le_gap_connect(config.remote,le_gap_address_type_public,le_gap_phy_1m);
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
    gecko_cmd_gatt_discover_primary_services_by_uuid(ED.connection,2,(uint8*)"\x27\x18");
    break;
#undef ED

  case gecko_evt_gatt_service_id: /********************************************************************************* gatt_service **/
#define ED evt->data.evt_gatt_service
    if((ED.uuid.len = 2)&&!memcmp(&ED.uuid.data[0],"\x27\x18",2)) {
      config.provisioning_service = ED.service;
    }
    break;
#undef ED

  case gecko_evt_gatt_characteristic_id: /******************************************************************* gatt_characteristic **/
#define ED evt->data.evt_gatt_characteristic
    if((2 == ED.uuid.len) && (0x2a == ED.uuid.data[1])) {
      switch(ED.uuid.data[0]) {
      case 0xdb:
	config.provisioning_in = ED.characteristic;
	break;
      case 0xdc:
	config.provisioning_out = ED.characteristic;
	break;
      default:
	printf("Unexpected UUID: 0x2a%02x\n",ED.uuid.data[0]);
      }
    }
    break;
#undef ED

  case gecko_evt_gatt_procedure_completed_id: /********************************************************* gatt_procedure_completed **/
#define ED evt->data.evt_gatt_procedure_completed
    switch(config.state) {
    case 0:
      if(!config.provisioning_service) {
	printf("Provisioning service not found\n");
	gecko_cmd_le_connection_close(ED.connection);
	break;
      }
      gecko_cmd_gatt_discover_characteristics(ED.connection,config.provisioning_service);
      config.state = 1;
      break;
    case 1:
      if(!config.provisioning_in || !config.provisioning_out) {
	printf("Incomplete provisioning characteristics\n");
	gecko_cmd_le_connection_close(ED.connection);
	break;
      }
      gecko_cmd_gatt_set_characteristic_notification(ED.connection,config.provisioning_out,1);
      config.state = 2;
      break;
    case 2:
      send_provisioning_invite(0);
      break;
    }
    break;
#undef ED

  case gecko_evt_gatt_characteristic_value_id: /******************************************************* gatt_characteristic_value **/
#define ED evt->data.evt_gatt_characteristic_value
    if(ED.characteristic == config.provisioning_out) {
      decode_proxy_pdu(ED.value.len,&ED.value.data[0]);
    }
    break;
#undef ED

  case gecko_evt_le_connection_closed_id: /***************************************************************** le_connection_closed **/
#define ED evt->data.evt_le_connection_closed
    exit(1);
    break;
#undef ED

  default:
    break;
  }
}
