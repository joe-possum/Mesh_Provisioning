/* standard library headers */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
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
#include "../protocol.h"

// App booted flag
static bool appBooted = false;

static struct {
  uint32 advertising_interval;
  uint16 mtu;
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

void appInit(void) {
  memcpy(&unprovisioned_gatt_adv[11],config.uuid,16);
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
    set_connection(ED.connection);
    break;
#undef ED

  case gecko_evt_gatt_mtu_exchanged_id: /********************************************************************* gatt_mtu_exchanged **/
#define ED evt->data.evt_gatt_mtu_exchanged
    config.mtu = ED.mtu;
    set_mtu(ED.mtu);
    break;
#undef ED

  case gecko_evt_le_connection_closed_id: /***************************************************************** le_connection_closed **/
#define ED evt->data.evt_le_connection_closed
    gecko_cmd_le_gap_start_advertising(0,le_gap_user_data,le_gap_connectable_scannable);
    //gecko_cmd_le_gap_start_discovery(le_gap_phy_1m, le_gap_discover_observation);
    break;
#undef ED

  case gecko_evt_gatt_server_user_write_request_id: /********************************************* gatt_server_user_write_request **/
#define ED evt->data.evt_gatt_server_user_write_request
    switch(ED.characteristic) {
    case gattdb_provisioning_in:
    case gattdb_proxy_in:
      decode_proxy_pdu(ED.value.len,&ED.value.data[0]);
      break;
    }
    break;
#undef ED

  default:
    break;
  }
}
