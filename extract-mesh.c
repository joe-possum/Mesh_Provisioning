#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

/* BG stack headers */
#include "bg_types.h"
#include "gecko_bglib.h"

int dump_element(uint8 type,uint8 len, uint8*data) {
  switch(type) {
  case 0x01:
    break;
  case 0x02:
    break;
  case 0x03:
    break;
  case 0x06:
    break;
  case 0x07:
    break;
  case 0x08:
    break;
  case 0x09:
    break;
  case 0x0a:
    break;
  case 0x12:
    break;
  case 0x16:
    break;
  case 0x19:
    break;
  case 0x1b:
    break;
  case 0x21:
    break;
  case 0x29:
    return 1; //dump_pbadv(len,data);
    break;
  case 0x2a:
    return 1; //dump_mesh_message(len,data);
    break;
  case 0x2b:
    return 1; //dump_mesh_beacon(len,data);
    break;
  case 0xff:
    break;
  default:
    printf("Unhandled advertising element: type: %02x, len: %d\n",type,len);
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

int main(int argc, char *argv[]) {
  if(isatty(0) || isatty(1)) {
    printf("This program extracts mesh data from bg-ncp-dump-advertisement -L logs\n");
    printf("Usage extract-mesh < {verbose-log} > {only-mesh-log}\n");
    return 1;
  }
  //  FILE *fh = fopen("t","r");
  //FILE *fho = fopen("mesh.log","w");
  uint8_t buf[512];
  uint8_t ss = sizeof(struct gecko_msg_le_gap_extended_scan_response_evt_t);
  struct gecko_msg_le_gap_extended_scan_response_evt_t *resp = (struct gecko_msg_le_gap_extended_scan_response_evt_t *)&buf[0];
  while(1) {
    if(1 != fread(buf,ss,1,stdin)) return 0;
    assert((1 == fread(buf+ss,resp->data.len,1,stdin)));
    if(dump_advertisement(resp->data.len,resp->data.data)) {
      fwrite(buf,ss+resp->data.len,1,stdout);
      fflush(stdout);
    }
  }
  return 0;
}
