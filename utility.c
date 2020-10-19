#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utility.h"

int myrnd(void*ctx, unsigned char *buf, size_t len) {
  for(size_t i = 0; i < len; i++) {
    buf[i] = rand();
  }
  return 0;
}

char *hex(uint8_t len, const uint8_t *in) {
  static char out[16][256];
  static uint8_t index;
  index &= 15;
  for(int i = 0; i < len; i++) sprintf(&out[index][i<<1],"%02x",in[i]);
  return &out[index++][0];
}

int hex2bin(const char*hex, uint8_t*bin) {
  char buf[3];
  unsigned int v;
  size_t count = strlen(hex) >> 1;
  for(int i = 0; i < count; i++) {
    strncpy(buf,&hex[i<<1],2);
    if(1 != sscanf(buf,"%x",&v)) return 1;
    bin[i] = v;
  }
  return 0;
}

uint32_t be2uint32(const uint8_t *be) {
  uint32_t rc = 0;
  for(int i = 0; i < 4; i++) {
    rc <<= 8;
    rc |= be[i];
  }
  return rc;
}

uint32_t be2uint24(const uint8_t *be) {
  uint32_t rc = 0;
  for(int i = 0; i < 3; i++) {
    rc <<= 8;
    rc |= be[i];
  }
  return rc;
}

uint16_t be2uint16(const uint8_t *be) {
  uint32_t rc = 0;
  for(int i = 0; i < 2; i++) {
    rc <<= 8;
    rc |= be[i];
  }
  return rc;
}

uint8_t *beuint32(uint32_t value) {
  static uint8_t be[4];
  for(int i = 0; i < 4; i++) {
    be[3-i] = value & 0xff;
    value >>= 8;
  }
  return be;
}

uint8_t *beuint24(uint32_t value) {
  static uint8_t be[3];
  for(int i = 0; i < 3; i++) {
    be[2-i] = value & 0xff;
    value >>= 8;
  }
  return be;
}

uint8_t *beuint16(uint16_t value) {
  static uint8_t be[2];
  for(int i = 0; i < 2; i++) {
    be[1-i] = value & 0xff;
    value >>= 8;
  }
  return be;
}
