#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mbedtls/md5.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/ccm.h>
#include <assert.h>
#include "s1.h"
#include "k1.h"
#include "provisioning-data.h"

struct __attribute__((packed)) provisioning_data {
  uint8_t confirmation_salt[16], provisioner_random[16], device_random[16], secret[32], provisioning_salt[16], session_key[16], nonce[13], data[25], mac[8];
} provisioning_data;

static char *hex(uint8_t len, const uint8_t *in) {
  static char out[4][256];
  static uint8_t index;
  index &= 3;
  for(int i = 0; i < len; i++) sprintf(&out[index][i<<1],"%02x",in[i]);
  return &out[index++][0];
}

#ifdef TEST_PROVISIONING_DATA
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

int provisioning_data_encrypt(uint8_t*plain, uint8_t*cypher, uint8_t*mic);

int main(int argc, char *argv[]) {
  assert((6 == argc)||(7 == argc) || ("provisioning_data <confirmation-salt> <random-provisioner> <random-device>" == NULL));
#define M(X,Y) assert(((sizeof(provisioning_data.X) << 1) == strlen(argv[Y]))||(-1 == printf("actual %ld\n",strlen(argv[Y]))))
  M(confirmation_salt,1);
  M(provisioner_random,2);
  M(device_random,3);
  M(secret,4);
  M(data,5);
  if(7 == argc)M(mac,6);
#undef M
  struct provisioning_data data;
#define M(X,Y) assert(!hex2bin(argv[Y],data.X))
  M(confirmation_salt,1);
  M(provisioner_random,2);
  M(device_random,3);
  M(secret,4);
  M(data,5);
  if(7 == argc)M(mac,6);
#undef M
  provisioning_data_init(data.confirmation_salt, data.provisioner_random, data.device_random, data.secret);
  if(7 == argc) {
    provisioning_data_decrypt(data.data,data.data,data.mac);
  } else {
    provisioning_data_encrypt(data.data,data.data,data.mac);
  }
  return 0;
}
#endif

int provisioning_data_init(uint8_t*confirmation_salt, uint8_t*provisioner_random, uint8_t*device_random, uint8_t*secret) {
#define M(X) memcpy(provisioning_data.X,X,sizeof(provisioning_data.X))
  M(confirmation_salt);
  M(provisioner_random);
  M(device_random);
  M(secret);
#undef M
#define M(X) printf("%24s: %s\n",#X,hex(sizeof(provisioning_data.X),provisioning_data.X))
  M(confirmation_salt);
  M(provisioner_random);
  M(device_random);
  M(secret);
  s1(48,provisioning_data.confirmation_salt,provisioning_data.provisioning_salt);
  M(provisioning_salt);
  k1(32,provisioning_data.secret,provisioning_data.provisioning_salt,4,(uint8_t*)"prsk",provisioning_data.session_key);
  M(session_key);
  uint8_t t[16];
  k1(32,provisioning_data.secret,provisioning_data.provisioning_salt,4,(uint8_t*)"prsn",t);
  memcpy(provisioning_data.nonce,t+3,13);
  M(nonce);
  return 0;
}

int provisioning_data_encrypt(uint8_t*plain, uint8_t*cipher, uint8_t*mac) {
  int rc;
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  struct provisioning_data *p = &provisioning_data;
  assert((0 == (rc = mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,p->session_key,128)))||(printf("rc = -%x\n",-rc)));
  assert((0 == (rc = mbedtls_ccm_encrypt_and_tag(&ctx,25,p->nonce,13,NULL,0,plain,p->data,p->mac,8)))||(printf("rc = -%x\n",-rc)));
  M(data);
  M(mac);
  memcpy(cipher,p->data,sizeof(p->data));
  memcpy(mac,p->mac,sizeof(p->mac));
  return 0;
}

int provisioning_data_decrypt(uint8_t*plain, uint8_t*cipher, uint8_t*mac) {
  int rc;
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  struct provisioning_data *p = &provisioning_data;
  assert((0 == (rc = mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,p->session_key,128)))||(printf("rc = -%x\n",-rc)));
  assert((0 == (rc = mbedtls_ccm_auth_decrypt(&ctx,25,p->nonce,13,NULL,0,cipher,p->data,mac,8)))||(printf("rc = -%x\n",-rc)));
  M(data);
  memcpy(plain,p->data,sizeof(p->data));
  return 0;
}
#undef M
