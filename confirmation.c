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
#include "confirmation.h"

static char *hex(uint8_t len, const uint8_t *in) {
  static char out[4][256];
  static uint8_t index;
  index &= 3;
  for(int i = 0; i < len; i++) sprintf(&out[index][i<<1],"%02x",in[i]);
  return &out[index++][0];
}

#ifdef TEST
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

int main(int argc, char *argv[]) {
  assert((5 == argc) || ("confirmation-provisioner <ecdh-secret> <confirmation-inputs> <random> <authvalue>" == NULL));
  printf("confirmation-provisioner\n");
  int mlen = strlen(argv[2]);
  assert(64 == strlen(argv[1]));
  assert(32 == strlen(argv[3]));
  assert(32 == strlen(argv[4]));
  assert(0 == (mlen & 1));
  mlen >>= 1;
  uint8_t *message, secret[32], random[16], authvalue[16];
  assert((message = malloc(mlen)));
  assert(!hex2bin(argv[1],secret));
  assert(!hex2bin(argv[2],message));
  assert(!hex2bin(argv[3],random));
  assert(!hex2bin(argv[4],authvalue));
  confirmation(secret, mlen, message, random, authvalue);
  return 0;
}
#endif

int confirmation(uint8_t*secret, int mlen, uint8_t*message, uint8_t*random, uint8_t*authvalue) {
  uint8_t random_authvalue[32], confirmation_salt[16], confirmation_key[16], result[16];
  memcpy(random_authvalue,random,16);
  memcpy(random_authvalue+16,authvalue,16);
  s1(mlen,message,confirmation_salt);
  printf("confirmation_salt: %s\n",hex(16,confirmation_salt));
  k1(32,secret,confirmation_salt,4,(uint8_t*)"prck",confirmation_key);
  printf("confirmation_key: %s\n",hex(16,confirmation_key));
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  assert(cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB));
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, confirmation_key, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, random_authvalue, 32));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,result));
  printf("result: %s\n",hex(16,result));
  mbedtls_cipher_free(&ctx);
  return 0;
}
