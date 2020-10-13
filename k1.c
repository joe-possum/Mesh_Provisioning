#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mbedtls/md5.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/ccm.h>
#include <assert.h>
#include "k1.h"

#ifdef TEST
static char *hex(uint8_t len, const uint8_t *in) {
  static char out[4][256];
  static uint8_t index;
  index &= 3;
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

int main(int argc, char *argv[]) {
  assert((4 == argc) || ("k1 <n> <salt:16> <p> " == NULL));
  int nlen = strlen(argv[1]);
  int plen = strlen(argv[3]);
  assert(0 == (nlen & 1));
  assert(0 == (plen & 1));
  assert(32 == strlen(argv[2]));
  nlen >>= 1;
  plen >>= 1;
  uint8_t *N, salt[16], *P, result[16];
  assert((N = malloc(nlen)));
  assert((P = malloc(plen)));
  assert(!hex2bin(argv[1],N));
  assert(!hex2bin(argv[2],salt));
  assert(!hex2bin(argv[3],P));
  k1(nlen,N,salt,plen,P,result);
  return 0;
}
#endif

int k1(const int nlen, const uint8_t *n, const uint8_t *salt, int plen, uint8_t *p, uint8_t *result) {
#ifdef TEST
  printf("k1(n: %s, salt: %s, p: %s)\n", hex(nlen,n), hex(16,salt), hex(plen,p));
#endif
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  uint8_t T[16];
  assert(cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB));
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, salt, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, n, nlen));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,T));  
#ifdef TEST
  printf("     T: %s\n",hex(16,T));
#endif
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, T, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, p, plen));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,result));
#ifdef TEST
  printf("return: %s\n",hex(16,result));
#endif
  return 0;
}
