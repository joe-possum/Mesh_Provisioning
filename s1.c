#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mbedtls/md5.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/ccm.h>
#include <assert.h>
#include "utility.h"
#include "s1.h"

#ifdef TEST_S1
int main(int argc, char *argv[]) {
  assert((2 == argc) || ("s1 <m>" == NULL));
  int mlen = strlen(argv[1]);
  assert(0 == (mlen & 1));
  mlen >>= 1;
  uint8_t *M, result[16];
  assert((M = malloc(mlen)));
  assert(!hex2bin(argv[1],M));
  s1(mlen,M,result);
  return 0;
}
#endif

int s1(int len, uint8_t m[], uint8_t *result) {
  unsigned char key[16];
  memset(key,0,16);
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  assert((cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB)));
  if(!cipher_info) return 1;
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, key, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, m, len));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,result));
  mbedtls_cipher_free(&ctx);
  return 0;
}
