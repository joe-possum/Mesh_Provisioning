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
#include "k3.h"

#ifdef TEST_K3
#define VERBOSE_K3
int main(int argc, char *argv[]) {
  assert((2 == argc) || ("k3 <n>" == NULL));
  int nlen = strlen(argv[1]);
  assert(0 == (nlen & 1));
  nlen >>= 1;
  uint8_t *N, result[16];
  assert((N = malloc(nlen)));
  assert(!hex2bin(argv[1],N));
  k3(nlen,N,result);
  return 0;
}
#endif

int k3(const int nlen, const uint8_t *n, uint8_t *result) {
#ifdef VERBOSE_K3
  printf("k1(n: %s)\n", hex(nlen,n));
#endif
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  uint8_t salt[16], T[16], T1[16];
  s1(4,(uint8_t*)"smk3",salt);
#ifdef VERBOSE_K3
  printf("  salt: %s\n",hex(16,salt));
#endif
  assert(cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB));
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, salt, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, n, nlen));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,T));  
#ifdef VERBOSE_K3
  printf("     T: %s\n",hex(16,T));
#endif
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, T, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, (uint8_t*)"id64\x01", 5));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,T1));
#ifdef VERBOSE_K3
  printf("    T1: %s\n",hex(16,T1));
#endif
  memcpy(result,T1+8,8);
#ifdef VERBOSE_K3
  printf("result: %s\n",hex(8,result));
#endif  
  return 0;
}
