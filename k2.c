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
#include "k1.h"
#include "k2.h"

#ifdef TEST_K2
#define VERBOSE_K2 1
int main(int argc, char *argv[]) {
  assert((3 == argc) || ("k2 <n> <p> " == NULL));
  int nlen = strlen(argv[1]);
  int plen = strlen(argv[2]);
  assert(0 == (nlen & 1));
  assert(0 == (plen & 1));
  nlen >>= 1;
  plen >>= 1;
  uint8_t *n, *p, nid[1], ek[16], result[16];
  assert((n = malloc(nlen)));
  assert((p = malloc(plen)));
  assert(!hex2bin(argv[1],n));
  assert(!hex2bin(argv[2],p));
  k2(nlen, n, plen, p, nid, ek, result);
  return 0;
}
#else
#define VERBOSE_K2 0
#endif

int k2(int nlen, const uint8_t *n, int plen, const uint8_t *p, uint8_t *nid, uint8_t *ek, uint8_t *pk) {
  if(VERBOSE_K2)printf("k2(n:%s, p:%s)\n",hex(nlen,n), hex(plen,p));
  uint8_t salt[16];
  if(s1(4,(uint8_t*)"smk2",salt)) {
    fprintf(stderr,"Error in s1\n");
    exit(1);
  }
  if(VERBOSE_K2)printf("  salt: %s\n",hex(16,salt));  
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  uint8_t t[16], t1[16];
  assert(cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB));
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, salt, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, n, nlen));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,t));
  if(VERBOSE_K2)printf("     t: %s\n",hex(16,t));
  uint8_t message[16+plen+1];
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, t, 128));
  memcpy(message,p,plen);
  message[plen] = 1;
  assert(0 == mbedtls_cipher_cmac_update(&ctx, message, plen+1));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,t1));
  if(VERBOSE_K2)printf("    t1: %s\n",hex(16,t1));
  *nid = t1[15] & 0x7f;
  if(VERBOSE_K2)printf("   nid: %s\n",hex(1,nid));
  assert(0 == mbedtls_cipher_cmac_reset(&ctx));
  memcpy(message,t1,16);
  memcpy(message+16,p,plen);
  message[16+plen] = 2;
  assert(0 == mbedtls_cipher_cmac_update(&ctx, message, plen+17));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,ek));
  if(VERBOSE_K2)printf("    ek: %s\n",hex(16,ek));
  assert(0 == mbedtls_cipher_cmac_reset(&ctx));
  memcpy(message,ek,16);
  memcpy(message+16,p,plen);
  message[16+plen] = 3;
  assert(0 == mbedtls_cipher_cmac_update(&ctx, message, plen+17));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,pk));
  if(VERBOSE_K2)printf("    pk: %s\n",hex(16,pk));  
  return 0;
}
