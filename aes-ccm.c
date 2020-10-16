#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <mbedtls/aes.h>
#include <mbedtls/ccm.h>
#include "utility.h"

#ifdef TEST_AES_CCM
#define VERBOSE_AES_CCM 1
int main(int argc, char *argv[]) {
  assert((6 == argc) || (5 == argc) || ("aes-ccm -e <key> <nonce> <payload> || aes-ccm -d <key> <nonce> <payload> <mic>" == NULL));
  assert(2 == strlen(argv[1]));
  assert('-' == argv[1][0]);
  assert(('d'+6) == (argv[1][1] + argc));
  assert(32 == strlen(argv[2]));
  assert(26 == strlen(argv[3]));
  int plen = strlen(argv[4]);
  assert(0 == (plen & 1));
  plen >>= 1;
  uint8_t key[16],nonce[13], mac[4], *payload, *ciphertext;
  assert((payload = malloc(plen)));
  assert((ciphertext = malloc(plen)));
  assert(!hex2bin(argv[2],key));
  assert(!hex2bin(argv[3],nonce));
  assert(!hex2bin(argv[4],payload));
  if('d' == argv[1][1]) assert(!hex2bin(argv[5],mac));
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  assert(0 == mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,key,128));
  int rc;
  if('e' == argv[1][1]) {
    assert(0 == (rc =  mbedtls_ccm_encrypt_and_tag(&ctx,plen,nonce,13,NULL,0,payload,ciphertext,mac,4)) || (printf("rc: -%x\n",-rc) == -1));
  } else {
    assert(0 == (rc =  mbedtls_ccm_auth_decrypt(&ctx,plen,nonce,13,NULL,0,payload,ciphertext,mac,4)) || (printf("rc: -%x\n",-rc) == -1));
  }
  printf("       key: %s\n",hex(16,key));
  printf("     nonce: %s\n",hex(13,nonce));
  printf("   payload: %s\n",hex(plen,payload));
  printf("ciphertext: %s\n",hex(plen,ciphertext));
  printf("       mac: %s\n",hex(4,mac));
  return 0;
}
#else
#define VERBOSE_AES_CCM 0
#endif

#if(0)
int dev_decrypt(int len, uint8_t *pdu, uint8_t szmic, uint32_t seq, uint16_t src, uint16_t dst, uint8_t nid) {
  struct netkey *nk = find_netkey(nid);
  uint8_t mic_len = (szmic) ? 8 : 4;
  int cipher_len = len - mic_len;
  uint8_t *ciphertext = pdu;
  uint8_t *mac = &pdu[cipher_len];
  uint8_t nonce[13];
  nonce[0] = 2;
  nonce[1] = szmic;
  memcpy(&nonce[2],beuint24(seq),3);
  memcpy(&nonce[5],beuint16(src),2);
  memcpy(&nonce[7],beuint16(dst),2);
  memcpy(&nonce[9],&nk->iv_bigendian[0],4);
  printf("  ciphertext: %s\n",hex(cipher_len,ciphertext));
  printf("         mac: %s\n",hex(4,mac));
  printf("       nonce: %s\n",hex(13,nonce));
  printf("      devkey: %s\n",hex(16,devkeys->key));
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  assert(0 == mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,devkeys->key,128));
  int rc =  mbedtls_ccm_auth_decrypt(&ctx,cipher_len,nonce,13,NULL,0,ciphertext,ciphertext,mac,4);
  switch(rc) {
  case MBEDTLS_ERR_CCM_AUTH_FAILED:
    printf("Auth failed\n");
    return 1;
    break;
  case 0:
    printf("Success!\n");
    printf("    ciphertext: %s\n",hex(cipher_len,ciphertext));
    memcpy(&pdu[10],ciphertext,cipher_len);
    break;
  default:
    printf("mbedtls_ccm_auth_decrypt returned -%x\n",-rc);
    return 2;
    break;
  }
  return 0;
}
#endif
