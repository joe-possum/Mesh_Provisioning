#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mbedtls/md5.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/ccm.h>
#include <assert.h>
#include "s1.h"
#include "k4.h"

static char *hex(uint8_t len, const uint8_t *in) {
  static char out[4][256];
  static uint8_t index;
  index &= 3;
  for(int i = 0; i < len; i++) sprintf(&out[index][i<<1],"%02x",in[i]);
  return &out[index++][0];
}

#ifdef TEST_K4
#define VERBOSE_K4 1
static int hex2bin(const char*hex, uint8_t*bin) {
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
  assert((2 == argc) || ("k4 <n>" == NULL));
  int nlen = strlen(argv[1]);
  assert(0 == (nlen & 1));
  nlen >>= 1;
  uint8_t *N, result[16];
  assert((N = malloc(nlen)));
  assert(!hex2bin(argv[1],N));
  k4(nlen,N,result);
  return 0;
}
#else
#define VERBOSE_K4 0
#endif

uint8_t k4(int klen, const uint8_t *key, uint8_t *aid) {
  /*
    salt = s1(b'smk4')
    t = CMAC.new(salt, ciphermod=AES).update(n).digest()
    result = CMAC.new(t, ciphermod=AES).update(b'id6' + b'\x01').digest()
    result = bytearray([result[-1]])[0] & 0x3f
    return bytes([result])
  */
  if(VERBOSE_K4)printf("k4(key:%s)\n",hex(klen,key));
  uint8_t salt[16];
  s1(4,(uint8_t*)"smk4",salt);
  printf("     salt: %s\n",hex(16,salt));
  uint8_t t[16];
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  assert((cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB)));
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, salt, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, key, klen));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,t));
  printf("        t: %s\n",hex(16,t));
  uint8_t message[4] = { 'i','d','6',01 };
  if(VERBOSE_K4)printf("  message: %s\n",hex(4,message));
  uint8_t result[16];
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, t, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, message, 4));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,result));
  if(VERBOSE_K4)printf("   result: %s\n",hex(16,result));
  memcpy(aid,&result[15],1);
  aid[0] &= 0x3f;
  if(VERBOSE_K4)printf("      aid: %s\n",hex(1,aid));
  return 0;
}
