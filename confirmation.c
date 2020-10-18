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
#include "confirmation.h"

struct __attribute__((packed)) confirmation_inputs {
  uint8_t invite[1], capabilities[11], start[5], provisioner_public_key[64], device_public_key[64];
} confirmation_inputs;

struct __attribute__((packed)) confirmation_data {
  uint8_t secret[32], random[16], authvalue[16], salt[16], key[16];
} confirmation_data;

#define M(X) void confirmation_set_ ## X (int len, uint8_t *data) { assert(sizeof(confirmation_inputs.X) == len); memcpy(&confirmation_inputs.X,data,len); }
  M(invite)
  M(capabilities)
  M(start)
  M(provisioner_public_key)
  M(device_public_key)
#undef M
#define M(X) void confirmation_set_ ## X (int len, uint8_t *data) { assert(sizeof(confirmation_data.X) == len); memcpy(&confirmation_data.X,data,len); }
  M(secret)
  M(random)
  M(authvalue)
#undef M

void confirmation_get_salt(uint8_t *salt) {
    memcpy(salt,confirmation_data.salt,sizeof(confirmation_data.salt));
}

#ifdef TEST_CONFIRMATION
int main(int argc, char *argv[]) {
  assert((9 == argc) || ("confirmation <invite> <capabilities> <start> <provisioner-pk> <device-pk> <ecdh-secret> <random> <authvalue>" == NULL));
  assert(145 == sizeof(confirmation_inputs));
#define M(X,Y) assert((sizeof(confirmation_inputs.X) << 1) == strlen(argv[Y]))
  M(invite,1);
  M(capabilities,2);
  M(start,3);
  M(provisioner_public_key,4);
  M(device_public_key,5);
#undef M
#define M(X,Y) assert((sizeof(confirmation_data.X) << 1) == strlen(argv[Y]))
  M(secret,6);
  M(random,7);
  M(authvalue,8);
#undef M
  uint8_t result[16];
  struct confirmation_inputs inputs;
  struct confirmation_data data;
#define M(X,Y) assert(!hex2bin(argv[Y],inputs.X))
  M(invite,1);
  M(capabilities,2);
  M(start,3);
  M(provisioner_public_key,4);
  M(device_public_key,5);
#undef M
#define M(X,Y) assert(!hex2bin(argv[Y],data.X))
  M(secret,6);
  M(random,7);
  M(authvalue,8);
#undef M
#define M(X) confirmation_set_ ## X (sizeof(inputs.X),inputs.X)
  M(invite);
  M(capabilities);
  M(start);
  M(provisioner_public_key);
  M(device_public_key);
#undef M
#define M(X) confirmation_set_ ## X (sizeof(data.X),data.X)
  M(secret);
  M(authvalue);
#undef M  
  confirmation(data.random,result);
  return 0;
}
#endif

int confirmation(uint8_t*random, uint8_t*result) {
  printf("confirmation(%s):\n",hex(16,random));
  confirmation_set_random(16,random);
#define M(X) printf("%24s: %s\n",#X,hex(sizeof(confirmation_inputs.X),confirmation_inputs.X))
  M(invite);
  M(capabilities);
  M(start);
  M(provisioner_public_key);
  M(device_public_key);
#undef M  
#define M(X) printf("%24s: %s\n",#X,hex(sizeof(confirmation_data.X),confirmation_data.X))
  M(secret);
  M(random);
  M(authvalue);
  s1(sizeof(confirmation_inputs),(void*)&confirmation_inputs,confirmation_data.salt);
  M(salt);
  k1(32,confirmation_data.secret,confirmation_data.salt,4,(uint8_t*)"prck",confirmation_data.key);
  M(key);
#undef M  
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  assert((cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB)));
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, confirmation_data.key, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, confirmation_data.random, 32)); // abuse packed structure
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,result));
  printf("result: %s\n",hex(16,result));
  mbedtls_cipher_free(&ctx);
  return 0;
}
