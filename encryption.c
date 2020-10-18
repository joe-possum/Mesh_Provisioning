#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <mbedtls/aes.h>
#include <mbedtls/ccm.h>
#include "encryption.h"
#include "utility.h"
#include "s1.h"
#include "k1.h"
#include "k2.h"

struct netkey {
  struct netkey *next;
  uint8_t network[16],encryption[16],privacy[16],beacon[16],iv_bigendian[4];
  uint32_t iv;
  uint8_t nid;
} *netkeys = NULL;

struct appkey {
  struct appkey *next;
  uint8_t key[16];
  uint8_t aid;
} *appkeys = NULL;

struct devkey {
  struct devkey *next;
  uint8_t key[16];
  uint16_t address;
} *devkeys = NULL;

struct netkey *find_netkey(uint8_t nid) {
  for(struct netkey *nk = netkeys; nk; nk= nk->next) {
    if(nid == nk->nid) return nk;
  }
  return NULL;
}

struct devkey *find_devkey(uint16_t address) {
  for(struct devkey *dk = devkeys; dk; dk= dk->next) {
    if(address == dk->address) return dk;
  }
  return NULL;
}

#define dprintf if(0)printf

struct netkey *deobfuscate(uint8_t len, uint8_t data[]) {
  dprintf("deobfuscate(%s)\n",hex(len,data));
  struct netkey *nk = find_netkey(data[0]&0x7f);
  if(!nk)return NULL;
  uint32_t iv = nk->iv;
  if((iv & 1) != (data[0] >> 7)) {
    iv = iv - 1;
  }
  uint8_t in[16],out[16];
  memset(in,0,5);
  memcpy(&in[5],&nk->iv_bigendian[0],4);
  memcpy(&in[5+4],&data[7],7);
  //printf(" in: %s\n",render128(in));
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  assert(0 == mbedtls_aes_setkey_enc(&ctx,nk->privacy,128));
  assert(0 == mbedtls_aes_crypt_ecb(&ctx,MBEDTLS_AES_ENCRYPT,in,out));
  //printf("out: %s\n",render128(out));
  for(int i = 0; i < 6; i++) {
    data[1+i] ^= out[i];
  }
  return nk;
}

int decrypt(uint8_t len, uint8_t data[]) {
  dprintf("decrypt(%s)\n",hex(len,data));
  struct netkey *nk = deobfuscate(len,data);
  if(!nk) return 0;
  uint8_t nonce[13];
  nonce[0] = 0;
  memcpy(&nonce[1],&data[1],6);
  memset(&nonce[7],0,2);
  memcpy(&nonce[9],&nk->iv_bigendian[0],4);
  uint8_t mac_len = 4;
  if(data[1] & 0x80) mac_len = 8;
  dprintf("  mac_len:%d\n",mac_len);
  int cipher_len = len - 7 - mac_len;
  if(cipher_len < 3) {
    printf("not decrypting due to cipher_len:%d < 10\n",cipher_len);
    return 0;
  }
  dprintf("cipher text long enough, %d bytes\n",cipher_len);
  uint8_t *ciphertext = &data[7];
  uint8_t *mac = &data[len-mac_len];
  dprintf("         nonce: %s\n",hex(13,nonce));
  dprintf("           mac: %s\n",hex(mac_len,mac));
  dprintf("    ciphertext: %s\n",hex(cipher_len,ciphertext));
  dprintf("encryption key: %s\n",hex(16,nk->encryption));
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  assert(0 == mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,nk->encryption,128));
  int rc =  mbedtls_ccm_auth_decrypt(&ctx,cipher_len,nonce,13,NULL,0,ciphertext,ciphertext,mac,mac_len);
  switch(rc) {
  case MBEDTLS_ERR_CCM_AUTH_FAILED:
    dprintf("NetKey decrypt: Auth failed\n");
    return 0;
    break;
  case 0:
    dprintf("Success!\n");
    dprintf("    ciphertext: %s\n",hex(cipher_len,ciphertext));
    memcpy(&data[7],ciphertext,cipher_len);
    break;
  default:
    printf("mbedtls_ccm_auth_decrypt returned -%x\n",-rc);
    return 0;
    break;
  }
  return 7+cipher_len;
}

int app_decrypt(uint8_t len, uint8_t *pdu, struct netkey *nk, struct appkey *ak) {
  int cipher_len = len - 10 - 8;
  uint8_t *ciphertext = &pdu[10];
  uint8_t *mac = &pdu[10+cipher_len];
  uint8_t nonce[13];
  nonce[0] = 1;
  nonce[1] = 0;
  memcpy(&nonce[2],&pdu[2],7);
  memcpy(&nonce[9],&nk->iv_bigendian[0],4);
  //printf("  ciphertext: %s\n",hex(cipher_len,ciphertext));
  //printf("         mac: %s\n",hex(4,mac));
  //printf("       nonce: %s\n",hex(13,nonce));
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  assert(0 == mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,ak->key,128));
  int rc =  mbedtls_ccm_auth_decrypt(&ctx,cipher_len,nonce,13,NULL,0,ciphertext,ciphertext,mac,4);
  switch(rc) {
  case MBEDTLS_ERR_CCM_AUTH_FAILED:
    //printf("Auth failed\n");
    return 1;
    break;
  case 0:
    //printf("Success!\n");
    //printf("    ciphertext: %s\n",hex(cipher_len,ciphertext));
    memcpy(&pdu[10],ciphertext,cipher_len);
    break;
  default:
    printf("mbedtls_ccm_auth_decrypt returned -%x\n",-rc);
    return 2;
    break;
  }
  return 0;
}

int dev_decrypt(int len, uint8_t *pdu, uint8_t szmic, uint32_t seq, uint16_t src, uint16_t dst, uint8_t nid) {
  struct netkey *nk = find_netkey(nid);
  struct devkey *dk = find_devkey(dst);
  if(!dk) dk = find_devkey(src);
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
  assert(0 == mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,dk->key,128));
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

void add_netkey(const uint8_t *netkey, uint32_t iv_index) {
  printf("add_netkey(netkey:%s, iv_index:%08x)\n",hex(16,netkey),iv_index);
  struct netkey *nk = malloc(sizeof(struct netkey));
  assert(nk);
  nk->next = netkeys;
  netkeys = nk;
  memcpy(nk->network,netkey,16);
  nk->iv = iv_index;
  for(int i = 0; i < 4; i++) {
    nk->iv_bigendian[i] = ((uint8_t*)&iv_index)[3-i];
  }
  printf("            iv: %08x\n",nk->iv);
  printf("  iv_bigendian: %s\n",hex(4,nk->iv_bigendian));
  k2(16,netkey,1,(uint8_t*)"",&nk->nid,nk->encryption,nk->privacy);
  uint8_t salt[16];
  s1(4,(uint8_t*)"nkbk",&salt[0]);
  k1(16,netkey,salt,6,(uint8_t*)"id128\x01",nk->beacon);
  printf("            NID: %x\n",nk->nid);
  printf("  enryption key: %s\n",hex(16,nk->encryption));
  printf("    privacy key: %s\n",hex(16,nk->privacy));
}

void add_devkey(const uint8_t *key128, uint16_t address) {
  printf("add_devkey(%s)\n",hex(16,key128));
  struct devkey *dk = malloc(sizeof(struct devkey));
  assert(dk);
  dk->next = devkeys;
  devkeys = dk;
  memcpy(dk->key,key128,16);
  dk->address = address;
  printf("      key: %s\n",hex(16,dk->key));
  printf("  address: %04x\n",dk->address);
}

#if(0)
void add_appkey(const char *str) {
  printf("add_appkey(str:%s)\n",str);
  if(32 != strlen(str)) {
    fprintf(stderr,"Error add_appkey: usage: -k a:<key-128>\n");
    exit(1);
  }
  uint8_t key128[16];
  for(int i = 0; i < 16; i++) {
    int iv;
    char buf[3];
    memcpy(buf,&str[i<<1],2);
    if(1 != sscanf(buf,"%x",&iv)) {
      fprintf(stderr,"Error add_appkey: issue parsing key at position %d ('%s')\n",i<<1,buf);
      exit(1);
    }
    key128[i] = iv;
  }
  struct appkey *ak = malloc(sizeof(struct appkey));
  assert(ak);
  ak->next = appkeys;
  appkeys = ak;
  memcpy(ak->key,key128,16);
  ak->aid = k4(ak->key);
  printf("  key: %s\n",hex(16,ak->key));
  printf("  AID: %x\n",ak->aid);
}
#endif
