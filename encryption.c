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
#include "k4.h"

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
  printf("No netkey found for NID:%02x",nid);
  return NULL;
}

struct devkey *find_devkey(uint16_t address) {
  for(struct devkey *dk = devkeys; dk; dk= dk->next) {
    if(address == dk->address) return dk;
  }
  return NULL;
}

struct appkey *find_appkey(uint8_t aid) {
  for(struct appkey *ak = appkeys; ak; ak= ak->next) {
    if(aid == ak->aid) return ak;
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

void obfuscate(uint8_t len, uint8_t *pdu, struct netkey *nk) {
  dprintf("obfuscate(%s)\n",hex(len,pdu));
  uint32_t iv = nk->iv;
  if((iv & 1) != (pdu[0] >> 7)) {
    iv = iv - 1;
  }
  uint8_t in[16],out[16];
  memset(in,0,5);
  memcpy(&in[5],&nk->iv_bigendian[0],4);
  memcpy(&in[5+4],&pdu[7],7);
  //printf(" in: %s\n",render128(in));
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  assert(0 == mbedtls_aes_setkey_enc(&ctx,nk->privacy,128));
  assert(0 == mbedtls_aes_crypt_ecb(&ctx,MBEDTLS_AES_ENCRYPT,in,out));
  //printf("out: %s\n",render128(out));
  for(int i = 0; i < 6; i++) {
    pdu[1+i] ^= out[i];
  }
}

int encrypt(uint8_t len, uint8_t *pdu) {
  printf("encrypt(%s)\n",hex(len,pdu));
  struct netkey *nk = find_netkey(pdu[0]&0x7f);
  if(!nk) return 1;
  uint8_t nonce[13];
  nonce[0] = 0;
  memcpy(&nonce[1],&pdu[1],6);
  memset(&nonce[7],0,2);
  memcpy(&nonce[9],&nk->iv_bigendian[0],4);
  uint8_t mac_len = 4;
  if(pdu[1] & 0x80) mac_len = 8;
  dprintf("  mac_len:%d\n",mac_len);
  uint8_t *mac = &pdu[len-mac_len];
  int cipher_len = len - 7 - mac_len;
  uint8_t *ciphertext = &pdu[7];
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  assert(0 == mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,nk->encryption,128));
  int rc;
  assert(0 == (rc =  mbedtls_ccm_encrypt_and_tag(&ctx,cipher_len,nonce,13,NULL,0,ciphertext,ciphertext,mac,mac_len)) || (printf("rc: -%x\n",-rc) == -1));
  printf("postenc:%s\n",hex(len,pdu));
  obfuscate(len,pdu,nk);
  printf("obfusca:%s\n",hex(len,pdu));
  return 0;
}

int decrypt(uint8_t len, uint8_t data[], uint8_t *netkey) {
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
  if(rc) {
    printf("decrypt(%s)\n",hex(len,data));
    printf("         nonce: %s\n",hex(13,nonce));
    printf("           mac: %s\n",hex(mac_len,mac));
    printf("    ciphertext: %s\n",hex(cipher_len,ciphertext));
    printf("encryption key: %s\n",hex(16,nk->encryption));
  }
  switch(rc) {
  case MBEDTLS_ERR_CCM_AUTH_FAILED:
    dprintf("NetKey decrypt: Auth failed\n");
    return 0;
    break;
  case 0:
    dprintf("Success!\n");
    dprintf("    ciphertext: %s\n",hex(cipher_len,ciphertext));
    memcpy(&data[7],ciphertext,cipher_len);
    memcpy(netkey,nk->network,16);
    break;
  default:
    printf("mbedtls_ccm_auth_decrypt returned -%x\n",-rc);
    return 0;
    break;
  }
  return 7+cipher_len;
}

int upper_decrypt(int len, uint8_t *pdu, uint8_t szmic, uint32_t seq, uint16_t src, uint16_t dst, uint8_t nid, uint8_t akf, uint8_t aid) {
  struct netkey *nk = find_netkey(nid);
  uint8_t *key;
  if(akf) {
    struct appkey *ak = find_appkey(aid);
    if(!ak) {
      printf("AID 0x%2x not known\n",aid);
      return 0;
    }
    key = ak->key;
  } else {
    struct devkey *dk = find_devkey(dst);
    if(!dk) dk = find_devkey(src);
    if(!dk) {
      printf("Can't find devkey for SRC:%04x or DST:%04x\n",src,dst);
      return 0;
    }
    key = dk->key;
  }
  uint8_t mic_len = (szmic) ? 8 : 4;
  int cipher_len = len - mic_len;
  uint8_t *ciphertext = pdu;
  uint8_t *mac = &pdu[cipher_len];
  uint8_t nonce[13];
  nonce[0] = (akf)?1:2;
  nonce[1] = szmic;
  memcpy(&nonce[2],beuint24(seq),3);
  memcpy(&nonce[5],beuint16(src),2);
  memcpy(&nonce[7],beuint16(dst),2);
  memcpy(&nonce[9],&nk->iv_bigendian[0],4);
  uint8_t plaintext[cipher_len];
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  assert(0 == mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,key,128));
  int rc =  mbedtls_ccm_auth_decrypt(&ctx,cipher_len,nonce,13,NULL,0,ciphertext,plaintext,mac,4);
  if(rc) {
    printf("dev_decrypt(pdu:%s, szmic:%d, seq:%06x, src:%04x, dst:%04x, nid:%02x, akf:%d, aid:%02x)\n",hex(len,pdu),szmic,seq,src,dst,nid,akf,aid);
    printf("  ciphertext: %s\n",hex(cipher_len,ciphertext));
    printf("         mac: %s\n",hex(4,mac));
    printf("       nonce: %s\n",hex(13,nonce));
    printf("         key: %s\n",hex(16,key));
  }
  switch(rc) {
  case MBEDTLS_ERR_CCM_AUTH_FAILED:
    printf("Auth failed\n");
    return 0;
    break;
  case 0:
    dprintf("Success!\n");
    dprintf("    ciphertext: %s\n",hex(cipher_len,ciphertext));
    memcpy(pdu,plaintext,cipher_len);
    break;
  default:
    printf("mbedtls_ccm_auth_decrypt returned -%x\n",-rc);
    return 0;
    break;
  }
  return cipher_len;
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
  printf("add_devkey(key128:%s, address:%04x)\n",hex(16,key128),address);
  struct devkey *dk = malloc(sizeof(struct devkey));
  assert(dk);
  dk->next = devkeys;
  devkeys = dk;
  memcpy(dk->key,key128,16);
  dk->address = address;
  printf("      key: %s\n",hex(16,dk->key));
  printf("  address: %04x\n",dk->address);
}

void add_appkey(const uint8_t *key128) {
  printf("add_appkey(key128:%s)\n",hex(16,key128));
  struct appkey *ak = malloc(sizeof(struct appkey));
  assert(ak);
  ak->next = appkeys;
  appkeys = ak;
  memcpy(ak->key,key128,16);
  k4(16,ak->key,&ak->aid);
  printf("  key: %s\n",hex(16,ak->key));
  printf("  AID: %x\n",ak->aid);
}

void add_friendship(uint8_t *netkey, uint16_t LPNAddress,uint16_t FriendAddress,uint16_t LPNCounter,uint16_t FriendCounter) {
  uint8_t p[9] = { 1, };
  memcpy(p+1,beuint16(LPNAddress),2);
  memcpy(p+3,beuint16(FriendAddress),2);
  memcpy(p+5,beuint16(LPNCounter),2);
  memcpy(p+7,beuint16(FriendCounter),2);
  struct netkey *nk = malloc(sizeof(struct netkey));
  assert(nk);
  nk->next = netkeys;
  netkeys = nk;
  k2(16,netkey,sizeof(p),p,&nk->nid,nk->encryption,nk->privacy);
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
