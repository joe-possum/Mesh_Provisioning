#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "host_gecko.h"
#include <mbedtls/aes.h>
#include <mbedtls/ccm.h>
#include <mbedtls/cmac.h>
#include "utility.h"
#include "cic.h"
#include "mesh-fault-values.h"
#include "mesh-model-lookup.h"
#include "provision_transaction.h"

#define VERBOSE_ADVERTISING 1

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

/*
8.2.6 BeaconKey
The Beacon key is used to help secure the Secure Network beacon.
k1 N : 7dd7364cd842ad18c17c2b820c84c3d6
k1 SALT : 2c24619ab793c1233f6e226738393dec
k1 P : 696431323801
k1 T : 829816cd429fde7d238b56d8bf771efb
BeaconKey : 5423d967da639a99cb02231a83f7d254
*/

int k1(const uint8_t *nk, const uint8_t *salt, int len, uint8_t *p, uint8_t *bk) {
  if(VERBOSE_ADVERTISING)printf("k1(nk: %s, salt: %s, len: %d, p: %s)\n", hex(16,nk), hex(16,salt), len, hex(len,p));
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  uint8_t T[16];
  assert((cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB)));
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, salt, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, p, len));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,T));  
  if(VERBOSE_ADVERTISING)printf("     T: %s\n",hex(16,T));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, T, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, nk, 16));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,bk));  
}

int k2(uint8_t *n, int len, uint8_t *p, uint8_t *nid, uint8_t *ek, uint8_t *pk) {
  printf("k2(n:%s,p:%s)\n",hex(16,n),hex(len,p));
  uint8_t salt[16];
  if(s1(4,(uint8_t*)"smk2",salt)) {
    fprintf(stderr,"Error in s1\n");
    exit(1);
  }
  printf("  salt: %s\n",hex(16,salt));  
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  uint8_t t[16], t1[16];
  assert((cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB)));
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, salt, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, n, 16));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,t));
  printf("     t: %s\n",hex(16,t));
  uint8_t message[18];
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, t, 128));
  memcpy(message,p,len);
  message[len] = 1;
  assert(0 == mbedtls_cipher_cmac_update(&ctx, message, len+1));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,t1));
  printf("    t1: %s\n",hex(16,t1));
  *nid = t1[15] & 0x7f;
  assert(0 == mbedtls_cipher_cmac_reset(&ctx));
  memcpy(message,t1,16);
  memcpy(message+16,p,len);
  message[16+len] = 2;
  assert(0 == mbedtls_cipher_cmac_update(&ctx, message, len+17));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,ek));
  //printf("  ek: %s\n",hex(16,ek));
  assert(0 == mbedtls_cipher_cmac_reset(&ctx));
  memcpy(message,ek,16);
  memcpy(message+16,p,len);
  message[16+len] = 3;
  assert(0 == mbedtls_cipher_cmac_update(&ctx, message, len+17));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,pk));
  //printf("  pk: %s\n",hex(16,pk));  
  return 0;
}

uint8_t k4(uint8 *key) {
  /*
    salt = s1(b'smk4')
    t = CMAC.new(salt, ciphermod=AES).update(n).digest()
    result = CMAC.new(t, ciphermod=AES).update(b'id6' + b'\x01').digest()
    result = bytearray([result[-1]])[0] & 0x3f
    return bytes([result])
  */
  printf("k4(key:%s)\n",hex(16,key));
  uint8_t salt[16];
  s1(4,(uint8_t*)"smk4",salt);
  printf("     salt: %s\n",hex(16,salt));
  uint8 t[16];
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  assert((cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB)));
  mbedtls_cipher_init(&ctx);
  assert(0 == mbedtls_cipher_setup(&ctx,cipher_info));
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, salt, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, key, 16));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,t));
  printf("        t: %s\n",hex(16,t));
  uint8_t message[4] = { 'i','d','6',01 };
  printf("  message: %s\n",hex(4,message));
  uint8_t result[16];
  assert(0 == mbedtls_cipher_cmac_starts(&ctx, t, 128));
  assert(0 == mbedtls_cipher_cmac_update(&ctx, message, 4));
  assert(0 == mbedtls_cipher_cmac_finish(&ctx,result));
  printf("   result: %s\n",hex(16,result));
  return result[15] & 0x3f;
}

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
} *devkeys = NULL;

void add_devkey(const char *str) {
  printf("add_devkey(str:%s)\n",str);
  if(32 != strlen(str)) {
    fprintf(stderr,"Error add_devkey: usage: -k a:<key-128>\n");
    exit(1);
  }
  uint8_t key128[16];
  for(int i = 0; i < 16; i++) {
    int iv;
    char buf[3];
    memcpy(buf,&str[i<<1],2);
    if(1 != sscanf(buf,"%x",&iv)) {
      fprintf(stderr,"Error add_devkey: issue parsing key at position %d ('%s')\n",i<<1,buf);
      exit(1);
    }
    key128[i] = iv;
  }
  struct devkey *dk = malloc(sizeof(struct devkey));
  assert(dk);
  dk->next = devkeys;
  devkeys = dk;
  memcpy(dk->key,key128,16);
  printf("  key: %s\n",hex(16,dk->key));
}

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

void add_netkey(const char *str) {
  printf("add_netkey(str:%s)\n",str);
  if(':' != str[32]) {
    fprintf(stderr,"Error add_netkey: usage: -k n:<key-128>:<iv_index>\n");
    exit(1);
  }
  int iv;
  uint32_t iv_index;
  uint8_t key128[16];
  for(int i = 0; i < 16; i++) {
    char buf[3];
    memcpy(buf,&str[i<<1],2);
    if(1 != sscanf(buf,"%x",&iv)) {
      fprintf(stderr,"Error add_netkey: issue parsing key at position %d ('%s')\n",i<<1,buf);
      exit(1);
    }
    key128[i] = iv;
  }
  if(1 != sscanf(str+33,"%i",&iv)) {
    fprintf(stderr,"Error add_netkey: issue parsing iv_index: '%s'\n",str+33);
    exit(1);
  }
  iv_index = iv;
  printf("iv_index: %d\n",iv_index);
  struct netkey *nk = malloc(sizeof(struct netkey));
  assert(nk);
  nk->next = netkeys;
  netkeys = nk;
  memcpy(nk->network,key128,16);
  nk->iv = iv_index;
  for(int i = 0; i < 4; i++) {
    nk->iv_bigendian[i] = ((uint8_t*)&iv_index)[3-i];
  }
  printf("          iv: %08x\n",nk->iv);
  printf("iv_bigendian: %s\n",hex(4,nk->iv_bigendian));
  k2(key128,1,(uint8_t*)"",&nk->nid,nk->encryption,nk->privacy);
  uint8_t salt[16];
  s1(4,(uint8_t*)"nkbk",&salt[0]);
  k1(key128,salt,6,(uint8_t*)"id128\x01",&nk->beacon);
  printf("          NID: %x\n",nk->nid);
  printf("enryption key: %s\n",hex(16,nk->encryption));
  printf("  privacy key: %s\n",hex(16,nk->privacy));
}

void deobfuscate(uint8 len, uint8 data[], struct netkey *nk) {
  //fprintf(stderr,"%s(len:%d, data:%s, netkey:%s)\n",__PRETTY_FUNCTION__,len,hex(len,data),hex(16,nk->network));
  uint32_t iv = nk->iv;
  if((iv & 1) != (data[0] >> 7)) {
    iv = iv - 1;
  }
  uint8_t in[16],out[16];
  memset(in,0,5);
  memcpy(&in[5],&nk->iv_bigendian[0],4);
  memcpy(&in[5+4],&data[7],7);
  //printf(" in: %s\n",hex(16,in));
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  assert(0 == mbedtls_aes_setkey_enc(&ctx,nk->privacy,128));
  assert(0 == mbedtls_aes_crypt_ecb(&ctx,MBEDTLS_AES_ENCRYPT,in,out));
  //printf("out: %s\n",hex(16,out));
  for(int i = 0; i < 6; i++) {
    data[1+i] ^= out[i];
  }
}

int decrypt(uint8 len, uint8 data[], struct netkey *nk) {
  if(VERBOSE_ADVERTISING)printf("%s(len:%d, data:%s, netkey:%s)\n",__PRETTY_FUNCTION__,len,hex(len,data),hex(16,nk->network));
  uint8_t nonce[13];
  nonce[0] = 0;
  memcpy(&nonce[1],&data[1],6);
  memset(&nonce[7],0,2);
  memcpy(&nonce[9],&nk->iv_bigendian[0],4);
  uint8_t mac_len = 4;
  if(data[1] & 0x80) mac_len = 8;
  if(VERBOSE_ADVERTISING)printf("  mac_len:%d\n",mac_len);
  int cipher_len = len - 7 - mac_len;
  if(cipher_len < 3) {
    printf("not decrypting due to cipher_len:%d < 10\n",cipher_len);
    return 1;
  }
  //printf("cipher text long enough, %d bytes\n",cipher_len);
  uint8_t *ciphertext = &data[7];
  uint8_t *mac = &data[len-mac_len];
  if(VERBOSE_ADVERTISING)printf("         nonce: %s\n",hex(13,nonce));
  if(VERBOSE_ADVERTISING)printf("           mac: %s\n",hex(mac_len,mac));
  if(VERBOSE_ADVERTISING)printf("    ciphertext: %s\n",hex(cipher_len,ciphertext));
  if(VERBOSE_ADVERTISING)printf("encryption key: %s\n",hex(16,nk->encryption));
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  assert(0 == mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,nk->encryption,128));
  int rc =  mbedtls_ccm_auth_decrypt(&ctx,cipher_len,nonce,13,NULL,0,ciphertext,ciphertext,mac,mac_len);
  switch(rc) {
  case MBEDTLS_ERR_CCM_AUTH_FAILED:
    if(VERBOSE_ADVERTISING)printf("NetKey decrypt: Auth failed\n");
    return 1;
    break;
  case 0:
    if(VERBOSE_ADVERTISING)printf("Success!\n");
    if(VERBOSE_ADVERTISING)printf("    ciphertext: %s\n",hex(cipher_len,ciphertext));
    memcpy(&data[7],ciphertext,cipher_len);
    break;
  default:
    printf("mbedtls_ccm_auth_decrypt returned -%x\n",-rc);
    return 2;
    break;
  }
  return 0;
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

void dump_flags(uint8 flags) {
  printf("Flags: %02x\n",flags);
  printf("  LE Limited Discoverable Mode: %d\n",flags&1);
  printf("  LE General Discoverable Mode: %d\n",(flags>>1)&1);
  printf("  BR/EDR Not Supported: %d\n",(flags>>2)&1);
  printf("  Simultaneous LE and BR/EDR to Same Device Capable (Controller).: %d\n",(flags>>3)&1);
  printf("  Simultaneous LE and BR/EDR to Same Device Capable (Host).: %d\n",(flags>>4)&1);
  if(flags >> 5) printf("  Reserved bits set: %02x",flags);
}

void dump_list_of_services(uint8 len,uint8*data, uint8 complete, uint16 bits) {
  printf("%somplete List of %d-bit Service Class UUIDs:",(complete)?"C":"Inc",bits);
  if(len & 1) {
    printf("length of %d-bit service UUIDs is odd!\n",bits);
    return;
  }
  uint8 bytes = bits >> 3;
  //printf("len: %d, bits: %d, bytes: %d\n",len,bits,bytes);
  for(int i = 0; i < len; i += bytes) {
    printf(" ");
    for(int j = 0; j < bytes; j++) printf("%02x",data[i+(bytes-1)-j]);
  }
  printf("\n");
}

void dump_incomplete_list_of_16bit_services(uint8 len,uint8*data) {
  dump_list_of_services(len,data,0,16);
}

void dump_complete_list_of_16bit_services(uint8 len,uint8*data) {
  dump_list_of_services(len,data,1,16);
}

void dump_incomplete_list_of_128bit_services(uint8 len,uint8*data) {
  dump_list_of_services(len,data,0,128);
}

void dump_complete_list_of_128bit_services(uint8 len,uint8*data) {
  dump_list_of_services(len,data,1,128);
}

void dump_shortened_local_name(uint8 len, uint8* data) {
  char str[len+1];
  memcpy(str,data,len);
  str[len]= 0;
  printf("Shortened Local Name: '%s'\n",str);
}

void dump_complete_local_name(uint8 len, uint8* data) {
  char str[len+1];
  memcpy(str,data,len);
  str[len]= 0;
  printf("Complete Local Name: '%s'\n",str);
}

void dump_slave_connection_interval_range(uint8 len, uint8* data) {
  uint16 min = data[0] + (data[1] << 8);
  uint16 max = data[2] + (data[3] << 8);
  printf("Slave Connection Interval Range: %02x - %02x (%.1f - %.1f ms)\n",min,max,min*1.25,max*1.25);
}

void dump_service_data_16(uint8 len, uint8* data) {
  printf("Service Data - 16-bit UUID: %02x%02x:",data[1],data[0]);
  for(int i = 2; i < len; i++) {
    printf(" %02x",data[i]);
  }
  printf("\n");
}

void dump_device_address(uint8 len, uint8* data) {
  printf("Device Address: ");
  for(int i = 0; i < len; i++) printf("%s%02x",(i)?":":"",data[7-i]);
  printf(" (%s)\n",(data[1])?"public":"random");
}

void dump_service_data_128(uint8 len, uint8* data) {
  printf("Service Data - 128-bit UUID: ");
  for(int i = 0; i < 16; i++) printf("%02x",data[15-i]);
  printf(":");
  for(int i = 16; i < len; i++) {
    printf(" %02x",data[i]);
  }
  printf("\n");
}

void dump_manufacturer_specific_data(uint8 len,uint8 *data) {
  uint16 id = *(uint16_t*)data;
  printf("Manufacturer Specific Data:\n");
  printf("  Manufacturer Identifier: %04x %s\n",id,get_cic(id));
  printf("  Data:");
  for (int i = 2; i < len; i++) printf(" %02x",data[i]);
  printf("\n");
}

void dump_pbadv(uint8 len, uint8 *data) {
  const char *close_reason[] = {"Success","Timeout","Fail"};
  uint32 link_id = 0;
  for(int i = 0; i < 4; i++) {
    link_id <<= 8;
    link_id += data[i];
  }
  printf("PB-ADV: Link ID:%08x",link_id);
  printf(", Transaction Number:%d, Generic Provisioning PDU:{",data[4]);
  for(int i = 5; i < len; i++) printf(" %02x",data[i]);
  printf(" }\n");
  uint8 segn;
  uint16 total_length;
  switch(data[5]&3){
  case 0:
    segn = data[5]>>2;
    total_length = (data[6]<<8UL)|data[7];
    printf("  Transaction Start: SegN:%d, TotalLength:%d, FCS:%02x\n",segn,total_length,data[8]);
    if(segn > 0) transaction_start(link_id,data[4],total_length,segn,len-9,&data[9]);
    break;
  case 1:
    printf("  Transaction Acknowledgement\n");
    break;
  case 2:
    printf("  Transaction Continuation: SegmentIndex: %d\n",data[5]>>2);
    break;
  case 3:
    printf("  Provisioning Bearer Control: ");
    switch(data[5] >> 2) {
    case 0:
      printf("Link Open UUID:");
      for(int i = 0; i < 16; i++) printf("%02x",data[6+i]);
      printf("\n");
      break;
    case 1:
      printf("Link ACK\n");
      break;
    case 2:
      printf("Link Close: %s\n",(data[6]>2)?"Unrecognized":close_reason[data[6]]);
      break;
    }
    break;
  }
}

void dump_mesh_health_current_status(uint8_t len,uint8_t *parameters) {
  uint8_t testid = parameters[0];
  uint16_t companyid = (parameters[1] << 8) | parameters[2];
  uint8_t *faultArray = &parameters[3];
  len -= 3;
  printf("    Mesh Health Current status: Test ID: %d, Company ID: %04x\n", testid,companyid);
  for(int i = 0; i < len; i++) {
    printf("      %s\n",lookup_fault_value(faultArray[i]));
  }    
}
  
void dump_mesh_unsegmented_access_message(uint8 len, uint8_t *utam, uint16_t src, uint16_t dst) {
  uint32_t opcode = utam[0];
  uint8_t *parameters = &utam[1];
  len --;
  switch(opcode >> 6) {
  case 0:
    break;
  case 1:
    if(0x7f == opcode) printf("RFU opcode");
    break;
  case 2:
    opcode <<= 8;
    opcode |= parameters[0];
    parameters++;
    len --;
    break;
  case 3:
    opcode <<= 8;
    opcode |= parameters[0];
    opcode <<= 8;
    opcode |= parameters[1];
    parameters += 2;
    len -= 2;
    break;
  }
  if((opcode < 0x10000)&&(mesh_model_lookup(opcode))) {
    printf("    %04x -> %04x Model: %s, Message: %s, parameters:%s\n",src, dst, mesh_model_lookup(opcode),mesh_message_lookup(opcode),hex(len,parameters));
    return;
  }
  printf("    Unsegmented Access Message: Opcode:%x, parameters:%s\n",opcode,hex(len,parameters));
  switch(opcode) {
  case 4:
    dump_mesh_health_current_status(len,parameters);
    break;
  }
}

void dump_mesh_message(uint8 len,uint8 *data) {
  uint8 ivi = data[0]>>7, nid = data[0]&0x7f;
  printf("Bluetooth Mesh Message: %s\n", hex(len,data));
  printf("  IVI:%d, NID:%x, ", ivi, nid);
  fflush(stdout);
  for(struct netkey *p = netkeys; p; p = p->next) {
    if(p->nid == nid) {
      uint8_t buf[len];
      memcpy(buf,data,len);
      //printf("\n  obfuscated PDU:%s\n",hex(len,buf));
      deobfuscate(len,buf,p);
      //printf("deobfuscated PDU:%s\n",hex(len,buf));
      uint8  ctl = buf[1]>>7, ttl = buf[1]&0x7f;
      uint32 seq = (buf[2] << 16UL)|(buf[3] << 8UL)|(buf[4]);
      uint16 src = (buf[5] << 8UL)|(buf[6]);
      printf("CTL:%d TTL:%d, SEQ:%06x, SRC:%04x",ctl,ttl,seq,src);
      if(decrypt(len,buf,p)) {
	printf(" <encrypted data> ");
	for(int i = 7; i < len; i++) printf("%02x",data[i]);
	printf("\n");
	return;
      }
      uint16 dst = (buf[7] << 8UL)|(buf[8]);
      uint8 seg = buf[9] >> 7;
      if(ctl) {
	if(seg) {
	} else {
	  printf("Unsegmented Control Message\n");
	}
      } else {
	uint8 akf = (buf[9] & 0x40) >> 6, aid = buf[9] & 0x3f;
	uint8 decrypted = 0;
	printf(", DST:%04x, SEG:%d, AKF:%d, AID:%02x\n",dst,seg,akf,aid);
	if(ctl) return;
	if(!akf) return;
	for(struct appkey *ak = appkeys; ak; ak = ak->next) {
	  if(aid == ak->aid) {
	    if(0 == app_decrypt(len,buf,p,ak)) {
	      printf("    Decrypted message: ");
	      for(int i = 10; i < (len-8); i++) printf("%02x",buf[i]);
	      printf("\n");
	      decrypted = 1;
	    }
	  }
	}
	if(decrypted) {
	  if(!seg) {
	    dump_mesh_unsegmented_access_message(len-10-8,&buf[10],src,dst);
	  } else {
	  }
	}
	return;
      }
    }
    printf("<obfuscated data> ");
    for(int i = 1; i < len; i++) printf("%02x",data[i]);
    printf("\n");
    return;
  }
}

void dump_secure_network_beacon(uint8 len,const uint8 *data) {
  uint8 key_refresh_flag = data[1]&1;
  uint8 iv_update_flag = (data[1]>>1)&1;
  const uint8 *network_id = &data[2];
  uint32_t iv_index = be2uint32(&data[10]);
  const uint8_t *authentication_value = &data[14];
  printf("Secure Network beacon, Key Refresh Flag:%d, IV Update Flag:%d, Network ID: %s, IV Index: %08x, Authentication Value: %s\n",
	 key_refresh_flag,
	 iv_update_flag,
	 hex(4, network_id),
	 iv_index,
	 hex(8, authentication_value));
}

void dump_mesh_beacon(uint8 len, const uint8 *data) {
  char*RFU = "Reserved for Future Use";
  char *oob_str[16] = {"Other","Electronic/URI","2D machine-readable code","Bar code","NFC","Number","String",RFU,RFU,RFU,RFU,"On box","Inside box","On peice of paper","Indide manual","On device"};
  uint16 oob_info = (data[17]<<8) + data[18];
  int comma = 0;
  printf("Bluetooth Mesh Beacon:\nBeacon Type: ");
  switch(data[0]) {
  case 0:
    printf("Unprovisioned Device beacon, UUID:");
    for(int i = 0; i < 16; i++) printf("%02x",data[1+i]);
    printf(", OOB Information:");
    for(int i = 0; i < 16; i++) {
      if(oob_info & (1<<i)) {
	printf("%s%s",(comma)?"|":"",oob_str[i]);
	comma=1;
      }
    }
    if(len>19) {
      printf(", URI Hash:");
      for(int i = 0; i < 4; i++) printf("%02x",data[19+i]);
    }
    printf("\n");
    break;
  case 1:
    dump_secure_network_beacon(len,data);
    break;
  default:
    printf("RESERVED\n");
  }
}

int dump_element(uint8 type,uint8 len, uint8*data) {
  switch(type) {
  case 0x01:
    dump_flags(data[0]);
    break;
  case 0x02:
    dump_incomplete_list_of_16bit_services(len,data);
    break;
  case 0x03:
    dump_complete_list_of_16bit_services(len,data);
    break;
  case 0x06:
    dump_incomplete_list_of_128bit_services(len,data);
    break;
  case 0x07:
    dump_complete_list_of_128bit_services(len,data);
    break;
  case 0x08:
    dump_shortened_local_name(len,data);
    break;
  case 0x09:
    dump_complete_local_name(len,data);
    break;
  case 0x0a:
    printf("TX Power Level: %d dBm\n",((int8*)data)[0]);
    break;
  case 0x12:
    dump_slave_connection_interval_range(len,data);
    break;
  case 0x16:
    dump_service_data_16(len,data);
    break;
  case 0x19:
    printf("Appearance:\n");
    break;
  case 0x1b:
    dump_device_address(len,data);
    break;
  case 0x21:
    dump_service_data_128(len,data);
    break;
  case 0x29:
    dump_pbadv(len,data);
    break;
  case 0x2a:
    dump_mesh_message(len,data);
    break;
  case 0x2b:
    dump_mesh_beacon(len,data);
    break;
  case 0xff:
    dump_manufacturer_specific_data(len,data);
    break;
  default:
    printf("Unhandled advertising element: type: %02x, len: %d\n",type,len);
    return 1;
  }
  return 0;
}

int dump_advertisement(uint8 len, uint8*data) {
  uint8 i = 0;
  while(i < len) {
    uint8 elen = data[i++];
    uint8 type = data[i];
    if(dump_element(type,elen-1,&data[i+1])) return 1;
    i += elen;
  }
  return 0;
}

void dump_address(bd_addr address,uint8 type,int8 rssi) {
  const char *ts = "*illegal address type*";
  switch(type) {
  case 0: ts = "public"; break;
  case 1: ts = "random"; break;
  case 255: ts = "anonymous"; break;
  }
  printf("Address: ");
  for(int i = 0; i < 6; i++) printf("%s%02x",(i)?":":"",address.addr[5-i]);
  printf(" %d dBm (%s)\n",rssi,ts);
}

void dump_packet_type(uint8 packet_type) {
  char *cs;
  switch(packet_type & 7) {
  case 0: cs = "Connectable scannable undirected advertising"; break;
  case 1: cs = "Connectable undirected advertising"; break;
  case 2: cs = "Scannable undirected advertising"; break;
  case 3: cs = "Non-connectable non-scannable undirected advertising"; break;
  case 4: cs = "Scan Response"; break;
  }
  printf("Packet type: %s (%s)\n",cs,(packet_type&0x80)?"Extended":"Legacy");
}

void cmdline_decrypt(const char *message) {
  fprintf(stderr,"%s(message:%s)\n",__PRETTY_FUNCTION__,message);
  uint8_t pdu[31];
  int n = strlen(message);
  if(n & 1) {
    fprintf(stderr,"Odd hex message length\n");
    exit(1);
  }
  n >>= 1;
  char buf[3];
  buf[2] = 0;
  for(int i = 0; i < n; i++) {
    unsigned int v;
    memcpy(buf,&message[i<<1],2);
    assert(1 == sscanf(buf,"%x",&v));
    pdu[2+i] = v;
  }
  pdu[0] = 1+n;
  pdu[1] = 0x2a;
  dump_advertisement(2+n,pdu);
  exit(0);
}

uint8 unique[512][16],md5sum[16];
uint16 ucount = 0;


int main(int argc, char *argv[]) {
  
}
