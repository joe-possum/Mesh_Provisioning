#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/ecdh.h>
#include <assert.h>

static char *hex(uint8_t len, const uint8_t *in) {
  static char out[256];
  for(int i = 0; i < len; i++) sprintf(&out[i<<1],"%02x",in[i]);
  return out;
}

int counter = 0;
int myrnd(void*ctx, unsigned char *buf, size_t len) {
  for(size_t i = 0; i < len; i++) {
    buf[i] = rand();
    counter++;
  }
  return 0;
}

void hex2bin(const char *str, unsigned char *bin, int count) {
  char buf[3];
  unsigned int v;
  assert(strlen(str) == (count << 1));
  for(int i = 0; i < count; i++) {
    strncpy(buf,str+(i<<1),2);
    assert(1 == sscanf(buf,"%x",&v));
    buf[i] = v;
  }
}

#define Px(X) printf(#X ": %x\n",X)
void tab(int indent) {
  for(int i = 0; i < indent; i++) printf(" ");  
}

void dump_ecp_group_id(int indent, const char *name, mbedtls_ecp_group_id id) {
  char *str = "*unknown*";
  switch(id) {
  case MBEDTLS_ECP_DP_NONE: str = "MBEDTLS_ECP_DP_NONE"; break;
  case MBEDTLS_ECP_DP_SECP192R1: str = "MBEDTLS_ECP_DP_SECP192R1"; break;
  case MBEDTLS_ECP_DP_SECP224R1: str = "MBEDTLS_ECP_DP_SECP224R1"; break;
  case MBEDTLS_ECP_DP_SECP256R1: str = "MBEDTLS_ECP_DP_SECP256R1"; break;
  case MBEDTLS_ECP_DP_SECP384R1: str = "MBEDTLS_ECP_DP_SECP384R1"; break;
  case MBEDTLS_ECP_DP_SECP521R1: str = "MBEDTLS_ECP_DP_SECP521R1"; break;
  case MBEDTLS_ECP_DP_BP256R1: str = "MBEDTLS_ECP_DP_BP256R1"; break;
  case MBEDTLS_ECP_DP_BP384R1: str = "MBEDTLS_ECP_DP_BP384R1"; break;
  case MBEDTLS_ECP_DP_BP512R1: str = "MBEDTLS_ECP_DP_BP512R1"; break;
  case MBEDTLS_ECP_DP_CURVE25519: str = "MBEDTLS_ECP_DP_CURVE25519"; break;
  case MBEDTLS_ECP_DP_SECP192K1: str = "MBEDTLS_ECP_DP_SECP192K1"; break;
  case MBEDTLS_ECP_DP_SECP224K1: str = "MBEDTLS_ECP_DP_SECP224K1"; break;
  case MBEDTLS_ECP_DP_SECP256K1: str = "MBEDTLS_ECP_DP_SECP256K1"; break;
  case MBEDTLS_ECP_DP_CURVE448: str = "MBEDTLS_ECP_DP_CURVE448"; break;
  }
  tab(indent);
  printf("mbedtls_ecp_group_id %s: %d (%s)\n",name,id,str);
}

void dump_size_t(int indent, const char *name, size_t *p) {
  tab(indent);
  printf("size_t %s: %ld\n", name, *p);
}

void dump_unsigned(int indent, const char *name, unsigned *p) {
  tab(indent);
  printf("size_t %s: %u\n", name, *p);
}

void dump_mpi(int indent, const char *prefix, struct mbedtls_mpi *p) {
  tab(indent);
  printf("struct mbedtls_mpi %s { int s:%d, size_t n:%ld, mpi_uint p: ",prefix, p->s, p->n);
  char format[16];
  mbedtls_mpi_uint digits = sizeof(mbedtls_mpi_uint) << 1;
  sprintf(format,"%%0%ldlx",digits);
  for(int i = 0; i < p->n; i++) {
    printf(format,p->p[p->n-1-i]);
  }
  printf("\n");
}

void dump_ecp_point(int indent, const char *name, struct mbedtls_ecp_point *p) {
  tab(indent);
  printf("struct mbedtls_ecp_point %s {\n", name);
  dump_mpi(indent+2,"X",&p->X);
  dump_mpi(indent+2,"Y",&p->Y);
  dump_mpi(indent+2,"Z",&p->Z);
}

void dump_ecp_group(int indent, char *name, struct mbedtls_ecp_group *p) {
  tab(indent);
  printf("struct mbedtls_ecp_group %s {\n",name);
  tab(indent);
  dump_ecp_group_id(indent+2,"id",p->id);
  dump_mpi(indent+2,"P",&p->P);
  dump_mpi(indent+2,"A",&p->P);
  dump_mpi(indent+2,"B",&p->P);
  dump_ecp_point(indent+2,"G",&p->G);
  dump_mpi(indent+2,"N",&p->N);
  dump_size_t(indent+2,"pbits",&p->pbits);
  dump_size_t(indent+2,"nbits",&p->nbits);
  dump_unsigned(indent+2,"h",&p->h);
}

void dump_ecp_keypair(int indent, char *name, struct mbedtls_ecp_keypair *p) {
  tab(indent);
  printf("struct mbedtls_ecp_keypair %s {\n",name);
  dump_ecp_group(indent+2,"grp",&p->grp);
  dump_mpi(indent+2,"d",&p->d);
  dump_ecp_point(indent+2,"Q",&p->Q);
}

int main(int argc, char *argv[]) {
  //mbedtls_ecdh_context ctx;
  int rc;
  //mbedtls_ecdh_init(&ctx);
  if (5 == argc) { // <public> <private> <shared> <data>
    mbedtls_ecp_group grp;
    mbedtls_ecp_point public;
    mbedtls_mpi private, shared, scratch;
    char xstr[65], ystr[65];
    assert(128 == strlen(argv[1]));
    assert(64 == strlen(argv[2]));
    assert(64 == strlen(argv[3]));
    assert(32 == strlen(argv[4]));
    memcpy(xstr,argv[1],64);
    xstr[64] = 0;
    memcpy(ystr,64+argv[1],64);
    ystr[64] = 0;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&public);
    mbedtls_mpi_init(&private);
    mbedtls_mpi_init(&shared);
    mbedtls_mpi_init(&scratch);
    assert(0 == (rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)) || (-1 == printf("rc = -%x\n",-rc)));
    assert(0 == (rc = mbedtls_ecp_point_read_string(&public, 16, xstr, ystr)) || (-1 == printf("rc = -%x\n",-rc)));
    assert(0 == (rc = mbedtls_mpi_read_string(&private, 16, argv[2])) || (-1 == printf("rc = -%x\n",-rc)));
    assert(0 == (rc = mbedtls_mpi_read_string(&shared, 16, argv[3])) || (-1 == printf("rc = -%x\n",-rc)));
    assert(0 == (rc = mbedtls_ecp_check_pubkey(&grp, &public)) || (-1 == printf("rc = -%x\n",-rc)));
    printf("Public key check passed\n");
    assert(0 == (rc = mbedtls_ecdh_compute_shared(&grp, &scratch, &public, &private,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
    assert(0 == mbedtls_mpi_cmp_mpi(&shared,&scratch));
    //dump_mpi(0,"shared",&shared);
    //dump_mpi(0,"scratch",&scratch);
    
  } else if(argc > 1) {
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    char xstr[65], ystr[65];
    assert(128 ==strlen(argv[1]));
    assert(0 == (rc = mbedtls_ecp_group_load(&kp.grp, MBEDTLS_ECP_DP_SECP256R1)) || (-1 == printf("rc = -%x\n",-rc)));
    dump_ecp_group(0,"kp.grp (after load)",&kp.grp);
    mbedtls_ecp_point_init(&kp.Q);
    dump_ecp_point(0,"kp.Q",&kp.Q);
    memcpy(xstr,argv[1],64);
    xstr[64] = 0;
    memcpy(ystr,64+argv[1],64);
    ystr[64] = 0;
    printf("xstr: %s\nystr: %s\n",xstr,ystr);
    assert(0 == (rc = mbedtls_ecp_point_read_string(&kp.Q, 16, xstr, ystr)) || (-1 == printf("rc = -%x\n",-rc)));
    printf("mbedtls_ecp_point_read_string success\n");
    dump_ecp_point(0,"kp.Q",&kp.Q);
    printf("    X: %s\n",hex(4*kp.Q.X.n,(uint8_t*)kp.Q.X.p));
    printf("    Y: %s\n",hex(4*kp.Q.Y.n,(uint8_t*)kp.Q.Y.p));
    assert(0 == (rc = mbedtls_ecp_check_pubkey(&kp.grp, &kp.Q)) || (-1 == printf("rc = -%x\n",-rc)));
  } else {
    mbedtls_ecp_keypair A, B;
    mbedtls_ecp_keypair_init(&A);
    mbedtls_ecp_keypair_init(&B);
    assert(0 == (rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,&A,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
    assert(0 == (rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,&B,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
    assert(0 == (rc = mbedtls_ecp_check_pubkey(&A.grp, &A.Q)) || (-1 == printf("rc = -%x\n",-rc)));
    assert(0 == (rc = mbedtls_ecp_check_pubkey(&B.grp, &B.Q)) || (-1 == printf("rc = -%x\n",-rc)));
    dump_ecp_keypair(0,"A",&A);
    dump_ecp_keypair(0,"B",&B);
    mbedtls_mpi shared_A ,shared_B;
    mbedtls_mpi_init(&shared_A);
    mbedtls_mpi_init(&shared_B);
    assert(0 == (rc = mbedtls_ecdh_compute_shared(&A.grp, &shared_A, &B.Q, &A.d,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
    assert(0 == (rc = mbedtls_ecdh_compute_shared(&B.grp, &shared_B, &A.Q, &B.d,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
    dump_mpi(0,"shared A",&shared_A);
    dump_mpi(0,"shared B",&shared_B);
  }
  printf("rand() was called %d times\n",counter);
  return 0;
}
