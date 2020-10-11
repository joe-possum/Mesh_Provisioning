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

int main(int argc, char *argv[]) {
  mbedtls_ecdh_context ctx;
  mbedtls_ecp_keypair kp;
  int rc;
  mbedtls_ecdh_init(&ctx);
  mbedtls_ecp_keypair_init(&kp);
  if(argc > 1) {
    char xstr[65], ystr[65];
    assert(128 ==strlen(argv[1]));
    assert(0 == (rc = mbedtls_ecp_group_load(&kp.grp, MBEDTLS_ECP_DP_SECP256R1)) || (-1 == printf("rc = -%x\n",-rc)));
    memcpy(xstr,argv[1],64);
    xstr[64] = 0;
    memcpy(ystr,64+argv[1],64);
    ystr[64] = 0;
    printf("xstr: %s\nystr: %s\n",xstr,ystr);
    assert(0 == (rc = mbedtls_ecp_point_read_string(&kp.Q, 16, xstr, ystr)) || (-1 == printf("rc = -%x\n",-rc)));
    printf("    X: %s\n",hex(4*kp.Q.X.n,(uint8_t*)kp.Q.X.p));
    printf("    Y: %s\n",hex(4*kp.Q.Y.n,(uint8_t*)kp.Q.Y.p));
  }    
  assert(0 == (rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,&kp,myrnd,NULL)) || (-1 == printf("rc = -%x\n",-rc)));
  if(rc) printf("mbedtls_ecp_group_load(&grp,MBEDTLS_ECP_DP_SECP256R1) returned -%x",-rc);
  printf("rand() was called %d times\n",counter);
  printf("Keypair generated:\n");
  printf("  d:\n");
  printf("  Q:\n");
  printf("    X: %s\n",hex(4*kp.Q.X.n,(uint8_t*)kp.Q.X.p));
  printf("      s: %d\n",kp.Q.X.s);
  printf("      n: %ld\n",kp.Q.X.n);
  mbedtls_mpi Q, R;
  mbedtls_mpi_init(&Q);
  mbedtls_mpi_init(&R);
  rc = mbedtls_mpi_div_mpi(&Q,&R,&kp.Q.X,&kp.Q.X);
  if(rc) printf("mbedtls_mpi_div_mpi(&Q,&R,&kp.Q.X,&kp.Q.X) returned -%x",-rc);
  printf("Q: %s\n",hex(4*Q.n,(uint8_t*)Q.p));
  rc = mbedtls_mpi_shift_l(&Q,30);
  printf("Q: %s\n",hex(4*Q.n,(uint8_t*)Q.p));
  rc = mbedtls_mpi_mul_mpi(&R,&Q,&Q);
  printf("Q*Q: %s\n",hex(4*R.n,(uint8_t*)R.p));
  return 0;
}
