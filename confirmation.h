int confirmation(uint8_t*random, uint8_t*result);
#define M(X) void confirmation_set_ ## X (int len, uint8_t *data);
  M(invite)
  M(capabilities)
  M(start)
  M(provisioner_public_key)
  M(device_public_key)
  M(secret);
  M(authvalue);
#undef M
