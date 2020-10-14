int provisioning_data_init(uint8_t*confirmation_salt, uint8_t*provisioner_random, uint8_t*device_random, uint8_t*secret);
int provisioning_data_encrypt(uint8_t*plain, uint8_t*cypher, uint8_t*mic);
int provisioning_data_decrypt(uint8_t*plain, uint8_t*cypher, uint8_t*mic);
