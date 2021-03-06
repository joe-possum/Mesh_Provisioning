#include <stdint.h>

void add_netkey(const uint8_t *netkey, uint32_t iv_index);
void add_devkey(const uint8_t *key128, uint16_t address);
void add_appkey(const uint8_t *key128);
void add_friendship(uint8_t *netkey, uint16_t LPNAddress,uint16_t FriendAddress,uint16_t LPNCounter,uint16_t FriendCounter);
int decrypt(uint8_t len, uint8_t data[], uint8_t *netkey);
int upper_decrypt(int len, uint8_t *pdu, uint8_t szmic, uint32_t seq, uint16_t src, uint16_t dst, uint8_t nid, uint8_t akf, uint8_t aid);
