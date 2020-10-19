#include <stdint.h>

/* utility.c */
int myrnd(void *ctx, unsigned char *buf, size_t len);
char *hex(uint8_t len, const uint8_t *in);
int hex2bin(const char *hex, uint8_t *bin);
uint32_t be2uint32(const uint8_t *be);
uint32_t be2uint24(const uint8_t *be);
uint16_t be2uint16(const uint8_t *be);
uint8_t *beuint32(uint32_t value);
uint8_t *beuint24(uint32_t value);
uint8_t *beuint16(uint16_t value);
