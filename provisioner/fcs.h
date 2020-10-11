#ifndef __FCS_H__
#define __FCS_H__

#include <stdint.h>
#include <stddef.h>

uint8_t calculate_fcs(size_t len, uint8_t *data);

#endif
