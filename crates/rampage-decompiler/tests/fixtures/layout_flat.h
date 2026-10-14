#ifndef RAMPAGE_LAYOUT_FLAT_H
#define RAMPAGE_LAYOUT_FLAT_H

#include <stdint.h>

typedef struct layout_flat {
    char tag;
    int32_t count;
    uint16_t flags;
    double weight;
    int32_t *value;
    uint8_t tail;
} layout_flat;

int32_t layout_use(layout_flat *item);

#endif
