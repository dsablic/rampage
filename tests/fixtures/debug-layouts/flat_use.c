/* SPDX-License-Identifier: Apache-2.0 */
#include "flat.h"

int debug_flat_read_first(debug_flat *item) {
    return item->tag;
}

int debug_flat_read_interior(debug_flat *item) {
    return item->count;
}

unsigned int debug_flat_read_flags(debug_flat *item) {
    return item->flags;
}

double debug_flat_read_weight(debug_flat *item) {
    return item->weight;
}

int *debug_flat_read_pointer(debug_flat *item) {
    return item->value;
}

unsigned int debug_flat_read_final(debug_flat *item) {
    return item->tail;
}

void debug_flat_write_first(debug_flat *item, signed char replacement) {
    item->tag = replacement;
}

void debug_flat_write_interior(debug_flat *item, int replacement) {
    item->count = replacement;
}

void debug_flat_write_final(debug_flat *item, unsigned char replacement) {
    item->tail = replacement;
}
