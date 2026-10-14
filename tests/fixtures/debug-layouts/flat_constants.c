/* SPDX-License-Identifier: Apache-2.0 */
#include "flat.h"

#define DEBUG_FIELD_FACTS(member, ctype) \
    __builtin_offsetof(debug_flat, member), sizeof(((debug_flat *)0)->member), _Alignof(ctype)

__attribute__((used, section(".rampage_debug_layout"), aligned(8)))
const unsigned long long debug_flat_layout_constants[] = {
    0x52414d5044424731ULL, 1, 8, 1, sizeof(debug_flat), _Alignof(debug_flat), 6,
    DEBUG_FIELD_FACTS(tag, signed char),
    DEBUG_FIELD_FACTS(count, int),
    DEBUG_FIELD_FACTS(flags, unsigned short),
    DEBUG_FIELD_FACTS(weight, double),
    DEBUG_FIELD_FACTS(value, int *),
    DEBUG_FIELD_FACTS(tail, unsigned char),
};

_Static_assert(sizeof(debug_flat_layout_constants) == 200, "oracle is 25 little-endian 64-bit words");
