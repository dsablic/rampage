/* A small owned "library" in two versions for the flywheel's synthetic version-split test. MINILIB_V2 adds a
 * function ahead of the others (so every function moves), changes ml_checksum's body and ml_scale's constants,
 * and leaves the rest unchanged in source: their masked bodies match across versions, their raw bytes do not. */
#include "minilib.h"

static unsigned ml_table[16] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3};
unsigned ml_state = 7;

#ifdef MINILIB_V2
unsigned ml_extra(unsigned value) {
    for (int round = 0; round < 3; round++) value = (value * 2654435761u) ^ (value >> 13) ^ ml_state;
    return value;
}
#endif

unsigned ml_checksum(const unsigned char *data, unsigned length) {
#ifdef MINILIB_V2
    unsigned a = 7, b = 0;
    for (unsigned i = 0; i < length; i++) {
        a = (a + data[i] * 3) % 65519u;
        b = (b + a) % 65519u;
    }
    return (b << 15) ^ a;
#else
    unsigned a = 1, b = 0;
    for (unsigned i = 0; i < length; i++) {
        a = (a + data[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
#endif
}

void ml_reverse(unsigned char *data, unsigned length) {
    for (unsigned i = 0, j = length ? length - 1 : 0; i < j; i++, j--) {
        unsigned char swap = data[i];
        data[i] = data[j];
        data[j] = swap;
    }
}

int ml_find(const unsigned char *data, unsigned length, unsigned char wanted) {
    for (unsigned i = 0; i < length; i++) {
        if (data[i] == wanted) return (int)i;
    }
    return -1;
}

unsigned ml_lookup(unsigned index) {
    unsigned value = ml_table[index & 15] * 31u + ml_state;
    ml_state = value ^ (value >> 7);
    return value;
}

unsigned long ml_sum_squares(const int *values, unsigned count) {
    unsigned long total = 0;
    for (unsigned i = 0; i < count; i++) total += (unsigned long)((long)values[i] * values[i]);
    return total;
}

unsigned ml_mix(unsigned a, unsigned b, unsigned c) {
    a -= c; a ^= (c << 4) | (c >> 28); c += b;
    b -= a; b ^= (a << 6) | (a >> 26); a += c;
    c -= b; c ^= (b << 8) | (b >> 24); b += a;
    return a ^ b ^ ml_lookup(c);
}

/* Version 2 changes only this function's constants, each to one of the same encoded size: the change operand
 * wildcarding carries across versions. */
unsigned ml_scale(const unsigned *values, unsigned count) {
#ifdef MINILIB_V2
    unsigned total = 0x9e3779b9u;
    for (unsigned i = 0; i < count; i++) total = (total ^ values[i]) * 0x2545f491u + 0x3du;
    return total ^ (total >> 11);
#else
    unsigned total = 0x811c9dc5u;
    for (unsigned i = 0; i < count; i++) total = (total ^ values[i]) * 0x01000193u + 0x2bu;
    return total ^ (total >> 13);
#endif
}
