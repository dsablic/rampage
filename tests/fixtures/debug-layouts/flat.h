/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RAMPAGE_DEBUG_FLAT_H
#define RAMPAGE_DEBUG_FLAT_H

#if !defined(__x86_64__) || !defined(__ELF__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "These fixtures require x86_64 little-endian ELF"
#endif

typedef struct __attribute__((aligned(8))) debug_flat {
    signed char tag;
    int count;
    unsigned short flags;
    double weight;
    int *value;
    unsigned char tail;
} debug_flat;

_Static_assert(__CHAR_BIT__ == 8, "eight-bit bytes required");
_Static_assert(sizeof(int) == 4 && sizeof(void *) == 8, "x86_64 LP64 required");
_Static_assert(sizeof(unsigned long long) == 8, "oracle word width required");
_Static_assert(sizeof(debug_flat) == 40 && _Alignof(debug_flat) == 8, "flat layout changed");

#define DEBUG_CHECK_FIELD(member, offset, width) \
    _Static_assert(__builtin_offsetof(debug_flat, member) == offset, "field offset changed"); \
    _Static_assert(sizeof(((debug_flat *)0)->member) == width, "field width changed")

DEBUG_CHECK_FIELD(tag, 0, 1);
DEBUG_CHECK_FIELD(count, 4, 4);
DEBUG_CHECK_FIELD(flags, 8, 2);
DEBUG_CHECK_FIELD(weight, 16, 8);
DEBUG_CHECK_FIELD(value, 24, 8);
DEBUG_CHECK_FIELD(tail, 32, 1);

#define DEBUG_NOINLINE __attribute__((noinline))

DEBUG_NOINLINE int debug_flat_read_first(debug_flat *item);
DEBUG_NOINLINE int debug_flat_read_interior(debug_flat *item);
DEBUG_NOINLINE unsigned int debug_flat_read_flags(debug_flat *item);
DEBUG_NOINLINE double debug_flat_read_weight(debug_flat *item);
DEBUG_NOINLINE int *debug_flat_read_pointer(debug_flat *item);
DEBUG_NOINLINE unsigned int debug_flat_read_final(debug_flat *item);
DEBUG_NOINLINE void debug_flat_write_first(debug_flat *item, signed char replacement);
DEBUG_NOINLINE void debug_flat_write_interior(debug_flat *item, int replacement);
DEBUG_NOINLINE void debug_flat_write_final(debug_flat *item, unsigned char replacement);

#endif
