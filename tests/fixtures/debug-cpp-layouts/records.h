/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RAMPAGE_DEBUG_CPP_RECORDS_H
#define RAMPAGE_DEBUG_CPP_RECORDS_H

#if !defined(__x86_64__) || !defined(__ELF__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "These fixtures require x86_64 little-endian ELF"
#endif

#define DEBUG_CPP_NOINLINE __attribute__((noinline))
#define DEBUG_CPP_FIELDS \
    signed char tag; \
    int count; \
    unsigned short flags; \
    double weight; \
    int *value; \
    unsigned char tail

class alignas(8) CheckedRecord {
public:
    DEBUG_CPP_FIELDS;

    DEBUG_CPP_NOINLINE int readTag();
    DEBUG_CPP_NOINLINE int readCount();
    DEBUG_CPP_NOINLINE unsigned int readTail();
    DEBUG_CPP_NOINLINE void writeCount(int replacement);
};

struct alignas(8) CompanionRecord {
    DEBUG_CPP_FIELDS;

    DEBUG_CPP_NOINLINE int readCount();
};

static_assert(__CHAR_BIT__ == 8, "eight-bit bytes required");
static_assert(sizeof(int) == 4 && sizeof(void *) == 8, "x86_64 LP64 required");
static_assert(sizeof(unsigned long long) == 8, "oracle word width required");

#define DEBUG_CPP_CHECK_FIELD(record, member, offset, width) \
    static_assert(__builtin_offsetof(record, member) == offset, "field offset changed"); \
    static_assert(sizeof(((record *)0)->member) == width, "field width changed")

#define DEBUG_CPP_CHECK_LAYOUT(record) \
    static_assert(__is_standard_layout(record), "offsetof requires standard layout"); \
    static_assert(__is_trivial(record), "no user constructor or destructor"); \
    static_assert(sizeof(record) == 40 && alignof(record) == 8, "record layout changed"); \
    DEBUG_CPP_CHECK_FIELD(record, tag, 0, 1); \
    DEBUG_CPP_CHECK_FIELD(record, count, 4, 4); \
    DEBUG_CPP_CHECK_FIELD(record, flags, 8, 2); \
    DEBUG_CPP_CHECK_FIELD(record, weight, 16, 8); \
    DEBUG_CPP_CHECK_FIELD(record, value, 24, 8); \
    DEBUG_CPP_CHECK_FIELD(record, tail, 32, 1)

DEBUG_CPP_CHECK_LAYOUT(CheckedRecord);
DEBUG_CPP_CHECK_LAYOUT(CompanionRecord);

#define DEBUG_CPP_FIELD_FACTS(record, member, ctype) \
    __builtin_offsetof(record, member), sizeof(((record *)0)->member), alignof(ctype)

#define DEBUG_CPP_LAYOUT_FACTS(record) \
    0x52414d5043505031ULL, 1, 8, 1, sizeof(record), alignof(record), 6, \
    DEBUG_CPP_FIELD_FACTS(record, tag, signed char), \
    DEBUG_CPP_FIELD_FACTS(record, count, int), \
    DEBUG_CPP_FIELD_FACTS(record, flags, unsigned short), \
    DEBUG_CPP_FIELD_FACTS(record, weight, double), \
    DEBUG_CPP_FIELD_FACTS(record, value, int *), \
    DEBUG_CPP_FIELD_FACTS(record, tail, unsigned char)

#endif
