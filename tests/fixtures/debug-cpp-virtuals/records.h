/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RAMPAGE_DEBUG_CPP_VIRTUAL_RECORDS_H
#define RAMPAGE_DEBUG_CPP_VIRTUAL_RECORDS_H

#if !defined(__clang__) || !defined(__x86_64__) || !defined(__ELF__)
#error "These fixtures require Clang targeting x86_64 ELF"
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "These fixtures require little-endian storage"
#endif

#define VIRTUAL_NOINLINE __attribute__((noinline))
#define VIRTUAL_FIELDS int count; unsigned char tail

class alignas(8) VirtualRecord {
public:
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE virtual int readCount();
    VIRTUAL_NOINLINE virtual void writeCount(int replacement);
    VIRTUAL_NOINLINE unsigned int readTail();
};

class alignas(8) PeerRecord {
public:
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE virtual int readCount();
    VIRTUAL_NOINLINE virtual void writeCount(int replacement);
    VIRTUAL_NOINLINE unsigned int readTail();
};

static_assert(__CHAR_BIT__ == 8, "eight-bit bytes required");
static_assert(sizeof(int) == 4 && sizeof(void *) == 8, "LP64 pointer width required");
static_assert(sizeof(unsigned long long) == 8, "oracle word width required");

/* Clang's non-standard-layout offsetof extension measures data fields, never the artificial vptr. */
#define VIRTUAL_CHECK_LAYOUT(record, bytes, count_offset, tail_offset) \
    static_assert(sizeof(record) == bytes && alignof(record) == 8, "record layout changed"); \
    static_assert(__builtin_offsetof(record, count) == count_offset, "count offset changed"); \
    static_assert(__builtin_offsetof(record, tail) == tail_offset, "tail offset changed"); \
    static_assert(sizeof(((record *)0)->count) == 4, "count width changed"); \
    static_assert(sizeof(((record *)0)->tail) == 1, "tail width changed")

#define VIRTUAL_LAYOUT_FACTS(record) \
    0x52414d5056495231ULL, 1, sizeof(void *), 1, sizeof(record), alignof(record), 2, \
    __builtin_offsetof(record, count), sizeof(((record *)0)->count), alignof(int), \
    __builtin_offsetof(record, tail), sizeof(((record *)0)->tail), alignof(unsigned char)

#define VIRTUAL_EMIT_FACTS(record, key) \
    extern "C" const unsigned long long debug_cpp_virtual_##key##_constants[] \
    __attribute__((used, section(".rampage_virtual_" #key), aligned(8))) = {VIRTUAL_LAYOUT_FACTS(record)}

VIRTUAL_CHECK_LAYOUT(VirtualRecord, 16, 8, 12);
VIRTUAL_CHECK_LAYOUT(PeerRecord, 16, 8, 12);
static_assert(__is_polymorphic(VirtualRecord) && __is_polymorphic(PeerRecord), "virtual dispatch required");
static_assert(!__has_virtual_destructor(VirtualRecord), "positive must not have a virtual destructor");
static_assert(!__has_virtual_destructor(PeerRecord), "positive must not have a virtual destructor");

#endif
