/* SPDX-License-Identifier: Apache-2.0; original checked-debug fixture, never executed. */
enum DebugMode { DEBUG_OFF = 0, DEBUG_READY = 7, DEBUG_FAULT = -3 };

struct DebugInner { int gain; short bias; };
union DebugPayload { long long number; unsigned char bytes[8]; };
struct DebugRecord;
typedef int (*DebugCallback)(struct DebugRecord *record, int value);

struct DebugRecord {
    unsigned int identifier;
    struct DebugInner nested;
    struct DebugInner taps[2];
    enum DebugMode mode;
    union DebugPayload payload;
    struct DebugRecord *next;
    DebugCallback callback;
};

struct DebugBits { unsigned int active:1; unsigned int mode:3; unsigned int reserved:28; };

struct DebugRecord debug_record = { 11, { 3, 5 }, { { 7, 2 }, { 9, 4 } }, DEBUG_READY, { 17 }, 0, 0 };
struct DebugBits debug_bits = { 1, 3, 0 };

_Static_assert(sizeof(struct DebugInner) == 8, "inner size");
_Static_assert(sizeof(struct DebugRecord) == 56, "record size");
_Static_assert(__builtin_offsetof(struct DebugRecord, nested) == 4, "nested offset");
_Static_assert(__builtin_offsetof(struct DebugRecord, taps) == 12, "array offset");
_Static_assert(__builtin_offsetof(struct DebugRecord, mode) == 28, "enum offset");
_Static_assert(__builtin_offsetof(struct DebugRecord, payload) == 32, "union offset");
_Static_assert(__builtin_offsetof(struct DebugRecord, next) == 40, "self pointer offset");
_Static_assert(__builtin_offsetof(struct DebugRecord, callback) == 48, "callback offset");

const unsigned int debug_type_layout[] = {
    sizeof(struct DebugInner), __alignof__(struct DebugInner),
    sizeof(struct DebugRecord), __alignof__(struct DebugRecord),
    __builtin_offsetof(struct DebugRecord, identifier), __builtin_offsetof(struct DebugRecord, nested),
    __builtin_offsetof(struct DebugRecord, taps), __builtin_offsetof(struct DebugRecord, mode),
    __builtin_offsetof(struct DebugRecord, payload), __builtin_offsetof(struct DebugRecord, next),
    __builtin_offsetof(struct DebugRecord, callback), sizeof(union DebugPayload),
    __alignof__(union DebugPayload), sizeof(struct DebugBits)
};

__attribute__((noinline)) int debug_types_query(struct DebugRecord *record, int index)
{
    if (record->mode != DEBUG_READY) return record->payload.bytes[0];
    return record->nested.gain + record->taps[index & 1].bias;
}

__attribute__((noinline)) struct DebugRecord *debug_types_identity(struct DebugRecord *record)
{
    __asm__ volatile ("" : "+r" (record) : : "memory");
    return record;
}

int debug_types_main(void)
{
    return debug_types_query(&debug_record, debug_bits.mode);
}
