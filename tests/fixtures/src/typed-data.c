/* SPDX-License-Identifier: Apache-2.0; compile and inspect, never execute. */
#include <stddef.h>
#include "typed-data.h"

_Static_assert(sizeof(struct TypedRecord) == 16, "record stride");
_Static_assert(offsetof(struct TypedRecord, mode) == 0, "mode offset");
_Static_assert(offsetof(struct TypedRecord, value) == 4, "value offset");
_Static_assert(offsetof(struct TypedRecord, label) == 8, "label offset");

const struct TypedRecord typed_records[2] = {
    { MODE_READY, 42, "alpha" },
    { MODE_FAULT, -7, "beta" }
};

const unsigned char typed_utf8[8] = { 0x47, 0x72, 0xc3, 0xbc, 0xc3, 0x9f, 0x65, 0 };
const uint16_t typed_utf16[4] = { 0x0041, 0xd83d, 0xde80, 0 };
const uint64_t typed_large = UINT64_C(0xfedcba9876543210);
const uint32_t typed_nan_bits = UINT32_C(0x7fc00000);
const uint32_t typed_layout[] = { sizeof(struct TypedRecord), 0, 4, 8, 2 };

__attribute__((noinline)) int typed_query(const struct TypedRecord *record)
{
    if (record->mode == MODE_READY) {
        return record->value;
    }
    return 0;
}

__attribute__((noinline)) int typed_global_query(void)
{
    return typed_query(&typed_records[0]) + typed_query(&typed_records[1]);
}
