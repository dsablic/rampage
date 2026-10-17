/* SPDX-License-Identifier: Apache-2.0; compiled for static analysis only. */
#include <stddef.h>
#include "type-library.h"

_Static_assert(sizeof(uint8_t) == 1, "fixture requires 8-bit bytes");
_Static_assert(sizeof(uint16_t) == 2, "fixture requires 16-bit uint16_t");
_Static_assert(sizeof(uint32_t) == 4, "fixture requires 32-bit uint32_t");
_Static_assert(sizeof(uint64_t) == 8, "fixture requires 64-bit uint64_t");
_Static_assert(sizeof(enum TypeLibraryMode) == sizeof(int), "fixture requires native int enums");
_Static_assert(sizeof(union TypeLibraryPayload) == 8, "payload size");
_Static_assert(offsetof(union TypeLibraryPayload, number) == 0, "union integer overlay");
_Static_assert(offsetof(union TypeLibraryPayload, bytes) == 0, "union byte overlay");
_Static_assert(sizeof(TypeLibraryPacked) == 7, "packed size");
_Static_assert(offsetof(TypeLibraryPacked, identifier) == 1, "packed identifier offset");
_Static_assert(offsetof(TypeLibraryPacked, flags) == 5, "packed flags offset");
_Static_assert(sizeof(struct TypeLibraryPackTwo) == 6, "nested pack-two size");
_Static_assert(offsetof(struct TypeLibraryPackTwo, value) == 2, "nested pack-two value offset");
_Static_assert(sizeof(struct TypeLibraryRestoredPackOne) == 5, "restored pack-one size");
_Static_assert(offsetof(struct TypeLibraryRestoredPackOne, value) == 1, "restored pack-one value offset");
_Static_assert(offsetof(struct TypeLibraryNatural, value) == 4, "restored natural value offset");

const size_t type_library_layout[] = {
    sizeof(TypeLibraryRecord),
    offsetof(TypeLibraryRecord, kind),
    offsetof(TypeLibraryRecord, mode),
    offsetof(TypeLibraryRecord, payload),
    offsetof(TypeLibraryRecord, callback),
    offsetof(TypeLibraryRecord, next),
    sizeof(TypeLibraryPacked),
    offsetof(TypeLibraryPacked, identifier),
    offsetof(TypeLibraryPacked, flags),
    sizeof(struct TypeLibraryPackTwo),
    offsetof(struct TypeLibraryPackTwo, value),
    sizeof(struct TypeLibraryRestoredPackOne),
    offsetof(struct TypeLibraryRestoredPackOne, value),
    sizeof(struct TypeLibraryNatural),
    offsetof(struct TypeLibraryNatural, value)
};

int type_library_record_score(TypeLibraryRecord *record, void *context)
{
    if (record->mode == TYPE_LIBRARY_FAILED) {
        return -3;
    }
    return (int)record->payload.bytes[0] + record->kind + (context != NULL);
}

int type_library_dispatch(TypeLibraryRecord *record, void *context)
{
    if (record->callback != NULL) {
        return record->callback(record, context);
    }
    return type_library_record_score(record, context);
}

uint32_t type_library_packed_identifier(const TypeLibraryPacked *record)
{
    return record->identifier + record->flags;
}

TypeLibraryRecord type_library_make(int count)
{
    TypeLibraryRecord record = { 0 };
    record.kind = (uint8_t)count;
    record.mode = TYPE_LIBRARY_READY;
    return record;
}

int type_library_take(TypeLibraryRecord record)
{
    return record.kind;
}

int main(void)
{
    TypeLibraryRecord record = { 0 };
    record.mode = TYPE_LIBRARY_READY;
    record.payload.bytes[0] = 5;
    record.callback = type_library_record_score;
    return type_library_dispatch(&record, NULL) == 5 ? 0 : 1;
}
