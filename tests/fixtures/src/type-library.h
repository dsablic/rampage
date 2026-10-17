/* SPDX-License-Identifier: Apache-2.0; original owned type-library fixture. */
#include <stdint.h>

enum TypeLibraryMode {
    TYPE_LIBRARY_IDLE = 0,
    TYPE_LIBRARY_READY = 7,
    TYPE_LIBRARY_FAILED = -3
};

union TypeLibraryPayload {
    uint64_t number;
    uint8_t bytes[8];
};

struct TypeLibraryRecord;
typedef int (*TypeLibraryCallback)(struct TypeLibraryRecord *record, void *context);

typedef struct TypeLibraryRecord {
    uint8_t kind;
    enum TypeLibraryMode mode;
    union TypeLibraryPayload payload;
    TypeLibraryCallback callback;
    struct TypeLibraryRecord *next;
} TypeLibraryRecord;

typedef TypeLibraryRecord (*TypeLibraryFactory)(int count);
typedef int (*TypeLibraryByValue)(TypeLibraryRecord record);

#pragma pack(push, 1)
typedef struct TypeLibraryPacked {
    uint8_t tag;
    uint32_t identifier;
    uint16_t flags;
} TypeLibraryPacked;

#pragma pack(push, 2)
struct TypeLibraryPackTwo {
    uint8_t tag;
    uint32_t value;
};
#pragma pack(pop)

struct TypeLibraryRestoredPackOne {
    uint8_t tag;
    uint32_t value;
};
#pragma pack(pop)

struct TypeLibraryNatural {
    uint8_t tag;
    uint32_t value;
};
