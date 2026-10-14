/* SPDX-License-Identifier: Apache-2.0 */
#include "flat.h"

struct debug_missing_alignment {
    signed char tag;
    int count;
    unsigned short flags;
    double weight;
    int *value;
    unsigned char tail;
};

struct __attribute__((packed)) debug_packed {
    unsigned char first;
    int tail;
};

struct __attribute__((aligned(16))) debug_overaligned {
    int first;
    unsigned char tail;
};

union __attribute__((aligned(8))) debug_union {
    int first;
    unsigned long long alternate;
};

struct __attribute__((aligned(8))) debug_bitfields {
    unsigned int first : 3;
    unsigned int flags : 5;
    int tail;
};

struct debug_leaf {
    int value;
};

struct __attribute__((aligned(8))) debug_nested {
    int first;
    struct debug_leaf inner;
    unsigned char tail;
};

struct __attribute__((aligned(8))) debug_recursive {
    int first;
    struct debug_recursive *next;
};

struct __attribute__((aligned(8))) debug_array {
    int first;
    unsigned short samples[2];
};

struct __attribute__((aligned(8))) debug_flexible {
    int count;
    unsigned char bytes[];
};

struct debug_unknown;

_Static_assert(sizeof(struct debug_missing_alignment) == 40, "missing alignment is not wrong size");
_Static_assert(_Alignof(struct debug_missing_alignment) == 8, "missing alignment is naturally supported");
_Static_assert(sizeof(struct debug_packed) == 5 && _Alignof(struct debug_packed) == 1, "packed refusal");
_Static_assert(__builtin_offsetof(struct debug_packed, tail) == 1, "packed unaligned member");
_Static_assert(sizeof(struct debug_overaligned) == 16 && _Alignof(struct debug_overaligned) == 16, "overalignment");
_Static_assert(sizeof(union debug_union) == 8, "union refusal");
_Static_assert(sizeof(struct debug_bitfields) == 8, "bitfield refusal");
_Static_assert(sizeof(struct debug_nested) == 16, "nested refusal");
_Static_assert(sizeof(struct debug_recursive) == 16, "recursive refusal");
_Static_assert(sizeof(struct debug_array) == 8, "array refusal");
_Static_assert(sizeof(struct debug_flexible) == 8, "flexible refusal");

DEBUG_NOINLINE int debug_missing_alignment_read(struct debug_missing_alignment *item) {
    return item->count;
}

DEBUG_NOINLINE int debug_packed_read(struct debug_packed *item) {
    return item->tail;
}

DEBUG_NOINLINE int debug_overaligned_read(struct debug_overaligned *item) {
    return item->first;
}

DEBUG_NOINLINE int debug_union_read(union debug_union *item) {
    return item->first;
}

DEBUG_NOINLINE unsigned int debug_bitfields_read(struct debug_bitfields *item) {
    return item->flags;
}

DEBUG_NOINLINE int debug_nested_read(struct debug_nested *item) {
    return item->inner.value;
}

DEBUG_NOINLINE int debug_recursive_read(struct debug_recursive *item) {
    return item->next->first;
}

DEBUG_NOINLINE unsigned int debug_array_read(struct debug_array *item) {
    return item->samples[1];
}

DEBUG_NOINLINE unsigned int debug_flexible_read(struct debug_flexible *item) {
    return item->bytes[0];
}

DEBUG_NOINLINE int debug_unknown_pointer(struct debug_unknown *item) {
    return item != 0;
}

DEBUG_NOINLINE int debug_by_value_argument(debug_flat item) {
    return item.count;
}

DEBUG_NOINLINE debug_flat debug_by_value_return(debug_flat *item) {
    return *item;
}
