/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RAMPAGE_DEBUG_IDENTITY_H
#define RAMPAGE_DEBUG_IDENTITY_H

struct __attribute__((aligned(8))) debug_identity {
    int first;
    unsigned char tail;
};

_Static_assert(sizeof(struct debug_identity) == 8, "compatible identity size");
_Static_assert(_Alignof(struct debug_identity) == 8, "compatible identity alignment");
_Static_assert(__builtin_offsetof(struct debug_identity, tail) == 4, "compatible identity tail");

#endif
