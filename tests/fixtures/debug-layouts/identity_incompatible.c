/* SPDX-License-Identifier: Apache-2.0 */
struct __attribute__((aligned(8))) debug_identity {
    unsigned long long first;
    int tail;
};

_Static_assert(sizeof(struct debug_identity) == 16, "incompatible identity size");
_Static_assert(_Alignof(struct debug_identity) == 8, "incompatible identity alignment");
_Static_assert(__builtin_offsetof(struct debug_identity, tail) == 8, "incompatible identity tail");

__attribute__((noinline)) int debug_identity_incompatible(struct debug_identity *item) {
    return item->tail;
}

__attribute__((used, section(".rampage_identity_incompatible"), aligned(8)))
const unsigned long long debug_identity_incompatible_constants[] = {
    sizeof(struct debug_identity), _Alignof(struct debug_identity),
    __builtin_offsetof(struct debug_identity, first), sizeof(((struct debug_identity *)0)->first),
    __builtin_offsetof(struct debug_identity, tail), sizeof(((struct debug_identity *)0)->tail),
};
