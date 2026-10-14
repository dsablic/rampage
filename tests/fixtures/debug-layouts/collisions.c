/* SPDX-License-Identifier: Apache-2.0 */
struct __attribute__((aligned(8))) debug_collision$slot {
    int first;
    unsigned char tail;
};

struct __attribute__((aligned(8))) debug_collision_slot {
    unsigned long long first;
    int tail;
};

_Static_assert(sizeof(struct debug_collision$slot) == 8, "dollar identity size");
_Static_assert(sizeof(struct debug_collision_slot) == 16, "underscore identity size");
_Static_assert(__builtin_offsetof(struct debug_collision$slot, tail) == 4, "dollar identity tail");
_Static_assert(__builtin_offsetof(struct debug_collision_slot, tail) == 8, "underscore identity tail");

__attribute__((noinline)) unsigned int debug_collision_dollar(struct debug_collision$slot *item) {
    return item->tail;
}

__attribute__((noinline)) int debug_collision_underscore(struct debug_collision_slot *item) {
    return item->tail;
}

__attribute__((used, section(".rampage_collision_dollar"), aligned(8)))
const unsigned long long debug_collision_dollar_constants[] = {
    sizeof(struct debug_collision$slot), _Alignof(struct debug_collision$slot),
    __builtin_offsetof(struct debug_collision$slot, first), sizeof(((struct debug_collision$slot *)0)->first),
    __builtin_offsetof(struct debug_collision$slot, tail), sizeof(((struct debug_collision$slot *)0)->tail),
};

__attribute__((used, section(".rampage_collision_underscore"), aligned(8)))
const unsigned long long debug_collision_underscore_constants[] = {
    sizeof(struct debug_collision_slot), _Alignof(struct debug_collision_slot),
    __builtin_offsetof(struct debug_collision_slot, first), sizeof(((struct debug_collision_slot *)0)->first),
    __builtin_offsetof(struct debug_collision_slot, tail), sizeof(((struct debug_collision_slot *)0)->tail),
};
