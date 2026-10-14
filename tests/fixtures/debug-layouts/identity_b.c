/* SPDX-License-Identifier: Apache-2.0 */
#include "identity.h"

__attribute__((noinline)) unsigned int debug_identity_b(struct debug_identity *item) {
    return item->tail;
}

__attribute__((used, section(".rampage_identity_b"), aligned(8)))
const unsigned long long debug_identity_b_constants[] = {
    sizeof(struct debug_identity), _Alignof(struct debug_identity),
    __builtin_offsetof(struct debug_identity, first), sizeof(((struct debug_identity *)0)->first),
    __builtin_offsetof(struct debug_identity, tail), sizeof(((struct debug_identity *)0)->tail),
};
