/* SPDX-License-Identifier: Apache-2.0 */
#include "identity.h"

__attribute__((noinline)) int debug_identity_a(struct debug_identity *item) {
    return item->first;
}

__attribute__((used, section(".rampage_identity_a"), aligned(8)))
const unsigned long long debug_identity_a_constants[] = {
    sizeof(struct debug_identity), _Alignof(struct debug_identity),
    __builtin_offsetof(struct debug_identity, first), sizeof(((struct debug_identity *)0)->first),
    __builtin_offsetof(struct debug_identity, tail), sizeof(((struct debug_identity *)0)->tail),
};
