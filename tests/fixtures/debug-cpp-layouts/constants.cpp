/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

extern "C" {
__attribute__((used, section(".rampage_cpp_checked"), aligned(8)))
extern const unsigned long long debug_cpp_checked_constants[] = {
    DEBUG_CPP_LAYOUT_FACTS(CheckedRecord),
};

__attribute__((used, section(".rampage_cpp_companion"), aligned(8)))
extern const unsigned long long debug_cpp_companion_constants[] = {
    DEBUG_CPP_LAYOUT_FACTS(CompanionRecord),
};
}

static_assert(sizeof(debug_cpp_checked_constants) == 200, "oracle is 25 LE u64 words");
static_assert(sizeof(debug_cpp_companion_constants) == 200, "oracle is 25 LE u64 words");
