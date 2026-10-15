/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class UnalignedRecord {
public:
    DEBUG_CPP_FIELDS;

    DEBUG_CPP_NOINLINE int readCount();
};

DEBUG_CPP_CHECK_LAYOUT(UnalignedRecord);

int UnalignedRecord::readCount() {
    return count;
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_unaligned_read(UnalignedRecord *item) {
    return item->readCount();
}

extern "C" {
__attribute__((used, section(".rampage_cpp_unaligned"), aligned(8)))
extern const unsigned long long debug_cpp_unaligned_constants[] = {
    DEBUG_CPP_LAYOUT_FACTS(UnalignedRecord),
};
}

static_assert(sizeof(debug_cpp_unaligned_constants) == 200, "oracle is 25 LE u64 words");
