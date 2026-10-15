/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class alignas(8) OverloadRecord {
public:
    DEBUG_CPP_FIELDS;

    DEBUG_CPP_NOINLINE int readCount();
    DEBUG_CPP_NOINLINE int readCount(int delta);
};

int OverloadRecord::readCount() {
    return count;
}

int OverloadRecord::readCount(int delta) {
    return count + delta;
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_overload_plain(OverloadRecord *item) {
    return item->readCount();
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_overload_delta(OverloadRecord *item, int delta) {
    return item->readCount(delta);
}
