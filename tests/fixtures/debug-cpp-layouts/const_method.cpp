/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class alignas(8) ConstRecord {
public:
    DEBUG_CPP_FIELDS;

    DEBUG_CPP_NOINLINE int readCount() const;
};

int ConstRecord::readCount() const {
    return count;
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_const_read(const ConstRecord *item) {
    return item->readCount();
}
