/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class alignas(8) ValueRecord {
public:
    DEBUG_CPP_FIELDS;

    DEBUG_CPP_NOINLINE int readOther(ValueRecord other);
    DEBUG_CPP_NOINLINE ValueRecord copy();
};

int ValueRecord::readOther(ValueRecord other) {
    return other.count;
}

ValueRecord ValueRecord::copy() {
    return *this;
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_byvalue_argument(ValueRecord *item, ValueRecord *other) {
    return item->readOther(*other);
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_byvalue_return(ValueRecord *item) {
    return item->copy().count;
}
