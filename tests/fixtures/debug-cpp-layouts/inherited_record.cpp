/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class BaseRecord {
public:
    int count;
};

class alignas(8) InheritedRecord : public BaseRecord {
public:
    double weight;

    DEBUG_CPP_NOINLINE int readCount();
};

int InheritedRecord::readCount() {
    return count;
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_inherited_read(InheritedRecord *item) {
    return item->readCount();
}
