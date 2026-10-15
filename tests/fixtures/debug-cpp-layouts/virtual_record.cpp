/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class alignas(8) VirtualRecord {
public:
    DEBUG_CPP_FIELDS;

    DEBUG_CPP_NOINLINE virtual int readCount();
};

int VirtualRecord::readCount() {
    return count;
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_virtual_read(VirtualRecord *item) {
    return item->VirtualRecord::readCount();
}
