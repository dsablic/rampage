/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class alignas(8) StaticRecord {
public:
    DEBUG_CPP_FIELDS;

    DEBUG_CPP_NOINLINE static int readCount(StaticRecord *item);
};

int StaticRecord::readCount(StaticRecord *item) {
    return item->count;
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_static_read(StaticRecord *item) {
    return StaticRecord::readCount(item);
}
