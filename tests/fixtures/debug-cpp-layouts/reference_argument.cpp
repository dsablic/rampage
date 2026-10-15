/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class alignas(8) ReferenceRecord {
public:
    DEBUG_CPP_FIELDS;

    DEBUG_CPP_NOINLINE void writeCount(int &replacement);
};

void ReferenceRecord::writeCount(int &replacement) {
    count = replacement;
}

extern "C" DEBUG_CPP_NOINLINE void debug_cpp_reference_write(ReferenceRecord *item, int *replacement) {
    item->writeCount(*replacement);
}
