/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

int CheckedRecord::readTag() {
    return tag;
}

int CheckedRecord::readCount() {
    return count;
}

unsigned int CheckedRecord::readTail() {
    return tail;
}

void CheckedRecord::writeCount(int replacement) {
    count = replacement;
}

int CompanionRecord::readCount() {
    return count;
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_read_tag(CheckedRecord *item) {
    return item->readTag();
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_read_count(CheckedRecord *item) {
    return item->readCount();
}

extern "C" DEBUG_CPP_NOINLINE unsigned int debug_cpp_read_tail(CheckedRecord *item) {
    return item->readTail();
}

extern "C" DEBUG_CPP_NOINLINE void debug_cpp_write_count(CheckedRecord *item, int replacement) {
    item->writeCount(replacement);
}

extern "C" DEBUG_CPP_NOINLINE int debug_cpp_companion_read(CompanionRecord *item) {
    return item->readCount();
}
