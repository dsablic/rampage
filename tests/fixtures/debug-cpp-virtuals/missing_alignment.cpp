/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class NoAlignRecord {
public:
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE virtual int readCount();
};

VIRTUAL_CHECK_LAYOUT(NoAlignRecord, 16, 8, 12);
int NoAlignRecord::readCount() { return count; }
extern "C" int debug_noalign_read(NoAlignRecord *record) { return record->readCount(); }
VIRTUAL_EMIT_FACTS(NoAlignRecord, noalign);
