/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class alignas(8) CallbackRecord {
public:
    int (*callback)(CallbackRecord *);
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE int readCount();
};

class alignas(8) ChainRecord {
public:
    int (**callback)(ChainRecord *);
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE int readCount();
};

VIRTUAL_CHECK_LAYOUT(CallbackRecord, 16, 8, 12);
VIRTUAL_CHECK_LAYOUT(ChainRecord, 16, 8, 12);
static_assert(!__is_polymorphic(CallbackRecord) && !__is_polymorphic(ChainRecord), "ordinary pointer controls");
static_assert(__builtin_offsetof(CallbackRecord, callback) == 0, "ordinary callback at zero");
static_assert(__builtin_offsetof(ChainRecord, callback) == 0, "ordinary pointer chain at zero");
int CallbackRecord::readCount() { return count; }
int ChainRecord::readCount() { return count; }
extern "C" int debug_callback_read(CallbackRecord *record) { return record->readCount(); }
extern "C" int debug_chain_read(ChainRecord *record) { return record->readCount(); }
VIRTUAL_EMIT_FACTS(CallbackRecord, callback);
VIRTUAL_EMIT_FACTS(ChainRecord, chain);
