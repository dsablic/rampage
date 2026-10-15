/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class alignas(8) ConstRecord {
public:
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE virtual int readCount() const;
};

class alignas(8) ReferenceRecord {
public:
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE virtual void writeCount(int &replacement);
};

struct ValuePayload { int count; };
class alignas(8) ValueRecord {
public:
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE virtual int readOther(ValuePayload other);
    VIRTUAL_NOINLINE virtual ValuePayload copy();
};

class alignas(8) DestructorRecord {
public:
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE virtual ~DestructorRecord();
    VIRTUAL_NOINLINE virtual int readCount();
    static void operator delete(void *);
};

VIRTUAL_CHECK_LAYOUT(ConstRecord, 16, 8, 12);
VIRTUAL_CHECK_LAYOUT(ReferenceRecord, 16, 8, 12);
VIRTUAL_CHECK_LAYOUT(ValueRecord, 16, 8, 12);
VIRTUAL_CHECK_LAYOUT(DestructorRecord, 16, 8, 12);
int ConstRecord::readCount() const { return count; }
void ReferenceRecord::writeCount(int &replacement) { count = replacement; }
int ValueRecord::readOther(ValuePayload other) { return other.count; }
ValuePayload ValueRecord::copy() { return {count}; }
DestructorRecord::~DestructorRecord() { count = 0; }
int DestructorRecord::readCount() { return count; }
void DestructorRecord::operator delete(void *) {}

extern "C" int debug_const_read(const ConstRecord *record) { return record->readCount(); }
extern "C" void debug_reference_write(ReferenceRecord *record, int *replacement) { record->writeCount(*replacement); }
extern "C" int debug_value_argument(ValueRecord *record, int count) { return record->readOther({count}); }
extern "C" int debug_value_return(ValueRecord *record) { return record->copy().count; }
extern "C" int debug_destructor_read(DestructorRecord *record) { return record->readCount(); }
VIRTUAL_EMIT_FACTS(ConstRecord, constant);
VIRTUAL_EMIT_FACTS(ReferenceRecord, reference);
VIRTUAL_EMIT_FACTS(ValueRecord, value);
VIRTUAL_EMIT_FACTS(DestructorRecord, destructor);
