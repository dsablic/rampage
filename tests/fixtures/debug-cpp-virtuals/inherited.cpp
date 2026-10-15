/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

class alignas(8) LeftRecord {
public:
    VIRTUAL_NOINLINE virtual int readLeft();
};

class alignas(8) RightRecord {
public:
    VIRTUAL_NOINLINE virtual int readRight();
};

class alignas(8) InheritedRecord : public LeftRecord, public RightRecord {
public:
    VIRTUAL_FIELDS;
    VIRTUAL_NOINLINE int readLeft() override;
    VIRTUAL_NOINLINE int readRight() override;
};

VIRTUAL_CHECK_LAYOUT(InheritedRecord, 24, 16, 20);
static_assert(sizeof(LeftRecord) == 8 && sizeof(RightRecord) == 8, "secondary base offset changed");
int LeftRecord::readLeft() { return 1; }
int RightRecord::readRight() { return 2; }
int InheritedRecord::readLeft() { return count; }
int InheritedRecord::readRight() { return count + 1; }
extern "C" int debug_inherited_left(InheritedRecord *record) { return record->readLeft(); }
extern "C" int debug_inherited_right(RightRecord *record) { return record->readRight(); }
VIRTUAL_EMIT_FACTS(InheritedRecord, inherited);
