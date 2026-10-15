/* SPDX-License-Identifier: Apache-2.0 */
#include "records.h"

int VirtualRecord::readCount() { return count; }
void VirtualRecord::writeCount(int replacement) { count = replacement; }
unsigned int VirtualRecord::readTail() { return tail; }

int PeerRecord::readCount() { return count + 17; }
void PeerRecord::writeCount(int replacement) { count = replacement - 3; }
unsigned int PeerRecord::readTail() { return static_cast<unsigned int>(tail) + 1; }

extern "C" int debug_virtual_read(VirtualRecord *record) { return record->readCount(); }
extern "C" void debug_virtual_write(VirtualRecord *record, int replacement) { record->writeCount(replacement); }
extern "C" unsigned int debug_virtual_tail(VirtualRecord *record) { return record->readTail(); }
extern "C" int debug_peer_read(PeerRecord *record) { return record->readCount(); }
extern "C" void debug_peer_write(PeerRecord *record, int replacement) { record->writeCount(replacement); }
extern "C" unsigned int debug_peer_tail(PeerRecord *record) { return record->readTail(); }

VIRTUAL_EMIT_FACTS(VirtualRecord, checked);
VIRTUAL_EMIT_FACTS(PeerRecord, peer);
