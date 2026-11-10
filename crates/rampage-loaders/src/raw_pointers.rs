//! Opt-in function discovery from tables of Thumb code pointers for the `ARM:LE:32:Cortex` Raw profile.
//!
//! A word is a code pointer when bit 0 is set, its target lies inside the mapped range and the target decodes like
//! code: a `push {…, lr}` in its first instructions, a `bl` elsewhere that calls it, or a straight-line decode that
//! reaches a return or branch. A table is a run of at least three code pointers at one stride (empty slots allowed
//! between them), and it is accepted only when one target has strong evidence (the prologue or the call), which
//! switch tables of case labels, string pointers and constants lack. Every table found is reported with its
//! verdict and the evidence per entry; only accepted entries become seeds.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::Arc;

use rampage_arch::{Arch, Flow, Target};
use serde::Serialize;

/// Code pointers a run needs before it is judged as a table.
pub const MIN_TABLE_ENTRIES: usize = 3;
/// Strides tried, in words: plain arrays and arrays of structs up to four words with one code pointer each.
const MAX_STRIDE_WORDS: usize = 4;
/// Empty (zero or erased) slots a run may skip in a row, like reserved vector slots.
const MAX_EMPTY_GAP: usize = 8;
/// Instructions a target's straight-line decode may take to reach an exit.
const MAX_WALK: usize = 256;
/// Instructions from a target within which a `push {…, lr}` counts as its prologue.
const PROLOGUE_WINDOW: usize = 4;
/// Refused tables listed; more are counted in `refused_tables_not_listed`.
const MAX_LISTED_REFUSED: usize = 64;
const ERASED: u32 = 0xffff_ffff;

/// Why an entry's target looks like code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// One of its first four instructions pushes `lr`: a non-leaf prologue. Strong.
    PushLr,
    /// A `bl` somewhere in the image calls it. Strong.
    CallTarget,
    /// Its straight-line decode reaches a return, branch or halt before any undecodable bytes. Weak: case labels
    /// and other code inside a function do too.
    ReachesExit,
}

impl Evidence {
    fn strong(self) -> bool {
        matches!(self, Evidence::PushLr | Evidence::CallTarget)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    /// A seed: the table was accepted.
    Accepted,
    /// Zero or 0xFFFFFFFF between code pointers: an empty slot.
    Empty,
    /// A code pointer in a refused table.
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TableStatus {
    Accepted,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TableRefusedReason {
    /// No target opens with a `push {…, lr}` or is a `bl` target: the shape of a switch table of case labels, or
    /// of constants that happen to point into code.
    NoStrongEvidence,
    /// Fewer than two distinct targets, like a fault-handler table that names one function throughout.
    TooFewFunctions,
}

/// One slot of a table and the verdict on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableEntry {
    pub index: u16,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub word: u64,
    pub status: EntryStatus,
    /// The instruction the word points at (Thumb bit cleared); absent for an empty slot.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// A run of code pointers at one stride.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PointerTable {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// Bytes from one entry to the next: 4 for an array, more for an array of structs.
    pub stride: u8,
    pub status: TableStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<TableRefusedReason>,
    pub entries: Vec<TableEntry>,
}

/// What the pointer-table scan found. Accepted tables are always listed; refused ones up to 64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PointerTables {
    /// Word-aligned words read (the vector table's words, when read, are skipped).
    pub words_scanned: usize,
    /// Words with bit 0 set and a target inside the image whose target does not decode like code; never used.
    pub pointers_without_evidence: usize,
    /// Code pointers in no run of at least three; never used.
    pub isolated_pointers: usize,
    pub accepted_tables: usize,
    pub refused_tables: usize,
    pub refused_tables_not_listed: usize,
    /// Distinct accepted targets.
    pub seeds: usize,
    pub tables: Vec<PointerTable>,
    pub note: &'static str,
}

impl PointerTables {
    /// Every accepted target, in table order (duplicates kept).
    pub fn targets(&self) -> impl Iterator<Item = u64> + '_ {
        self.tables
            .iter()
            .flat_map(|table| &table.entries)
            .filter(|entry| entry.status == EntryStatus::Accepted)
            .filter_map(|entry| entry.target)
    }
}

/// Scans `bytes` mapped at `base` for tables of Thumb code pointers, skipping the `skip` range (a vector table
/// already read).
pub(crate) fn scan(bytes: &[u8], base: u64, skip: Option<Range<u64>>) -> PointerTables {
    let end = base + bytes.len() as u64;
    let first = base.next_multiple_of(4);
    let count = usize::try_from(end.saturating_sub(first) / 4).unwrap_or(0);
    let slot = |index: usize| first + 4 * index as u64;
    let skipped = |index: usize| skip.as_ref().is_some_and(|range| range.contains(&slot(index)));
    let words: Vec<u32> = (0..count)
        .map(|index| {
            let offset = (slot(index) - base) as usize;
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
        })
        .collect();

    // Judge every pointer-shaped word once per target.
    let mut judge = Judge::new(bytes, base);
    let mut evidence: Vec<Option<Vec<Evidence>>> = vec![None; count];
    let mut without_evidence = 0;
    for index in 0..count {
        let word = u64::from(words[index]);
        if skipped(index) || word & 1 == 0 || words[index] == ERASED || !(base..end).contains(&(word & !1)) {
            continue;
        }
        let found = judge.evidence(word & !1);
        if found.is_empty() {
            without_evidence += 1;
        } else {
            evidence[index] = Some(found);
        }
    }
    let code = |index: usize| evidence[index].is_some();
    let empty = |index: usize| !skipped(index) && matches!(words[index], 0 | ERASED);

    let mut used = vec![false; count];
    let mut accepted = Vec::new();
    let mut refused = Vec::new();
    let mut refused_tables = 0;
    // Plain arrays first, then wider strides over what is left, so a struct array never swallows a plain one.
    for stride in 1..=MAX_STRIDE_WORDS {
        for start in 0..count {
            if used[start] || !code(start) {
                continue;
            }
            let mut slots = Vec::new();
            let mut gap = 0;
            let mut index = start;
            while index < count && !used[index] {
                if code(index) {
                    gap = 0;
                } else if empty(index) && gap < MAX_EMPTY_GAP {
                    gap += 1;
                } else {
                    break;
                }
                slots.push(index);
                index += stride;
            }
            slots.truncate(slots.len() - gap);
            if slots.iter().filter(|&&index| code(index)).count() < MIN_TABLE_ENTRIES {
                continue;
            }
            for &index in &slots {
                used[index] = true;
            }
            let entries = slots
                .iter()
                .enumerate()
                .map(|(position, &index)| TableEntry {
                    index: position as u16,
                    address: slot(index),
                    word: u64::from(words[index]),
                    status: if code(index) { EntryStatus::Accepted } else { EntryStatus::Empty },
                    target: code(index).then_some(u64::from(words[index]) & !1),
                    evidence: evidence[index].clone().unwrap_or_default(),
                })
                .collect();
            let table = verdict(slot(start), (4 * stride) as u8, entries);
            if table.status == TableStatus::Accepted {
                accepted.push(table);
            } else {
                refused_tables += 1;
                if refused.len() < MAX_LISTED_REFUSED {
                    refused.push(table);
                }
            }
        }
    }
    let isolated = (0..count).filter(|&index| code(index) && !used[index]).count();
    let accepted_tables = accepted.len();
    let listed_refused = refused.len();
    let mut tables = accepted;
    tables.extend(refused);
    tables.sort_by_key(|table| table.address);
    let mut result = PointerTables {
        words_scanned: (0..count).filter(|&index| !skipped(index)).count(),
        pointers_without_evidence: without_evidence,
        isolated_pointers: isolated,
        accepted_tables,
        refused_tables,
        refused_tables_not_listed: refused_tables - listed_refused,
        seeds: 0,
        tables,
        note: "a table is a run of at least three Thumb code pointers whose targets decode like code; it is accepted \
               when two targets differ and one opens with push {..., lr} or is a bl target, and its targets become \
               seeds",
    };
    result.seeds = result.targets().collect::<BTreeSet<_>>().len();
    result
}

/// Accepts a run when it names two functions and one target has strong evidence; otherwise refuses every entry.
fn verdict(address: u64, stride: u8, mut entries: Vec<TableEntry>) -> PointerTable {
    let targets: BTreeSet<u64> = entries.iter().filter_map(|entry| entry.target).collect();
    let strong = entries.iter().flat_map(|entry| &entry.evidence).any(|evidence| evidence.strong());
    let refused_reason = if !strong {
        Some(TableRefusedReason::NoStrongEvidence)
    } else if targets.len() < 2 {
        Some(TableRefusedReason::TooFewFunctions)
    } else {
        None
    };
    if refused_reason.is_some() {
        for entry in entries.iter_mut().filter(|entry| entry.status == EntryStatus::Accepted) {
            entry.status = EntryStatus::Refused;
        }
    }
    let status = if refused_reason.is_some() { TableStatus::Refused } else { TableStatus::Accepted };
    PointerTable { address, stride, status, refused_reason, entries }
}

/// Judges targets by decoding them in Thumb mode, with the image's `bl` targets as evidence.
struct Judge<'a> {
    bytes: &'a [u8],
    base: u64,
    decoder: Box<dyn rampage_arch::Disassembler>,
    calls: BTreeSet<u64>,
    cache: BTreeMap<u64, Vec<Evidence>>,
}

impl<'a> Judge<'a> {
    fn new(bytes: &'a [u8], base: u64) -> Self {
        let end = base + bytes.len() as u64;
        let target = Target {
            thumb: Arc::from(std::iter::once(base..end).collect::<Vec<_>>()),
            m_profile: true,
            ..Target::new(Arch::Arm)
        };
        let decoder = rampage_arch::decoder(&target).expect("the native ARM decoder is always available");
        Self { bytes, base, decoder, calls: bl_targets(bytes, base), cache: BTreeMap::new() }
    }

    fn halfword(&self, address: u64) -> Option<u16> {
        let offset = usize::try_from(address.checked_sub(self.base)?).ok()?;
        Some(u16::from_le_bytes(self.bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
    }

    /// The evidence that `target` is code; empty when its first instruction does not decode or nothing was found.
    fn evidence(&mut self, target: u64) -> Vec<Evidence> {
        if let Some(found) = self.cache.get(&target) {
            return found.clone();
        }
        let found = self.walk(target);
        self.cache.insert(target, found.clone());
        found
    }

    fn walk(&mut self, target: u64) -> Vec<Evidence> {
        let mut evidence = BTreeSet::new();
        let mut address = target;
        self.decoder.begin_run();
        for step in 0..MAX_WALK {
            let offset = (address - self.base) as usize;
            let Some(bytes) = self.bytes.get(offset..).filter(|bytes| !bytes.is_empty()) else { break };
            let insn = self.decoder.decode(&bytes[..bytes.len().min(4)], address);
            if insn.flow == Flow::Invalid || insn.len == 0 {
                if step == 0 {
                    return Vec::new();
                }
                break;
            }
            if step < PROLOGUE_WINDOW && self.pushes_lr(address) {
                evidence.insert(Evidence::PushLr);
            }
            if !insn.conditional && matches!(insn.flow, Flow::Return | Flow::Jump(_) | Flow::IndirectJump | Flow::Halt)
            {
                evidence.insert(Evidence::ReachesExit);
                break;
            }
            address += u64::from(insn.len);
        }
        if self.calls.contains(&target) {
            evidence.insert(Evidence::CallTarget);
        }
        evidence.into_iter().collect()
    }

    /// `push {…, lr}` (T1), `push.w {…, lr}` (T2) or `str lr, [sp, #-4]!` (T3).
    fn pushes_lr(&self, address: u64) -> bool {
        let Some(first) = self.halfword(address) else { return false };
        if first & 0xff00 == 0xb500 {
            return true;
        }
        let second = self.halfword(address + 2);
        match first {
            0xe92d => second.is_some_and(|second| second & 0x4000 != 0),
            0xf84d => second == Some(0xed04),
            _ => false,
        }
    }
}

/// Targets of every Thumb `bl` encoding at a halfword boundary, kept when they land inside the image.
fn bl_targets(bytes: &[u8], base: u64) -> BTreeSet<u64> {
    let end = base + bytes.len() as u64;
    let halfwords: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    halfwords
        .windows(2)
        .enumerate()
        .filter(|(_, pair)| pair[0] & 0xf800 == 0xf000 && pair[1] & 0xd000 == 0xd000)
        .filter_map(|(index, pair)| {
            let (first, second) = (u32::from(pair[0]), u32::from(pair[1]));
            let sign = (first >> 10) & 1;
            let i1 = !((second >> 13) & 1 ^ sign) & 1;
            let i2 = !((second >> 11) & 1 ^ sign) & 1;
            let offset = (sign << 24) | (i1 << 23) | (i2 << 22) | ((first & 0x3ff) << 12) | ((second & 0x7ff) << 1);
            // Sign-extend the 25-bit offset.
            let offset = i64::from(((offset << 7) as i32) >> 7);
            let pc = base + 2 * index as u64 + 4;
            let target = pc.checked_add_signed(offset)?;
            (base..end).contains(&target).then_some(target)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(halfwords: &[u16], length: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = halfwords.iter().flat_map(|halfword| halfword.to_le_bytes()).collect();
        bytes.resize(length, 0);
        bytes
    }

    fn put_word(bytes: &mut [u8], offset: usize, word: u32) {
        bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }

    #[test]
    fn bl_targets_decode_forward_and_backward_calls() {
        // At 0x100: bl 0x200 (offset 0xfc); at 0x104: bl 0x40 (offset -0xc8).
        let mut bytes = vec![0u8; 0x300];
        bytes[0x100..0x104].copy_from_slice(&[0x00, 0xf0, 0x7e, 0xf8]);
        bytes[0x104..0x108].copy_from_slice(&[0xff, 0xf7, 0x9c, 0xff]);
        let targets = bl_targets(&bytes, 0x0800_0000);
        assert_eq!(targets.into_iter().collect::<Vec<_>>(), [0x0800_0040, 0x0800_0200]);
    }

    /// Three functions (push/pop, a leaf `bx lr`, push/pop) behind a table, and a run of case-label-like targets
    /// (`adds; b`) with no prologue or call.
    #[test]
    fn function_tables_are_accepted_and_case_label_tables_refused() {
        let base = 0x0800_0000;
        let mut bytes = image(&[], 0x400);
        let code = |bytes: &mut Vec<u8>, at: usize, halfwords: &[u16]| {
            for (index, halfword) in halfwords.iter().enumerate() {
                bytes[at + 2 * index..at + 2 * index + 2].copy_from_slice(&halfword.to_le_bytes());
            }
        };
        code(&mut bytes, 0x100, &[0xb580, 0x2001, 0xbd80]); // push {r7, lr}; movs r0, #1; pop {r7, pc}
        code(&mut bytes, 0x110, &[0x2002, 0x4770]); // movs r0, #2; bx lr
        code(&mut bytes, 0x120, &[0xb510, 0x2003, 0xbd10]); // push {r4, lr}; movs r0, #3; pop {r4, pc}
        code(&mut bytes, 0x140, &[0x3201, 0xe7fe, 0x3202, 0xe7fe, 0x3203, 0xe7fe]); // adds r2, #n; b .
        for (index, target) in [0x101u32, 0x111, 0, 0x121].into_iter().enumerate() {
            put_word(&mut bytes, 0x200 + 4 * index, if target == 0 { 0 } else { base as u32 + target });
        }
        for (index, target) in [0x141u32, 0x145, 0x149].into_iter().enumerate() {
            put_word(&mut bytes, 0x300 + 4 * index, base as u32 + target);
        }
        // Two pointers alone are not a table.
        put_word(&mut bytes, 0x380, base as u32 + 0x101);
        put_word(&mut bytes, 0x384, base as u32 + 0x111);
        let tables = scan(&bytes, base, None);
        assert_eq!((tables.accepted_tables, tables.refused_tables, tables.isolated_pointers), (1, 1, 2), "{tables:#?}");
        let accepted = &tables.tables[0];
        assert_eq!((accepted.address, accepted.stride, accepted.status), (base + 0x200, 4, TableStatus::Accepted));
        assert_eq!(tables.targets().collect::<Vec<_>>(), [base + 0x100, base + 0x110, base + 0x120]);
        assert_eq!(accepted.entries[0].evidence, [Evidence::PushLr, Evidence::ReachesExit]);
        assert_eq!(accepted.entries[1].evidence, [Evidence::ReachesExit]);
        assert_eq!(accepted.entries[2].status, EntryStatus::Empty);
        let refused = &tables.tables[1];
        assert_eq!(refused.refused_reason, Some(TableRefusedReason::NoStrongEvidence));
        assert!(refused.entries.iter().all(|entry| entry.status == EntryStatus::Refused));
        assert_eq!(tables.seeds, 3);
    }

    /// An array of {name, handler} structs: the handlers form a stride-8 table between even name pointers.
    #[test]
    fn struct_arrays_are_found_at_their_stride_and_skipped_ranges_ignored() {
        let base = 0x0800_0000;
        let mut bytes = image(&[], 0x400);
        for at in [0x100, 0x110, 0x120] {
            bytes[at..at + 6].copy_from_slice(&[0x80, 0xb5, 0x01, 0x20, 0x80, 0xbd]);
        }
        for (index, target) in [0x101u32, 0x111, 0x121].into_iter().enumerate() {
            put_word(&mut bytes, 0x200 + 8 * index, base as u32 + 0x300);
            put_word(&mut bytes, 0x204 + 8 * index, base as u32 + target);
        }
        let tables = scan(&bytes, base, None);
        assert_eq!(tables.accepted_tables, 1);
        assert_eq!((tables.tables[0].address, tables.tables[0].stride), (base + 0x204, 8));
        let skipped = scan(&bytes, base, Some(base + 0x200..base + 0x220));
        assert_eq!(skipped.tables.len(), 0);
        assert_eq!(skipped.words_scanned, 0x100 - 8);
    }

    #[test]
    fn a_target_that_does_not_decode_breaks_the_run() {
        let mut bytes = image(&[], 0x200);
        for at in [0x100, 0x110] {
            bytes[at..at + 6].copy_from_slice(&[0x80, 0xb5, 0x01, 0x20, 0x80, 0xbd]);
        }
        // 0xe800 0x0000 is not a valid M-profile Thumb-2 instruction.
        bytes[0x120..0x124].copy_from_slice(&[0x00, 0xe8, 0x00, 0x00]);
        for (index, target) in [0x101u32, 0x121, 0x111, 0x101].into_iter().enumerate() {
            put_word(&mut bytes, 0x180 + 4 * index, target);
        }
        let tables = scan(&bytes, 0, None);
        assert!(tables.tables.is_empty(), "{tables:#?}");
        assert_eq!((tables.pointers_without_evidence, tables.isolated_pointers), (1, 3));
        // Without the undecodable word the run is a table.
        put_word(&mut bytes, 0x184, 0x111);
        assert_eq!(scan(&bytes, 0, None).accepted_tables, 1);
    }
}
