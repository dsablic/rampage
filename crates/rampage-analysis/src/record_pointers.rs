//! Raw Cortex-M only: code pointers held in data records that discovered code addresses.
//!
//! Firmware often names a function only inside a record: an RTOS thread definition (`{name, entry, stack, ...}`),
//! a driver or init descriptor, a callback registration. The code forms or loads the record's address and passes it
//! on, so neither a call nor a literal-pool word names the function, and a table scan misses it because the record
//! holds one code pointer among other fields. After discovery, the words just past each data reference are read;
//! an odd word that does not point at text, whose target is executable and outside every discovered function,
//! becomes a seed for another round when the target opens with `push {..., lr}`, or follows a function end (a
//! return, an unconditional branch or padding) outside an array; either way its straight-line decode must reach a
//! return or branch with no undecodable bytes. A word in an array (three code pointers in a row) needs the
//! `push {..., lr}`, which a switch's case labels and constants pointing into code lack.
//!
//! The work is bounded across all rounds: each record and each target is judged once, and words read plus
//! instructions decoded share one budget; when it runs out the pass stops and says so.

use std::collections::BTreeSet;

use rampage_arch::{Disassembler, Flow};
use rampage_loaders::Binary;

use crate::discover::{Program, RecordSeeds, XrefKind};
use crate::memory::Memory;

/// Words read from each referenced address: records of up to 16 fields.
const RECORD_WORDS: u64 = 16;
/// Rounds of discovery that may add record seeds after the first.
pub(crate) const MAX_ROUNDS: usize = 3;
/// Seeds one round may add.
const MAX_SEEDS_PER_ROUND: usize = 4096;
/// Instructions a target's straight-line decode may take to reach an exit.
const MAX_WALK: usize = 128;
/// Words read and instructions decoded by every round together.
pub(crate) const WORK_BUDGET: u64 = 1_000_000;

/// Whether `binary` is a Raw Cortex-M project, the only kind this applies to.
pub(crate) fn applies(binary: &Binary) -> bool {
    binary.raw_code_image().is_some() && binary.m_profile() && !binary.big_endian
}

/// The record pass across rounds: what it has read and judged, and the work it has done.
pub(crate) struct RecordPass {
    read: BTreeSet<u64>,
    judged: BTreeSet<u64>,
    report: RecordSeeds,
    budget: u64,
    cap: usize,
}

impl RecordPass {
    pub(crate) fn new() -> Self {
        Self::with_limits(WORK_BUDGET, MAX_SEEDS_PER_ROUND)
    }

    fn with_limits(budget: u64, cap: usize) -> Self {
        Self { read: BTreeSet::new(), judged: BTreeSet::new(), report: RecordSeeds::default(), budget, cap }
    }

    pub(crate) fn report(self) -> RecordSeeds {
        self.report
    }

    /// Records a round's seeds (or carried ones) in the report.
    pub(crate) fn accept(&mut self, seeds: &[u64]) {
        self.report.rounds += 1;
        self.report.seeds.extend(seeds);
        self.report.seeds.sort_unstable();
        self.report.seeds.dedup();
    }

    /// Spends `amount` of the budget; false, and the report marked truncated, when it is gone.
    fn spend(&mut self, amount: u64) -> bool {
        if self.report.work + amount > self.budget {
            self.report.truncated = true;
            return false;
        }
        self.report.work += amount;
        true
    }

    /// Of `carried` (starts an earlier interpretation's record pass found), those still outside every function of
    /// `program`; each is judged again, within the budget.
    pub(crate) fn carried(
        &mut self,
        binary: &Binary,
        program: &Program,
        decoder: &mut dyn Disassembler,
        carried: &[u64],
    ) -> Vec<u64> {
        let functions = Functions::of(program);
        let mut kept = Vec::new();
        for &target in carried {
            if self.report.truncated || !self.judged.insert(target) {
                continue;
            }
            if binary.is_code(target)
                && !functions.starts.contains(&target)
                && !functions.inside(target)
                && pushes_lr(binary, target)
                && self.decodes_like_code(binary, decoder, target)
            {
                kept.push(target);
            }
        }
        kept
    }

    /// Thumb functions that records newly referenced by `program`'s code point at and discovery has not found,
    /// sorted; at most [`MAX_SEEDS_PER_ROUND`] (the pass's cap).
    pub(crate) fn round(&mut self, binary: &Binary, program: &Program, decoder: &mut dyn Disassembler) -> Vec<u64> {
        let functions = Functions::of(program);
        let records: BTreeSet<u64> = program
            .xrefs
            .iter()
            .filter(|xref| xref.kind == XrefKind::Data)
            .map(|xref| xref.to & !3)
            .filter(|&record| !self.read.contains(&record))
            .filter(|&record| !binary.is_code(record) || !functions.inside(record))
            .collect();
        let word_at = |slot: u64| -> Option<u64> {
            let bytes = binary.read(slot, 4)?;
            Some(u64::from(u32::from_le_bytes(bytes.try_into().expect("four bytes"))))
        };
        let code_pointer = |word: u64| word & 1 == 1 && binary.is_code(word & !1);
        let mut found = BTreeSet::new();
        'records: for record in records {
            if !self.spend(RECORD_WORDS + 4) {
                break;
            }
            self.read.insert(record);
            let words: Vec<u64> =
                (0..RECORD_WORDS).map_while(|index| word_at(record.checked_add(4 * index)?)).collect();
            // A word in a run of three code pointers (the two words before the record and two after the window
            // count) belongs to an array.
            let around = |back: u64| record.checked_sub(back).and_then(word_at).is_some_and(code_pointer);
            let after = |index: u64| record.checked_add(4 * index).and_then(word_at).is_some_and(code_pointer);
            let end = words.len() as u64;
            let flags: Vec<bool> = [around(8), around(4)]
                .into_iter()
                .chain(words.iter().map(|&word| code_pointer(word)))
                .chain([after(end), after(end + 1)])
                .collect();
            for (index, &word) in words.iter().enumerate() {
                let at = index + 2;
                let in_array = (at - 2..=at).any(|first| flags[first..first + 3].iter().all(|&flag| flag));
                let target = word & !1;
                // An odd pointer at text (a record's name) is a string, not Thumb code.
                if word & 1 == 0
                    || !Memory::may_point_to_code(binary, word)
                    || !binary.is_code(target)
                    || functions.starts.contains(&target)
                    || found.contains(&target)
                    || !self.judged.insert(target)
                    || functions.inside(target)
                {
                    continue;
                }
                let opens = pushes_lr(binary, target);
                if !(opens || !in_array && follows_function_end(binary, target)) {
                    continue;
                }
                if !self.decodes_like_code(binary, decoder, target) {
                    if self.report.truncated {
                        break 'records;
                    }
                    continue;
                }
                found.insert(target);
                if found.len() == self.cap {
                    self.report.truncated = true;
                    break 'records;
                }
            }
        }
        found.into_iter().collect()
    }

    /// A straight-line decode from `target` that reaches an unconditional return, branch or halt before any
    /// undecodable bytes, within [`MAX_WALK`] instructions and the budget.
    fn decodes_like_code(&mut self, binary: &Binary, decoder: &mut dyn Disassembler, target: u64) -> bool {
        decoder.begin_run();
        let mut address = target;
        for _ in 0..MAX_WALK {
            if !self.spend(1) {
                return false;
            }
            let Some(code) = binary.code_from(address) else { return false };
            let insn = decoder.decode(&code[..code.len().min(4)], address);
            if insn.flow == Flow::Invalid || insn.len == 0 {
                return false;
            }
            if !insn.conditional && matches!(insn.flow, Flow::Return | Flow::Jump(_) | Flow::IndirectJump | Flow::Halt)
            {
                return true;
            }
            address += u64::from(insn.len);
        }
        false
    }
}

/// The discovered functions' starts and block ranges.
struct Functions {
    starts: BTreeSet<u64>,
    blocks: Vec<(u64, u64)>,
}

impl Functions {
    fn of(program: &Program) -> Self {
        let mut blocks: Vec<(u64, u64)> = program
            .functions
            .iter()
            .flat_map(|function| function.blocks.iter().map(|block| (block.start, block.end)))
            .collect();
        blocks.sort_unstable();
        Self { starts: program.functions.iter().map(|function| function.address).collect(), blocks }
    }

    fn inside(&self, address: u64) -> bool {
        let index = self.blocks.partition_point(|&(start, _)| start <= address);
        self.blocks[..index].iter().rev().take(64).any(|&(start, end)| (start..end).contains(&address))
    }
}

fn halfword(binary: &Binary, address: u64) -> Option<u16> {
    binary.read(address, 2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Whether the instruction at `target` is `push {..., lr}` (T1) or `push.w {..., lr}` (T2).
fn pushes_lr(binary: &Binary, target: u64) -> bool {
    match halfword(binary, target) {
        Some(first) if first & 0xff00 == 0xb500 => true,
        Some(0xe92d) => halfword(binary, target + 2).is_some_and(|second| second & 0x4000 != 0),
        _ => false,
    }
}

/// Whether the code before `target` ends a function: `bx lr`, `pop {..., pc}`, `pop.w {..., pc}`, an unconditional
/// 16-bit branch, or `nop`/zero padding.
fn follows_function_end(binary: &Binary, target: u64) -> bool {
    let Some(previous) = target.checked_sub(2).and_then(|at| halfword(binary, at)) else { return false };
    let wide_pop = target
        .checked_sub(4)
        .and_then(|at| halfword(binary, at))
        .is_some_and(|first| first == 0xe8bd && previous & 0x8000 != 0);
    previous == 0x4770
        || previous & 0xff00 == 0xbd00
        || previous & 0xf800 == 0xe000
        || matches!(previous, 0xbf00 | 0)
        || wide_pop
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_loaders::{RawCodeOptions, RawProfile};

    const BASE: u64 = 0x0800_0000;

    fn binary(bytes: Vec<u8>) -> Binary {
        let options = RawCodeOptions {
            profile: RawProfile::CortexM,
            base: BASE,
            entry: None,
            seeds: vec![],
            vector_table: None,
            pointer_tables: false,
        };
        Binary::from_raw_code(bytes, options).unwrap()
    }

    /// A program whose one function at BASE references `records` as data.
    fn program(records: &[u64]) -> Program {
        let mut program = Program::default();
        program.functions.push(crate::discover::DiscoveredFunction {
            address: BASE,
            blocks: vec![crate::discover::Block { start: BASE, end: BASE + 4 }],
            instruction_count: 2,
            switches: Vec::new(),
        });
        program.xrefs =
            records.iter().map(|&to| crate::discover::Xref { to, from: BASE, kind: XrefKind::Data }).collect();
        program
    }

    fn put(bytes: &mut [u8], at: u64, data: &[u8]) {
        let at = (at - BASE) as usize;
        bytes[at..at + data.len()].copy_from_slice(data);
    }

    fn word(value: u64) -> [u8; 4] {
        (value as u32).to_le_bytes()
    }

    fn decoder(binary: &Binary) -> Box<dyn Disassembler> {
        binary.decoder().unwrap()
    }

    /// A record with one entry next to other fields seeds a function that opens with `push {r7, lr}`; a pointer
    /// into data (undecodable bytes) and an array of pointers at bytes that only start like a prologue do not.
    #[test]
    fn records_seed_functions_and_refuse_data_and_garbage_arrays() {
        let mut bytes = vec![0xffu8; 0x400];
        put(&mut bytes, BASE, &[0x70, 0x47, 0x00, 0xbf]); // bx lr; nop
        put(&mut bytes, BASE + 0x100, &[0x80, 0xb5, 0x80, 0xbd]); // push {r7, lr}; pop {r7, pc}
        // The record: {name 0, entry, 1024, 3}.
        put(&mut bytes, BASE + 0x200, &[word(0), word(BASE + 0x101), word(1024), word(3)].concat());
        // An odd pointer into 0xff fill (undecodable as code).
        put(&mut bytes, BASE + 0x240, &[word(0), word(BASE + 0x301), word(0)].concat());
        // An array of three pointers at `push {lr}` followed by undecodable bytes.
        for (index, target) in [0x340u64, 0x350, 0x360].into_iter().enumerate() {
            put(&mut bytes, BASE + target, &[0x00, 0xb5, 0xff, 0xff]);
            put(&mut bytes, BASE + 0x280 + 4 * index as u64, &word(BASE + target + 1));
        }
        let binary = binary(bytes);
        let mut pass = RecordPass::new();
        let found =
            pass.round(&binary, &program(&[BASE + 0x200, BASE + 0x240, BASE + 0x280]), decoder(&binary).as_mut());
        assert_eq!(found, [BASE + 0x100]);
        // A record already read is not read again in a later round.
        let again = pass.round(&binary, &program(&[BASE + 0x200]), decoder(&binary).as_mut());
        assert!(again.is_empty());
    }

    /// Many records of pointers into a run of `nop`s (each decodes, none reaches an exit) stop at the budget, and
    /// the report says so; a round never adds more than the per-round cap. (The round bound is tested on a whole
    /// discovery in rampage-api's raw_project tests.)
    #[test]
    fn the_pass_stops_at_its_work_budget_and_its_seed_cap() {
        let records = 64u64;
        let mut bytes = vec![0u8; 0x8000];
        put(&mut bytes, BASE, &[0x70, 0x47]);
        for index in 0..records {
            let record = BASE + 0x100 + 64 * index;
            for slot in 0..8 {
                let target = BASE + 0x2000 + 2 * (8 * index + slot);
                put(&mut bytes, record + 8 * slot, &[word(target + 1), word(0)].concat());
            }
        }
        for at in (0x2000..0x8000).step_by(2) {
            put(&mut bytes, BASE + at, &[0x00, 0xbf]);
        }
        let binary = binary(bytes);
        let references: Vec<u64> = (0..records).map(|index| BASE + 0x100 + 64 * index).collect();
        let mut pass = RecordPass::with_limits(10_000, MAX_SEEDS_PER_ROUND);
        let found = pass.round(&binary, &program(&references), decoder(&binary).as_mut());
        assert!(found.is_empty());
        let report = pass.report();
        assert!(report.truncated && report.work <= 10_000, "{report:?}");

        // Five records naming five functions each, with a cap of three: one round adds three and says so.
        let mut bytes = vec![0xffu8; 0x800];
        put(&mut bytes, BASE, &[0x70, 0x47, 0x00, 0xbf]);
        let mut references = Vec::new();
        for index in 0..5u64 {
            let function = BASE + 0x400 + 8 * index;
            put(&mut bytes, function, &[0x80, 0xb5, 0x80, 0xbd]);
            let record = BASE + 0x100 + 64 * index;
            put(&mut bytes, record, &[word(0), word(function + 1), word(7)].concat());
            references.push(record);
        }
        let capped = self::binary(bytes);
        let mut pass = RecordPass::with_limits(WORK_BUDGET, 3);
        let found = pass.round(&capped, &program(&references), decoder(&capped).as_mut());
        assert_eq!(found.len(), 3);
        assert!(pass.report().truncated);
    }
}
