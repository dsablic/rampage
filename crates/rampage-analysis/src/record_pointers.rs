//! Raw Cortex-M only: code pointers held in data records that discovered code addresses.
//!
//! Firmware often names a function only inside a record: an RTOS thread definition (`{name, entry, stack, ...}`),
//! a driver or init descriptor, a callback registration. The code forms or loads the record's address and passes it
//! on, so neither a call nor a literal-pool word names the function, and a table scan misses it because the record
//! holds one code pointer among other fields. After discovery, the words just past each data reference are read;
//! an odd word that does not point at text, whose target is executable, outside every discovered function, and
//! decodes like code (a `push {..., lr}` first, or a straight-line run that reaches a return or branch) becomes a
//! seed for another round. A word in an array (three code pointers in a row) needs the `push {..., lr}`.

use std::collections::BTreeSet;

use rampage_arch::{Disassembler, Flow};
use rampage_loaders::Binary;

use crate::discover::{Program, XrefKind};
use crate::memory::Memory;

/// Words read from each referenced address: records of up to 16 fields.
const RECORD_WORDS: u64 = 16;
/// Rounds of discovery that may add record seeds after the first.
pub(crate) const MAX_ROUNDS: usize = 3;
/// Seeds one round may add.
const MAX_SEEDS_PER_ROUND: usize = 4096;
/// Data references read per round.
const MAX_RECORDS: usize = 65536;
/// Instructions a target's straight-line decode may take to reach an exit.
const MAX_WALK: usize = 128;

/// Whether `binary` is a Raw Cortex-M project, the only kind this applies to.
pub(crate) fn applies(binary: &Binary) -> bool {
    binary.raw_code_image().is_some() && binary.m_profile() && !binary.big_endian
}

/// Thumb functions that records referenced by `program`'s code point at and discovery has not found, sorted.
pub(crate) fn seeds(binary: &Binary, program: &Program, decoder: &mut dyn Disassembler) -> Vec<u64> {
    let mut blocks: Vec<(u64, u64)> = program
        .functions
        .iter()
        .flat_map(|function| function.blocks.iter().map(|block| (block.start, block.end)))
        .collect();
    blocks.sort_unstable();
    let inside_function = |address: u64| {
        let index = blocks.partition_point(|&(start, _)| start <= address);
        blocks[..index].iter().rev().take(64).any(|&(start, end)| (start..end).contains(&address))
    };
    let starts: BTreeSet<u64> = program.functions.iter().map(|function| function.address).collect();
    let records: BTreeSet<u64> = program
        .xrefs
        .iter()
        .filter(|xref| xref.kind == XrefKind::Data)
        .map(|xref| xref.to & !3)
        .filter(|&record| !binary.is_code(record) || !inside_function(record))
        .take(MAX_RECORDS)
        .collect();
    let mut found = BTreeSet::new();
    let mut judged = BTreeSet::new();
    let word_at = |slot: u64| -> Option<u64> {
        let bytes = binary.read(slot, 4)?;
        Some(u64::from(u32::from_le_bytes(bytes.try_into().expect("four bytes"))))
    };
    let code_pointer = |word: u64| word & 1 == 1 && binary.is_code(word & !1);
    'records: for record in records {
        let words: Vec<u64> = (0..RECORD_WORDS).map_while(|index| word_at(record.checked_add(4 * index)?)).collect();
        // A word in a run of three code pointers (the two words before the record and two after the window count)
        // belongs to an array: a switch's case labels and constants that point into code fill those too, so an
        // array entry counts only when its target opens with `push {..., lr}` (an init or handler table).
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
            if in_array && !pushes_lr(binary, target) {
                continue;
            }
            // An odd pointer at text (a record's name) is a string, not Thumb code.
            if word & 1 == 0
                || !Memory::may_point_to_code(binary, word)
                || !binary.is_code(target)
                || starts.contains(&target)
                || found.contains(&target)
                || !judged.insert(target)
                || inside_function(target)
                || !decodes_like_code(binary, decoder, target)
            {
                continue;
            }
            found.insert(target);
            if found.len() == MAX_SEEDS_PER_ROUND {
                break 'records;
            }
        }
    }
    found.into_iter().collect()
}

/// A `push {..., lr}` first, or a straight-line decode that reaches an unconditional return, branch or halt before
/// any undecodable bytes.
/// Whether the instruction at `target` is `push {..., lr}` (T1) or `push.w {..., lr}` (T2).
fn pushes_lr(binary: &Binary, target: u64) -> bool {
    let halfword = |address: u64| binary.read(address, 2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
    match halfword(target) {
        Some(first) if first & 0xff00 == 0xb500 => true,
        Some(0xe92d) => halfword(target + 2).is_some_and(|second| second & 0x4000 != 0),
        _ => false,
    }
}

fn decodes_like_code(binary: &Binary, decoder: &mut dyn Disassembler, target: u64) -> bool {
    let pushes_lr = pushes_lr(binary, target);
    decoder.begin_run();
    let mut address = target;
    for step in 0..MAX_WALK {
        let Some(code) = binary.code_from(address) else { return false };
        let insn = decoder.decode(&code[..code.len().min(4)], address);
        if insn.flow == Flow::Invalid || insn.len == 0 {
            return false;
        }
        if step == 0 && pushes_lr {
            return true;
        }
        if !insn.conditional && matches!(insn.flow, Flow::Return | Flow::Jump(_) | Flow::IndirectJump | Flow::Halt) {
            return true;
        }
        address += u64::from(insn.len);
    }
    false
}
