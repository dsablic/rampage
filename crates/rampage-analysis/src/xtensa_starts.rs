//! Function starts in Xtensa code found by their prologues, for functions only reached through pointers (task
//! entries, handler tables, callbacks). A windowed-ABI function (ESP32) must open with `entry a1, frame`, and every
//! call target is 4-byte aligned; a call0-ABI function (ESP8266) that keeps a frame opens with `addi a1, a1, -frame`.
//! A candidate is kept only when straight-line decoding from it reaches a return or jump without an invalid
//! instruction, which rules out literal-pool words that happen to match.

use rampage_arch::{Arch, Disassembler, Flow, XtensaDisassembler};
use rampage_loaders::Binary;

/// Instructions decoded from a candidate before it must have reached a return or an unconditional jump.
const MAX_CHECKED_INSTRUCTIONS: usize = 256;

/// Whether the 3 bytes at the start of `bytes` are this ABI's prologue.
fn prologue(bytes: &[u8], call0: bool) -> bool {
    let [first, second, third, ..] = *bytes else { return false };
    if call0 {
        // addi a1, a1, imm8: a negative multiple of 16.
        first == 0x12 && second == 0xc1 && third >= 0x80 && third & 0xf == 0
    } else {
        // entry a1, imm12 << 3 with a frame of at least 16 bytes.
        let frame = (u32::from(third) << 4) | u32::from(second >> 4);
        first == 0x36 && second & 0xf == 1 && frame >= 2
    }
}

/// Whether straight-line decoding from `address` ends in a return, jump or call that never comes back before any
/// invalid instruction.
fn decodes_cleanly(binary: &Binary, decoder: &mut XtensaDisassembler, address: u64) -> bool {
    decoder.reset();
    let mut at = address;
    for _ in 0..MAX_CHECKED_INSTRUCTIONS {
        let Some(bytes) = binary.code_from(at) else { return false };
        let insn = decoder.decode_with_memory(bytes, at, &|target, size| binary.read_pointer(target, size));
        match insn.flow {
            Flow::Invalid => return false,
            Flow::Return | Flow::Jump(_) | Flow::IndirectJump | Flow::Halt => return true,
            _ => at += u64::from(insn.len),
        }
    }
    true
}

/// Bytes GCC may schedule before a call0 prologue (argument moves and literal loads).
const MAX_SCHEDULED_BEFORE_PROLOGUE: u64 = 24;

/// Whether `before` (the bytes ahead of a candidate start) ends a function: a return, then up to 3 bytes of zero
/// padding (`ill`).
fn ends_function(before: &[u8]) -> bool {
    let trimmed = before.len() - before.iter().rev().take(3).take_while(|&&byte| byte == 0).count();
    let before = &before[..trimmed];
    before.ends_with(&[0x0d, 0xf0])
        || before.ends_with(&[0x1d, 0xf0])
        || before.ends_with(&[0x80, 0x00, 0x00])
        || before.ends_with(&[0x90, 0x00, 0x00])
}

/// Where the call0 function whose `addi a1, a1, -frame` is at `prologue` starts: GCC schedules argument moves and
/// literal loads ahead of the stack adjustment, so the start is the 4-byte aligned address just after the previous
/// function's return (and padding) from which straight-line decoding lands on the prologue. `prologue` itself when
/// no such address is near.
fn scheduled_start(before: &[u8], base: u64, prologue: u64) -> u64 {
    let lowest = prologue.saturating_sub(MAX_SCHEDULED_BEFORE_PROLOGUE).max(base).next_multiple_of(4);
    for start in (lowest..prologue).step_by(4) {
        let offset = (start - base) as usize;
        if !ends_function(&before[..offset]) {
            continue;
        }
        let mut at = offset;
        while (at as u64 + base) < prologue {
            let Some(length) = before.get(at).and_then(|&first| match first & 0xf {
                0..=7 => Some(3),
                8..=13 => Some(2),
                _ => None,
            }) else {
                break;
            };
            // Only moves, constants, literal loads and stores stand before the stack adjustment.
            if matches!(before[at] & 0xf, 5..=7) || (before[at] & 0xf == 0xd && before.get(at + 1) == Some(&0xf0)) {
                break;
            }
            at += length;
        }
        if at as u64 + base == prologue {
            return start;
        }
    }
    prologue
}

/// Whether a code pointer to `address` may name a function: windowed code must open with `entry`, and call0 code
/// must decode cleanly to its first return or jump.
pub(crate) fn may_start_function(binary: &Binary, address: u64) -> bool {
    let Some(code) = binary.code_from(address) else { return false };
    if binary.xtensa_call0() {
        return decodes_cleanly(binary, &mut XtensaDisassembler::new(), address);
    }
    code.len() >= 3 && code[0] == 0x36 && code[1] & 0xf == 1
}

/// Prologue starts in the executable segments of an Xtensa image.
pub fn prologue_seeds(binary: &Binary) -> Vec<u64> {
    if binary.arch != Arch::Xtensa || binary.big_endian {
        return Vec::new();
    }
    let call0 = binary.xtensa_call0();
    let mut decoder = XtensaDisassembler::new();
    let mut seeds = Vec::new();
    for segment in binary.segments.iter().filter(|segment| segment.perms.execute && segment.size >= 3) {
        let Some(bytes) = binary.read(segment.address, segment.size.min(segment.file_size)) else { continue };
        let first = segment.address.next_multiple_of(4) - segment.address;
        for offset in (first as usize..bytes.len().saturating_sub(2)).step_by(4) {
            let address = segment.address + offset as u64;
            if prologue(&bytes[offset..], call0) && decodes_cleanly(binary, &mut decoder, address) {
                let start = if call0 { scheduled_start(&bytes[..offset], segment.address, address) } else { address };
                seeds.push(start);
            }
        }
    }
    seeds
}

#[cfg(test)]
mod tests {
    use super::prologue;

    #[test]
    fn prologues_by_abi() {
        assert!(prologue(&[0x36, 0x41, 0x00], false));
        assert!(prologue(&[0x36, 0x81, 0x01], false));
        assert!(!prologue(&[0x36, 0x42, 0x00], false));
        assert!(!prologue(&[0x36, 0x01, 0x00], false));
        assert!(prologue(&[0x12, 0xc1, 0xf0], true));
        assert!(!prologue(&[0x12, 0xc1, 0x10], true));
        assert!(!prologue(&[0x36, 0x41, 0x00], true));
    }
}
