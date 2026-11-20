//! Xtensa execution state the Sleigh p-code leaves to Ghidra's emulator state modifier, modelled here so
//! evaluate_function runs ESP32 code: register-window calls and zero-overhead loops.
//!
//! A windowed call (`call4/8/12`, `callx4/8/12`) runs its p-code, whose `swapN` fixup moves the caller's a(N+2)..
//! into the callee's a2.., then the callee gets the return address in a0 (Ghidra's fixups leave a0 to the caller).
//! When execution reaches the return address again, the caller's registers come back, with the callee's a2.. in the
//! caller's a(N+2).. (the result of a `call8` lands in a10), as the window rotating back gives it. `retw` jumps to a0
//! with the top two bits of its own address, which code at 0x4xxxxxxx keeps.
//!
//! `loop`, `loopnez` and `loopgtz` set a loop of LCOUNT more iterations from the next instruction to the loop end:
//! falling through into the end address branches back to the start while the count is not zero.

use super::Run;
use crate::ApiError;

const REGISTERS: [&str; 16] =
    ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15"];

/// A windowed call in progress: where it returns, the caller's registers and its window increment (1, 2 or 3).
struct Frame {
    returns_to: u64,
    saved: [u128; 16],
    increment: usize,
}

/// A zero-overhead loop: the first instruction of its body, its end and the iterations left.
struct ZeroLoop {
    begin: u64,
    end: u64,
    remaining: u64,
}

/// What an instruction about to run means to the model.
pub(super) enum Pending {
    Call { increment: usize, saved: Box<[u128; 16]>, returns_to: u64 },
    Loop { kind: LoopKind, count: u64, begin: u64, end: u64 },
    None,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LoopKind {
    Loop,
    NotZero,
    GreaterThanZero,
}

#[derive(Default)]
pub(super) struct Windows {
    frames: Vec<Frame>,
    zero_loop: Option<ZeroLoop>,
    /// Whether the instruction just run returned (`ret`, `retw` and their narrow forms, or an import's model): only
    /// a return reaching a call's return address ends that call. Recursive code also gets there by a branch, as a
    /// join after its own call (`if (n) walk(n - 1); count++;`).
    returning: bool,
}

fn read_all(run: &mut Run<'_>) -> Result<[u128; 16], ApiError> {
    let mut values = [0u128; 16];
    for (value, name) in values.iter_mut().zip(REGISTERS) {
        *value = run.get_register(name)?;
    }
    Ok(values)
}

impl Windows {
    /// Called before the instruction at `pc` (`length` bytes, rendered `text`) runs.
    pub(super) fn before(
        &mut self,
        run: &mut Run<'_>,
        pc: u64,
        length: u64,
        text: &str,
        code: Option<&[u8]>,
    ) -> Result<Pending, ApiError> {
        let mnemonic = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        self.returning = matches!(mnemonic.as_str(), "ret" | "ret.n" | "retw" | "retw.n");
        let increment = match mnemonic.as_str() {
            "call4" | "callx4" => 1,
            "call8" | "callx8" => 2,
            "call12" | "callx12" => 3,
            _ => 0,
        };
        if increment > 0 {
            let saved = Box::new(read_all(run)?);
            return Ok(Pending::Call { increment, saved, returns_to: pc.wrapping_add(length) });
        }
        let kind = match mnemonic.as_str() {
            "loop" => LoopKind::Loop,
            "loopnez" => LoopKind::NotZero,
            "loopgtz" => LoopKind::GreaterThanZero,
            _ => return Ok(Pending::None),
        };
        // The loop end and counter register come from the encoding: `loop as, end`.
        let Some(code) = code.filter(|code| code.len() >= 3) else { return Ok(Pending::None) };
        let register = usize::from(code[1] & 0xf);
        let end = pc.wrapping_add(4).wrapping_add(u64::from(code[2]));
        let count = run.get_register(REGISTERS[register])? as u32;
        Ok(Pending::Loop { kind, count: u64::from(count), begin: pc.wrapping_add(length), end })
    }

    /// Called after the instruction ran; `next` is where execution goes. Returns where it really goes.
    pub(super) fn after(
        &mut self,
        run: &mut Run<'_>,
        pending: Pending,
        fell_through: bool,
        next: u64,
    ) -> Result<u64, ApiError> {
        match pending {
            Pending::Call { increment, saved, returns_to } => {
                run.set_register("a0", u128::from(returns_to))?;
                self.frames.push(Frame { returns_to, saved: *saved, increment });
                Ok(next)
            }
            Pending::Loop { kind, count, begin, end } => {
                let signed = count as u32 as i32;
                let skipped = match kind {
                    LoopKind::Loop => false,
                    LoopKind::NotZero => count == 0,
                    LoopKind::GreaterThanZero => signed <= 0,
                };
                if skipped {
                    self.zero_loop = None;
                    return Ok(end);
                }
                self.zero_loop = Some(ZeroLoop { begin, end, remaining: u64::from((count as u32).wrapping_sub(1)) });
                Ok(begin)
            }
            Pending::None => {
                if fell_through
                    && let Some(zero_loop) = &mut self.zero_loop
                    && next == zero_loop.end
                {
                    if zero_loop.remaining > 0 {
                        zero_loop.remaining -= 1;
                        return Ok(zero_loop.begin);
                    }
                    self.zero_loop = None;
                }
                Ok(next)
            }
        }
    }

    /// An import's model ran and returned to its caller.
    pub(super) fn returned_from_model(&mut self) {
        self.returning = true;
    }

    /// Called before the instruction at `pc`: a windowed call returning there gets the caller's registers back.
    pub(super) fn returned(&mut self, run: &mut Run<'_>, pc: u64) -> Result<(), ApiError> {
        if !std::mem::take(&mut self.returning) || self.frames.last().is_none_or(|frame| frame.returns_to != pc) {
            return Ok(());
        }
        let Some(frame) = self.frames.pop() else { return Ok(()) };
        let callee = read_all(run)?;
        let mut registers = frame.saved;
        let shift = frame.increment * 4;
        let end = (16 - shift).min(8);
        registers[shift + 2..shift + end].copy_from_slice(&callee[2..end]);
        for (value, name) in registers.into_iter().zip(REGISTERS) {
            run.set_register(name, value)?;
        }
        Ok(())
    }
}
