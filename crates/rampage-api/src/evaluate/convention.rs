//! Where integer arguments go and where the integer result comes back, per calling convention.

use rampage_arch::Arch;
use rampage_loaders::Format;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A calling convention `evaluate_function` can set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Convention {
    #[default]
    Default,
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Sysv,
    Win64,
    Aapcs64,
    Aapcs,
    /// AAPCS with the VFP variant: float arguments and results in s/d registers (hard float).
    AapcsVfp,
    MipsO32,
    MipsN64,
    Riscv,
    PpcSysv,
    Ppc64,
}

/// Where the return address goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Link {
    /// Pushed below the stack arguments, as x86 `call` does.
    Stack,
    Register(&'static str),
}

/// Where float arguments and results go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FloatAbi {
    /// In float registers counted apart from the integer ones: x86-64 System V (XMM0-7) and AArch64 (s/d0-7).
    Separate { single: &'static [&'static str], double: &'static [&'static str] },
    /// Win64: the argument's position picks XMM0-3 in place of RCX, RDX, R8, R9.
    Positional,
    /// ARM hard float: s0-s15 and d0-d7, a single back-filling a gap a double left.
    Vfp,
    /// As integers of their size: on the x86-32 stack (results in ST0) and in ARM soft-float core registers.
    Integer,
    /// No float support for this convention.
    Unsupported,
}

const XMM: &[&str] = &["XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7"];
const SINGLE_V: &[&str] = &["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"];
const DOUBLE_V: &[&str] = &["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"];
const VFP_SINGLE: &[&str] =
    &["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15"];

/// How a two-register value lines up in the argument registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairRule {
    /// The next two free registers.
    Next,
    /// An even-numbered position in the argument-register list (ARM r0/r2, MIPS a0/a2, PowerPC r3/r5/...).
    Even,
    /// Never in registers (x86 fastcall/thiscall put 64-bit values on the stack).
    Stack,
}

#[derive(Debug, Clone)]
pub(crate) struct Abi {
    pub convention: Convention,
    pub registers: &'static [&'static str],
    /// Bytes in one register and one stack slot.
    pub width: u32,
    pub stack_pointer: &'static str,
    pub link: Link,
    /// The integer result: low register, then the high register of a double-width result.
    pub result: (&'static str, &'static str),
    pub pair: PairRule,
    /// Bytes between the stack pointer at entry (after any pushed return address) and the first stack argument.
    pub stack_arguments: u64,
    /// Whether o32-style positional slots apply: register arguments also own stack slots.
    pub positional_slots: bool,
    /// Whether a 32-bit argument is sign-extended into a 64-bit register (MIPS64, RV64).
    pub sign_extend_words: bool,
    /// Registers that receive the entry address (MIPS `t9` for PIC prologues; PowerPC64 ELFv2 `r12`).
    pub entry_registers: &'static [&'static str],
    /// Register that receives the image's global pointer, when it has one.
    pub global_pointer: Option<&'static str>,
    pub stack_alignment: u64,
    /// Apple arm64: stack arguments take their own size and alignment, not 8-byte slots.
    pub natural_stack_slots: bool,
    pub float: FloatAbi,
}

const X86_NONE: &[&str] = &[];
const X86_FASTCALL: &[&str] = &["ECX", "EDX"];
const X86_THISCALL: &[&str] = &["ECX"];
const SYSV: &[&str] = &["RDI", "RSI", "RDX", "RCX", "R8", "R9"];
const WIN64: &[&str] = &["RCX", "RDX", "R8", "R9"];
const AARCH64: &[&str] = &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
const ARM: &[&str] = &["r0", "r1", "r2", "r3"];
const O32: &[&str] = &["a0", "a1", "a2", "a3"];
const N64: &[&str] = &["a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3"];
const RISCV: &[&str] = &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"];
const PPC: &[&str] = &["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"];

impl Abi {
    /// The convention for `arch` in a `format` image, or why none applies.
    pub fn select(arch: Arch, format: Format, big_endian: bool, wanted: Convention) -> Result<Self, String> {
        let base = |convention, registers, width, stack_pointer, link, result, pair, stack_arguments| Abi {
            convention,
            registers,
            width,
            stack_pointer,
            link,
            result,
            pair,
            stack_arguments,
            positional_slots: false,
            sign_extend_words: false,
            entry_registers: &[],
            global_pointer: None,
            stack_alignment: 16,
            natural_stack_slots: false,
            float: FloatAbi::Unsupported,
        };
        let x86 = |convention, registers, pair| Abi {
            float: FloatAbi::Integer,
            ..base(convention, registers, 4, "ESP", Link::Stack, ("EAX", "EDX"), pair, 0)
        };
        let abi = match (arch, wanted) {
            (Arch::X86, Convention::Default | Convention::Cdecl) => x86(Convention::Cdecl, X86_NONE, PairRule::Stack),
            (Arch::X86, Convention::Stdcall) => x86(Convention::Stdcall, X86_NONE, PairRule::Stack),
            (Arch::X86, Convention::Fastcall) => x86(Convention::Fastcall, X86_FASTCALL, PairRule::Stack),
            (Arch::X86, Convention::Thiscall) => x86(Convention::Thiscall, X86_THISCALL, PairRule::Stack),
            (Arch::X86_64, Convention::Win64) | (Arch::X86_64, Convention::Default)
                if format == Format::Pe || wanted == Convention::Win64 =>
            {
                Abi {
                    float: FloatAbi::Positional,
                    ..base(Convention::Win64, WIN64, 8, "RSP", Link::Stack, ("RAX", "RDX"), PairRule::Next, 0x20)
                }
            }
            (Arch::X86_64, Convention::Default | Convention::Sysv) => Abi {
                float: FloatAbi::Separate { single: XMM, double: XMM },
                ..base(Convention::Sysv, SYSV, 8, "RSP", Link::Stack, ("RAX", "RDX"), PairRule::Next, 0)
            },
            (Arch::Aarch64, Convention::Default | Convention::Aapcs64) => Abi {
                natural_stack_slots: format == Format::MachO,
                float: FloatAbi::Separate { single: SINGLE_V, double: DOUBLE_V },
                ..base(Convention::Aapcs64, AARCH64, 8, "sp", Link::Register("x30"), ("x0", "x1"), PairRule::Next, 0)
            },
            (Arch::Arm, Convention::Default | Convention::Aapcs | Convention::AapcsVfp) => {
                let hard = wanted == Convention::AapcsVfp;
                Abi {
                    stack_alignment: 8,
                    float: if hard { FloatAbi::Vfp } else { FloatAbi::Integer },
                    ..base(
                        if hard { Convention::AapcsVfp } else { Convention::Aapcs },
                        ARM,
                        4,
                        "sp",
                        Link::Register("lr"),
                        ("r0", "r1"),
                        PairRule::Even,
                        0,
                    )
                }
            }
            (Arch::Mips, Convention::Default | Convention::MipsO32) => Abi {
                positional_slots: true,
                entry_registers: &["t9"],
                global_pointer: Some("gp"),
                stack_alignment: 8,
                ..base(Convention::MipsO32, O32, 4, "sp", Link::Register("ra"), ("v0", "v1"), PairRule::Even, 0)
            },
            (Arch::Mips64, Convention::Default | Convention::MipsN64) => Abi {
                sign_extend_words: true,
                entry_registers: &["t9"],
                global_pointer: Some("gp"),
                ..base(Convention::MipsN64, N64, 8, "sp", Link::Register("ra"), ("v0", "v1"), PairRule::Next, 0)
            },
            (Arch::Riscv32 | Arch::Riscv64, Convention::Default | Convention::Riscv) => {
                let width = if arch == Arch::Riscv64 { 8 } else { 4 };
                Abi {
                    sign_extend_words: arch == Arch::Riscv64,
                    global_pointer: Some("gp"),
                    ..base(Convention::Riscv, RISCV, width, "sp", Link::Register("ra"), ("a0", "a1"), PairRule::Next, 0)
                }
            }
            (Arch::PowerPc, Convention::Default | Convention::PpcSysv) => {
                base(Convention::PpcSysv, PPC, 4, "r1", Link::Register("LR"), ("r3", "r4"), PairRule::Even, 8)
            }
            (Arch::PowerPc64, Convention::Default | Convention::Ppc64) => Abi {
                entry_registers: &["r12"],
                global_pointer: Some("r2"),
                // The parameter save area follows the ELFv1 (48-byte) or ELFv2 (32-byte) frame header.
                ..base(
                    Convention::Ppc64,
                    PPC,
                    8,
                    "r1",
                    Link::Register("LR"),
                    ("r3", "r4"),
                    PairRule::Next,
                    if big_endian { 48 + 64 } else { 32 + 64 },
                )
            },
            (_, Convention::Default) => {
                return Err(format!("evaluate_function has no calling convention for {arch:?}"));
            }
            (_, wanted) => {
                return Err(format!(
                    "convention {} does not apply to {arch:?}",
                    serde_json::to_value(wanted)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_default()
                ));
            }
        };
        Ok(abi)
    }

    /// The name this convention is reported by.
    pub fn name(&self) -> String {
        if self.natural_stack_slots {
            return "aapcs64_darwin".to_owned();
        }
        serde_json::to_value(self.convention)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default()
    }
}

/// Where one argument word or pair went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Place {
    Register(&'static str),
    /// Two registers: the one holding the low half, then the high half.
    Pair(&'static str, &'static str),
    /// Bytes above the first stack argument's position.
    Stack(u64),
    /// RISC-V: a double-width value split between the last argument register (low half) and the stack (high).
    Split(&'static str, u64),
}

/// Assigns argument locations: `widths` are each argument's bytes (the register width, or twice it for a pair).
pub(crate) fn assign(abi: &Abi, widths: &[u32], big_endian: bool) -> Vec<Place> {
    let mut next_register = 0usize;
    let mut stack = 0u64;
    let width = u64::from(abi.width);
    let mut places = Vec::with_capacity(widths.len());
    for &bytes in widths {
        let double = bytes > abi.width;
        if abi.positional_slots {
            // o32: every argument owns stack words; the first four words travel in a0-a3 instead.
            if double {
                stack = stack.next_multiple_of(2 * width);
            }
            let slot = (stack / width) as usize;
            let place = if double && slot + 1 < abi.registers.len() {
                pair_place(abi.registers[slot], abi.registers[slot + 1], big_endian)
            } else if !double && slot < abi.registers.len() {
                Place::Register(abi.registers[slot])
            } else {
                Place::Stack(stack)
            };
            stack += if double { 2 * width } else { width };
            places.push(place);
            continue;
        }
        if double {
            let mut start = next_register;
            if abi.pair == PairRule::Even {
                start = start.next_multiple_of(2);
            }
            if abi.pair != PairRule::Stack && start + 1 < abi.registers.len() {
                places.push(pair_place(abi.registers[start], abi.registers[start + 1], big_endian));
                next_register = start + 2;
                continue;
            }
            if abi.pair == PairRule::Next && start + 1 == abi.registers.len() {
                // RISC-V: one register left takes the low half, the stack the high half; later arguments follow it.
                places.push(Place::Split(abi.registers[start], stack));
                next_register = abi.registers.len();
                stack += width;
                continue;
            }
            if abi.pair == PairRule::Even {
                // AAPCS and PowerPC: a pair that no longer fits leaves the remaining registers unused.
                next_register = abi.registers.len();
            }
            if abi.link != Link::Stack {
                // Outside x86, a double-width value on the stack is aligned to its size.
                stack = stack.next_multiple_of(2 * width);
            }
            places.push(Place::Stack(stack));
            stack += 2 * width;
        } else if next_register < abi.registers.len() {
            places.push(Place::Register(abi.registers[next_register]));
            next_register += 1;
        } else if abi.natural_stack_slots {
            let size = u64::from(bytes);
            stack = stack.next_multiple_of(size);
            places.push(Place::Stack(stack));
            stack += size;
        } else {
            places.push(Place::Stack(stack));
            stack += width;
        }
    }
    places
}

/// Assigns argument locations as [`assign`] does, with float arguments (`floats[i]` is a float's bytes, 4 or 8)
/// placed by the convention's float rules. A float placed as an integer takes `widths[i]` like any other.
pub(crate) fn assign_with_floats(
    abi: &Abi,
    widths: &[u32],
    floats: &[Option<u32>],
    big_endian: bool,
) -> Result<Vec<Place>, String> {
    let is_float = |index: usize| floats.get(index).copied().flatten();
    match abi.float {
        // x86 fastcall and thiscall: floats go on the stack, in order with the other stack arguments, never in
        // ECX/EDX.
        FloatAbi::Integer if abi.link == Link::Stack && !abi.registers.is_empty() => {
            let mut next_register = 0usize;
            let mut stack = 0u64;
            let places = widths
                .iter()
                .enumerate()
                .map(|(index, &bytes)| {
                    if is_float(index).is_none() && bytes <= abi.width && next_register < abi.registers.len() {
                        next_register += 1;
                        return Place::Register(abi.registers[next_register - 1]);
                    }
                    let place = Place::Stack(stack);
                    stack += u64::from(bytes.max(abi.width));
                    place
                })
                .collect();
            Ok(places)
        }
        FloatAbi::Integer => Ok(assign(abi, widths, big_endian)),
        FloatAbi::Unsupported if floats.iter().any(Option::is_some) => {
            Err(format!("float arguments are not supported under the {} convention", abi.name()))
        }
        FloatAbi::Unsupported => Ok(assign(abi, widths, big_endian)),
        FloatAbi::Positional => {
            let mut places = assign(abi, widths, big_endian);
            for (index, place) in places.iter_mut().enumerate() {
                if is_float(index).is_some()
                    && let Place::Register(name) = place
                {
                    let position = abi.registers.iter().position(|register| register == name).ok_or_else(|| {
                        format!("float argument {index} was placed in {name}, not an argument register")
                    })?;
                    *place = Place::Register(XMM[position]);
                }
            }
            Ok(places)
        }
        FloatAbi::Separate { .. } | FloatAbi::Vfp => {
            let integers: Vec<u32> =
                (0..widths.len()).filter(|&index| is_float(index).is_none()).map(|index| widths[index]).collect();
            let mut integer_places = assign(abi, &integers, big_endian).into_iter();
            let mut used = [false; 16];
            let mut next = 0usize;
            let mut places = Vec::with_capacity(widths.len());
            for index in 0..widths.len() {
                let Some(bytes) = is_float(index) else {
                    places.push(integer_places.next().ok_or("argument placement ran out")?);
                    continue;
                };
                let place = match abi.float {
                    FloatAbi::Separate { single, double } => {
                        let list = if bytes == 4 { single } else { double };
                        next += 1;
                        list.get(next - 1).map(|name| Place::Register(name))
                    }
                    _ if bytes == 4 => used.iter().position(|taken| !taken).map(|slot| {
                        used[slot] = true;
                        Place::Register(VFP_SINGLE[slot])
                    }),
                    _ => (0..8).find(|&pair| !used[2 * pair] && !used[2 * pair + 1]).map(|pair| {
                        used[2 * pair] = true;
                        used[2 * pair + 1] = true;
                        Place::Register(["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"][pair])
                    }),
                };
                places.push(place.ok_or_else(|| {
                    format!("float arguments past the float argument registers are not supported ({})", abi.name())
                })?);
            }
            Ok(places)
        }
    }
}

/// The register holding a float result of `bytes` (4 or 8), and whether it is the x87 ST0 (an 80-bit value);
/// `None` when floats return in integer registers (ARM soft float) or the convention has no float support.
pub(crate) fn float_result(abi: &Abi, bytes: u32) -> Result<Option<(&'static str, bool)>, String> {
    Ok(match abi.float {
        FloatAbi::Separate { single, double } => Some((if bytes == 4 { single[0] } else { double[0] }, false)),
        FloatAbi::Positional => Some(("XMM0", false)),
        FloatAbi::Vfp => Some((if bytes == 4 { "s0" } else { "d0" }, false)),
        FloatAbi::Integer if abi.link == Link::Stack => Some(("ST0", true)),
        FloatAbi::Integer => None,
        FloatAbi::Unsupported => {
            return Err(format!("float results are not supported under the {} convention", abi.name()));
        }
    })
}

fn pair_place(first: &'static str, second: &'static str, big_endian: bool) -> Place {
    // A big-endian target puts the high half in the lower-numbered register.
    if big_endian { Place::Pair(second, first) } else { Place::Pair(first, second) }
}

/// The registers holding a double-width result: low, then high. A single-width result is in the first.
pub(crate) fn result_pair(abi: &Abi, big_endian: bool) -> (&'static str, &'static str) {
    let (first, second) = abi.result;
    let x86 = matches!(
        abi.convention,
        Convention::Cdecl
            | Convention::Stdcall
            | Convention::Fastcall
            | Convention::Thiscall
            | Convention::Sysv
            | Convention::Win64
    );
    // A big-endian target puts the high half in the lower-numbered register.
    if !x86 && big_endian { (second, first) } else { (first, second) }
}
