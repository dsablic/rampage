//! A native decoder for the Xtensa core instruction set as Espressif's ESP32 (LX6/LX7, windowed ABI) and ESP8266
//! (LX106, call0 ABI) implement it: the 24-bit and 16-bit (density) formats, the windowed-register, loop, MUL/DIV,
//! MIN/MAX, boolean and single-precision floating-point options, and special-register moves. MAC16 and other
//! optional instructions keep their length and fall through, rendered by their opcode fields.
//!
//! Control flow and references come from the encoding: `l32r` loads a literal from the pool below it, so it is a
//! data reference to the literal and its value (read from memory) is a constant that may be an address, as ARM's
//! `ldr r0, =value`. A run follows registers loaded that way (and `movi`, `mov`, `addi`) to resolve `callx`/`jx`
//! targets (`-mlongcalls` makes every far call an `l32r` + `callx`), loads and stores through a known base, and
//! switch tables (`bgeui` bound, `l32r` table, `addx4`, `l32i`, `jx`).

use crate::{Disassembler, Flow, Insn, JumpTable, OperandEvidence, TargetWidth};

/// The constant shifts of the `B4CONST` and `B4CONSTU` branch-immediate encodings.
const B4CONST: [i32; 16] = [-1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256];
const B4CONSTU: [u32; 16] = [32768, 65536, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256];

/// Special-register names (`rsr`/`wsr`/`xsr`) for the ones ESP code commonly touches.
fn special_register(number: u32) -> Option<&'static str> {
    Some(match number {
        0 => "lbeg",
        1 => "lend",
        2 => "lcount",
        3 => "sar",
        4 => "br",
        5 => "litbase",
        12 => "scompare1",
        16 => "acclo",
        17 => "acchi",
        32 => "m0",
        33 => "m1",
        34 => "m2",
        35 => "m3",
        72 => "windowbase",
        73 => "windowstart",
        83 => "ptevaddr",
        89 => "mmid",
        90 => "rasid",
        91 => "itlbcfg",
        92 => "dtlbcfg",
        96 => "ibreakenable",
        97 => "memctl",
        98 => "cacheattr",
        99 => "atomctl",
        104 => "ddr",
        128 => "ibreaka0",
        129 => "ibreaka1",
        144 => "dbreaka0",
        145 => "dbreaka1",
        160 => "dbreakc0",
        161 => "dbreakc1",
        177 => "epc1",
        178 => "epc2",
        179 => "epc3",
        180 => "epc4",
        181 => "epc5",
        182 => "epc6",
        183 => "epc7",
        192 => "depc",
        194 => "eps2",
        195 => "eps3",
        196 => "eps4",
        197 => "eps5",
        198 => "eps6",
        199 => "eps7",
        209 => "excsave1",
        210 => "excsave2",
        211 => "excsave3",
        212 => "excsave4",
        213 => "excsave5",
        214 => "excsave6",
        215 => "excsave7",
        224 => "cpenable",
        226 => "interrupt",
        227 => "intclear",
        228 => "intenable",
        230 => "ps",
        231 => "vecbase",
        232 => "exccause",
        233 => "debugcause",
        234 => "ccount",
        235 => "prid",
        236 => "icount",
        237 => "icountlevel",
        238 => "excvaddr",
        240 => "ccompare0",
        241 => "ccompare1",
        242 => "ccompare2",
        244 => "misc0",
        245 => "misc1",
        246 => "misc2",
        247 => "misc3",
        _ => return None,
    })
}

/// What one instruction does to the registers a run follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    None,
    /// `l32r at, literal`.
    LoadLiteral {
        t: u8,
        literal: u32,
    },
    /// The register is set to a constant (`movi`, `movi.n`).
    Constant {
        t: u8,
        value: u32,
    },
    /// `mov`, `mov.n`, `or ar, as, as`.
    Copy {
        to: u8,
        from: u8,
    },
    /// `addi`, `addi.n`, `addmi`.
    AddImmediate {
        to: u8,
        from: u8,
        value: i32,
    },
    /// `addx2/4/8 ar, as, at` (`ar = (as << shift) + at`), or `add` with shift 0.
    AddScaled {
        to: u8,
        index: u8,
        base: u8,
        shift: u8,
    },
    /// A load from `base + offset`, `size` bytes, into `t` (an AR register unless `float`).
    Load {
        t: u8,
        base: u8,
        offset: i32,
        size: u8,
        float: bool,
    },
    /// A store to `base + offset`.
    Store {
        base: u8,
        offset: i32,
        size: u8,
    },
    /// `callN`/`callxN`: `window` is N/4 (0 for the call0 ABI).
    Call {
        window: u8,
    },
    /// An instruction that writes this AR register in a way not followed.
    Writes(u8),
    /// An instruction whose register effects are not modelled: forget everything.
    Clobber,
    /// `bgeui as, bound` or `bgeu as, at`: on the fall-through path `as` is below `bound` (unsigned).
    UnsignedBound {
        s: u8,
        bound: Bound,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bound {
    Constant(u32),
    Register(u8),
}

/// One decoded instruction: its length, rendering pieces, flow and register effect.
#[derive(Debug, Clone)]
struct Decoded {
    len: u8,
    mnemonic: &'static str,
    operands: Vec<Operand>,
    flow: Flow,
    effect: Effect,
    /// A `callx`/`jx` through this register.
    through: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    Ar(u8),
    Fr(u8),
    Br(u8),
    Special(u32),
    User(u32),
    Imm(i64),
    Address(u32),
}

impl Operand {
    fn render(self) -> String {
        match self {
            Operand::Ar(r) => format!("a{r}"),
            Operand::Fr(r) => format!("f{r}"),
            Operand::Br(r) => format!("b{r}"),
            Operand::Special(number) => special_register(number).map_or_else(|| number.to_string(), str::to_owned),
            Operand::User(number) => match number {
                231 => "threadptr".to_owned(),
                232 => "fcr".to_owned(),
                233 => "fsr".to_owned(),
                _ => number.to_string(),
            },
            Operand::Imm(value) => value.to_string(),
            Operand::Address(address) => format!("{address:#x}"),
        }
    }
}

fn sign_extend(value: u32, bits: u32) -> i32 {
    ((value << (32 - bits)) as i32) >> (32 - bits)
}

/// The instruction's length from its first byte: 2 for the density formats (op0 8..=13), 3 otherwise; op0 14 and
/// 15 (FLIX and reserved) are not implemented by ESP cores.
fn length(first: u8) -> Option<u8> {
    match first & 0xf {
        0..=7 => Some(3),
        8..=13 => Some(2),
        _ => None,
    }
}

fn insn(len: u8, mnemonic: &'static str, operands: Vec<Operand>, flow: Flow, effect: Effect) -> Decoded {
    Decoded { len, mnemonic, operands, flow, effect, through: None }
}

fn next(len: u8, mnemonic: &'static str, operands: Vec<Operand>, effect: Effect) -> Decoded {
    insn(len, mnemonic, operands, Flow::Next, effect)
}

/// Decodes the instruction at the start of `bytes`, at `address` (32-bit).
fn decode(bytes: &[u8], address: u32) -> Option<Decoded> {
    let len = length(*bytes.first()?)?;
    if bytes.len() < usize::from(len) {
        return None;
    }
    let word = if len == 3 {
        u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2]) << 16
    } else {
        u32::from(bytes[0]) | u32::from(bytes[1]) << 8
    };
    let op0 = word & 0xf;
    let t = ((word >> 4) & 0xf) as u8;
    let s = ((word >> 8) & 0xf) as u8;
    let r = ((word >> 12) & 0xf) as u8;
    let op1 = (word >> 16) & 0xf;
    let op2 = (word >> 20) & 0xf;
    let imm8 = (word >> 16) & 0xff;
    let (ar, as_, at) = (Operand::Ar(r), Operand::Ar(s), Operand::Ar(t));
    let pc = address;
    let branch8 = pc.wrapping_add(4).wrapping_add(sign_extend(imm8, 8) as u32);
    if len == 2 {
        return Some(match op0 {
            8 => next(
                2,
                "l32i.n",
                vec![at, as_, Operand::Imm(i64::from(r) << 2)],
                Effect::Load { t, base: s, offset: i32::from(r) << 2, size: 4, float: false },
            ),
            9 => next(
                2,
                "s32i.n",
                vec![at, as_, Operand::Imm(i64::from(r) << 2)],
                Effect::Store { base: s, offset: i32::from(r) << 2, size: 4 },
            ),
            10 => next(2, "add.n", vec![ar, as_, at], Effect::AddScaled { to: r, index: s, base: t, shift: 0 }),
            11 => {
                let value = if t == 0 { -1 } else { i32::from(t) };
                next(
                    2,
                    "addi.n",
                    vec![ar, as_, Operand::Imm(value.into())],
                    Effect::AddImmediate { to: r, from: s, value },
                )
            }
            12 if t & 8 == 0 => {
                let raw = (u32::from(t & 7) << 4) | u32::from(r);
                let value = if raw & 0x60 == 0x60 { raw as i32 - 128 } else { raw as i32 };
                next(2, "movi.n", vec![as_, Operand::Imm(value.into())], Effect::Constant { t: s, value: value as u32 })
            }
            12 => {
                let target = pc.wrapping_add(4).wrapping_add((u32::from(t & 3) << 4) | u32::from(r));
                let mnemonic = if t & 4 == 0 { "beqz.n" } else { "bnez.n" };
                insn(
                    2,
                    mnemonic,
                    vec![as_, Operand::Address(target)],
                    Flow::ConditionalJump(target.into()),
                    Effect::None,
                )
            }
            13 => match r {
                0 => next(2, "mov.n", vec![at, as_], Effect::Copy { to: t, from: s }),
                15 => match t {
                    0 => insn(2, "ret.n", vec![], Flow::Return, Effect::None),
                    1 => insn(2, "retw.n", vec![], Flow::Return, Effect::None),
                    2 => next(2, "break.n", vec![Operand::Imm(s.into())], Effect::None),
                    3 => next(2, "nop.n", vec![], Effect::None),
                    6 => insn(2, "ill.n", vec![], Flow::Halt, Effect::None),
                    _ => return None,
                },
                _ => return None,
            },
            _ => return None,
        });
    }
    let decoded = match op0 {
        0 => return qrst(word, pc),
        1 => {
            let offset = ((word >> 8) | 0xffff_0000) << 2;
            let literal = ((pc.wrapping_add(3)) & !3).wrapping_add(offset);
            next(3, "l32r", vec![at, Operand::Address(literal)], Effect::LoadLiteral { t, literal })
        }
        2 => {
            let load = |mnemonic, scale: u32, size| {
                let offset = (imm8 << scale) as i32;
                next(
                    3,
                    mnemonic,
                    vec![at, as_, Operand::Imm(offset.into())],
                    Effect::Load { t, base: s, offset, size, float: false },
                )
            };
            let store = |mnemonic, scale: u32, size| {
                let offset = (imm8 << scale) as i32;
                next(3, mnemonic, vec![at, as_, Operand::Imm(offset.into())], Effect::Store { base: s, offset, size })
            };
            match r {
                0 => load("l8ui", 0, 1),
                1 => load("l16ui", 1, 2),
                2 => load("l32i", 2, 4),
                4 => store("s8i", 0, 1),
                5 => store("s16i", 1, 2),
                6 => store("s32i", 2, 4),
                7 => {
                    let mnemonic = match t {
                        0 => "dpfr",
                        1 => "dpfw",
                        2 => "dpfro",
                        3 => "dpfwo",
                        4 => "dhwb",
                        5 => "dhwbi",
                        6 => "dhi",
                        7 => "dii",
                        8 => "dcache",
                        12 => "ipf",
                        13 => "icache",
                        14 => "ihi",
                        15 => "iii",
                        _ => return None,
                    };
                    next(3, mnemonic, vec![as_, Operand::Imm(i64::from(imm8) << 2)], Effect::None)
                }
                9 => load("l16si", 1, 2),
                10 => {
                    let value = sign_extend((u32::from(s) << 8) | imm8, 12);
                    next(3, "movi", vec![at, Operand::Imm(value.into())], Effect::Constant { t, value: value as u32 })
                }
                11 => load("l32ai", 2, 4),
                12 => {
                    let value = sign_extend(imm8, 8);
                    next(
                        3,
                        "addi",
                        vec![at, as_, Operand::Imm(value.into())],
                        Effect::AddImmediate { to: t, from: s, value },
                    )
                }
                13 => {
                    let value = sign_extend(imm8, 8) << 8;
                    next(
                        3,
                        "addmi",
                        vec![at, as_, Operand::Imm(value.into())],
                        Effect::AddImmediate { to: t, from: s, value },
                    )
                }
                14 => next(3, "s32c1i", vec![at, as_, Operand::Imm(i64::from(imm8) << 2)], Effect::Writes(t)),
                15 => store("s32ri", 2, 4),
                _ => return None,
            }
        }
        3 => {
            let (mnemonic, store, update) = match r {
                0 => ("lsi", false, false),
                4 => ("ssi", true, false),
                8 => ("lsiu", false, true),
                12 => ("ssiu", true, true),
                _ => return None,
            };
            let offset = (imm8 << 2) as i32;
            let effect = match (store, update) {
                (_, true) => Effect::Writes(s),
                (true, false) => Effect::Store { base: s, offset, size: 4 },
                (false, false) => Effect::Load { t, base: s, offset, size: 4, float: true },
            };
            next(3, mnemonic, vec![Operand::Fr(t), as_, Operand::Imm(offset.into())], effect)
        }
        4 => {
            // MAC16: the load forms (op1 0 and 1 with op2 0..=3 in the LDINC/LDDEC groups) update `as`.
            let effect = if op2 <= 1 && op1 <= 1 { Effect::Writes(s) } else { Effect::None };
            next(3, "mac16", vec![Operand::Imm(i64::from(word))], effect)
        }
        5 => {
            let n = (word >> 4) & 3;
            let offset = sign_extend(word >> 6, 18) << 2;
            let target = (pc & !3).wrapping_add(offset as u32).wrapping_add(4);
            let mnemonic = ["call0", "call4", "call8", "call12"][n as usize];
            insn(
                3,
                mnemonic,
                vec![Operand::Address(target)],
                Flow::Call(target.into()),
                Effect::Call { window: n as u8 },
            )
        }
        6 => {
            let n = (word >> 4) & 3;
            let m = (word >> 6) & 3;
            match n {
                0 => {
                    let target = pc.wrapping_add(4).wrapping_add(sign_extend(word >> 6, 18) as u32);
                    insn(3, "j", vec![Operand::Address(target)], Flow::Jump(target.into()), Effect::None)
                }
                1 => {
                    let target = pc.wrapping_add(4).wrapping_add(sign_extend(word >> 12, 12) as u32);
                    let mnemonic = ["beqz", "bnez", "bltz", "bgez"][m as usize];
                    insn(
                        3,
                        mnemonic,
                        vec![as_, Operand::Address(target)],
                        Flow::ConditionalJump(target.into()),
                        Effect::None,
                    )
                }
                2 => {
                    let mnemonic = ["beqi", "bnei", "blti", "bgei"][m as usize];
                    let constant = B4CONST[usize::from(r)];
                    insn(
                        3,
                        mnemonic,
                        vec![as_, Operand::Imm(constant.into()), Operand::Address(branch8)],
                        Flow::ConditionalJump(branch8.into()),
                        Effect::None,
                    )
                }
                _ => match m {
                    0 => {
                        let frame = ((word >> 12) & 0xfff) << 3;
                        next(3, "entry", vec![as_, Operand::Imm(frame.into())], Effect::Writes(s))
                    }
                    1 => {
                        let end = pc.wrapping_add(4).wrapping_add(imm8);
                        let (mnemonic, operand) = match r {
                            0 => ("bf", Operand::Br(s)),
                            1 => ("bt", Operand::Br(s)),
                            8 => ("loop", as_),
                            9 => ("loopnez", as_),
                            10 => ("loopgtz", as_),
                            _ => return None,
                        };
                        let target = if r <= 1 { branch8 } else { end };
                        // A zero-overhead loop runs its body and leaves at its end: both are reached.
                        insn(
                            3,
                            mnemonic,
                            vec![operand, Operand::Address(target)],
                            Flow::ConditionalJump(target.into()),
                            Effect::None,
                        )
                    }
                    _ => {
                        let mnemonic = if m == 2 { "bltui" } else { "bgeui" };
                        let constant = B4CONSTU[usize::from(r)];
                        let effect = if m == 3 {
                            Effect::UnsignedBound { s, bound: Bound::Constant(constant) }
                        } else {
                            Effect::None
                        };
                        insn(
                            3,
                            mnemonic,
                            vec![as_, Operand::Imm(constant.into()), Operand::Address(branch8)],
                            Flow::ConditionalJump(branch8.into()),
                            effect,
                        )
                    }
                },
            }
        }
        7 => {
            let mnemonic = match r {
                0 => "bnone",
                1 => "beq",
                2 => "blt",
                3 => "bltu",
                4 => "ball",
                5 => "bbc",
                6 | 7 => "bbci",
                8 => "bany",
                9 => "bne",
                10 => "bge",
                11 => "bgeu",
                12 => "bnall",
                13 => "bbs",
                _ => "bbsi",
            };
            let (operands, effect) = if matches!(r, 6 | 7 | 14 | 15) {
                let bit = (u32::from(r & 1) << 4) | u32::from(t);
                (vec![as_, Operand::Imm(bit.into()), Operand::Address(branch8)], Effect::None)
            } else {
                let effect =
                    if r == 11 { Effect::UnsignedBound { s, bound: Bound::Register(t) } } else { Effect::None };
                (vec![as_, at, Operand::Address(branch8)], effect)
            };
            insn(3, mnemonic, operands, Flow::ConditionalJump(branch8.into()), effect)
        }
        _ => return None,
    };
    Some(decoded)
}

/// The QRST group (op0 0): arithmetic, shifts, special registers, calls and returns through registers.
fn qrst(word: u32, _pc: u32) -> Option<Decoded> {
    let t = ((word >> 4) & 0xf) as u8;
    let s = ((word >> 8) & 0xf) as u8;
    let r = ((word >> 12) & 0xf) as u8;
    let op1 = (word >> 16) & 0xf;
    let op2 = (word >> 20) & 0xf;
    let (ar, as_, at) = (Operand::Ar(r), Operand::Ar(s), Operand::Ar(t));
    let (fr, fs, ft) = (Operand::Fr(r), Operand::Fr(s), Operand::Fr(t));
    let rrr = |mnemonic| next(3, mnemonic, vec![ar, as_, at], Effect::Writes(r));
    let sr = (u32::from(r) << 4) | u32::from(s);
    Some(match op1 {
        0 => match op2 {
            0 => match r {
                0 => {
                    let (m, n) = (t >> 2, t & 3);
                    match (m, n) {
                        (0, 0) if s == 0 => insn(3, "ill", vec![], Flow::Halt, Effect::None),
                        (2, 0) if s == 0 => insn(3, "ret", vec![], Flow::Return, Effect::None),
                        (2, 1) if s == 0 => insn(3, "retw", vec![], Flow::Return, Effect::None),
                        (2, 2) => {
                            Decoded { through: Some(s), ..insn(3, "jx", vec![as_], Flow::IndirectJump, Effect::None) }
                        }
                        (3, _) => Decoded {
                            through: Some(s),
                            ..insn(
                                3,
                                ["callx0", "callx4", "callx8", "callx12"][usize::from(n)],
                                vec![as_],
                                Flow::IndirectCall,
                                Effect::Call { window: n },
                            )
                        },
                        _ => return None,
                    }
                }
                1 => next(3, "movsp", vec![at, as_], Effect::Writes(t)),
                2 if s == 0 => {
                    let mnemonic = match t {
                        0 => "isync",
                        1 => "rsync",
                        2 => "esync",
                        3 => "dsync",
                        8 => "excw",
                        12 => "memw",
                        13 => "extw",
                        15 => "nop",
                        _ => return None,
                    };
                    next(3, mnemonic, vec![], Effect::None)
                }
                3 => match (t, s) {
                    (0, 0) => insn(3, "rfe", vec![], Flow::Return, Effect::None),
                    (0, 1) => insn(3, "rfue", vec![], Flow::Return, Effect::None),
                    (0, 2) => insn(3, "rfde", vec![], Flow::Return, Effect::None),
                    (0, 4) => insn(3, "rfwo", vec![], Flow::Return, Effect::Clobber),
                    (0, 5) => insn(3, "rfwu", vec![], Flow::Return, Effect::Clobber),
                    (1, _) => insn(3, "rfi", vec![Operand::Imm(s.into())], Flow::Return, Effect::None),
                    _ => return None,
                },
                4 => next(3, "break", vec![Operand::Imm(s.into()), Operand::Imm(t.into())], Effect::None),
                5 if t == 0 && s == 0 => next(3, "syscall", vec![], Effect::Clobber),
                5 if t == 0 && s == 1 => next(3, "simcall", vec![], Effect::Clobber),
                6 => next(3, "rsil", vec![at, Operand::Imm(s.into())], Effect::Writes(t)),
                7 if t == 0 => next(3, "waiti", vec![Operand::Imm(s.into())], Effect::None),
                8..=11 => {
                    let mnemonic = ["any4", "all4", "any8", "all8"][usize::from(r - 8)];
                    next(3, mnemonic, vec![Operand::Br(t), Operand::Br(s)], Effect::None)
                }
                _ => return None,
            },
            1 => rrr("and"),
            2 if s == t => next(3, "mov", vec![ar, as_], Effect::Copy { to: r, from: s }),
            2 => rrr("or"),
            3 => rrr("xor"),
            4 => match r {
                0 => next(3, "ssr", vec![as_], Effect::None),
                1 => next(3, "ssl", vec![as_], Effect::None),
                2 => next(3, "ssa8l", vec![as_], Effect::None),
                3 => next(3, "ssa8b", vec![as_], Effect::None),
                4 => next(3, "ssai", vec![Operand::Imm((u32::from(s) | (u32::from(t & 1) << 4)).into())], Effect::None),
                6 => next(3, "rer", vec![at, as_], Effect::Writes(t)),
                7 => next(3, "wer", vec![at, as_], Effect::None),
                8 => next(3, "rotw", vec![Operand::Imm(sign_extend(t.into(), 4).into())], Effect::Clobber),
                14 => next(3, "nsa", vec![at, as_], Effect::Writes(t)),
                15 => next(3, "nsau", vec![at, as_], Effect::Writes(t)),
                _ => return None,
            },
            5 => {
                let (mnemonic, writes) = match r {
                    3 => ("ritlb0", true),
                    4 => ("iitlb", false),
                    5 => ("pitlb", true),
                    6 => ("witlb", false),
                    7 => ("ritlb1", true),
                    11 => ("rdtlb0", true),
                    12 => ("idtlb", false),
                    13 => ("pdtlb", true),
                    14 => ("wdtlb", false),
                    15 => ("rdtlb1", true),
                    _ => return None,
                };
                let effect = if writes { Effect::Writes(t) } else { Effect::None };
                next(3, mnemonic, vec![at, as_], effect)
            }
            6 => match s {
                0 => next(3, "neg", vec![ar, at], Effect::Writes(r)),
                1 => next(3, "abs", vec![ar, at], Effect::Writes(r)),
                _ => return None,
            },
            8 => next(3, "add", vec![ar, as_, at], Effect::AddScaled { to: r, index: s, base: t, shift: 0 }),
            9 => next(3, "addx2", vec![ar, as_, at], Effect::AddScaled { to: r, index: s, base: t, shift: 1 }),
            10 => next(3, "addx4", vec![ar, as_, at], Effect::AddScaled { to: r, index: s, base: t, shift: 2 }),
            11 => next(3, "addx8", vec![ar, as_, at], Effect::AddScaled { to: r, index: s, base: t, shift: 3 }),
            12 => rrr("sub"),
            13 => rrr("subx2"),
            14 => rrr("subx4"),
            15 => rrr("subx8"),
            _ => return None,
        },
        1 => match op2 {
            0 | 1 => {
                let shift = 32 - ((op2 & 1) << 4 | u32::from(t));
                next(3, "slli", vec![ar, as_, Operand::Imm(shift.into())], Effect::Writes(r))
            }
            2 | 3 => {
                let shift = (op2 & 1) << 4 | u32::from(s);
                next(3, "srai", vec![ar, at, Operand::Imm(shift.into())], Effect::Writes(r))
            }
            4 => next(3, "srli", vec![ar, at, Operand::Imm(s.into())], Effect::Writes(r)),
            6 => next(3, "xsr", vec![at, Operand::Special(sr)], Effect::Writes(t)),
            8 => rrr("src"),
            9 if s == 0 => next(3, "srl", vec![ar, at], Effect::Writes(r)),
            10 if t == 0 => next(3, "sll", vec![ar, as_], Effect::Writes(r)),
            11 if s == 0 => next(3, "sra", vec![ar, at], Effect::Writes(r)),
            12 => rrr("mul16u"),
            13 => rrr("mul16s"),
            15 => next(3, "imp", vec![Operand::Imm(word.into())], Effect::Clobber),
            _ => return None,
        },
        2 => match op2 {
            0..=4 => {
                let mnemonic = ["andb", "andbc", "orb", "orbc", "xorb"][op2 as usize];
                next(3, mnemonic, vec![Operand::Br(r), Operand::Br(s), Operand::Br(t)], Effect::None)
            }
            8 => rrr("mull"),
            10 => rrr("muluh"),
            11 => rrr("mulsh"),
            12 => rrr("quou"),
            13 => rrr("quos"),
            14 => rrr("remu"),
            15 => rrr("rems"),
            _ => return None,
        },
        3 => match op2 {
            0 => next(3, "rsr", vec![at, Operand::Special(sr)], Effect::Writes(t)),
            1 => next(3, "wsr", vec![at, Operand::Special(sr)], Effect::None),
            2 => next(3, "sext", vec![ar, as_, Operand::Imm(i64::from(t) + 7)], Effect::Writes(r)),
            3 => next(3, "clamps", vec![ar, as_, Operand::Imm(i64::from(t) + 7)], Effect::Writes(r)),
            4 => rrr("min"),
            5 => rrr("max"),
            6 => rrr("minu"),
            7 => rrr("maxu"),
            8 => rrr("moveqz"),
            9 => rrr("movnez"),
            10 => rrr("movltz"),
            11 => rrr("movgez"),
            12 => next(3, "movf", vec![ar, as_, Operand::Br(t)], Effect::Writes(r)),
            13 => next(3, "movt", vec![ar, as_, Operand::Br(t)], Effect::Writes(r)),
            14 => next(3, "rur", vec![ar, Operand::User((u32::from(s) << 4) | u32::from(t))], Effect::Writes(r)),
            15 => next(3, "wur", vec![at, Operand::User(sr)], Effect::None),
            _ => return None,
        },
        4 | 5 => {
            let shift = ((op1 & 1) << 4) | u32::from(s);
            next(
                3,
                "extui",
                vec![ar, at, Operand::Imm(shift.into()), Operand::Imm(i64::from(op2) + 1)],
                Effect::Writes(r),
            )
        }
        6 | 7 => next(3, if op1 == 6 { "cust0" } else { "cust1" }, vec![Operand::Imm(word.into())], Effect::Clobber),
        8 => match op2 {
            0 => next(3, "lsx", vec![fr, as_, at], Effect::None),
            1 => next(3, "lsxu", vec![fr, as_, at], Effect::Writes(s)),
            4 => next(3, "ssx", vec![fr, as_, at], Effect::None),
            5 => next(3, "ssxu", vec![fr, as_, at], Effect::Writes(s)),
            _ => return None,
        },
        9 => {
            let offset = sign_extend(u32::from(r) | 0xffff_fff0, 32) << 2;
            match op2 {
                0 => next(3, "l32e", vec![at, as_, Operand::Imm(offset.into())], Effect::Writes(t)),
                4 => next(3, "s32e", vec![at, as_, Operand::Imm(offset.into())], Effect::None),
                _ => return None,
            }
        }
        10 => match op2 {
            0 => next(3, "add.s", vec![fr, fs, ft], Effect::None),
            1 => next(3, "sub.s", vec![fr, fs, ft], Effect::None),
            2 => next(3, "mul.s", vec![fr, fs, ft], Effect::None),
            4 => next(3, "madd.s", vec![fr, fs, ft], Effect::None),
            5 => next(3, "msub.s", vec![fr, fs, ft], Effect::None),
            8..=11 => {
                let mnemonic = ["round.s", "trunc.s", "floor.s", "ceil.s"][(op2 - 8) as usize];
                next(3, mnemonic, vec![ar, fs, Operand::Imm(t.into())], Effect::Writes(r))
            }
            12 => next(3, "float.s", vec![fr, as_, Operand::Imm(t.into())], Effect::None),
            13 => next(3, "ufloat.s", vec![fr, as_, Operand::Imm(t.into())], Effect::None),
            14 => next(3, "utrunc.s", vec![ar, fs, Operand::Imm(t.into())], Effect::Writes(r)),
            15 => match t {
                0 => next(3, "mov.s", vec![fr, fs], Effect::None),
                1 => next(3, "abs.s", vec![fr, fs], Effect::None),
                4 => next(3, "rfr", vec![ar, fs], Effect::Writes(r)),
                5 => next(3, "wfr", vec![fr, as_], Effect::None),
                6 => next(3, "neg.s", vec![fr, fs], Effect::None),
                _ => next(3, "fp1op", vec![fr, fs, Operand::Imm(t.into())], Effect::None),
            },
            _ => next(3, "fp0op", vec![fr, fs, ft, Operand::Imm(op2.into())], Effect::None),
        },
        11 => match op2 {
            1..=7 => {
                let mnemonic = ["un.s", "oeq.s", "ueq.s", "olt.s", "ult.s", "ole.s", "ule.s"][(op2 - 1) as usize];
                next(3, mnemonic, vec![Operand::Br(r), fs, ft], Effect::None)
            }
            8..=11 => {
                let mnemonic = ["moveqz.s", "movnez.s", "movltz.s", "movgez.s"][(op2 - 8) as usize];
                next(3, mnemonic, vec![fr, fs, at], Effect::None)
            }
            12 => next(3, "movf.s", vec![fr, fs, Operand::Br(t)], Effect::None),
            13 => next(3, "movt.s", vec![fr, fs, Operand::Br(t)], Effect::None),
            _ => return None,
        },
        _ => return None,
    })
}

/// What a run knows about one AR register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Known {
    Unknown,
    Value(u32),
    /// An index below `entries`, proven by the bounding branch at `guard`.
    Bounded {
        entries: u32,
        guard: u64,
    },
    /// The address of entry `index` of a table: `table + (index << shift)`.
    Slot {
        table: u32,
        entries: u32,
        guard: u64,
        shift: u8,
    },
    /// A value loaded from such a slot.
    Entry {
        table: u32,
        entries: u32,
        guard: u64,
        size: u8,
    },
}

/// rampage's native Xtensa decoder, with the register run it follows.
pub struct XtensaDisassembler {
    registers: [Known; 16],
    jump_table: Option<JumpTable>,
}

impl Default for XtensaDisassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl XtensaDisassembler {
    pub fn new() -> Self {
        Self { registers: [Known::Unknown; 16], jump_table: None }
    }

    fn value(&self, register: u8) -> Option<u32> {
        match self.registers[usize::from(register & 15)] {
            Known::Value(value) => Some(value),
            _ => None,
        }
    }

    fn set(&mut self, register: u8, known: Known) {
        self.registers[usize::from(register & 15)] = known;
    }
}

impl Disassembler for XtensaDisassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        self.decode_with_memory(bytes, address, &|_, _| None)
    }

    fn decode_with_memory(&mut self, bytes: &[u8], address: u64, read: &dyn Fn(u64, u8) -> Option<u64>) -> Insn {
        self.jump_table = None;
        let mut insn = Insn {
            address,
            len: bytes.first().and_then(|&first| length(first)).unwrap_or(1).min(bytes.len().max(1) as u8),
            flow: Flow::Invalid,
            data_ref: None,
            accesses: false,
            immediate: None,
            conditional: false,
        };
        let Some(decoded) = u32::try_from(address).ok().and_then(|pc| decode(bytes, pc)) else {
            self.registers = [Known::Unknown; 16];
            return insn;
        };
        insn.len = decoded.len;
        insn.flow = decoded.flow;
        if let Some(register) = decoded.through {
            match self.registers[usize::from(register)] {
                Known::Value(target) => {
                    insn.flow = match decoded.flow {
                        Flow::IndirectCall => Flow::Call(target.into()),
                        _ => Flow::Jump(target.into()),
                    };
                }
                Known::Entry { table, entries, guard, size: 4 } if decoded.flow == Flow::IndirectJump => {
                    self.jump_table = Some(JumpTable {
                        guard,
                        table: table.into(),
                        entry_size: 4,
                        entries: entries.into(),
                        signed: false,
                        base: None,
                        shift: 0,
                        alignment: 1,
                        target_width: TargetWidth::Bits32,
                    });
                }
                _ => {}
            }
        }
        match decoded.effect {
            Effect::None => {}
            Effect::LoadLiteral { t, literal } => {
                insn.data_ref = Some(literal.into());
                insn.accesses = true;
                let value = read(literal.into(), 4).and_then(|value| u32::try_from(value).ok());
                insn.immediate = value.map(u64::from);
                self.set(t, value.map_or(Known::Unknown, Known::Value));
            }
            Effect::Constant { t, value } => self.set(t, Known::Value(value)),
            Effect::Copy { to, from } => self.set(to, self.registers[usize::from(from)]),
            Effect::AddImmediate { to, from, value } => {
                let known =
                    self.value(from).map_or(Known::Unknown, |base| Known::Value(base.wrapping_add(value as u32)));
                self.set(to, known);
            }
            Effect::AddScaled { to, index, base, shift } => {
                let known = match (self.registers[usize::from(index)], self.registers[usize::from(base)]) {
                    (Known::Value(index), Known::Value(base)) => Known::Value(base.wrapping_add(index << shift)),
                    (Known::Bounded { entries, guard }, Known::Value(table)) if shift > 0 => {
                        Known::Slot { table, entries, guard, shift }
                    }
                    _ => Known::Unknown,
                };
                self.set(to, known);
            }
            Effect::Load { t, base, offset, size, float } => {
                let known = match self.registers[usize::from(base)] {
                    Known::Value(base) => {
                        insn.data_ref = Some(base.wrapping_add(offset as u32).into());
                        insn.accesses = true;
                        Known::Unknown
                    }
                    Known::Slot { table, entries, guard, shift } if offset == 0 && u32::from(size) == 1 << shift => {
                        Known::Entry { table, entries, guard, size }
                    }
                    _ => Known::Unknown,
                };
                if !float {
                    self.set(t, known);
                }
            }
            Effect::Store { base, offset, .. } => {
                if let Some(base) = self.value(base) {
                    insn.data_ref = Some(base.wrapping_add(offset as u32).into());
                    insn.accesses = true;
                }
            }
            Effect::Call { window } => {
                // call0 (and callx0): a12-a15 and the stack pointer survive; windowed callN: the caller's a0 to
                // a(4N-1) survive, and the callee works in (and returns into) the rest.
                let first = if window == 0 { 0 } else { usize::from(window) * 4 };
                for (register, known) in self.registers.iter_mut().enumerate() {
                    let kept = if window == 0 { register == 1 || register >= 12 } else { register < first };
                    if !kept {
                        *known = Known::Unknown;
                    }
                }
            }
            Effect::Writes(register) => self.set(register, Known::Unknown),
            Effect::Clobber => self.registers = [Known::Unknown; 16],
            Effect::UnsignedBound { s, bound } => {
                let bound = match bound {
                    Bound::Constant(value) => Some(value),
                    Bound::Register(register) => self.value(register),
                };
                // The fall-through path (decoded next in this run) has the index below the bound.
                if let Some(entries) =
                    bound.filter(|&entries| entries > 0 && u64::from(entries) <= crate::MAX_JUMP_TABLE_ENTRIES)
                {
                    self.set(s, Known::Bounded { entries, guard: address });
                }
            }
        }
        insn
    }

    fn reset(&mut self) {
        self.registers = [Known::Unknown; 16];
        self.jump_table = None;
    }

    fn jump_table(&self) -> Option<JumpTable> {
        self.jump_table
    }

    fn operands(&self, bytes: &[u8], address: u64) -> Option<Vec<OperandEvidence>> {
        let decoded = decode(bytes, u32::try_from(address).ok()?)?;
        if usize::from(decoded.len) != bytes.len() {
            return None;
        }
        Some(
            decoded
                .operands
                .iter()
                .enumerate()
                .map(|(index, operand)| {
                    let index = index as u8;
                    match *operand {
                        Operand::Ar(_) | Operand::Fr(_) | Operand::Br(_) => OperandEvidence {
                            kind: crate::OperandKind::Register,
                            ..OperandEvidence::unsupported(index)
                        },
                        Operand::Imm(value) if !decoded.mnemonic.starts_with("mac16") => {
                            OperandEvidence::immediate(index, value as u64, 32)
                        }
                        _ => OperandEvidence::unsupported(index),
                    }
                })
                .collect(),
        )
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        let Some(decoded) = u32::try_from(address).ok().and_then(|pc| decode(bytes, pc)) else {
            return "(bad)".to_owned();
        };
        if decoded.operands.is_empty() {
            return decoded.mnemonic.to_owned();
        }
        let operands: Vec<String> = decoded.operands.iter().map(|operand| operand.render()).collect();
        format!("{} {}", decoded.mnemonic, operands.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8], address: u64) -> String {
        XtensaDisassembler::new().format(bytes, address)
    }

    /// Encodings checked against GNU objdump on the ESP32 fixture.
    #[test]
    fn renders_as_objdump_reads_the_esp32_fixture() {
        assert_eq!(text(&[0x36, 0x41, 0x00], 0x4008_0004), "entry a1, 32");
        assert_eq!(text(&[0xa1, 0xfe, 0xff], 0x4008_0007), "l32r a10, 0x40080000");
        assert_eq!(text(&[0xe5, 0x0e, 0x50], 0x4008_000a), "call8 0x400d00f8");
        assert_eq!(text(&[0x06, 0xff, 0xff], 0x4008_0010), "j 0x40080010");
        assert_eq!(text(&[0x87, 0x39, 0xf4], 0x400d_00d1), "bltu a9, a8, 0x400d00c9");
        assert_eq!(text(&[0x80, 0x80, 0x75], 0), "extui a8, a8, 16, 8");
        assert_eq!(text(&[0xc0, 0x20, 0x00], 0), "memw");
        assert_eq!(text(&[0xe0, 0x08, 0x00], 0), "callx8 a8");
        assert_eq!(text(&[0x56, 0x4a, 0xff], 0x400d_0106), "bnez a10, 0x400d00fe");
        assert_eq!(text(&[0x1d, 0xf0], 0), "retw.n");
        assert_eq!(text(&[0xad, 0x01], 0), "mov.n a10, a1");
        assert_eq!(text(&[0x7c, 0xf2], 0), "movi.n a2, -1");
        assert_eq!(text(&[0x92, 0xa0, 0x7d], 0), "movi a9, 125");
        assert_eq!(text(&[0x88, 0x0a], 0), "l32i.n a8, a10, 0");
        assert_eq!(text(&[0x29, 0x08], 0), "s32i.n a2, a8, 0");
        assert_eq!(text(&[0xa2, 0x02, 0x00], 0), "l8ui a10, a2, 0");
        assert_eq!(text(&[0x1b, 0x22], 0), "addi.n a2, a2, 1");
        assert_eq!(text(&[0x12, 0xc1, 0xf0], 0), "addi a1, a1, -16");
        assert_eq!(text(&[0xc0, 0x00, 0x00], 0), "callx0 a0");
        assert_eq!(text(&[0x00, 0x00, 0x00], 0), "ill");
        assert_eq!(text(&[0x0e, 0x00, 0x00], 0), "(bad)");
    }

    #[test]
    fn long_calls_resolve_through_the_literal_they_load() {
        let mut decoder = XtensaDisassembler::new();
        let read = |address: u64, size: u8| (address == 0x400d_0030 && size == 4).then_some(0x4000_7d54);
        let load = decoder.decode_with_memory(&[0x81, 0xd1, 0xff], 0x400d_00eb, &read);
        assert_eq!(load.data_ref, Some(0x400d_0030));
        assert!(load.accesses);
        assert_eq!(load.immediate, Some(0x4000_7d54));
        let call = decoder.decode_with_memory(&[0xe0, 0x08, 0x00], 0x400d_00ee, &read);
        assert_eq!(call.flow, Flow::Call(0x4000_7d54));
        // A windowed call8 keeps the caller's a0-a7 and forgets a8-a15.
        decoder.decode_with_memory(&[0x81, 0xd1, 0xff], 0x400d_00eb, &read);
        decoder.decode_with_memory(&[0xe5, 0x0e, 0x50], 0x4008_000a, &read);
        assert_eq!(decoder.decode_with_memory(&[0xe0, 0x08, 0x00], 0x400d_00ee, &read).flow, Flow::IndirectCall);
    }

    #[test]
    fn switch_tables_are_bounded_by_bgeui() {
        let mut decoder = XtensaDisassembler::new();
        let read = |address: u64, _| (address == 0x1000).then_some(0x2000);
        // bgeui a2, 8, +x; l32r a8, 0x1000; addx4 a2, a2, a8; l32i.n a2, a2, 0; jx a2
        decoder.decode_with_memory(&[0xf6, 0x82, 0x20], 0x1010, &read);
        let at = 0x1013u32;
        let imm16 = ((0x1000u32.wrapping_sub((at + 3) & !3)) >> 2) & 0xffff;
        let l32r = [0x81, imm16 as u8, (imm16 >> 8) as u8];
        decoder.decode_with_memory(&l32r, at.into(), &read);
        decoder.decode_with_memory(&[0x80, 0x22, 0xa0], 0x1016, &read);
        decoder.decode_with_memory(&[0x28, 0x02], 0x1019, &read);
        let jump = decoder.decode_with_memory(&[0xa0, 0x02, 0x00], 0x101b, &read);
        assert_eq!(jump.flow, Flow::IndirectJump);
        let table = decoder.jump_table().unwrap();
        assert_eq!((table.guard, table.table, table.entries), (0x1010, 0x2000, 8));
    }
}
