//! MIPS16e, the compressed instruction set of MIPS32 processors: decoding, rendering, control flow and what each
//! instruction does to the registers address tracking follows.
//!
//! Instructions are 16 bits. `jal` and `jalx` take 32, and an `EXTEND` prefix widens the immediate of the
//! instruction after it; the pair is decoded as one 4-byte instruction, as GNU objdump shows it. Only eight
//! registers are directly encoded (`$s0`, `$s1`, `$v0`, `$v1`, `$a0`-`$a3`); `move` reaches the other 24.
//! Branches have no delay slot, nor do the compact jumps (`jrc`, `jalrc`); `jal`, `jalx`, `jr` and `jalr` have one.
//! 64-bit MIPS16e instructions are not decoded.

/// The MIPS32 register each 3-bit MIPS16e register field names.
const REGISTERS: [u8; 8] = [16, 17, 2, 3, 4, 5, 6, 7];

const NAMES: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2",
    "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
];

pub(crate) const SP: u8 = 29;
pub(crate) const RA: u8 = 31;
/// `$t8`, the condition register (`T`) that `slt`, `cmp` and their kin set and `bteqz`/`btnez` test.
const T: u8 = 24;

/// The ABI name of MIPS32 register `register`.
pub(crate) fn register_name(register: u8) -> &'static str {
    NAMES[usize::from(register & 31)]
}

/// How an instruction transfers control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Control {
    Next,
    Branch {
        target: u64,
        conditional: bool,
    },
    /// `jal` (stays in MIPS16e) or `jalx` (`exchange`: calls MIPS32 code).
    Call {
        target: u64,
        exchange: bool,
    },
    /// `jr`, `jrc`, `jalr` or `jalrc` through a register other than `$ra`; `link` for the calls.
    Register {
        register: u8,
        link: bool,
    },
    Return,
}

/// What an instruction does to a register value address tracking can follow. Registers are MIPS32 numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    /// A load (`store: false`) or store of `size` bytes at `disp(base)`.
    Memory {
        register: u8,
        base: u8,
        disp: i64,
        size: u8,
        store: bool,
    },
    Move {
        to: u8,
        from: u8,
    },
    AddImmediate {
        to: u8,
        from: u8,
        value: i64,
    },
    Add {
        to: u8,
        left: u8,
        right: u8,
    },
    Constant {
        to: u8,
        value: u64,
    },
    ShiftLeft {
        to: u8,
        from: u8,
        amount: u8,
    },
    /// `addiu rx, $pc, imm`: an address formed relative to the program counter.
    PcAddress {
        to: u8,
        address: u64,
    },
    /// `lw rx, imm($pc)`: a literal-pool word.
    PcLoad {
        to: u8,
        address: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decoded {
    pub(crate) len: u8,
    pub(crate) mnemonic: &'static str,
    pub(crate) operands: String,
    pub(crate) control: Control,
    pub(crate) delay_slots: u8,
    /// Every register the instruction changes.
    pub(crate) writes: Vec<u8>,
    pub(crate) effect: Effect,
}

impl Decoded {
    pub(crate) fn text(&self) -> String {
        if self.operands.is_empty() { self.mnemonic.to_owned() } else { format!("{} {}", self.mnemonic, self.operands) }
    }
}

fn reg(register: u8) -> String {
    format!("${}", register_name(register))
}

/// An immediate as Capstone prints MIPS ones: small values in decimal, others in hex.
fn imm(value: i64) -> String {
    match value {
        -9..=9 => value.to_string(),
        _ if value < 0 => format!("-{:#x}", value.unsigned_abs()),
        _ => format!("{value:#x}"),
    }
}

fn signed(value: u16, bits: u32) -> i64 {
    let shift = 16 - bits;
    i64::from(((value << shift) as i16) >> shift)
}

fn halfword(bytes: &[u8], index: usize, big_endian: bool) -> Option<u16> {
    let pair: [u8; 2] = bytes.get(index * 2..index * 2 + 2)?.try_into().ok()?;
    Some(if big_endian { u16::from_be_bytes(pair) } else { u16::from_le_bytes(pair) })
}

/// The base of a PC-relative address: the instruction's address (its `EXTEND`'s, when extended) with the low two
/// bits cleared, or the jump's address for an instruction in a jump's delay slot.
fn pc_base(address: u64, delay_slot_of: Option<u64>) -> u64 {
    delay_slot_of.unwrap_or(address) & !3
}

/// Register lists of `save` and `restore`, with consecutive registers written as ranges (`$s0-$s1`).
fn register_list(registers: &[u8]) -> Vec<String> {
    let mut runs: Vec<(u8, u8)> = Vec::new();
    for &register in registers {
        match runs.last_mut() {
            Some((_, last)) if *last + 1 == register => *last = register,
            _ => runs.push((register, register)),
        }
    }
    runs.into_iter()
        .map(|(first, last)| if first == last { reg(first) } else { format!("{}-{}", reg(first), reg(last)) })
        .collect()
}

/// `save` and `restore`: `extend` is the `EXTEND` prefix's 11 bits, if any.
fn save_restore(first: u16, extend: Option<u16>, len: u8) -> Option<Decoded> {
    let save = first & 0x80 != 0;
    let low = first & 0xf;
    let (frame, extra, aregs) = match extend {
        None => (if low == 0 { 128 } else { u32::from(low) * 8 }, 0, 0),
        Some(ext) => ((u32::from((ext >> 4) & 0xf) << 4 | u32::from(low)) * 8, (ext >> 8) & 7, ext & 0xf),
    };
    let (arguments, statics) = match aregs {
        0xe => (4, 0),
        0xb => (0, 4),
        0xf => return None,
        _ => (aregs >> 2, aregs & 3),
    };
    let mut saved = Vec::new();
    if first & 0x20 != 0 {
        saved.push(16);
    }
    if first & 0x10 != 0 {
        saved.push(17);
    }
    // Extra static registers: `$s2` up to `$s7`, then `$s8` (`$fp`).
    for index in 0..extra {
        saved.push(if index == 6 { 30 } else { 18 + index as u8 });
    }
    saved.extend((0..statics).map(|index| 7 - (statics - 1 - index) as u8));
    let mut parts = register_list(&(4..4 + arguments as u8).collect::<Vec<_>>());
    parts.push(frame.to_string());
    if first & 0x40 != 0 {
        parts.push(reg(RA));
    }
    parts.extend(register_list(&saved));
    let mut writes = vec![SP];
    if !save {
        writes.extend(saved);
        if first & 0x40 != 0 {
            writes.push(RA);
        }
    }
    Some(Decoded {
        len,
        mnemonic: if save { "save" } else { "restore" },
        operands: parts.join(", "),
        control: Control::Next,
        delay_slots: 0,
        writes,
        effect: Effect::None,
    })
}

fn plain(len: u8, mnemonic: &'static str, operands: String, writes: Vec<u8>, effect: Effect) -> Option<Decoded> {
    Some(Decoded { len, mnemonic, operands, control: Control::Next, delay_slots: 0, writes, effect })
}

fn branch(len: u8, mnemonic: &'static str, prefix: String, target: u64, conditional: bool) -> Option<Decoded> {
    let operands = if prefix.is_empty() { format!("{target:#x}") } else { format!("{prefix}, {target:#x}") };
    Some(Decoded {
        len,
        mnemonic,
        operands,
        control: Control::Branch { target, conditional },
        delay_slots: 0,
        writes: Vec::new(),
        effect: Effect::None,
    })
}

fn memory(
    len: u8,
    mnemonic: &'static str,
    register: u8,
    base: u8,
    disp: i64,
    size: u8,
    store: bool,
) -> Option<Decoded> {
    let operands = format!("{}, {}({})", reg(register), imm(disp), reg(base));
    let writes = if store { Vec::new() } else { vec![register] };
    plain(len, mnemonic, operands, writes, Effect::Memory { register, base, disp, size, store })
}

/// Decodes the MIPS16e instruction at the start of `bytes`, at `address`. `delay_slot_of` is the address of the
/// jump whose delay slot this instruction fills, which PC-relative instructions take as their base. `None` for
/// bytes that are no MIPS16e instruction rampage decodes, including the 64-bit ones and reserved encodings.
pub(crate) fn decode(bytes: &[u8], address: u64, big_endian: bool, delay_slot_of: Option<u64>) -> Option<Decoded> {
    let first = halfword(bytes, 0, big_endian)?;
    match first >> 11 {
        0b11110 => {
            let second = halfword(bytes, 1, big_endian)?;
            extended(first & 0x7ff, second, address, delay_slot_of)
        }
        0b00011 => {
            let second = halfword(bytes, 1, big_endian)?;
            let index = u64::from(first & 0x1f) << 21 | u64::from((first >> 5) & 0x1f) << 16 | u64::from(second);
            // The 256 MiB region is the delay slot's.
            let target = (address.wrapping_add(4) & !0x0fff_ffff & 0xffff_ffff) | index << 2;
            let exchange = first & 0x400 != 0;
            Some(Decoded {
                len: 4,
                mnemonic: if exchange { "jalx" } else { "jal" },
                operands: format!("{target:#x}"),
                control: Control::Call { target, exchange },
                delay_slots: 1,
                writes: vec![RA],
                effect: Effect::None,
            })
        }
        _ => short(first, address, delay_slot_of),
    }
}

fn short(first: u16, address: u64, delay_slot_of: Option<u64>) -> Option<Decoded> {
    let rx = REGISTERS[usize::from((first >> 8) & 7)];
    let ry = REGISTERS[usize::from((first >> 5) & 7)];
    let rz = REGISTERS[usize::from((first >> 2) & 7)];
    let imm8 = first & 0xff;
    let imm5 = i64::from(first & 0x1f);
    let next = address.wrapping_add(2);
    let relative = |offset: i64| next.wrapping_add((offset << 1) as u64);
    match first >> 11 {
        0 => {
            let value = i64::from(imm8) << 2;
            let operands = format!("{}, $sp, {}", reg(rx), imm(value));
            plain(2, "addiu", operands, vec![rx], Effect::AddImmediate { to: rx, from: SP, value })
        }
        1 => {
            let value = i64::from(imm8) << 2;
            let address = pc_base(address, delay_slot_of).wrapping_add(value as u64) & 0xffff_ffff;
            plain(
                2,
                "addiu",
                format!("{}, $pc, {}", reg(rx), imm(value)),
                vec![rx],
                Effect::PcAddress { to: rx, address },
            )
        }
        2 => branch(2, "b", String::new(), relative(signed(first & 0x7ff, 11)), false),
        4 => branch(2, "beqz", reg(rx), relative(signed(imm8, 8)), true),
        5 => branch(2, "bnez", reg(rx), relative(signed(imm8, 8)), true),
        6 => {
            let amount = match (first >> 2) & 7 {
                0 => 8,
                amount => amount as u8,
            };
            let operands = format!("{}, {}, {}", reg(rx), reg(ry), imm(i64::from(amount)));
            match first & 3 {
                0 => plain(2, "sll", operands, vec![rx], Effect::ShiftLeft { to: rx, from: ry, amount }),
                2 => plain(2, "srl", operands, vec![rx], Effect::None),
                3 => plain(2, "sra", operands, vec![rx], Effect::None),
                _ => None,
            }
        }
        8 if first & 0x10 == 0 => {
            let value = signed(first & 0xf, 4);
            let operands = format!("{}, {}, {}", reg(ry), reg(rx), imm(value));
            plain(2, "addiu", operands, vec![ry], Effect::AddImmediate { to: ry, from: rx, value })
        }
        9 => {
            let value = signed(imm8, 8);
            plain(
                2,
                "addiu",
                format!("{}, {}", reg(rx), imm(value)),
                vec![rx],
                Effect::AddImmediate { to: rx, from: rx, value },
            )
        }
        10 => plain(2, "slti", format!("{}, {}", reg(rx), imm(i64::from(imm8))), vec![T], Effect::None),
        11 => plain(2, "sltiu", format!("{}, {}", reg(rx), imm(i64::from(imm8))), vec![T], Effect::None),
        12 => {
            let offset = signed(imm8, 8);
            match (first >> 8) & 7 {
                0 => branch(2, "bteqz", String::new(), relative(offset), true),
                1 => branch(2, "btnez", String::new(), relative(offset), true),
                2 => memory(2, "sw", RA, SP, i64::from(imm8) << 2, 4, true),
                3 => {
                    let value = offset << 3;
                    plain(
                        2,
                        "addiu",
                        format!("$sp, {}", imm(value)),
                        vec![SP],
                        Effect::AddImmediate { to: SP, from: SP, value },
                    )
                }
                4 => save_restore(first, None, 2),
                5 => {
                    let to = ((first >> 3) & 3) << 3 | ((first >> 5) & 7);
                    let from = REGISTERS[usize::from(first & 7)];
                    if to == 0 {
                        return plain(2, "nop", String::new(), Vec::new(), Effect::None);
                    }
                    let to = to as u8;
                    plain(2, "move", format!("{}, {}", reg(to), reg(from)), vec![to], Effect::Move { to, from })
                }
                7 => {
                    let from = (first & 0x1f) as u8;
                    plain(2, "move", format!("{}, {}", reg(ry), reg(from)), vec![ry], Effect::Move { to: ry, from })
                }
                _ => None,
            }
        }
        13 => {
            let value = u64::from(imm8);
            plain(2, "li", format!("{}, {}", reg(rx), imm(value as i64)), vec![rx], Effect::Constant { to: rx, value })
        }
        14 => plain(2, "cmpi", format!("{}, {}", reg(rx), imm(i64::from(imm8))), vec![T], Effect::None),
        16 => memory(2, "lb", ry, rx, imm5, 1, false),
        17 => memory(2, "lh", ry, rx, imm5 << 1, 2, false),
        18 => memory(2, "lw", rx, SP, i64::from(imm8) << 2, 4, false),
        19 => memory(2, "lw", ry, rx, imm5 << 2, 4, false),
        20 => memory(2, "lbu", ry, rx, imm5, 1, false),
        21 => memory(2, "lhu", ry, rx, imm5 << 1, 2, false),
        22 => {
            let value = i64::from(imm8) << 2;
            let address = pc_base(address, delay_slot_of).wrapping_add(value as u64) & 0xffff_ffff;
            plain(2, "lw", format!("{}, {}($pc)", reg(rx), imm(value)), vec![rx], Effect::PcLoad { to: rx, address })
        }
        24 => memory(2, "sb", ry, rx, imm5, 1, true),
        25 => memory(2, "sh", ry, rx, imm5 << 1, 2, true),
        26 => memory(2, "sw", rx, SP, i64::from(imm8) << 2, 4, true),
        27 => memory(2, "sw", ry, rx, imm5 << 2, 4, true),
        28 => {
            let operands = format!("{}, {}, {}", reg(rz), reg(rx), reg(ry));
            match first & 3 {
                1 => plain(2, "addu", operands, vec![rz], Effect::Add { to: rz, left: rx, right: ry }),
                3 => plain(2, "subu", operands, vec![rz], Effect::None),
                _ => None,
            }
        }
        29 => register_register(first, rx, ry),
        _ => None,
    }
}

/// The RR major opcode: jumps through registers, two-register ALU operations, moves from `HI`/`LO`.
fn register_register(first: u16, rx: u8, ry: u8) -> Option<Decoded> {
    let two = |mnemonic, writes| plain(2, mnemonic, format!("{}, {}", reg(rx), reg(ry)), writes, Effect::None);
    let shift = |mnemonic| plain(2, mnemonic, format!("{}, {}", reg(ry), reg(rx)), vec![ry], Effect::None);
    let one = |mnemonic| plain(2, mnemonic, reg(rx), vec![rx], Effect::None);
    match first & 0x1f {
        0 => {
            let (compact, link, through_ra) = (first & 0x80 != 0, first & 0x40 != 0, first & 0x20 != 0);
            let mnemonic = match (compact, link) {
                (false, false) => "jr",
                (false, true) => "jalr",
                (true, false) => "jrc",
                (true, true) => "jalrc",
            };
            let (control, operands) = match (link, through_ra) {
                (false, true) => (Control::Return, reg(RA)),
                (true, true) => return None,
                (_, false) => (Control::Register { register: rx, link }, reg(rx)),
            };
            Some(Decoded {
                len: 2,
                mnemonic,
                operands,
                control,
                delay_slots: u8::from(!compact),
                writes: if link { vec![RA] } else { Vec::new() },
                effect: Effect::None,
            })
        }
        1 => plain(2, "sdbbp", ((first >> 5) & 0x3f).to_string(), Vec::new(), Effect::None),
        2 => two("slt", vec![T]),
        3 => two("sltu", vec![T]),
        4 => shift("sllv"),
        5 => plain(2, "break", ((first >> 5) & 0x3f).to_string(), Vec::new(), Effect::None),
        6 => shift("srlv"),
        7 => shift("srav"),
        10 => two("cmp", vec![T]),
        11 => two("neg", vec![rx]),
        12 => two("and", vec![rx]),
        13 => two("or", vec![rx]),
        14 => two("xor", vec![rx]),
        15 => two("not", vec![rx]),
        16 => one("mfhi"),
        17 => match (first >> 5) & 7 {
            0 => one("zeb"),
            1 => one("zeh"),
            4 => one("seb"),
            5 => one("seh"),
            _ => None,
        },
        18 => one("mflo"),
        24 => two("mult", Vec::new()),
        25 => two("multu", Vec::new()),
        26 => plain(2, "div", format!("$zero, {}, {}", reg(rx), reg(ry)), Vec::new(), Effect::None),
        27 => plain(2, "divu", format!("$zero, {}, {}", reg(rx), reg(ry)), Vec::new(), Effect::None),
        _ => None,
    }
}

/// An instruction after an `EXTEND` prefix whose 11 bits are `ext`; the pair is 4 bytes at `address`.
fn extended(ext: u16, second: u16, address: u64, delay_slot_of: Option<u64>) -> Option<Decoded> {
    let rx = REGISTERS[usize::from((second >> 8) & 7)];
    let ry = REGISTERS[usize::from((second >> 5) & 7)];
    let value16 = (ext & 0x1f) << 11 | (ext & 0x7e0) | (second & 0x1f);
    let s16 = i64::from(value16 as i16);
    let u16 = u64::from(value16);
    let next = address.wrapping_add(4);
    let relative = |offset: i64| next.wrapping_add((offset << 1) as u64);
    // Formats with one register and an immediate keep bits 7:5 zero; others are reserved.
    let ri = (second >> 5) & 7 == 0;
    match second >> 11 {
        0 if ri => plain(
            4,
            "addiu",
            format!("{}, $sp, {}", reg(rx), imm(s16)),
            vec![rx],
            Effect::AddImmediate { to: rx, from: SP, value: s16 },
        ),
        1 if ri => {
            let address = pc_base(address, delay_slot_of).wrapping_add(s16 as u64) & 0xffff_ffff;
            plain(
                4,
                "addiu",
                format!("{}, $pc, {}", reg(rx), imm(s16)),
                vec![rx],
                Effect::PcAddress { to: rx, address },
            )
        }
        2 if second & 0x7e0 == 0 => branch(4, "b", String::new(), relative(s16), false),
        4 if ri => branch(4, "beqz", reg(rx), relative(s16), true),
        5 if ri => branch(4, "bnez", reg(rx), relative(s16), true),
        6 if second & 0x1c == 0 && ext & 0x3f == 0 => {
            let amount = ((ext >> 6) & 0x1f) as u8;
            let operands = format!("{}, {}, {}", reg(rx), reg(ry), imm(i64::from(amount)));
            match second & 3 {
                0 => plain(4, "sll", operands, vec![rx], Effect::ShiftLeft { to: rx, from: ry, amount }),
                2 => plain(4, "srl", operands, vec![rx], Effect::None),
                3 => plain(4, "sra", operands, vec![rx], Effect::None),
                _ => None,
            }
        }
        8 if second & 0x10 == 0 => {
            let value15 = (ext & 0xf) << 11 | ((ext >> 4) & 0x7f) << 4 | (second & 0xf);
            let value = signed(value15, 15);
            let operands = format!("{}, {}, {}", reg(ry), reg(rx), imm(value));
            plain(4, "addiu", operands, vec![ry], Effect::AddImmediate { to: ry, from: rx, value })
        }
        9 if ri => plain(
            4,
            "addiu",
            format!("{}, {}", reg(rx), imm(s16)),
            vec![rx],
            Effect::AddImmediate { to: rx, from: rx, value: s16 },
        ),
        10 if ri => plain(4, "slti", format!("{}, {}", reg(rx), imm(s16)), vec![T], Effect::None),
        11 if ri => plain(4, "sltiu", format!("{}, {}", reg(rx), imm(s16)), vec![T], Effect::None),
        12 => match (second >> 8) & 7 {
            0 if ri => branch(4, "bteqz", String::new(), relative(s16), true),
            1 if ri => branch(4, "btnez", String::new(), relative(s16), true),
            2 if ri => memory(4, "sw", RA, SP, s16, 4, true),
            3 if ri => plain(
                4,
                "addiu",
                format!("$sp, {}", imm(s16)),
                vec![SP],
                Effect::AddImmediate { to: SP, from: SP, value: s16 },
            ),
            4 => save_restore(second, Some(ext), 4),
            _ => None,
        },
        13 if ri => plain(
            4,
            "li",
            format!("{}, {}", reg(rx), imm(u16 as i64)),
            vec![rx],
            Effect::Constant { to: rx, value: u16 },
        ),
        14 if ri => plain(4, "cmpi", format!("{}, {}", reg(rx), imm(u16 as i64)), vec![T], Effect::None),
        16 => memory(4, "lb", ry, rx, s16, 1, false),
        17 => memory(4, "lh", ry, rx, s16, 2, false),
        18 if ri => memory(4, "lw", rx, SP, s16, 4, false),
        19 => memory(4, "lw", ry, rx, s16, 4, false),
        20 => memory(4, "lbu", ry, rx, s16, 1, false),
        21 => memory(4, "lhu", ry, rx, s16, 2, false),
        22 if ri => {
            let address = pc_base(address, delay_slot_of).wrapping_add(s16 as u64) & 0xffff_ffff;
            plain(4, "lw", format!("{}, {}($pc)", reg(rx), imm(s16)), vec![rx], Effect::PcLoad { to: rx, address })
        }
        24 => memory(4, "sb", ry, rx, s16, 1, true),
        25 => memory(4, "sh", ry, rx, s16, 2, true),
        26 if ri => memory(4, "sw", rx, SP, s16, 4, true),
        27 => memory(4, "sw", ry, rx, s16, 4, true),
        _ => None,
    }
}

#[cfg(test)]
#[path = "mips16_tests.rs"]
mod tests;
