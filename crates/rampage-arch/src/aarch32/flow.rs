//! Control flow and address tracking for decoded A32 and T32 instructions, and the AArch32 `Disassembler`.

use crate::{Disassembler, Flow, Got, Insn, Target};

use super::operands::label_target;
use super::spec_types::a32_expand_imm;
use super::{Decoded, ItState, LabelStyle, Set, decode_a32, decode_t32, format};

const PC: u64 = 15;
const LR: u64 = 14;
const SP: u64 = 13;

/// What an instruction does to control flow, before conditions apply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Next,
    Jump(Option<u64>),
    Call(Option<u64>),
    Return,
    Halt,
}

fn field(decoded: &Decoded, name: &str) -> Option<u64> {
    decoded.field(name)
}

/// Whether the instruction executes only under a condition: its own `cond` field or its IT block's.
fn conditional(decoded: &Decoded) -> bool {
    if matches!(decoded.mnemonic(), "CBZ" | "CBNZ") {
        return true;
    }
    let own = decoded.syntax.operands.iter().any(|operand| operand.name == "<c>" && !operand.fields.is_empty());
    match (own, field(decoded, "cond")) {
        (true, Some(cond)) => cond < 14,
        _ => decoded.it.condition().is_some_and(|condition| condition < 14),
    }
}

/// The registers an LDM, POP or similar loads, including LR and PC from T32's M and P bits.
fn loaded_registers(decoded: &Decoded) -> u64 {
    let mut list = field(decoded, "register_list").unwrap_or(0);
    if decoded.set != Set::A32 {
        if field(decoded, "P") == Some(1) {
            list |= 1 << PC;
        }
        if field(decoded, "M") == Some(1) {
            list |= 1 << LR;
        }
    }
    if decoded.syntax.operands.iter().any(|operand| operand.name == "<registers_with_pc>") {
        list |= 1 << PC;
    }
    list
}

fn kind(decoded: &Decoded, address: u64) -> Kind {
    let mnemonic = decoded.mnemonic();
    let name = decoded.encoding.name;
    let target = || label_target(decoded, address);
    let rd = field(decoded, "Rd").or_else(|| field(decoded, "Rdm")).or_else(|| field(decoded, "Rdn"));
    match mnemonic {
        "B" => Kind::Jump(target()),
        "BL" | "BLX" if decoded.syntax.operands.iter().any(|operand| operand.name == "<label>") => Kind::Call(target()),
        "BLX" => Kind::Call(None),
        "BX" | "BXJ" if field(decoded, "Rm") == Some(LR) => Kind::Return,
        "BX" | "BXJ" => Kind::Jump(None),
        "CBZ" | "CBNZ" => Kind::Jump(target()),
        "TBB" | "TBH" => Kind::Jump(None),
        "POP" | "LDM" | "LDMIA" | "LDMFD" | "LDMDB" | "LDMIB" | "LDMDA"
            if loaded_registers(decoded) & (1 << PC) != 0 =>
        {
            Kind::Return
        }
        // POP of a single register is a post-indexed load from SP.
        "POP" if field(decoded, "Rt") == Some(PC) => Kind::Return,
        // Pops of PC (`ldr pc, [sp], #4`) return; other loads of PC jump through a table or veneer.
        "LDR" if field(decoded, "Rt") == Some(PC) => {
            if field(decoded, "Rn") == Some(SP) && field(decoded, "P") == Some(0) {
                Kind::Return
            } else {
                Kind::Jump(None)
            }
        }
        "MOV" | "MOVS" if rd == Some(PC) => {
            if field(decoded, "Rm") == Some(LR) {
                Kind::Return
            } else {
                Kind::Jump(None)
            }
        }
        "ADD" | "SUB" | "ORR" | "AND" | "EOR" | "RSB" | "ADC" | "SBC" | "BIC" | "MVN" if rd == Some(PC) => {
            Kind::Jump(None)
        }
        "UDF" | "HLT" | "BKPT" => Kind::Halt,
        "ERET" | "RFE" | "RFEIA" | "RFEDA" | "RFEDB" | "RFEIB" => Kind::Return,
        _ if name.starts_with("SUBS_PC_LR") => Kind::Return,
        _ => Kind::Next,
    }
}

/// The instruction's flow, with conditions applied: a conditional return or indirect jump falls through.
pub fn flow(decoded: &Decoded, address: u64) -> Flow {
    let conditional = conditional(decoded);
    let next = address + u64::from(decoded.size());
    match kind(decoded, address) {
        Kind::Next => Flow::Next,
        Kind::Halt => Flow::Halt,
        Kind::Return if conditional => Flow::Next,
        Kind::Return => Flow::Return,
        // A call to the next instruction only reads the program counter.
        Kind::Call(Some(target)) if target == next => Flow::Next,
        Kind::Call(Some(target)) => Flow::Call(target),
        Kind::Call(None) => Flow::IndirectCall,
        Kind::Jump(Some(target)) if conditional => Flow::ConditionalJump(target),
        Kind::Jump(Some(target)) => Flow::Jump(target),
        Kind::Jump(None) if conditional => Flow::Next,
        Kind::Jump(None) => Flow::IndirectJump,
    }
}

/// Register values known within a straight-line run: addresses built from literal pools, MOVW/MOVT pairs and
/// PC-relative additions, and the GOT entries loaded through them.
#[derive(Default)]
struct Registers {
    values: [Option<Value>; 16],
}

#[derive(Clone, Copy)]
struct Value {
    value: u64,
    /// Formed from PC (or loaded from the GOT): certainly an address. Other constants only may be.
    address: bool,
}

/// What tracking learned from one instruction.
#[derive(Default)]
struct Found {
    data_ref: Option<u64>,
    immediate: Option<u64>,
}

impl Registers {
    fn get(&self, register: u64) -> Option<Value> {
        self.values[register as usize & 15]
    }

    fn set(&mut self, register: u64, value: Option<Value>) {
        if register < 15 {
            self.values[register as usize] = value.map(|value| Value { value: value.value & 0xffff_ffff, ..value });
        }
    }
}

pub struct Aarch32Disassembler {
    target: Target,
    /// The IT state for the instruction at the given address, while an IT block lasts.
    it: Option<(u64, ItState)>,
    /// The address last decoded and the IT state it was decoded in, for formatting it afterwards.
    decoded_in: Option<(u64, ItState)>,
    registers: Registers,
}

impl Aarch32Disassembler {
    pub fn new(target: &Target) -> Self {
        Self { target: target.clone(), it: None, decoded_in: None, registers: Registers::default() }
    }

    fn it_at(&self, address: u64) -> ItState {
        match self.it {
            Some((at, state)) if at == address => state,
            _ => ItState::default(),
        }
    }

    fn halfword(&self, bytes: &[u8], offset: usize) -> Option<u16> {
        let pair: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
        Some(if self.target.big_endian { u16::from_be_bytes(pair) } else { u16::from_le_bytes(pair) })
    }

    fn decode_at(&self, bytes: &[u8], address: u64, it: ItState) -> Option<Decoded> {
        if self.target.is_thumb(address) {
            let first = self.halfword(bytes, 0)?;
            decode_t32(first, self.halfword(bytes, 2), it)
        } else {
            let word: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
            decode_a32(if self.target.big_endian { u32::from_be_bytes(word) } else { u32::from_le_bytes(word) })
        }
    }

    /// The minimum instruction size, which is how far undecodable bytes are skipped.
    fn unit(&self, address: u64) -> u8 {
        if self.target.is_thumb(address) { 2 } else { 4 }
    }

    fn track(&mut self, decoded: &Decoded, address: u64, bytes: &[u8]) -> Found {
        let mut found = Found::default();
        let thumb = decoded.set != Set::A32;
        let pc = address + if thumb { 4 } else { 8 };
        let name = decoded.encoding.name;
        let mnemonic = decoded.mnemonic();
        let f = |name: &str| field(decoded, name);
        let rd = f("Rd").or_else(|| f("Rdn")).or_else(|| f("Rdm"));
        let conditional = conditional(decoded);
        let literal = |at: u64| -> Option<u64> {
            let offset = usize::try_from(at.checked_sub(address)?).ok()?;
            let word: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
            Some(u64::from(if self.target.big_endian { u32::from_be_bytes(word) } else { u32::from_le_bytes(word) }))
        };
        let read = |registers: &Registers, register: u64| -> Option<Value> {
            if register == PC { Some(Value { value: pc, address: true }) } else { registers.get(register) }
        };

        // The register written, and its new value when known.
        let mut written: Option<(u64, Option<Value>)> = None;
        if name.starts_with("LDR_l")
            || name.starts_with("LDRD_l")
            || mnemonic.starts_with("VLDR") && f("Rn") == Some(PC)
        {
            if let Some(slot) = label_target(decoded, address) {
                found.data_ref = Some(slot);
                if name.starts_with("LDR_l") {
                    let value = literal(slot);
                    found.immediate = value;
                    written = f("Rt").map(|rt| (rt, value.map(|value| Value { value, address: false })));
                }
            }
        } else if name.starts_with("ADR") {
            // A32 `add ip, pc, #0, #12` begins a PLT entry's address; it is not one yet.
            let partial = is_non_canonical(decoded) || label_target(decoded, address) == Some(pc);
            if let Some(target) = label_target(decoded, address) {
                if !partial {
                    found.data_ref = Some(target);
                }
                written = rd.map(|rd| (rd, Some(Value { value: target, address: true })));
            }
        } else if matches!(mnemonic, "MOVW") || name.starts_with("MOV_i_A2") || name.starts_with("MOV_i_T3") {
            let value = f("imm4").unwrap_or(0) << 12
                | f("i").unwrap_or(0) << 11
                | f("imm3").unwrap_or(0) << 8
                | f("imm8").unwrap_or(0);
            let value =
                if decoded.set == Set::A32 { f("imm4").unwrap_or(0) << 12 | f("imm12").unwrap_or(0) } else { value };
            written = rd.map(|rd| (rd, Some(Value { value, address: false })));
        } else if mnemonic == "MOVT" {
            let high = if decoded.set == Set::A32 {
                f("imm4").unwrap_or(0) << 12 | f("imm12").unwrap_or(0)
            } else {
                f("imm4").unwrap_or(0) << 12
                    | f("i").unwrap_or(0) << 11
                    | f("imm3").unwrap_or(0) << 8
                    | f("imm8").unwrap_or(0)
            };
            if let Some(rd) = rd {
                let low = self.registers.get(rd).map(|value| value.value & 0xffff);
                let value = low.map(|low| Value { value: high << 16 | low, address: false });
                found.immediate = value.map(|value| value.value);
                written = Some((rd, value));
            }
        } else if matches!(mnemonic, "ADD" | "SUB") && name.contains("_i_") && f("Rn").is_some() {
            // Add or subtract an immediate to a known base; linker-made PLT entries build addresses so.
            let rn = f("Rn").unwrap_or(0);
            let imm = if decoded.set == Set::A32 { f("imm12").map(a32_expand_imm) } else { None };
            let value = read(&self.registers, rn).zip(imm).map(|(base, imm)| {
                let value = if mnemonic == "ADD" { base.value.wrapping_add(imm) } else { base.value.wrapping_sub(imm) };
                Value { value, ..base }
            });
            written = rd.map(|rd| (rd, value));
        } else if mnemonic == "ADD" && (name.starts_with("ADD_r") || name.starts_with("ADD_SP_r")) {
            // `add r0, pc, r0` and Thumb's `add r0, pc`: a PC-relative offset made an address.
            let (rn, rm) = (f("Rn").or(rd).unwrap_or(0), f("Rm").unwrap_or(0));
            let value = match (rn, rm) {
                (PC, other) | (other, PC) if other != PC => self
                    .registers
                    .get(other)
                    .map(|offset| Value { value: pc.wrapping_add(offset.value), address: true }),
                _ => None,
            };
            if let Some(value) = value {
                found.data_ref = Some(value.value & 0xffff_ffff);
            }
            written = rd.map(|rd| (rd, value));
        } else if mnemonic == "MOV" && name.starts_with("MOV_r") && f("imm5").is_none_or(|amount| amount == 0) {
            written = rd.map(|rd| (rd, f("Rm").and_then(|rm| self.registers.get(rm))));
        } else if mnemonic.starts_with("LDR") || mnemonic.starts_with("STR") {
            // Loads and stores through a known base, with an immediate offset.
            if let Some(base) = f("Rn").and_then(|rn| read(&self.registers, rn)) {
                let imm = f("imm12").or_else(|| f("imm8")).or_else(|| Some(f("imm4H")? << 4 | f("imm4L")?));
                let indexed = f("P") != Some(0);
                if let (Some(imm), true, None) = (imm, indexed, f("Rm")) {
                    let scale = if decoded.set == Set::T16 && mnemonic == "LDR" { 4 } else { 1 };
                    let offset = imm * scale;
                    let at = if f("U") == Some(0) {
                        base.value.wrapping_sub(offset)
                    } else {
                        base.value.wrapping_add(offset)
                    };
                    found.data_ref = Some(at & 0xffff_ffff);
                    if mnemonic == "LDR" {
                        let entry =
                            self.target.got.as_ref().and_then(|got: &Got| got.entry(at, 4)).filter(|&entry| entry != 0);
                        written = f("Rt").map(|rt| (rt, entry.map(|value| Value { value, address: true })));
                    }
                }
            }
            if mnemonic.starts_with("LDR") && written.is_none() {
                written = f("Rt").map(|rt| (rt, None));
            }
        } else if let Some(rd) = rd {
            written = Some((rd, None));
        }

        // A formed address is reported once complete: not halfway (PC itself, MOVW before MOVT).
        if let Some((register, value)) = written {
            let value = value.filter(|_| !conditional);
            if let Some(value) = value
                && value.address
                && value.value != pc
                && found.data_ref.is_none()
                && !(mnemonic == "ADD" && decoded.set == Set::A32 && is_non_canonical(decoded))
            {
                found.data_ref = Some(value.value & 0xffff_ffff);
            }
            self.registers.set(register, value);
        }
        // Writeback, list loads and calls change other registers.
        if (f("W") == Some(1) || f("P") == Some(0))
            && let Some(rn) = f("Rn")
        {
            self.registers.set(rn, None);
        }
        let loaded = loaded_registers(decoded);
        if matches!(mnemonic, "POP" | "LDM" | "LDMIA" | "LDMFD" | "LDMDB" | "LDMIB" | "LDMDA") {
            for register in 0..15 {
                if loaded & (1 << register) != 0 {
                    self.registers.set(register, None);
                }
            }
        }
        if mnemonic == "LDRD"
            && let Some(rt) = f("Rt")
        {
            self.registers.set(rt + 1, None);
        }
        if matches!(mnemonic, "BL" | "BLX" | "SVC") {
            self.registers = Registers::default();
        }
        found
    }
}

/// Whether an A32 ADD's modified immediate uses a rotation an assembler would not choose; only linker-made PLT
/// entries do (`add ip, ip, #16, #20`), and their sums are halfway addresses.
fn is_non_canonical(decoded: &Decoded) -> bool {
    let Some(imm12) = decoded.field("imm12") else { return false };
    let rotation = 2 * (imm12 >> 8) as u32;
    let value = a32_expand_imm(imm12) as u32;
    rotation != 0 && (0..rotation).step_by(2).any(|smaller| value.rotate_left(smaller) <= 0xff)
}

impl Disassembler for Aarch32Disassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        let invalid = Insn { address, len: self.unit(address), flow: Flow::Invalid, data_ref: None, immediate: None };
        let it = self.it_at(address);
        self.decoded_in = Some((address, it));
        let Some(decoded) = self.decode_at(bytes, address, it) else {
            self.it = None;
            return invalid;
        };
        let next = address + u64::from(decoded.size());
        // An IT instruction starts a block; inside one, each instruction advances it.
        self.it = if decoded.mnemonic() == "IT" {
            let state = ItState::new(
                field(&decoded, "firstcond").unwrap_or(0) as u8,
                field(&decoded, "mask").unwrap_or(0) as u8,
            );
            Some((next, state))
        } else {
            let advanced = decoded.it.advance();
            advanced.in_block().then_some((next, advanced))
        };
        let found = self.track(&decoded, address, bytes);
        Insn {
            address,
            len: decoded.size(),
            flow: flow(&decoded, address),
            data_ref: found.data_ref,
            immediate: found.immediate,
        }
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        // Formatting follows decoding of the same instruction, whose IT state `decode` has already moved on.
        let it = match self.decoded_in {
            Some((at, it)) if at == address => it,
            _ => self.it_at(address),
        };
        self.decode_at(bytes, address, it)
            .and_then(|decoded| format(&decoded, address, LabelStyle::Absolute))
            .unwrap_or_else(|| "(bad)".to_owned())
    }

    fn reset(&mut self) {
        self.it = None;
        self.decoded_in = None;
        self.registers = Registers::default();
    }
}
