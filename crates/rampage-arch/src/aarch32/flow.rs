//! Control flow and address tracking for decoded A32 and T32 instructions, and the AArch32 `Disassembler`.

use crate::flow::Kind;
use crate::mrs::read_u32;
use crate::{Disassembler, Flow, Got, Insn, Target};
use std::collections::BTreeMap;

use super::operands::{canonical_rotation, label_target};
use super::spec_types::a32_expand_imm;
use super::{Decoded, ItState, LabelStyle, Set, decode_a32, decode_t32, format};

const PC: u64 = 15;
const LR: u64 = 14;
const SP: u64 = 13;

fn register(decoded: &Decoded, name: &str) -> Option<u64> {
    let operand = decoded.syntax.operands.iter().find(|operand| {
        operand.name.strip_prefix('<').and_then(|name| name.strip_suffix('>')) == Some(name)
            && !operand.fields.is_empty()
    });
    let value = operand
        .map(|operand| decoded.encoding.operand_bits(decoded.word, operand).0)
        .or_else(|| decoded.field(name))?;
    if name == "Rdm" && decoded.encoding.name == "ADD_SP_r_T1" {
        Some(decoded.field("DM").unwrap_or(0) << 3 | value)
    } else {
        Some(value)
    }
}

fn destination(decoded: &Decoded) -> Option<u64> {
    ["Rd", "Rdn", "Rdm"].into_iter().find_map(|name| {
        decoded
            .syntax
            .operands
            .iter()
            .find(|operand| operand.name.strip_prefix('<').and_then(|name| name.strip_suffix('>')) == Some(name))
            .and_then(|_| register(decoded, name))
    })
}

fn loads_register_list(mnemonic: &str) -> bool {
    matches!(mnemonic, "POP" | "LDM" | "LDMIA" | "LDMFD" | "LDMDB" | "LDMIB" | "LDMDA")
}

fn wide_immediate(decoded: &Decoded) -> u64 {
    let f = |name| decoded.field(name).unwrap_or(0);
    let low = if decoded.set == Set::A32 { f("imm12") } else { f("i") << 11 | f("imm3") << 8 | f("imm8") };
    f("imm4") << 12 | low
}

fn unshifted(decoded: &Decoded) -> bool {
    decoded.field("type").is_none_or(|kind| kind == 0)
        && decoded.field("stype").is_none_or(|kind| kind == 0)
        && decoded.field("imm5").is_none_or(|amount| amount == 0)
        && decoded.field("imm3").is_none_or(|amount| amount == 0)
        && decoded.field("imm2").is_none_or(|amount| amount == 0)
        && decoded.field("Rs").is_none_or(|_| decoded.set == Set::T16)
}

/// Whether the instruction executes only under a condition: its own `cond` field or its IT block's.
fn conditional(decoded: &Decoded) -> bool {
    if matches!(decoded.mnemonic(), "CBZ" | "CBNZ") {
        return true;
    }
    let own = decoded.syntax.operands.iter().any(|operand| operand.name == "<c>" && !operand.fields.is_empty());
    match (own, decoded.field("cond")) {
        (true, Some(cond)) => cond < 14,
        _ => decoded.it.condition().is_some_and(|condition| condition < 14),
    }
}

/// The registers an LDM, POP or similar loads, including LR and PC from T32's M and P bits.
fn loaded_registers(decoded: &Decoded) -> u64 {
    let mut list = decoded.field("register_list").unwrap_or(0);
    if decoded.set != Set::A32 {
        if decoded.field("P") == Some(1) {
            list |= 1 << PC;
        }
        if decoded.field("M") == Some(1) {
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
    let target = || label_target(decoded, address);
    let rd = destination(decoded);
    match mnemonic {
        "B" => Kind::Jump(target()),
        "BL" | "BLX" if decoded.syntax.operands.iter().any(|operand| operand.name == "<label>") => Kind::Call(target()),
        "BLX" => Kind::Call(None),
        "BX" | "BXJ" if register(decoded, "Rm") == Some(LR) => Kind::Return,
        "BX" | "BXJ" => Kind::Jump(None),
        "CBZ" | "CBNZ" => Kind::Jump(target()),
        "TBB" | "TBH" => Kind::Jump(None),
        _ if loads_register_list(mnemonic) && loaded_registers(decoded) & (1 << PC) != 0 => {
            if mnemonic == "POP" || register(decoded, "Rn") == Some(SP) { Kind::Return } else { Kind::Jump(None) }
        }
        // POP of a single register is a post-indexed load from SP.
        "POP" if register(decoded, "Rt") == Some(PC) => Kind::Return,
        // Pops of PC (`ldr pc, [sp], #4`) return; other loads of PC jump through a table or veneer.
        "LDR" if register(decoded, "Rt") == Some(PC) => {
            if register(decoded, "Rn") == Some(SP) && decoded.field("P") == Some(0) {
                Kind::Return
            } else {
                Kind::Jump(None)
            }
        }
        "MOV" | "MOVS" if rd == Some(PC) => {
            if register(decoded, "Rm") == Some(LR) && unshifted(decoded) {
                Kind::Return
            } else {
                Kind::Jump(None)
            }
        }
        "SUBS"
            if (rd == Some(PC) && register(decoded, "Rn") == Some(LR))
                || decoded.encoding.name.starts_with("SUBS_PC_") =>
        {
            Kind::Return
        }
        _ if rd == Some(PC)
            && matches!(
                mnemonic.trim_end_matches('S'),
                "ADD"
                    | "SUB"
                    | "ORR"
                    | "AND"
                    | "EOR"
                    | "RSB"
                    | "ADC"
                    | "SBC"
                    | "BIC"
                    | "MVN"
                    | "LSL"
                    | "LSR"
                    | "ASR"
                    | "ROR"
                    | "RRX"
            ) =>
        {
            Kind::Jump(None)
        }
        // BKPT and HLT are debugger or semihosting calls, which resume at the next instruction.
        "UDF" => Kind::Halt,
        "ERET" | "RFE" | "RFEIA" | "RFEDA" | "RFEDB" | "RFEIB" => Kind::Return,
        _ => Kind::Next,
    }
}

/// The instruction's flow, with conditions applied: a conditional return or indirect jump falls through. The flag
/// is [`Insn::conditional`].
pub fn flow(decoded: &Decoded, address: u64) -> (Flow, bool) {
    let kind = kind(decoded, address);
    let conditional = conditional(decoded);
    (kind.flow(conditional), kind.is_conditional_transfer(conditional))
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
    decoded_in: Option<(u64, ItState, bool)>,
    registers: Registers,
    modes: BTreeMap<u64, bool>,
    switches: BTreeMap<u64, bool>,
    sequential_mode: Option<(u64, bool)>,
}

impl Aarch32Disassembler {
    pub fn new(target: &Target) -> Self {
        Self {
            target: target.clone(),
            it: None,
            decoded_in: None,
            registers: Registers::default(),
            modes: BTreeMap::new(),
            switches: BTreeMap::new(),
            sequential_mode: None,
        }
    }

    fn is_thumb(&self, address: u64) -> bool {
        self.modes
            .get(&address)
            .copied()
            .or_else(|| {
                self.sequential_mode
                    .filter(|&(at, _)| {
                        at == address
                            && self.decoded_in.is_some_and(|(previous, _, _)| {
                                self.target.is_thumb(previous) == self.target.is_thumb(address)
                            })
                    })
                    .map(|(_, thumb)| thumb)
            })
            .unwrap_or_else(|| self.target.is_thumb(address))
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
        self.decode_in_mode(bytes, if self.is_thumb(address) { Set::T32 } else { Set::A32 }, it)
    }

    fn decode_in_mode(&self, bytes: &[u8], set: Set, it: ItState) -> Option<Decoded> {
        if set != Set::A32 {
            let first = self.halfword(bytes, 0)?;
            decode_t32(first, self.halfword(bytes, 2), it)
        } else {
            decode_a32(read_u32(bytes, 0, self.target.big_endian)?)
        }
    }

    /// The minimum instruction size, which is how far undecodable bytes are skipped.
    fn unit(&self, address: u64) -> u8 {
        if self.is_thumb(address) { 2 } else { 4 }
    }

    fn track(&mut self, decoded: &Decoded, address: u64, bytes: &[u8]) -> Found {
        let mut found = Found::default();
        let thumb = decoded.set != Set::A32;
        let pc = address.wrapping_add(if thumb { 4 } else { 8 });
        let name = decoded.encoding.name;
        let mnemonic = decoded.mnemonic();
        let f = |name: &str| decoded.field(name);
        let r = |name: &str| register(decoded, name);
        let rd = destination(decoded);
        let conditional = conditional(decoded);
        let literal = |at: u64| -> Option<u64> {
            let offset = usize::try_from(at.checked_sub(address)?).ok()?;
            read_u32(bytes, offset, self.target.data_big_endian).map(u64::from)
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
                    written = r("Rt").map(|rt| (rt, value.map(|value| Value { value, address: false })));
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
            let value = wide_immediate(decoded);
            written = rd.map(|rd| (rd, Some(Value { value, address: false })));
        } else if mnemonic == "MOVT" {
            let high = wide_immediate(decoded);
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
            let (rn, rm) = (r("Rn").or(rd).unwrap_or(0), r("Rm").unwrap_or(0));
            let value = match (rn, rm) {
                (PC, other) | (other, PC) if other != PC && unshifted(decoded) && !conditional => self
                    .registers
                    .get(other)
                    .map(|offset| Value { value: pc.wrapping_add(offset.value), address: true }),
                _ => None,
            };
            if let Some(value) = value {
                found.data_ref = Some(value.value & 0xffff_ffff);
            }
            written = rd.map(|rd| (rd, value));
        } else if mnemonic == "MOV" && name.starts_with("MOV_r") && unshifted(decoded) {
            written = rd.map(|rd| (rd, r("Rm").and_then(|rm| self.registers.get(rm))));
        } else if mnemonic.starts_with("LDR") || mnemonic.starts_with("STR") {
            // Loads and stores through a known base, with an immediate offset.
            let rn = r("Rn").or_else(|| {
                decoded
                    .syntax
                    .tokens
                    .iter()
                    .any(|token| matches!(token, crate::mrs::Token::Text(text) if text.contains("[SP")))
                    .then_some(SP)
            });
            if let Some(base) = rn.and_then(|rn| read(&self.registers, rn)) {
                let imm = f("imm12")
                    .or_else(|| f("imm8"))
                    .or_else(|| f("imm5"))
                    .or_else(|| Some(f("imm4H")? << 4 | f("imm4L")?));
                let indexed = f("P") != Some(0);
                if let (Some(imm), true, None) = (imm, indexed, f("Rm")) {
                    let scale = match decoded.set {
                        Set::T16 if matches!(mnemonic, "LDR" | "STR") => 4,
                        Set::T16 if matches!(mnemonic, "LDRH" | "STRH") => 2,
                        Set::T32 if f("imm8").is_some() && matches!(mnemonic, "LDRD" | "STRD" | "LDREX" | "STREX") => 4,
                        _ => 1,
                    };
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
                        written = r("Rt").map(|rt| (rt, entry.map(|value| Value { value, address: true })));
                    }
                }
            }
            if mnemonic.starts_with("LDR") && written.is_none() {
                written = r("Rt").map(|rt| (rt, None));
            }
        } else if let Some(rd) = rd {
            written = Some((rd, None));
        }

        let core_transfer = decoded
            .syntax
            .operands
            .iter()
            .find(|operand| {
                operand.name.starts_with("<R") || operand.name.starts_with("<S") || operand.name.starts_with("<D")
            })
            .is_some_and(|operand| matches!(operand.name, "<Rt>" | "<Rt2>"));
        for operand in decoded.syntax.operands {
            let Some(name) = operand.name.strip_prefix('<').and_then(|name| name.strip_suffix('>')) else {
                continue;
            };
            if !matches!(name, "Rd" | "Rdn" | "Rdm" | "RdLo" | "RdHi" | "Rt" | "Rt2") {
                continue;
            }
            if matches!(name, "Rt" | "Rt2")
                && (mnemonic.starts_with("ST")
                    || mnemonic.starts_with("VST")
                    || mnemonic.starts_with("MCR")
                    || mnemonic == "PUSH"
                    || matches!(mnemonic, "VMSR" | "VDUP")
                    || mnemonic == "VMOV" && !core_transfer)
            {
                continue;
            }
            if let Some(register) = register(decoded, name) {
                self.registers.set(register, None);
            }
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
        let list_writeback = decoded.set == Set::T16
            && (mnemonic == "STM"
                || loads_register_list(mnemonic)
                    && r("Rn").is_some_and(|rn| loaded_registers(decoded) & (1 << rn) == 0));
        if (f("W") == Some(1) || f("P") == Some(0) || list_writeback)
            && let Some(rn) = r("Rn")
        {
            self.registers.set(rn, None);
        }
        let loaded = loaded_registers(decoded);
        if loads_register_list(mnemonic) {
            for register in 0..15 {
                if loaded & (1 << register) != 0 {
                    self.registers.set(register, None);
                }
            }
        }
        if matches!(mnemonic, "LDRD" | "LDREXD")
            && decoded.set == Set::A32
            && let Some(rt) = r("Rt")
        {
            self.registers.set(rt + 1, None);
        }
        if matches!(mnemonic, "BL" | "BLX" | "SVC") {
            self.registers = Registers::default();
        }
        if matches!(mnemonic, "PUSH" | "POP") || decoded.syntax.operands.iter().any(|operand| operand.name == "SP") {
            self.registers.set(SP, None);
        }
        found
    }
}

/// Whether an A32 ADD's modified immediate uses a rotation an assembler would not choose; only linker-made PLT
/// entries do (`add ip, ip, #16, #20`), and their sums are halfway addresses.
fn is_non_canonical(decoded: &Decoded) -> bool {
    let Some(imm12) = decoded.field("imm12") else { return false };
    let rotation = 2 * (imm12 >> 8) as u32;
    canonical_rotation(a32_expand_imm(imm12) as u32) != rotation
}

impl Disassembler for Aarch32Disassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        self.switches.clear();
        let invalid = Insn {
            address,
            len: self.unit(address),
            flow: Flow::Invalid,
            data_ref: None,
            immediate: None,
            conditional: false,
        };
        let it = self.it_at(address);
        let thumb = self.is_thumb(address);
        let decoded = self.decode_at(bytes, address, it);
        self.decoded_in = Some((address, it, thumb));
        let Some(decoded) = decoded else {
            let next = address.wrapping_add(u64::from(invalid.len));
            let advanced = it.advance();
            self.it = advanced.in_block().then_some((next, advanced));
            self.sequential_mode = Some((next, thumb));
            self.registers = Registers::default();
            return invalid;
        };
        let next = address.wrapping_add(u64::from(decoded.size()));
        // An IT instruction starts a block; inside one, each instruction advances it.
        self.it = if decoded.mnemonic() == "IT" {
            let state =
                ItState::new(decoded.field("firstcond").unwrap_or(0) as u8, decoded.field("mask").unwrap_or(0) as u8);
            Some((next, state))
        } else {
            let advanced = decoded.it.advance();
            advanced.in_block().then_some((next, advanced))
        };
        let found = self.track(&decoded, address, bytes);
        let (mut flow, mut conditional_transfer) = flow(&decoded, address);
        if decoded.mnemonic() == "LDR"
            && register(&decoded, "Rt") == Some(PC)
            && let Some(pointer) = found.immediate
        {
            flow = Kind::Jump(Some(pointer & !1)).flow(conditional(&decoded));
            conditional_transfer = false;
            self.modes.entry(pointer & !1).or_insert(pointer & 1 != 0);
            self.switches.insert(pointer & !1, pointer & 1 != 0);
        }
        let thumb = decoded.set != Set::A32;
        if let Flow::Call(target) | Flow::Jump(target) | Flow::ConditionalJump(target) = flow {
            let mode = if decoded.mnemonic() == "BLX" { !thumb } else { thumb };
            if !(decoded.mnemonic() == "LDR" && found.immediate.is_some()) {
                self.modes.entry(target).or_insert(mode);
            }
            if !(decoded.mnemonic() == "LDR" && found.immediate.is_some()) {
                self.switches.insert(target, mode);
            }
        }
        if matches!(flow, Flow::ConditionalJump(_)) {
            let mode = if self.target.is_thumb(address) == self.target.is_thumb(next) {
                thumb
            } else {
                self.target.is_thumb(next)
            };
            self.modes.entry(next).or_insert(mode);
            self.switches.insert(next, mode);
        }
        self.sequential_mode =
            matches!(flow, Flow::Next | Flow::Call(_) | Flow::IndirectCall | Flow::ConditionalJump(_))
                .then_some((next, thumb));
        Insn {
            address,
            len: decoded.size(),
            flow,
            data_ref: found.data_ref,
            immediate: found.immediate,
            conditional: conditional_transfer,
        }
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        // Formatting follows decoding of the same instruction, whose IT state `decode` has already moved on.
        let decoded = match self.decoded_in {
            Some((at, it, thumb)) if at == address => {
                self.decode_in_mode(bytes, if thumb { Set::T32 } else { Set::A32 }, it)
            }
            _ => self.decode_at(bytes, address, self.it_at(address)),
        };
        decoded
            .and_then(|decoded| format(&decoded, address, LabelStyle::Absolute))
            .unwrap_or_else(|| "(bad)".to_owned())
    }

    fn reset(&mut self) {
        self.it = None;
        self.decoded_in = None;
        self.registers = Registers::default();
        self.sequential_mode = None;
    }

    fn join(&mut self) {
        self.registers = Registers::default();
    }

    fn set_code_modes(&mut self, modes: &[(u64, bool)]) {
        self.modes = modes.iter().copied().collect();
        self.switches.clear();
    }

    fn code_modes(&self) -> Vec<(u64, bool)> {
        self.switches.iter().map(|(&address, &thumb)| (address, thumb)).collect()
    }

    fn instruction_mode(&self) -> Option<bool> {
        self.decoded_in.map(|(_, _, thumb)| thumb)
    }

    fn code_mode_at(&self, address: u64) -> Option<bool> {
        if let Some((next, thumb)) = self.sequential_mode
            && next == address
        {
            let previous = self.decoded_in.map(|(at, _, _)| at)?;
            if self.target.is_thumb(previous) == self.target.is_thumb(address) {
                return Some(thumb);
            }
        }
        Some(self.is_thumb(address))
    }
}
