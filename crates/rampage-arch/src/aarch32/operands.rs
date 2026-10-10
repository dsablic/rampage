//! Operand semantics for A32 and T32: how the fields behind each placeholder of the specification's assembly
//! syntax become text, following the Arm ARM operand descriptions and LLVM's spelling.

use crate::mrs::{LabelStyle, Operand, Value, is_literal};

use super::spec_types::{a32_expand_imm, sign_extend, t32_expand_imm};
use super::{Decoded, Set, decode_word, mnemonic};

pub struct Context<'a> {
    pub decoded: &'a Decoded,
    pub address: u64,
    pub labels: LabelStyle,
}

/// Condition names as LLVM prints them (`hs`/`lo` rather than `cs`/`cc`).
pub const CONDITIONS: [&str; 16] =
    ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", ""];

const REGISTERS: [&str; 16] =
    ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"];

const SHIFTS: [&str; 4] = ["lsl", "lsr", "asr", "ror"];

impl Context<'_> {
    fn word(&self) -> u32 {
        self.decoded.word
    }

    fn field(&self, name: &str) -> Option<u64> {
        self.decoded.field(name)
    }

    fn bits(&self, operand: &Operand) -> (u64, u32) {
        self.decoded.encoding.operand_bits(self.word(), operand)
    }

    fn mnemonic(&self) -> &'static str {
        mnemonic(self.decoded.syntax)
    }

    fn is_thumb(&self) -> bool {
        self.decoded.set != Set::A32
    }

    /// The value reading PC gives: the instruction plus 8 (A32) or 4 (T32).
    fn pc(&self) -> u64 {
        self.address.wrapping_add(if self.is_thumb() { 4 } else { 8 })
    }

    fn label(&self, base: u64, offset: i64) -> Value {
        match self.labels {
            LabelStyle::Absolute => Value::Text(format!("{:#x}", base.wrapping_add(offset as u64) & 0xffff_ffff)),
            // LLVM writes PC-relative loads with PC as their base register, with any indexing they encode.
            LabelStyle::Relative if self.is_load() => match (self.field("P"), self.field("W")) {
                (Some(0), _) => Value::Text(format!("[pc], #{offset}")),
                (_, Some(1)) => Value::Text(format!("[pc, #{offset}]!")),
                _ => Value::Text(format!("[pc, #{offset}]")),
            },
            LabelStyle::Relative => Value::Text(format!("#{offset}")),
        }
    }

    fn is_load(&self) -> bool {
        let mnemonic = self.mnemonic();
        mnemonic.starts_with("LD") || mnemonic.starts_with("VLD") || mnemonic.starts_with("PL")
    }

    fn ranked_choice(&self, operand: &Operand) -> Option<String> {
        let set = self.decoded.set;
        let it = self.decoded.it;
        let lookup = move |word: u32| decode_word(set, word, it).map(|decoded| decoded.encoding);
        self.decoded.encoding.ranked_choice(self.word(), operand, &lookup)
    }
}

pub fn register_name(number: u64) -> &'static str {
    REGISTERS[number as usize & 0xf]
}

/// Renders one operand.
pub fn render(context: &Context, operand: &Operand) -> Value {
    match operand.name {
        "<c>" => condition(context, operand),
        "<q>" => Value::Default(String::new()),
        "<Rd>" | "<Rn>" | "<Rm>" | "<Rt>" | "<Rs>" | "<Ra>" | "<RdLo>" | "<RdHi>" | "<Rdn>" | "<Rdm>" => {
            general_register(context, operand)
        }
        "<Rt2>" => {
            // The second register of a pair is Rt + 1 unless the encoding has its own field.
            let own_field = context.field("Rt2").is_some();
            let number =
                if own_field { context.field("Rt2").unwrap_or(0) } else { context.field("Rt").map_or(0, |rt| rt + 1) };
            Value::Text(register_name(number).to_owned())
        }
        // 16-bit Thumb names SP once when it is both source and destination (`add sp, #8`).
        "SP" if context.decoded.set == Set::T16 => Value::Default("sp".to_owned()),
        "SP" => Value::Text("sp".to_owned()),
        "+/-" => match context.field("U") {
            Some(0) => Value::Text("-".to_owned()),
            _ => Value::Default(String::new()),
        },
        "+" => Value::Default(String::new()),
        // The specification's optional space, as in `<shift> #<amount>`; `format` drops it before `,` and `]`.
        " " => Value::Default(" ".to_owned()),
        "!" => writeback(context, operand),
        // RFE and SRS spell out the default increment-after mode; LDM and STM leave it implied.
        "IA" if matches!(context.mnemonic(), "RFE" | "SRS") => Value::Text("ia".to_owned()),
        "IA" => Value::Default(String::new()),
        "<label>" => label(context),
        "<const>" => modified_immediate(context),
        "<shift>" if operand.choices.iter().any(|choice| choice.contains('#')) => shift_with_amount(context),
        "<shift>" | "<type>" => shift_type(context, operand),
        "<amount>" => shift_amount(context, operand),
        "<registers>" | "<registers_with_pc>" | "<registers_without_pc>" => register_list(context),
        "<lsb>" => Value::Text(bitfield_lsb(context).to_string()),
        "<width>" => width(context),
        "<x>" | "<y>" | "<z>" => it_suffix(context, operand.name),
        "<cond>" => Value::Text(CONDITIONS[context.field("firstcond").unwrap_or(0) as usize].to_owned()),
        "<option>" => barrier(context, operand),
        "<coproc>" => {
            Value::Text(context.ranked_choice(operand).unwrap_or_else(|| format!("p{}", context.bits(operand).0)))
        }
        "<amode>" => address_mode(context),
        "<iflags>" => interrupt_flags(context),
        "<spec_reg>" => special_register(context),
        "<banked_reg>" => banked_register(context),
        "<CRn>" | "<CRm>" => Value::Text(format!("c{}", context.bits(operand).0)),
        "<rotate>" if !is_literal(operand.choices) => rotation(context, operand),
        _ => immediate(context, operand).unwrap_or_else(|| match context.ranked_choice(operand) {
            Some(text) => Value::Text(text),
            None => Value::Text(context.bits(operand).0.to_string()),
        }),
    }
}

fn general_register(context: &Context, operand: &Operand) -> Value {
    let mut number = context.bits(operand).0;
    if context.decoded.set == Set::T16 && matches!(operand.name, "<Rdn>" | "<Rdm>") {
        // The high bit of a 16-bit encoding's four-bit register sits apart from the other three.
        let high = if operand.name == "<Rdn>" { context.field("DN") } else { context.field("DM") };
        number |= high.unwrap_or(0) << 3;
        // A register that is both source and destination is named once (`adds r1, #4`), except where LLVM
        // spells it out: ADD (SP plus register) and MUL's trailing repeat.
        if !matches!(context.decoded.encoding.name, "ADD_SP_r_T1" | "MUL_T1") {
            return Value::Default(register_name(number).to_owned());
        }
    }
    Value::Text(register_name(number).to_owned())
}

/// `!`: base register writeback, from `W`; a 16-bit LDM writes back unless it loads its base.
fn writeback(context: &Context, operand: &Operand) -> Value {
    let writes = match operand.fields {
        [] => match (context.field("Rn"), context.field("register_list")) {
            (Some(rn), Some(list)) => list & (1 << rn) == 0,
            _ => false,
        },
        _ => context.bits(operand).0 == 1,
    };
    if writes { Value::Text("!".to_owned()) } else { Value::Default(String::new()) }
}

/// A shift with its amount, as register-offset loads and stores write it: `lsl #2`, `asr #32`, `rrx`.
fn shift_with_amount(context: &Context) -> Value {
    let kind = context.field("stype").or_else(|| context.field("type")).unwrap_or(0);
    let amount = immediate_shift_amount(context).unwrap_or(0);
    match (kind, amount) {
        (0, 0) => Value::Default(String::new()),
        (1 | 2, 0) => Value::Text(format!("{} #32", SHIFTS[kind as usize])),
        (3, 0) => Value::Text("rrx".to_owned()),
        _ => Value::Text(format!("{} #{amount}", SHIFTS[kind as usize])),
    }
}

/// LDM and STM's address mode from P and U: increment or decrement, before or after; IA is the default.
fn address_mode(context: &Context) -> Value {
    match (context.field("P").unwrap_or(0), context.field("U").unwrap_or(1)) {
        (0, 0) => Value::Text("da".to_owned()),
        (0, 1) => Value::Default(String::new()),
        (1, 0) => Value::Text("db".to_owned()),
        _ => Value::Text("ib".to_owned()),
    }
}

/// CPS's interrupt flags: some of `a`, `i` and `f`, or `none`.
fn interrupt_flags(context: &Context) -> Value {
    let flags: String = [("A", 'a'), ("I", 'i'), ("F", 'f')]
        .iter()
        .filter(|(field, _)| context.field(field) == Some(1))
        .map(|&(_, letter)| letter)
        .collect();
    Value::Text(if flags.is_empty() { "none".to_owned() } else { flags })
}

/// MRS and MSR's status register: APSR or SPSR for MRS; for MSR, the fields written (`CPSR_fc`, `APSR_g`).
fn special_register(context: &Context) -> Value {
    let spsr = context.field("R") == Some(1);
    let mask = context.field("mask").filter(|_| context.mnemonic() == "MSR");
    let Some(mask) = mask else {
        return Value::Text(if spsr { "spsr" } else { "apsr" }.to_owned());
    };
    let name = match (spsr, mask) {
        (false, 0b1000) => "APSR_nzcvq".to_owned(),
        (false, 0b0100) => "APSR_g".to_owned(),
        (false, 0b1100) => "APSR_nzcvqg".to_owned(),
        _ => {
            let fields: String = [(8, 'f'), (4, 's'), (2, 'x'), (1, 'c')]
                .iter()
                .filter(|(bit, _)| mask & bit != 0)
                .map(|p| p.1)
                .collect();
            format!("{}_{fields}", if spsr { "SPSR" } else { "CPSR" })
        }
    };
    Value::Text(name)
}

/// MRS and MSR (banked register): the register of another mode, from `R:M1:M` (`SYSm`).
fn banked_register(context: &Context) -> Value {
    let r = context.field("R").unwrap_or(0);
    let sysm = context.field("M1").unwrap_or(0) << 4 | context.field("M").unwrap_or(0);
    const USR_FIQ: [&str; 7] = ["r8", "r9", "r10", "r11", "r12", "sp", "lr"];
    let name = match (r, sysm) {
        (0, 0..=6) => format!("{}_usr", USR_FIQ[sysm as usize]),
        (0, 8..=14) => format!("{}_fiq", USR_FIQ[sysm as usize - 8]),
        (0, 16..=23) => {
            let mode = ["irq", "svc", "abt", "und"][(sysm as usize - 16) / 2];
            format!("{}_{mode}", if sysm.is_multiple_of(2) { "lr" } else { "sp" })
        }
        (0, 28) => "lr_mon".to_owned(),
        (0, 29) => "sp_mon".to_owned(),
        (0, 30) => "elr_hyp".to_owned(),
        (0, 31) => "sp_hyp".to_owned(),
        (1, 14) => "spsr_fiq".to_owned(),
        (1, 16) => "spsr_irq".to_owned(),
        (1, 18) => "spsr_svc".to_owned(),
        (1, 20) => "spsr_abt".to_owned(),
        (1, 22) => "spsr_und".to_owned(),
        (1, 28) => "spsr_mon".to_owned(),
        (1, 30) => "spsr_hyp".to_owned(),
        _ => return Value::Invalid,
    };
    Value::Text(name)
}

/// `<c>`: the condition field, or inside an IT block the block's condition. AL is not printed.
fn condition(context: &Context, operand: &Operand) -> Value {
    let condition = match operand.fields {
        [] => context.decoded.it.condition(),
        _ => Some(context.bits(operand).0 as u8),
    };
    match condition {
        Some(condition @ 0..=13) => Value::Text(CONDITIONS[condition as usize].to_owned()),
        _ => Value::Default(String::new()),
    }
}

fn label(context: &Context) -> Value {
    let field = |name| context.field(name);
    let pc = context.pc();
    let aligned_pc = pc & !3;
    // Branches: the offset's bits differ by encoding.
    if let Some(imm24) = field("imm24") {
        let h = if context.mnemonic() == "BLX" { field("H").unwrap_or(0) } else { 0 };
        let offset = sign_extend(imm24 << 2 | h << 1, 26);
        // BLX switches to Thumb from a word-aligned A32 address, so its target is relative to PC.
        return context.label(pc, offset);
    }
    if let (Some(s), Some(j1), Some(j2), Some(imm11)) = (field("S"), field("J1"), field("J2"), field("imm11")) {
        if let Some(imm6) = field("imm6") {
            let offset = sign_extend(s << 20 | j2 << 19 | j1 << 18 | imm6 << 12 | imm11 << 1, 21);
            return context.label(pc, offset);
        }
        let (i1, i2) = (!(j1 ^ s) & 1, !(j2 ^ s) & 1);
        let imm10 = field("imm10").unwrap_or(0);
        let offset = sign_extend(s << 24 | i1 << 23 | i2 << 22 | imm10 << 12 | imm11 << 1, 25);
        return context.label(pc, offset);
    }
    if let (Some(s), Some(j1), Some(j2), Some(high), Some(low)) =
        (field("S"), field("J1"), field("J2"), field("imm10H"), field("imm10L"))
    {
        // BLX to A32 code: the target is word-aligned.
        let (i1, i2) = (!(j1 ^ s) & 1, !(j2 ^ s) & 1);
        let offset = sign_extend(s << 24 | i1 << 23 | i2 << 22 | high << 12 | low << 2, 25);
        return context.label(aligned_pc, offset);
    }
    if let (Some(i), Some(imm5)) = (field("i"), field("imm5")) {
        // CBZ and CBNZ.
        return context.label(pc, (i << 6 | imm5 << 1) as i64);
    }
    if context.decoded.set == Set::T16 {
        if let Some(imm11) = field("imm11") {
            return context.label(pc, sign_extend(imm11 << 1, 12));
        }
        if let Some(imm8) = field("imm8") {
            return match context.mnemonic() {
                "B" => context.label(pc, sign_extend(imm8 << 1, 9)),
                // ADR and literal loads count words from the aligned PC.
                _ => context.label(aligned_pc, (imm8 << 2) as i64),
            };
        }
    }
    // PC-relative loads and ADR: an unsigned offset added or subtracted.
    let magnitude = if let Some(imm12) = field("imm12") {
        match (context.mnemonic(), context.decoded.set) {
            ("ADR" | "ADD" | "SUB", Set::A32) => a32_expand_imm(imm12),
            _ => imm12,
        }
    } else if let (Some(high), Some(low)) = (field("imm4H"), field("imm4L")) {
        high << 4 | low
    } else if let (Some(i), Some(imm3), Some(imm8)) = (field("i"), field("imm3"), field("imm8")) {
        i << 11 | imm3 << 8 | imm8
    } else if let Some(imm8) = field("imm8") {
        imm8 << 2
    } else {
        return Value::Invalid;
    };
    // ADR's encoding T2 subtracts, as A32's SUB form does.
    let negative = field("U") == Some(0) || context.mnemonic() == "SUB" || context.decoded.encoding.name == "ADR_T2";
    let offset = if negative { -(magnitude as i64) } else { magnitude as i64 };
    context.label(aligned_pc, offset)
}

/// `<const>`: an A32 or T32 modified immediate.
fn modified_immediate(context: &Context) -> Value {
    let value = match context.decoded.set {
        Set::A32 => return a32_modified_immediate(context.field("imm12").unwrap_or(0)),
        _ => {
            let i = context.field("i").unwrap_or(0);
            t32_expand_imm(i << 11 | context.field("imm3").unwrap_or(0) << 8 | context.field("imm8").unwrap_or(0))
        }
    };
    Value::Text(value.to_string())
}

/// An A32 modified immediate as LLVM prints it: the value, signed, when the encoding is the one an assembler
/// picks for it; otherwise the explicit byte and rotation (`#200, #18`).
fn a32_modified_immediate(imm12: u64) -> Value {
    let (byte, rotation) = (imm12 as u32 & 0xff, 2 * (imm12 as u32 >> 8));
    let value = byte.rotate_right(rotation);
    if canonical_rotation(value) == rotation {
        Value::Text((value as i32).to_string())
    } else {
        Value::Text(format!("{byte}, #{rotation}"))
    }
}

/// The right rotation an assembler encodes `value` with (LLVM's `getSOImmValRotate`): none for a byte, else the
/// one that puts the lowest set bits at the bottom, trying again above bit 5 for values that wrap around.
fn canonical_rotation(value: u32) -> u32 {
    if value & !0xff == 0 {
        return 0;
    }
    let fits = |rotation: u32| value.rotate_right(rotation) & !0xff == 0;
    let rotation = value.trailing_zeros() & !1;
    if fits(rotation) {
        return (32 - rotation) & 31;
    }
    if value & 63 != 0 {
        let rotation = (value & !63).trailing_zeros() & !1;
        if fits(rotation) {
            return (32 - rotation) & 31;
        }
    }
    (0..32).step_by(2).find(|&rotation| value.rotate_left(rotation) & !0xff == 0).unwrap_or(0)
}

fn shift_type(context: &Context, operand: &Operand) -> Value {
    let kind = match operand.fields {
        [] => context.field("stype").or_else(|| context.field("type")).unwrap_or(0),
        _ => context.bits(operand).0,
    };
    let amount = immediate_shift_amount(context);
    // Register-controlled shifts always print; LSL #0 is no shift at all.
    if context.field("Rs").is_some() || amount.is_none() {
        return Value::Text(SHIFTS[kind as usize & 3].to_owned());
    }
    if kind == 0 && amount == Some(0) {
        Value::Default("lsl".to_owned())
    } else {
        Value::Text(SHIFTS[kind as usize & 3].to_owned())
    }
}

/// The 5-bit immediate shift amount, from `imm5` or T32's `imm3:imm2`.
fn immediate_shift_amount(context: &Context) -> Option<u64> {
    context.field("imm5").or_else(|| Some(context.field("imm3")? << 2 | context.field("imm2")?))
}

fn shift_amount(context: &Context, operand: &Operand) -> Value {
    // Extend instructions rotate by whole bytes.
    if let Some(rotate) = context.field("rotate") {
        return match rotate {
            0 => Value::Default("0".to_owned()),
            _ => Value::Text((rotate * 8).to_string()),
        };
    }
    let amount = match operand.fields {
        [] => immediate_shift_amount(context).unwrap_or(0),
        _ => context.bits(operand).0,
    };
    let kind = context.field("stype").or_else(|| context.field("type")).unwrap_or(0);
    // LSR #32 and ASR #32 are encoded as 0.
    match (kind, amount) {
        (1 | 2, 0) => Value::Text("32".to_owned()),
        (_, 0) => Value::Default("0".to_owned()),
        _ => Value::Text(amount.to_string()),
    }
}

fn register_list(context: &Context) -> Value {
    let mut list = context.field("register_list").unwrap_or(0);
    if context.decoded.syntax.operands.iter().any(|operand| operand.name == "<registers_with_pc>") {
        list |= 1 << 15;
    }
    // T32 adds LR (M) and PC (P) to the low registers it lists.
    if context.is_thumb() {
        if context.field("M") == Some(1) {
            list |= 1 << 14;
        }
        if context.field("P") == Some(1) && (context.decoded.set == Set::T32 || context.mnemonic() == "POP") {
            list |= 1 << 15;
        }
    }
    let names: Vec<&str> = (0..16).filter(|bit| list & (1 << bit) != 0).map(register_name).collect();
    Value::Text(format!("{{{}}}", names.join(", ")))
}

/// A bitfield's lowest bit: `lsb` in A32, `imm3:imm2` in T32.
fn bitfield_lsb(context: &Context) -> u64 {
    context.field("lsb").unwrap_or_else(|| context.field("imm3").unwrap_or(0) << 2 | context.field("imm2").unwrap_or(0))
}

fn width(context: &Context) -> Value {
    // BFC and BFI encode the top bit; SBFX and UBFX the width minus one (their T32 groups share both fields).
    let encodes_msb = matches!(context.mnemonic(), "BFC" | "BFI");
    if let Some(widthm1) = context.field("widthm1").filter(|_| !encodes_msb) {
        return Value::Text((widthm1 + 1).to_string());
    }
    // BFI and BFC: msb - lsb + 1.
    let (Some(msb), lsb) = (context.field("msb"), bitfield_lsb(context)) else { return Value::Invalid };
    if msb < lsb {
        return Value::Invalid;
    }
    Value::Text((msb - lsb + 1).to_string())
}

/// IT's `<x>`, `<y>` and `<z>`: `t` or `e` for the second to fourth instructions, from the mask bits.
fn it_suffix(context: &Context, name: &str) -> Value {
    let mask = context.field("mask").unwrap_or(0);
    let firstcond = context.field("firstcond").unwrap_or(0);
    let (bit, terminated) = match name {
        "<x>" => (3, mask & 0x7 != 0),
        "<y>" => (2, mask & 0x3 != 0),
        _ => (1, mask & 0x1 != 0),
    };
    if !terminated {
        return Value::Default(String::new());
    }
    let same = (mask >> bit) & 1 == firstcond & 1;
    Value::Text(if same { "t" } else { "e" }.to_owned())
}

/// Barrier options (DMB, DSB, ISB) by their names, and DBG's numeric option.
fn barrier(context: &Context, operand: &Operand) -> Value {
    let value = context.bits(operand).0;
    match context.mnemonic() {
        // ISB has only the one option.
        "ISB" if value != 0b1111 => return Value::Text(format!("#{value:#x}")),
        "DMB" | "DSB" | "ISB" => {}
        "LDC" | "LDC2" | "STC" | "STC2" | "LDCL" | "STCL" => return Value::Text(format!("{{{value}}}")),
        _ => return Value::Text(value.to_string()),
    }
    let name = match value {
        0b1111 => "sy",
        0b1110 => "st",
        0b1101 => "ld",
        0b1011 => "ish",
        0b1010 => "ishst",
        0b1001 => "ishld",
        0b0111 => "nsh",
        0b0110 => "nshst",
        0b0101 => "nshld",
        0b0011 => "osh",
        0b0010 => "oshst",
        0b0001 => "oshld",
        _ => return Value::Text(format!("#{value:#x}")),
    };
    Value::Text(name.to_owned())
}

/// Extend and rotate instructions' rotation: `ror #8`, `#16` or `#24`; none for 0.
fn rotation(context: &Context, operand: &Operand) -> Value {
    let rotate = context.bits(operand).0 * 8;
    if rotate == 0 { Value::Default("0".to_owned()) } else { Value::Text(rotate.to_string()) }
}

/// Plain immediates, scaled the way each instruction applies them.
fn immediate(context: &Context, operand: &Operand) -> Option<Value> {
    let name = operand.name;
    if !matches!(name, "<imm>" | "<imm3>" | "<imm4>" | "<imm7>" | "<imm8>" | "<imm12>" | "<imm16>") {
        return None;
    }
    let (value, _) = context.bits(operand);
    let mnemonic = context.mnemonic();
    if mnemonic == "MSR" && context.decoded.set == Set::A32 {
        return Some(a32_modified_immediate(value));
    }
    let fields: Vec<&str> =
        operand.fields.iter().map(|&index| context.decoded.encoding.fields[index as usize].name).collect();
    let scale = match (context.decoded.set, fields.as_slice()) {
        (Set::T16, ["imm5"]) => match mnemonic {
            "LDRH" | "STRH" => 2,
            "LDRB" | "STRB" => 1,
            "LDR" | "STR" => 4,
            _ => 1,
        },
        (Set::T16, ["imm7" | "imm8"]) if matches!(mnemonic, "LDR" | "STR" | "ADD" | "SUB" | "ADR") => 4,
        (Set::T32, ["imm8"]) if matches!(mnemonic, "LDRD" | "STRD" | "LDREX" | "STREX" | "LDA" | "TT") => 4,
        (_, ["imm8"]) if matches!(mnemonic, "LDC" | "LDC2" | "STC" | "STC2" | "LDCL" | "STCL") => 4,
        _ => 1,
    };
    // SSAT saturates to `sat_imm + 1` bits.
    let value = if fields == ["sat_imm"] && mnemonic.starts_with("SSAT") { value + 1 } else { value * scale };
    // An offset of zero is the operand's default; the syntax leaves it out unless subtracted.
    let subtracted = context.field("U") == Some(0) && operand.fields.iter().any(|_| true);
    if value == 0 && !subtracted && name == "<imm>" {
        return Some(Value::Default("0".to_owned()));
    }
    Some(Value::Text(value.to_string()))
}
