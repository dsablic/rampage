//! Operand semantics for A32 and T32: how the fields behind each placeholder of the specification's assembly
//! syntax become text, following the Arm ARM operand descriptions and LLVM's spelling.

use crate::mrs::{LabelStyle, Operand, Token, Value, is_literal};

use super::spec_types::{a32_expand_imm, sign_extend, t32_expand_imm};
use super::{Decoded, Set, decode_word};

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
        self.decoded.mnemonic()
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
        "<shift>" | "<type>" if !is_simd(context) => shift_type(context, operand),
        "<amount>" => shift_amount(context, operand),
        "<registers>" | "<registers_with_pc>" | "<registers_without_pc>" => register_list(context),
        "<single_register_list>" => Value::Text(format!("{{{}}}", register_name(context.field("Rt").unwrap_or(0)))),
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
        "<Dd>" | "<Dn>" | "<Dm>" | "<Ddm>" => register(context, operand, format!("d{}", context.bits(operand).0)),
        "<Sd>" | "<Sn>" | "<Sm>" | "<Sdm>" => register(context, operand, format!("s{}", context.bits(operand).0)),
        // The register after Sm, for moves of a pair of single-precision registers.
        "<Sm1>" => {
            Value::Text(format!("s{}", ((context.field("Vm").unwrap_or(0) << 1) | context.field("M").unwrap_or(0)) + 1))
        }
        "<Qd>" | "<Qn>" | "<Qm>" => {
            // A Q register is a pair of D registers; an odd D number is UNDEFINED.
            let number = context.bits(operand).0;
            if number % 2 == 1 { Value::Invalid } else { register(context, operand, format!("q{}", number / 2)) }
        }
        "<dt>" | "<dt1>" | "<dt2>" | "<size>" | "<type>" if is_simd(context) => simd_type(context, operand),
        // A data size the instruction implies; LLVM leaves it out (`vldr s0, [r0]`).
        ".32" | ".64" => Value::Default(String::new()),
        "<list>" => simd_list(context),
        "<dreglist>" | "<sreglist>" => fp_register_list(context, operand),
        "<align>" => alignment(context),
        "<fbits>" => fixed_point_bits(context),
        "<Dd[x]>" | "<Dn[x]>" | "<Dm[x]>" => scalar(context, operand),
        "<index>" => Value::Text(scalar_index(context).1.to_string()),
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
    }
    register(context, operand, register_name(number).to_owned())
}

/// A register operand's text. One the syntax names twice, as both source and destination, is a default: the
/// optional repeat is left out (`adds r1, #4`, `vorr.i32 d1, #255`), except where LLVM spells it out.
fn register(context: &Context, operand: &Operand, name: String) -> Value {
    let spelled_out = matches!(context.decoded.encoding.name, "ADD_SP_r_T1" | "MUL_T1");
    if !spelled_out && occurrences(context.decoded.syntax.tokens, context.decoded.syntax, operand) > 1 {
        Value::Default(name)
    } else {
        Value::Text(name)
    }
}

/// How many times `tokens` show `operand`.
fn occurrences(tokens: &[Token], syntax: &crate::mrs::Syntax, operand: &Operand) -> usize {
    tokens
        .iter()
        .map(|token| match token {
            Token::Operand(index) => usize::from(std::ptr::eq(&syntax.operands[*index as usize], operand)),
            Token::Optional(inner) => occurrences(inner, syntax, operand),
            Token::Choice(alternatives) => {
                alternatives.iter().map(|alternative| occurrences(alternative, syntax, operand)).max().unwrap_or(0)
            }
            Token::Text(_) => 0,
        })
        .sum()
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
    if matches!(context.mnemonic(), "VMRS" | "VMSR") {
        return fp_system_register(context);
    }
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

/// VMRS and VMSR's floating-point system register, by `reg`; VMRS to PC moves the flags to APSR.
fn fp_system_register(context: &Context) -> Value {
    let name = match context.field("reg").unwrap_or(1) {
        0b0000 => "fpsid",
        0b0001 if context.mnemonic() == "VMRS" && context.field("Rt") == Some(15) => "APSR_nzcv",
        0b0001 => "fpscr",
        0b0101 => "mvfr2",
        0b0110 => "mvfr1",
        0b0111 => "mvfr0",
        0b1000 => "fpexc",
        0b1001 => "fpinst",
        0b1010 => "fpinst2",
        other => return Value::Text(format!("{other}")),
    };
    Value::Text(name.to_owned())
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
    match label_parts(context) {
        Some((base, offset)) => context.label(base, offset),
        None => Value::Invalid,
    }
}

/// The absolute address a `<label>` operand names, for flow analysis.
pub fn label_target(decoded: &Decoded, address: u64) -> Option<u64> {
    let context = Context { decoded, address, labels: LabelStyle::Absolute };
    let (base, offset) = label_parts(&context)?;
    Some(base.wrapping_add(offset as u64) & 0xffff_ffff)
}

/// A label as the base it counts from (PC, or PC aligned down to a word) and the offset from it.
fn label_parts(context: &Context) -> Option<(u64, i64)> {
    let field = |name| context.field(name);
    let pc = context.pc();
    let aligned_pc = pc & !3;
    // Branches: the offset's bits differ by encoding.
    if let Some(imm24) = field("imm24") {
        let h = if context.mnemonic() == "BLX" { field("H").unwrap_or(0) } else { 0 };
        let offset = sign_extend(imm24 << 2 | h << 1, 26);
        // BLX switches to Thumb from a word-aligned A32 address, so its target is relative to PC.
        return Some((pc, offset));
    }
    if let (Some(s), Some(j1), Some(j2), Some(imm11)) = (field("S"), field("J1"), field("J2"), field("imm11")) {
        if let Some(imm6) = field("imm6") {
            let offset = sign_extend(s << 20 | j2 << 19 | j1 << 18 | imm6 << 12 | imm11 << 1, 21);
            return Some((pc, offset));
        }
        let (i1, i2) = (!(j1 ^ s) & 1, !(j2 ^ s) & 1);
        let imm10 = field("imm10").unwrap_or(0);
        let offset = sign_extend(s << 24 | i1 << 23 | i2 << 22 | imm10 << 12 | imm11 << 1, 25);
        return Some((pc, offset));
    }
    if let (Some(s), Some(j1), Some(j2), Some(high), Some(low)) =
        (field("S"), field("J1"), field("J2"), field("imm10H"), field("imm10L"))
    {
        // BLX to A32 code: the target is word-aligned.
        let (i1, i2) = (!(j1 ^ s) & 1, !(j2 ^ s) & 1);
        let offset = sign_extend(s << 24 | i1 << 23 | i2 << 22 | high << 12 | low << 2, 25);
        return Some((aligned_pc, offset));
    }
    if let (Some(i), Some(imm5)) = (field("i"), field("imm5")) {
        // CBZ and CBNZ.
        return Some((pc, (i << 6 | imm5 << 1) as i64));
    }
    if context.decoded.set == Set::T16 {
        if let Some(imm11) = field("imm11") {
            return Some((pc, sign_extend(imm11 << 1, 12)));
        }
        if let Some(imm8) = field("imm8") {
            return match context.mnemonic() {
                "B" => Some((pc, sign_extend(imm8 << 1, 9))),
                // ADR and literal loads count words from the aligned PC.
                _ => Some((aligned_pc, (imm8 << 2) as i64)),
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
    } else {
        field("imm8")? << 2
    };
    // ADR's encoding T2 subtracts, as A32's SUB form does.
    let negative = field("U") == Some(0) || context.mnemonic() == "SUB" || context.decoded.encoding.name == "ADR_T2";
    let offset = if negative { -(magnitude as i64) } else { magnitude as i64 };
    Some((aligned_pc, offset))
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
pub(super) fn canonical_rotation(value: u32) -> u32 {
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
    if is_simd(context)
        && let Some(value) = simd_immediate(context, mnemonic)
    {
        return Some(value);
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
        // VLDR and VSTR count words, or halfwords for the 16-bit form.
        (_, ["imm8"]) if matches!(mnemonic, "VLDR" | "VSTR") => {
            if context.field("size") == Some(1) {
                2
            } else {
                4
            }
        }
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

/// Floating-point and Advanced SIMD instructions, whose mnemonics start with V (and the crypto ones).
fn is_simd(context: &Context) -> bool {
    let mnemonic = context.mnemonic();
    mnemonic.starts_with('V') || mnemonic.starts_with("AES") || mnemonic.starts_with("SHA")
}

/// A vector instruction's data type or element size (`.s16`, `.u32`, `.i8`, `.f32`, `.64`): mapped from the
/// fields onto the operand's legal spellings by element size and, where a field gives it, signedness.
fn simd_type(context: &Context, operand: &Operand) -> Value {
    let encoding = context.decoded.encoding.name;
    if encoding.starts_with("VCVT_is_") || encoding.starts_with("VCVT_xs_") {
        let fixed = encoding.starts_with("VCVT_xs_");
        let unsigned =
            if fixed { context.field("U") == Some(1) } else { context.field("op").is_some_and(|op| op & 1 != 0) };
        let to_integer = if fixed {
            context.field("op").is_some_and(|op| op & 1 != 0)
        } else {
            context.field("op").is_some_and(|op| op & 2 != 0)
        };
        let size = if !fixed && context.field("size") == Some(1) { 16 } else { 32 };
        let letter = if (operand.name == "<dt1>") == to_integer { if unsigned { 'u' } else { 's' } } else { 'f' };
        return Value::Text(format!("{letter}{size}"));
    }
    if let Some(text) = element_type(context) {
        return Value::Text(text);
    }
    if operand.fields.is_empty() && shift_element(context).is_none() {
        // An assembler-only qualifier (`vand.i8`), or one implied by the encoding.
        return match operand.choices {
            [single] => Value::Text(single.to_ascii_lowercase()),
            _ => Value::Default(String::new()),
        };
    }
    if shift_element(context).is_none()
        && let Some(text) = context.ranked_choice(operand)
    {
        return Value::Text(text);
    }
    let names: Vec<&str> =
        operand.fields.iter().map(|&index| context.decoded.encoding.fields[index as usize].name).collect();
    // A sign bit (U or op) and a size: S or U, and 8 << size bits.
    if let [sign, "size"] = names.as_slice() {
        let letters: Vec<char> = {
            let mut letters = Vec::new();
            for choice in operand.choices {
                let letter = choice.chars().next().unwrap_or(' ');
                if !letters.contains(&letter) {
                    letters.push(letter);
                }
            }
            letters
        };
        // A two-bit `op` (VQMOVN, VQMOVUN) keeps the sign in its low bit.
        let sign_value = (context.field(sign).unwrap_or(0) & 1) as usize;
        let letter = letters.get(sign_value).copied().unwrap_or(' ');
        // Narrowing instructions name their source, twice the element size.
        let size = context.field("size").unwrap_or(0);
        let found = [8u64 << size, 16u64 << size]
            .iter()
            .find_map(|bits| operand.choices.iter().find(|choice| **choice == format!("{letter}{bits}")));
        return match found {
            Some(choice) => Value::Text(choice.to_ascii_lowercase()),
            None => Value::Invalid,
        };
    }
    // Shift-by-immediate instructions encode the element size as the top set bit of L:imm6.
    if let Some((esize, _)) = shift_element(context) {
        // VQSHLU, VQSHRUN and VQRSHRUN shift a signed source into an unsigned result; LLVM names the source.
        let signed_source = context.mnemonic() == "VQSHLU" || context.mnemonic().ends_with("UN");
        let unsigned = context.field("U") == Some(1) && !signed_source;
        let letters: Vec<char> = operand.choices.iter().filter_map(|choice| choice.chars().next()).collect();
        let text = match (operand.name, letters.first()) {
            ("<type>", _) => {
                if unsigned {
                    "u".to_owned()
                } else {
                    "s".to_owned()
                }
            }
            (_, Some(letter)) if letter.is_ascii_alphabetic() => {
                let letter = if *letter == 'S' && unsigned { 'u' } else { letter.to_ascii_lowercase() };
                format!("{letter}{esize}")
            }
            _ => esize.to_string(),
        };
        return Value::Text(text);
    }
    if let Some(size) = context.field("size") {
        let bits = (8u64 << size).to_string();
        if let Some(choice) =
            operand.choices.iter().find(|choice| choice.trim_start_matches(char::is_alphabetic) == bits)
        {
            return Value::Text(choice.to_ascii_lowercase());
        }
    }
    Value::Text(context.bits(operand).0.to_string())
}

/// The element size and shift amount of a shift by immediate (VSHR, VSHL, VQSHRN...): the element size is the
/// top set bit of L:imm6's top four bits; right shifts count down from twice it, left shifts up from it.
fn shift_element(context: &Context) -> Option<(u64, u64)> {
    let imm6 = context.field("imm6")?;
    let high = context.field("L").unwrap_or(0) << 3 | imm6 >> 3;
    let esize = match high {
        0 => return None,
        8.. => 64,
        4.. => 32,
        2.. => 16,
        _ => 8,
    };
    let mnemonic = context.mnemonic();
    let left = mnemonic.contains("SHL") || mnemonic == "VSLI";
    // Narrowing shifts (VSHRN and friends) are named by their source, twice the result element.
    let narrowing = mnemonic.ends_with('N');
    let amount = if left {
        if esize == 64 { imm6 } else { imm6 - esize }
    } else if esize == 64 {
        64 - imm6
    } else {
        2 * esize - imm6
    };
    Some((if narrowing { 2 * esize } else { esize }, amount))
}

/// Vector immediates: shift amounts, fixed-point bits, modified immediates and floating-point constants.
fn simd_immediate(context: &Context, mnemonic: &str) -> Option<Value> {
    if let Some((_, amount)) = shift_element(context) {
        return Some(Value::Text(amount.to_string()));
    }
    if let (Some(cmode), Some(imm3), Some(imm4)) =
        (context.field("cmode"), context.field("imm3"), context.field("imm4"))
    {
        let imm8 = context.field("i").unwrap_or(0) << 7 | imm3 << 4 | imm4;
        return Some(modified_simd_immediate(context.field("op").unwrap_or(0), cmode, imm8));
    }
    if matches!(mnemonic, "VMOV") {
        // VFP: the floating-point constant VFPExpandImm makes of imm4H:imm4L.
        if let (Some(high), Some(low)) = (context.field("imm4H"), context.field("imm4L")) {
            return Some(Value::Text(float_immediate(high << 4 | low)));
        }
    }
    None
}

/// `AdvSIMDExpandImm`, printed as LLVM does: hex for integers, a float for the F32 form.
fn modified_simd_immediate(op: u64, cmode: u64, imm8: u64) -> Value {
    let value = match cmode >> 1 {
        0 => imm8,
        1 => imm8 << 8,
        2 => imm8 << 16,
        3 => imm8 << 24,
        4 => imm8,
        5 => imm8 << 8,
        6 if cmode & 1 == 0 => imm8 << 8 | 0xff,
        6 => imm8 << 16 | 0xffff,
        _ => match (cmode & 1, op) {
            (0, 0) => imm8,
            (0, _) => (0..8).filter(|bit| imm8 & (1 << bit) != 0).map(|bit| 0xffu64 << (8 * bit)).sum(),
            (_, 0) => return Value::Text(float_immediate(imm8)),
            _ => return Value::Invalid,
        },
    };
    Value::Text(format!("{value:#x}"))
}

/// `VFPExpandImm`'s constant in C's `%e` style, as LLVM prints it (`#-9.000000e+00`).
fn float_immediate(imm8: u64) -> String {
    let sign = if imm8 & 0x80 != 0 { -1.0 } else { 1.0 };
    let exponent = ((imm8 >> 4) & 0x7) as i32;
    let exponent = if exponent & 0x4 != 0 { exponent - 7 } else { exponent + 1 };
    let value = sign * (1.0 + (imm8 & 0xf) as f64 / 16.0) * 2f64.powi(exponent);
    let text = format!("{value:.6e}");
    // Rust writes `9.000000e0`; C writes `9.000000e+00`.
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    format!("{mantissa}e{}{:02}", if exponent < 0 { '-' } else { '+' }, exponent.abs())
}

/// VCVT's fixed-point fraction bits: the element size minus `imm4:i`.
fn fixed_point_bits(context: &Context) -> Value {
    if context.decoded.encoding.name.starts_with("VCVT_xs_") {
        return match context.field("imm6").and_then(|imm| 64u64.checked_sub(imm)) {
            Some(bits @ 1..=32) => Value::Text(bits.to_string()),
            _ => Value::Invalid,
        };
    }
    let size: u64 = if context.field("sx") == Some(1) { 32 } else { 16 };
    let imm = context.field("imm4").unwrap_or(0) << 1 | context.field("i").unwrap_or(0);
    match size.checked_sub(imm) {
        Some(bits) => Value::Text(bits.to_string()),
        None => Value::Invalid,
    }
}

/// VLDM, VSTM, VPUSH and VPOP's consecutive registers: `imm8` words from Sd or doublewords from Dd.
fn fp_register_list(context: &Context, operand: &Operand) -> Value {
    let vd = context.field("Vd").unwrap_or(0);
    let d = context.field("D").unwrap_or(0);
    let imm8 = context.field("imm8").unwrap_or(0);
    let (prefix, first, count) =
        if operand.name == "<dreglist>" { ("d", d << 4 | vd, imm8 / 2) } else { ("s", vd << 1 | d, imm8) };
    if count == 0 || first + count > 32 {
        return Value::Invalid;
    }
    let names: Vec<String> = (first..first + count).map(|number| format!("{prefix}{number}")).collect();
    Value::Text(format!("{{{}}}", names.join(", ")))
}

/// The registers of a VLDn/VSTn or VTBL/VTBX list, with a lane index for single-lane forms.
fn simd_list(context: &Context) -> Value {
    let mnemonic = context.mnemonic();
    if let Some(len) = context.field("len").filter(|_| matches!(mnemonic, "VTBL" | "VTBX")) {
        let first = context.field("N").unwrap_or(0) << 4 | context.field("Vn").unwrap_or(0);
        return d_registers(first, len + 1, 1, None);
    }
    let first = context.field("D").unwrap_or(0) << 4 | context.field("Vd").unwrap_or(0);
    let structures = mnemonic.trim_start_matches("VLD").trim_start_matches("VST").parse::<u64>().unwrap_or(1);
    if let Some(itype) = context.field("itype") {
        // Multiple structures: the count of registers and their spacing by `itype`.
        let (count, spacing) = match itype {
            0b0111 => (1, 1),
            0b1010 => (2, 1),
            0b0110 => (3, 1),
            0b0010 => (4, 1),
            0b1000 => (2, 1),
            0b1001 => (2, 2),
            0b0011 => (4, 1),
            0b0100 => (3, 1),
            0b0101 => (3, 2),
            0b0000 => (4, 1),
            0b0001 => (4, 2),
            _ => return Value::Invalid,
        };
        return d_registers(first, count, spacing, None);
    }
    // Single structure to one lane, or to all lanes (`T` field).
    let size = context.field("size").unwrap_or(0);
    if context.field("T").is_some() && context.field("index_align").is_none() {
        let spacing = context.field("T").unwrap_or(0) + 1;
        let count = if structures == 1 { context.field("T").unwrap_or(0) + 1 } else { structures };
        let spacing = if structures == 1 { 1 } else { spacing };
        return d_registers_all_lanes(first, count, spacing);
    }
    let index_align = context.field("index_align").unwrap_or(0);
    let (index, spacing) = match size {
        0 => (index_align >> 1, 1),
        1 => (index_align >> 2, if index_align & 2 != 0 { 2 } else { 1 }),
        _ => (index_align >> 3, if index_align & 4 != 0 { 2 } else { 1 }),
    };
    let spacing = if structures == 1 { 1 } else { spacing };
    d_registers(first, structures, spacing, Some(index))
}

fn d_registers(first: u64, count: u64, spacing: u64, lane: Option<u64>) -> Value {
    if first + (count - 1) * spacing > 31 {
        return Value::Invalid;
    }
    let names: Vec<String> = (0..count)
        .map(|n| match lane {
            Some(lane) => format!("d{}[{lane}]", first + n * spacing),
            None => format!("d{}", first + n * spacing),
        })
        .collect();
    Value::Text(format!("{{{}}}", names.join(", ")))
}

fn d_registers_all_lanes(first: u64, count: u64, spacing: u64) -> Value {
    if first + (count - 1) * spacing > 31 {
        return Value::Invalid;
    }
    let names: Vec<String> = (0..count).map(|n| format!("d{}[]", first + n * spacing)).collect();
    Value::Text(format!("{{{}}}", names.join(", ")))
}

/// A VLDn/VSTn alignment in bits (`:64`); none when the field is 0.
fn alignment(context: &Context) -> Value {
    let mnemonic = context.mnemonic();
    let structures = mnemonic.trim_start_matches("VLD").trim_start_matches("VST").parse::<u64>().unwrap_or(1);
    let bits = if let Some(align) = context.field("align") {
        if context.field("itype").is_some() {
            match align {
                0 => 0,
                1 => 64,
                2 => 128,
                _ => 256,
            }
        } else {
            // All lanes: the element size times the structure count, with VLD4's 32-bit case at 128.
            let size = context.field("size").unwrap_or(0);
            match (align, structures, size) {
                (0, ..) => 0,
                (_, 1, _) => 8 << size,
                (_, 2, _) => 16 << size,
                (_, 4, 3) => 128,
                (_, 4, _) => 32 << size,
                _ => 0,
            }
        }
    } else {
        let index_align = context.field("index_align").unwrap_or(0);
        match (structures, context.field("size").unwrap_or(0)) {
            (1, 1) if index_align & 1 != 0 => 16,
            (1, 2) if index_align & 3 != 0 => 32,
            (2, 0) if index_align & 1 != 0 => 16,
            (2, 1) if index_align & 1 != 0 => 32,
            (2, 2) if index_align & 1 != 0 => 64,
            (4, 0) if index_align & 1 != 0 => 32,
            (4, 1) if index_align & 1 != 0 => 64,
            (4, 2) => [0, 64, 128, 0][(index_align & 3) as usize],
            _ => 0,
        }
    };
    if bits == 0 { Value::Default("0".to_owned()) } else { Value::Text(bits.to_string()) }
}

/// A scalar operand `Dm[x]`: the register and the element index, by element size.
fn scalar(context: &Context, operand: &Operand) -> Value {
    let (register, index) = scalar_index(context);
    let register = match operand.name {
        "<Dd[x]>" if context.field("Vd").is_some() && context.field("opc1").is_some() => {
            context.field("D").unwrap_or(0) << 4 | context.field("Vd").unwrap_or(0)
        }
        "<Dn[x]>" => context.field("N").unwrap_or(0) << 4 | context.field("Vn").unwrap_or(0),
        _ => register,
    };
    Value::Text(format!("d{register}[{index}]"))
}

/// The register and lane of a scalar: VMOV and VDUP between core registers and lanes encode the lane with
/// the size (opc1:opc2 or imm4); by-element arithmetic splits M:Vm by element size.
fn scalar_index(context: &Context) -> (u64, u64) {
    if let (Some(opc1), Some(opc2)) = (context.field("opc1"), context.field("opc2")) {
        let bits = opc1 << 2 | opc2;
        let index = match bits {
            8.. => bits & 7,
            _ if bits & 1 != 0 => bits >> 1 & 3,
            _ => bits >> 2 & 1,
        };
        let register = context.field("D").or(context.field("N")).unwrap_or(0) << 4
            | context.field("Vd").or(context.field("Vn")).unwrap_or(0);
        return (register, index);
    }
    let m = context.field("M").unwrap_or(0);
    let vm = context.field("Vm").unwrap_or(0);
    if let Some(imm4) = context.field("imm4").filter(|_| context.mnemonic() == "VDUP") {
        let index = if imm4 & 1 != 0 {
            imm4 >> 1
        } else if imm4 & 2 != 0 {
            imm4 >> 2
        } else {
            imm4 >> 3
        };
        return (m << 4 | vm, index);
    }
    match context.field("size") {
        Some(1) => (vm & 7, m << 1 | vm >> 3),
        _ => (vm, m),
    }
}

/// The element type of instructions that encode it apart from a size field: lane moves and duplicates (by
/// `opc1:opc2`, `imm4` or `B:E`) and vector immediates (by `cmode` and `op`).
fn element_type(context: &Context) -> Option<String> {
    let mnemonic = context.mnemonic();
    if let (Some(opc1), Some(opc2), "VMOV") = (context.field("opc1"), context.field("opc2"), mnemonic) {
        let bits = opc1 << 2 | opc2;
        let size = if bits & 0b1000 != 0 {
            8
        } else if bits & 1 != 0 {
            16
        } else {
            32
        };
        // Moves to a core register sign- or zero-extend narrow lanes.
        let to_core = context.decoded.encoding.name.starts_with("VMOV_sr");
        return Some(match (to_core, size, context.field("U")) {
            (true, 8 | 16, Some(1)) => format!("u{size}"),
            (true, 8 | 16, _) => format!("s{size}"),
            _ => size.to_string(),
        });
    }
    if mnemonic == "VDUP" {
        if let Some(imm4) = context.field("imm4") {
            let size = if imm4 & 1 != 0 {
                "8"
            } else if imm4 & 2 != 0 {
                "16"
            } else {
                "32"
            };
            return Some(size.to_owned());
        }
        if let (Some(b), Some(e)) = (context.field("B"), context.field("E")) {
            return Some(
                match (b, e) {
                    (0, 0) => "32",
                    (0, 1) => "16",
                    _ => "8",
                }
                .to_owned(),
            );
        }
    }
    if let (Some(cmode), true) = (context.field("cmode"), matches!(mnemonic, "VMOV" | "VMVN" | "VORR" | "VBIC")) {
        let op = context.field("op").unwrap_or(0);
        let kind = match cmode {
            0..=7 | 12 | 13 => "i32",
            8..=11 => "i16",
            14 if op == 0 => "i8",
            14 => "i64",
            _ => "f32",
        };
        return Some(kind.to_owned());
    }
    None
}
