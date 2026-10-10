//! Operand semantics: how the fields behind each placeholder of the specification's assembly syntax become
//! text. The open-source specification names the placeholders, the fields that encode them and, for many,
//! their legal spellings, but not the mapping from field values; that follows the Arm ARM operand
//! descriptions. Output follows LLVM's conventions.

use super::helpers::{decode_bit_masks, system_operation};
use super::spec_types::{Operand, SysKind};
use super::{Decoded, extract, lookup, spec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelStyle {
    /// Branch targets and literals as absolute addresses (`0x1000`).
    Absolute,
    /// As signed offsets from the instruction (`#-8`), the way `llvm-mc` prints them.
    Relative,
}

pub enum Value {
    Text(String),
    /// The operand's default value; an optional group holding only defaults is left out.
    Default(String),
    /// No rendering exists for this encoding; the enclosing alternative does not apply.
    Invalid,
}

pub struct Context<'a> {
    pub decoded: &'a Decoded,
    pub address: u64,
    pub labels: LabelStyle,
}

const CONDITIONS: [&str; 16] =
    ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"];

impl Context<'_> {
    fn word(&self) -> u32 {
        self.decoded.word
    }

    fn field(&self, name: &str) -> Option<u64> {
        self.decoded.field(name)
    }

    /// The operand's fields concatenated in the specification's order, with their total width.
    fn raw(&self, operand: &Operand) -> (u64, u32) {
        let mut value = 0u64;
        let mut width = 0u32;
        for &index in operand.fields {
            let field = &self.decoded.encoding.fields[index as usize];
            value = (value << field.width) | extract(self.word(), field.start, field.width);
            width += field.width as u32;
        }
        (value, width)
    }

    fn field_names(&self, operand: &Operand) -> Vec<&'static str> {
        operand.fields.iter().map(|&index| self.decoded.encoding.fields[index as usize].name).collect()
    }

    /// The mnemonic of the displayed syntax, uppercase as the specification writes it.
    fn mnemonic(&self) -> &'static str {
        match self.decoded.syntax.tokens.first() {
            Some(super::spec_types::Token::Text(text)) => text.split([' ', '{']).next().unwrap_or(""),
            _ => "",
        }
    }

    fn encoding_name(&self) -> &'static str {
        self.decoded.encoding.name
    }

    /// SVE and SME encodings are the ones the specification names in lowercase.
    fn is_sve(&self) -> bool {
        self.encoding_name().starts_with(|c: char| c.is_ascii_lowercase())
    }

    /// Whether the displayed syntax contains `needle` in its literal text, such as `MUL VL`.
    fn has_text(&self, needle: &str) -> bool {
        fn search(tokens: &[super::spec_types::Token], needle: &str) -> bool {
            use super::spec_types::Token;
            tokens.iter().any(|token| match token {
                Token::Text(text) => text.contains(needle),
                Token::Operand(_) => false,
                Token::Optional(inner) => search(inner, needle),
                Token::Choice(alternatives) => alternatives.iter().any(|a| search(a, needle)),
            })
        }
        search(self.decoded.syntax.tokens, needle)
    }

    /// The element size in bytes of an SVE load or store, from its mnemonic (LD1RH, LD1SW, ST1D...).
    fn sve_memory_element(&self) -> u64 {
        let mnemonic = self.mnemonic();
        match mnemonic.chars().last() {
            Some('B') => 1,
            Some('H') => 2,
            Some('W') => 4,
            Some('D') => 8,
            Some('Q') => 16,
            _ => 1,
        }
    }

    fn has_operand(&self, name: &str) -> bool {
        self.decoded.syntax.operands.iter().any(|operand| operand.name == name)
    }

    /// Bytes moved per register by a load or store, from its register operands and mnemonic.
    fn transfer_size(&self) -> u64 {
        let mnemonic = self.mnemonic();
        if mnemonic.starts_with("PRF") {
            return 8;
        }
        for operand in self.decoded.syntax.operands {
            let name = operand.name.trim_start_matches('<');
            let size = match name.as_bytes().first() {
                Some(b'B') => 1,
                Some(b'H') => 2,
                Some(b'S') => 4,
                Some(b'D') => 8,
                Some(b'Q') => 16,
                Some(b'X') | Some(b'W') if name.starts_with("Xn") || name.starts_with("Xm") => continue,
                Some(b'X') | Some(b'W') if name.starts_with("Xs") || name.starts_with("Ws") => continue,
                Some(b'X') => 8,
                Some(b'W') => 4,
                _ => continue,
            };
            if name.starts_with('W') || name.starts_with('X') {
                if mnemonic.ends_with("SW") {
                    return 4;
                }
                if mnemonic.ends_with('B') {
                    return 1;
                }
                if mnemonic.ends_with('H') {
                    return 2;
                }
            }
            return size;
        }
        1
    }

    fn label(&self, target: u64, offset: i64) -> Value {
        match self.labels {
            LabelStyle::Absolute => Value::Text(format!("{target:#x}")),
            LabelStyle::Relative => Value::Text(format!("#{offset}")),
        }
    }

    /// The legal values of an operand's fields: those for which the word still decodes as this encoding.
    fn valid_values(&self, operand: &Operand) -> Vec<u64> {
        let fields: Vec<_> = operand.fields.iter().map(|&i| &self.decoded.encoding.fields[i as usize]).collect();
        let width: u32 = fields.iter().map(|f| f.width as u32).sum();
        if width > 8 {
            return Vec::new();
        }
        let mut cleared = self.word();
        for field in &fields {
            cleared &= !((((1u64 << field.width) - 1) as u32) << field.start);
        }
        (0..1u64 << width)
            .filter(|&candidate| {
                let mut word = cleared;
                let mut remaining = width;
                for field in &fields {
                    remaining -= field.width as u32;
                    let bits = (candidate >> remaining) & ((1 << field.width) - 1);
                    word |= (bits as u32) << field.start;
                }
                lookup(word).is_some_and(|encoding| std::ptr::eq(encoding, self.decoded.encoding))
            })
            .collect()
    }
}

fn sign_extend(value: u64, width: u32) -> i64 {
    let shift = 64 - width.clamp(1, 64);
    ((value << shift) as i64) >> shift
}

fn is_literal(choices: &[&str]) -> bool {
    !choices.is_empty() && choices.iter().all(|choice| !choice.contains('<') && !choice.contains('['))
}

/// Maps the operand's value onto its list of legal spellings: the choices name the values that decode to
/// this encoding, in increasing order.
fn ranked_choice(context: &Context, operand: &Operand) -> Option<String> {
    if !is_literal(operand.choices) {
        return None;
    }
    let (value, width) = context.raw(operand);
    if operand.choices.len() == 1 << width {
        return Some(operand.choices[value as usize].to_ascii_lowercase());
    }
    let valid = context.valid_values(operand);
    if valid.len() != operand.choices.len() {
        return None;
    }
    let rank = valid.iter().position(|&v| v == value)?;
    Some(operand.choices[rank].to_ascii_lowercase())
}

/// Renders one operand.
pub fn render(context: &Context, operand: &Operand) -> Value {
    let name = operand.name.trim_start_matches('<').trim_end_matches('>');
    if let Some(value) = special(context, operand, name) {
        return value;
    }
    if let Some(value) = register(context, operand, name) {
        return value;
    }
    if let Some(value) = arrangement(context, operand, name) {
        return value;
    }
    if let Some(value) = immediate(context, operand, name) {
        return value;
    }
    if let Some(text) = ranked_choice(context, operand) {
        return Value::Text(text);
    }
    Value::Text(context.raw(operand).0.to_string())
}

fn special(context: &Context, operand: &Operand, name: &str) -> Option<Value> {
    let (value, width) = context.raw(operand);
    Some(match name {
        " " => Value::Default(" ".to_owned()),
        "2" => {
            if value == 1 {
                Value::Text("2".to_owned())
            } else {
                Value::Default(String::new())
            }
        }
        "label" => label(context, operand),
        "cond" => Value::Text(CONDITIONS[value as usize & 15].to_owned()),
        "invcond" => Value::Text(CONDITIONS[(value as usize & 15) ^ 1].to_owned()),
        "nzcv" | "op1" | "op2" | "uimm4" | "imm2" => Value::Text(format!("{value}")),
        "op0" => Value::Text(format!("{}", value + 2)),
        "Cn" | "Cm" => Value::Text(format!("c{value}")),
        "systemreg" => system_register(context, value),
        "pstatefield" => pstate_field(value),
        "option" => barrier(context, operand, value),
        "prfop" if context.is_sve() => sve_prefetch(operand, value),
        "rprfop" => match range_prefetch_operation(context) {
            0 => Value::Text("pldkeep".to_owned()),
            1 => Value::Text("pstkeep".to_owned()),
            4 => Value::Text("pldstrm".to_owned()),
            5 => Value::Text("pststrm".to_owned()),
            _ => Value::Invalid,
        },
        "imm6" if context.mnemonic() == "RPRFM" => Value::Text(range_prefetch_operation(context).to_string()),
        "prfop" => prefetch(value),
        "mod" if context.field_names(operand) == ["msz"] => {
            if value == 0 {
                Value::Default(String::new())
            } else {
                Value::Text("lsl".to_owned())
            }
        }
        "dc_op" | "ic_op" | "at_op" | "tlbi_op" | "brb_op" | "gsb_op" | "gic_op" | "plbi_op" | "gicr_op"
        | "tlbip_op" => system_operation_name(context),
        "shift" => shift(context, operand, value),
        "amount" => amount(context, operand, value),
        "extend" => extend(context, value),
        "lsb" => bitfield_lsb(context, value),
        "width" => bitfield_width(context),
        "fbits" => fixed_point_bits(context, operand, value),
        "index" | "index1" | "index2" => element_index(context, operand, value),
        "offs1" | "offs2" | "offs3" | "offs4" => {
            // Consecutive slices: the field names the first of a group of 2 or 4.
            let count = if context.has_operand("<offs4>") { 4 } else { 2 };
            let index = name.trim_start_matches("offs").parse::<u64>().unwrap_or(1) - 1;
            Value::Text((value * count + index).to_string())
        }
        "targets" => Value::Text(["", "c", "j", "jc"][(value as usize >> 1) & 3].to_owned()),
        "pattern" => sve_pattern(operand, value),
        "const" => sve_constant(context, operand, value, width),
        "nb" if context.field("op1").is_some() => {
            if value & 1 == 1 {
                Value::Text("nb".to_owned())
            } else {
                Value::Invalid
            }
        }
        "" => {
            // The empty alternative of TCHANGEB/TCHANGEF, taken when the nb flag is clear.
            if context.field("op1").is_some_and(|op1| op1 & 1 == 1) {
                Value::Invalid
            } else {
                Value::Default(String::new())
            }
        }
        _ => return None,
    })
}

fn label(context: &Context, operand: &Operand) -> Value {
    let (raw, width) = context.raw(operand);
    let encoding = context.encoding_name();
    let (offset, base) = if encoding.starts_with("ADRP") {
        (sign_extend(raw, width) << 12, context.address & !0xfff)
    } else if encoding.starts_with("ADR_") {
        (sign_extend(raw, width), context.address)
    } else if context.field_names(operand) == ["imm16"] {
        // AUTIASPPC and friends: the label lies before the instruction.
        (-((raw << 2) as i64), context.address)
    } else {
        (sign_extend(raw, width) << 2, context.address)
    };
    context.label(base.wrapping_add(offset as u64), offset)
}

fn system_register(context: &Context, encoded: u64) -> Value {
    // o0 selects op0 = 2 or 3.
    let key = (encoded | (1 << 15)) as u16;
    let lookup =
        |table: &[(u16, &'static str)]| table.binary_search_by_key(&key, |&(k, _)| k).ok().map(|index| table[index].1);
    let name = if context.mnemonic().starts_with("MSR") {
        lookup(&spec::MSR_REGISTERS).or_else(|| lookup(&spec::MRS_REGISTERS))
    } else {
        lookup(&spec::MRS_REGISTERS).or_else(|| lookup(&spec::MSR_REGISTERS))
    };
    match name {
        Some(name) => Value::Text(name.to_owned()),
        None => Value::Text(format!(
            "S{}_{}_C{}_C{}_{}",
            (key >> 14) & 3,
            (key >> 11) & 7,
            (key >> 7) & 15,
            (key >> 3) & 15,
            key & 7
        )),
    }
}

fn pstate_field(encoded: u64) -> Value {
    // Encoded as CRm:op1:op2; the table is keyed by op1:CRm:op2.
    let crm = (encoded >> 6) & 0xf;
    let op1 = (encoded >> 3) & 0x7;
    let op2 = encoded & 0x7;
    let key = ((op1 << 7) | (crm << 3) | op2) as u16;
    match spec::PSTATE_FIELDS.binary_search_by_key(&key, |&(k, _)| k) {
        Ok(index) => Value::Text(spec::PSTATE_FIELDS[index].1.to_owned()),
        Err(_) => Value::Invalid,
    }
}

fn barrier(context: &Context, operand: &Operand, value: u64) -> Value {
    if context.mnemonic() == "ISB" {
        return if value == 15 { Value::Default(String::new()) } else { Value::Invalid };
    }
    if context.field_names(operand) == ["imm2"] {
        // DSB ... nXS
        return Value::Text(["osh", "nsh", "ish", "sy"][value as usize & 3].to_owned());
    }
    if context.field_names(operand) != ["CRm"] {
        return match ranked_choice(context, operand) {
            Some(text) => Value::Text(text),
            None => Value::Invalid,
        };
    }
    let name = match value {
        0b0001 => "oshld",
        0b0010 => "oshst",
        0b0011 => "osh",
        0b0101 => "nshld",
        0b0110 => "nshst",
        0b0111 => "nsh",
        0b1001 => "ishld",
        0b1010 => "ishst",
        0b1011 => "ish",
        0b1101 => "ld",
        0b1110 => "st",
        0b1111 => "sy",
        _ => return Value::Invalid,
    };
    Value::Text(name.to_owned())
}

fn prefetch(value: u64) -> Value {
    let kind = match value >> 3 {
        0 => "pld",
        1 => "pli",
        2 => "pst",
        _ => return Value::Invalid,
    };
    let target = match (value >> 1) & 3 {
        0 => "l1",
        1 => "l2",
        2 => "l3",
        _ => "slc",
    };
    let policy = if value & 1 == 0 { "keep" } else { "strm" };
    Value::Text(format!("{kind}{target}{policy}"))
}

fn system_operation_name(context: &Context) -> Value {
    let (op1, crn, crm, op2) = (context.field("op1"), context.field("CRn"), context.field("CRm"), context.field("op2"));
    let (Some(op1), Some(crn), Some(crm), Some(op2)) = (op1, crn, crm, op2) else { return Value::Invalid };
    let wanted = match context.mnemonic() {
        "AT" => SysKind::At,
        "BRB" => SysKind::Brb,
        "DC" => SysKind::Dc,
        "GIC" => SysKind::Gic,
        "GICR" => SysKind::Gicr,
        "GSB" => SysKind::Gsb,
        "IC" => SysKind::Ic,
        "PLBI" => SysKind::Plbi,
        "TLBI" => SysKind::Tlbi,
        "TLBIP" => SysKind::Tlbip,
        _ => return Value::Invalid,
    };
    match system_operation(op1, crn, crm, op2, |kind| kind == wanted) {
        Some((_, name)) => Value::Text(name.to_ascii_lowercase()),
        None => Value::Invalid,
    }
}

fn shift(context: &Context, operand: &Operand, value: u64) -> Value {
    let fields = context.field_names(operand);
    let register_width = if context.field("sf") == Some(1) { 64 } else { 32 };
    match fields.as_slice() {
        ["shift"] => {
            let name = ["lsl", "lsr", "asr", "ror"][value as usize & 3];
            let amount = context.field("imm6").unwrap_or(0);
            if value == 0 && amount == 0 { Value::Default(name.to_owned()) } else { Value::Text(name.to_owned()) }
        }
        ["hw"] => {
            let amount = value * 16;
            if amount == 0 { Value::Default("0".to_owned()) } else { Value::Text(amount.to_string()) }
        }
        ["sh"] if operand.choices.len() == 2 => {
            let text = operand.choices[value as usize & 1].to_ascii_lowercase();
            // SVE folds the shift into the immediate, except for #0, lsl #8.
            let folded = context.is_sve() && context.field("imm8") != Some(0);
            if value == 0 || folded { Value::Default(text) } else { Value::Text(text) }
        }
        ["immr"] => {
            let amount = if context.mnemonic() == "LSL" { (register_width - value) % register_width } else { value };
            Value::Text(amount.to_string())
        }
        ["imms"] => Value::Text(value.to_string()),
        ["size"] if context.mnemonic().starts_with("SHLL") => Value::Text((8u64 << value).to_string()),
        _ if fields.contains(&"immh") && fields.contains(&"immb") => {
            let shift = (context.field("immh").unwrap_or(0) << 3) | context.field("immb").unwrap_or(0);
            let element = 8u64 << (63 - (shift >> 3).max(1).leading_zeros()).min(3);
            if right_shift(context.mnemonic()) {
                Value::Text((2 * element - shift).to_string())
            } else {
                Value::Text((shift - element).to_string())
            }
        }
        _ => match ranked_choice(context, operand) {
            Some(text) => Value::Text(text),
            None => Value::Text(value.to_string()),
        },
    }
}

fn right_shift(mnemonic: &str) -> bool {
    ["SHR", "SRA", "SRI", "SHRN", "SHRUN"].iter().any(|suffix| mnemonic.contains(suffix))
}

fn amount(context: &Context, operand: &Operand, value: u64) -> Value {
    let fields = context.field_names(operand);
    match fields.as_slice() {
        ["S"] => {
            if !operand.choices.is_empty() {
                let text = operand.choices.get(value as usize).map(|c| c.to_ascii_lowercase()).unwrap_or_default();
                // A shift of zero is implied unless S is set.
                return if value == 1 { Value::Text(text) } else { Value::Default(text) };
            }
            let shift = context.transfer_size().trailing_zeros();
            if value == 1 { Value::Text(format!("#{shift}")) } else { Value::Default(String::new()) }
        }
        ["imm6"] | ["imm3"] => {
            if value == 0 {
                Value::Default("0".to_owned())
            } else {
                Value::Text(value.to_string())
            }
        }
        _ => {
            if let Some(text) = ranked_choice(context, operand) {
                return if text == "0" { Value::Default(text) } else { Value::Text(text) };
            }
            // One choice fewer than legal values: the lowest value is the implied, unprinted amount.
            let valid = context.valid_values(operand);
            if is_literal(operand.choices) && valid.len() == operand.choices.len() + 1 {
                return match valid.iter().position(|&v| v == value) {
                    Some(0) | None => Value::Default(String::new()),
                    Some(rank) => Value::Text(operand.choices[rank - 1].to_ascii_lowercase()),
                };
            }
            Value::Text(value.to_string())
        }
    }
}

fn extend(context: &Context, option: u64) -> Value {
    const NAMES: [&str; 8] = ["uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"];
    let name = NAMES[option as usize & 7];
    let is_load_store = context.field("Rt").is_some() || context.mnemonic().starts_with("PRFM");
    if is_load_store {
        // Register-offset loads: LSL stands for UXTX and is implied without a shift.
        return if option == 0b011 { Value::Default("lsl".to_owned()) } else { Value::Text(name.to_owned()) };
    }
    // ADD/SUB (extended register): with SP as destination or first source, the natural extend is LSL.
    let is_64 = context.field("sf") == Some(1);
    let uses_sp = context.field("Rd") == Some(31) && context.field("S") != Some(1) || context.field("Rn") == Some(31);
    let natural = if is_64 { 0b011 } else { 0b010 };
    if uses_sp && option == natural {
        let amount = context.field("imm3").unwrap_or(0);
        return if amount == 0 { Value::Default("lsl".to_owned()) } else { Value::Text("lsl".to_owned()) };
    }
    Value::Text(name.to_owned())
}

fn bitfield_lsb(context: &Context, value: u64) -> Value {
    let width = if context.field("sf") == Some(1) { 64 } else { 32 };
    if matches!(context.mnemonic(), "BFI" | "BFC" | "SBFIZ" | "UBFIZ") {
        // UBFIZ/SBFIZ/BFI: lsb = -immr MOD width.
        let immr = context.field("immr").unwrap_or(value);
        return Value::Text(((width - immr) % width).to_string());
    }
    Value::Text(value.to_string())
}

fn bitfield_width(context: &Context) -> Value {
    let imms = context.field("imms").unwrap_or(0);
    let immr = context.field("immr").unwrap_or(0);
    if matches!(context.mnemonic(), "BFI" | "BFC" | "SBFIZ" | "UBFIZ") {
        return Value::Text((imms + 1).to_string());
    }
    Value::Text((imms + 1 - immr.min(imms + 1)).to_string())
}

fn fixed_point_bits(context: &Context, operand: &Operand, value: u64) -> Value {
    let fields = context.field_names(operand);
    if fields == ["scale"] {
        return Value::Text((64 - value).to_string());
    }
    if fields.contains(&"immh") {
        let shift = (context.field("immh").unwrap_or(0) << 3) | context.field("immb").unwrap_or(0);
        let element = 8u64 << (63 - (shift >> 3).max(1).leading_zeros()).min(3);
        return Value::Text((2 * element - shift).to_string());
    }
    Value::Text(value.to_string())
}

/// Element size in bits named by a size field: `size` counts from bytes, `sz` from words.
fn element_bits(context: &Context) -> Option<u64> {
    if let Some(size) = context.field("size") {
        return Some(8 << size);
    }
    context.field("sz").map(|sz| 32 << sz)
}

fn element_index(context: &Context, operand: &Operand, value: u64) -> Value {
    let fields = context.field_names(operand);
    let has = |name| fields.contains(&name);
    let text = if has("imm5") && has("imm4") {
        let imm5 = context.field("imm5").unwrap_or(0);
        context.field("imm4").unwrap_or(0) >> imm5.trailing_zeros().min(4)
    } else if fields == ["imm5"] {
        let imm5 = context.field("imm5").unwrap_or(0);
        imm5 >> (imm5.trailing_zeros() + 1).min(5)
    } else if has("H") && !context.is_sve() && (has("size") || has("sz")) {
        // The element size picks how many of H, L and M form the index. FCMLA indexes pairs of elements.
        let h = context.field("H").unwrap_or(0);
        let l = context.field("L").unwrap_or(0);
        let m = context.field("M").unwrap_or(0);
        let bits = element_bits(context).unwrap_or(32) * if context.mnemonic() == "FCMLA" { 2 } else { 1 };
        match bits {
            16 => (h << 2) | (l << 1) | m,
            32 => (h << 1) | l,
            _ => h,
        }
    } else if has("Q") && has("S") && !context.is_sve() {
        // Single-structure loads and stores: Q:S:size holds the byte index of the lane.
        let q = context.field("Q").unwrap_or(0);
        let s = context.field("S").unwrap_or(0);
        let size = context.field("size").unwrap_or(0);
        let bytes = (q << 3) | (s << 2) | size;
        let name = context.encoding_name();
        if name.contains("_B") {
            bytes
        } else if name.contains("_H") {
            bytes >> 1
        } else {
            bytes >> 2
        }
    } else if has("H") && has("Rm") && !context.is_sve() {
        // FP8 by-element forms: the index is H:L:M:Rm<3>, and Rm<2:0> names the register.
        let h = context.field("H").unwrap_or(0);
        let hlm = (h << 2) | (context.field("L").unwrap_or(0) << 1) | context.field("M").unwrap_or(0);
        (hlm << 1) | (context.field("Rm").unwrap_or(0) >> 3)
    } else if fields == ["Q"] && !context.is_sve() {
        value
    } else if fields.iter().any(|field| field.starts_with("tsz")) {
        // The bits above the lowest set bit of tsz.
        let tsz_width: u32 = operand
            .fields
            .iter()
            .map(|&i| &context.decoded.encoding.fields[i as usize])
            .filter(|field| field.name.starts_with("tsz"))
            .map(|field| field.width as u32)
            .sum();
        let tsz = value & ((1 << tsz_width) - 1);
        value >> (tsz.trailing_zeros() + 1).min(63)
    } else if has("imm4") && has("Q") {
        // EXT: Q only restricts the byte index.
        context.field("imm4").unwrap_or(0)
    } else {
        value
    };
    Value::Text(text.to_string())
}

/// General-purpose, SIMD&FP, SVE and SME registers.
fn register(context: &Context, operand: &Operand, name: &str) -> Option<Value> {
    let fields = context.field_names(operand);
    let (value, width) = context.raw(operand);
    let is_register_field =
        |field: &&str| field.len() >= 2 && matches!(field.as_bytes()[0], b'R' | b'Z' | b'P' | b'V') && *field != "VL";
    if !fields.iter().any(is_register_field) {
        return None;
    }
    let split = name.find(|c: char| c.is_ascii_lowercase() || c == '(').unwrap_or(name.len());
    let (base, rest) = name.split_at(split);
    let offset = if let Some((_, added)) = rest.split_once('+') {
        added.trim_end_matches(')').parse::<u64>().unwrap_or(0)
    } else if base == "V" {
        // Vt2, Vt3, Vt4 follow Vt.
        rest.trim_start_matches(|c: char| c.is_ascii_lowercase()).parse::<u64>().map_or(0, |n| n.saturating_sub(1))
    } else {
        0
    };
    // A pair's second register shares the first's field when the pair is consecutive (SYSP <Xt1>, <Xt2>).
    let shares_first = name.ends_with('2')
        && !name.contains('+')
        && context.decoded.syntax.operands.iter().any(|other| {
            other.name.trim_start_matches('<').trim_end_matches('>') == format!("{}1", &name[..name.len() - 1])
                && other.fields == operand.fields
        });
    let offset = if shares_first { 1 } else { offset };
    let number = (value + offset) % 32;
    let allows_sp = name.contains("|SP") || name.contains("|WSP");
    Some(Value::Text(match base {
        "W" | "X" => {
            // Register-offset addressing picks W or X by the extend: option<0> is set for X.
            if let Some(option) = context.field("option")
                && context.has_operand("<Wm>")
                && context.has_operand("<Xm>")
                && rest.starts_with('m')
                && (option & 1 == 1) != (base == "X")
            {
                return Some(Value::Invalid);
            }
            let prefix = base.to_ascii_lowercase();
            if width == 2 && (name == "Wv" || name == "Ws") {
                // SME slice selectors: W12-W15 index tiles, W8-W11 index the ZA array.
                let array = context.has_text("ZA.") || context.has_text("ZA[");
                format!("w{}", if array { 8 } else { 12 } + value)
            } else if number == 31 {
                match (allows_sp, base) {
                    (true, "W") => "wsp".to_owned(),
                    (true, _) => "sp".to_owned(),
                    // XZR is the default of optional register operands (SYS, TLBI, IRG).
                    _ => return Some(Value::Default(format!("{prefix}zr"))),
                }
            } else if number == 30 && context.mnemonic().starts_with("RET") {
                return Some(Value::Default("x30".to_owned()));
            } else {
                format!("{prefix}{number}")
            }
        }
        "B" | "H" | "S" | "D" | "Q" => format!("{}{number}", base.to_ascii_lowercase()),
        "V" if fields == ["Rm"] && fp8_by_element(context) => format!("v{}", value & 7),
        "V" => {
            if fields.contains(&"M") && fields.contains(&"Rm") {
                // By-element forms: Rm is 4 bits wide for 16-bit elements (M joins the index), except in FCMLA.
                let rm = context.field("Rm").unwrap_or(0);
                let m = context.field("M").unwrap_or(0);
                let narrow = element_bits(context) == Some(16) && context.mnemonic() != "FCMLA";
                if narrow { format!("v{rm}") } else { format!("v{}", (m << 4) | rm) }
            } else {
                format!("v{number}")
            }
        }
        "Z" if context.encoding_name().contains("mop4") => {
            // MOP4: Zn names even registers z0-z14, Zm even registers z16-z30.
            let index = if name.ends_with('2') { 1 } else { 0 };
            let base = if rest.starts_with('m') { 16 } else { 0 };
            format!("z{}", base + value * 2 + index)
        }
        "Z" if name == "Zk" && fields.contains(&"K") => {
            let k = context.field("K").unwrap_or(0);
            format!("z{}", 20 + 8 * k + context.field("Zk").unwrap_or(0))
        }
        "Z" | "Za" => format!("z{}", multi_vector(context, operand, name, value, width)),
        "P" if name.ends_with('1') || name.ends_with('2') => {
            // Predicate pairs { <Pd1>, <Pd2> }: the field names an even register.
            let index = if name.ends_with('2') { 1 } else { 0 };
            if width == 3 { format!("p{}", value * 2 + index) } else { format!("p{}", value + index) }
        }
        "P" => format!("p{value}"),
        "PN" => format!("pn{}", if width == 3 { value + 8 } else { value }),
        "ZA" => format!("za{value}"),
        "" if matches!(name, "d" | "n" | "m" | "t" | "dn" | "n|SP") => {
            if fields.contains(&"M") && fields.contains(&"size") {
                let rm = context.field("Rm").unwrap_or(0);
                let m = context.field("M").unwrap_or(0);
                return Some(Value::Text(if context.field("size") == Some(1) {
                    rm.to_string()
                } else {
                    ((m << 4) | rm).to_string()
                }));
            }
            if value == 31 && operand.choices.iter().any(|choice| choice.ends_with("ZR")) {
                return Some(Value::Text("zr".to_owned()));
            }
            if value == 31 && name == "n|SP" {
                return Some(Value::Text("sp".to_owned()));
            }
            value.to_string()
        }
        _ => return None,
    }))
}

/// The register number of a member of a multi-vector list such as `{ <Zn1>.S-<Zn2>.S }`.
fn multi_vector(context: &Context, operand: &Operand, name: &str, value: u64, width: u32) -> u64 {
    let in_list = name.chars().last().is_some_and(|c| c.is_ascii_digit());
    if !in_list {
        return value;
    }
    let index = name.trim_start_matches(|c: char| !c.is_ascii_digit()).parse::<u64>().unwrap_or(1);
    if operand.fields.len() == 2 {
        // Strided lists: T:Zt names the first register, the rest are spaced by 8 (pairs) or 4 (quads).
        let count = if context.has_operand("<Zt4>") || context.has_operand("<Zd4>") { 4 } else { 2 };
        let stride = 16 / count;
        let first = ((value >> (width - 1)) << 4) | (value & ((1 << (width - 1)) - 1));
        return (first + (index - 1) * stride) % 32;
    }
    let scale = 1u64 << (5 - width.min(5));
    (value * scale + index - 1) % 32
}

/// Element arrangement and size specifiers: `<T>`, `<Ta>`, `<Tb>`, `<Ts>`, `<V>`, `<R>`.
fn arrangement(context: &Context, operand: &Operand, name: &str) -> Option<Value> {
    if !matches!(name, "T" | "Ta" | "Tb" | "Ts" | "V" | "Va" | "Vb" | "R" | "bt") {
        return None;
    }
    if let Some(text) = ranked_choice(context, operand) {
        return Some(Value::Text(text));
    }
    let fields = context.field_names(operand);
    let (value, width) = context.raw(operand);
    let has = |name| fields.contains(&name);
    if let Some(value) = parallel_choice(context, operand, name) {
        return Some(value);
    }
    if fields.iter().all(|field| field.starts_with("tsz")) && !fields.is_empty() && indexed_by_tsz(context, operand) {
        // DUP (indexed), DUPQ and PSEL: the lowest set bit of tsz gives the element size, the bits above it
        // the index.
        if value == 0 {
            return Some(Value::Invalid);
        }
        let letters = ["b", "h", "s", "d", "q"];
        return Some(Value::Text(letters[(value.trailing_zeros() as usize).min(4)].to_owned()));
    }
    if fields == ["imm13"] {
        let Some(element) = sve_logical_element(value) else { return Some(Value::Invalid) };
        return Some(Value::Text(["b", "h", "s", "d"][element.trailing_zeros() as usize - 3].to_owned()));
    }
    if fields.is_empty() && name == "V" {
        // FP16 across-lanes forms fix the element size: take it from the <T> arrangement.
        let arrangement_operand = context.decoded.syntax.operands.iter().find(|other| other.name == "<T>")?;
        return match arrangement(context, arrangement_operand, "T")? {
            Value::Text(text) => Some(Value::Text(text.trim_start_matches(|c: char| c.is_ascii_digit()).to_owned())),
            other => Some(other),
        };
    }
    if name == "R" {
        let is_x = match fields.as_slice() {
            ["size"] | ["sz"] => value == (1 << width) - 1,
            ["option"] => value & 0b011 == 0b011,
            ["imm5"] => value & 0b1111 == 0b1000,
            _ => value == 1,
        };
        return Some(Value::Text(if is_x { "x" } else { "w" }.to_owned()));
    }
    let element = if has("size") {
        8u64 << context.field("size").unwrap_or(0)
    } else if has("sz") {
        32u64 << context.field("sz").unwrap_or(0)
    } else if has("immh") {
        let immh = context.field("immh").unwrap_or(0);
        if immh == 0 {
            return Some(Value::Invalid);
        }
        8u64 << (63 - immh.leading_zeros())
    } else if has("imm5") {
        let imm5 = context.field("imm5").unwrap_or(0);
        if imm5 & 0xf == 0 {
            return Some(Value::Invalid);
        }
        8u64 << imm5.trailing_zeros()
    } else if has("tszh") || has("tsz") {
        if value == 0 {
            return Some(Value::Invalid);
        }
        8u64 << (63 - value.leading_zeros())
    } else {
        return None;
    };
    let letter = |bits: u64| ["b", "h", "s", "d", "q"][(bits.trailing_zeros().saturating_sub(3) as usize).min(4)];
    let letters_only = !operand.choices.is_empty() && operand.choices.iter().all(|choice| choice.len() == 1);
    let vector_bits = match context.field("Q") {
        Some(q) if has("Q") => 64 << q,
        _ => 128,
    };
    // Wide operands of long and narrowing operations have double-width elements.
    // SVE encodes the wide element and halves it for <Tb>; AdvSIMD encodes the narrow one and doubles it.
    let long_across_lanes = matches!(context.mnemonic(), "SADDLV" | "UADDLV");
    let scaled: &[(u64, u64)] = match name {
        "Ta" | "Va" => &[(2, 1), (1, 1)],
        "V" if long_across_lanes => &[(2, 1)],
        "Tb" if context.is_sve() && (has("tszh") || has("tsz")) && !context.mnemonic().contains("SHLL") => {
            &[(2, 1), (1, 1)]
        }
        "T" if context.is_sve() && (has("tszh") || has("tsz")) && context.mnemonic().contains("SHLL") => &[(2, 1)],
        "Tb" if context.is_sve() && narrowing(context.mnemonic()) => &[(1, 1)],
        "T" if context.is_sve() && narrowing(context.mnemonic()) && has("size") => &[(1, 2)],
        "Tb" if context.is_sve() => &[(1, 2), (1, 4), (1, 1)],
        _ => &[(1, 1), (2, 1)],
    };
    let render = |bits: u64| {
        if name.starts_with('V') || name == "Ts" || letters_only {
            letter(bits).to_owned()
        } else {
            format!("{}{}", vector_bits / bits, letter(bits))
        }
    };
    for &(multiply, divide) in scaled {
        let text = render(element * multiply / divide);
        if operand.choices.is_empty() || operand.choices.iter().any(|choice| choice.eq_ignore_ascii_case(&text)) {
            return Some(Value::Text(text));
        }
    }
    Some(Value::Invalid)
}

fn immediate(context: &Context, operand: &Operand, name: &str) -> Option<Value> {
    let fields = context.field_names(operand);
    let (value, width) = context.raw(operand);
    let has = |name| fields.contains(&name);
    let register_width = if context.field("sf") == Some(1) || context.has_operand("<Xd|SP>") { 64 } else { 32 };
    let default_if_zero = |number: i64| {
        if number == 0 { Value::Default("0".to_owned()) } else { Value::Text(number.to_string()) }
    };
    let text = match name {
        "imm" if has("immr") && has("imms") && !context.is_sve() => {
            let n = context.field("N").unwrap_or(0);
            let imms = context.field("imms").unwrap_or(0);
            let immr = context.field("immr").unwrap_or(0);
            let Some(mask) = decode_bit_masks(n, imms, immr, true, register_width) else {
                return Some(Value::Invalid);
            };
            if context.mnemonic() == "MOV" { signed_for_width(mask, register_width) } else { format!("{mask:#x}") }
        }
        "imm" if has("imm16") && has("hw") => {
            let shifted = context.field("imm16").unwrap_or(0) << (16 * context.field("hw").unwrap_or(0));
            let mask = if register_width == 64 { u64::MAX } else { 0xffff_ffff };
            let inverted = context.encoding_name().starts_with("MOVN");
            signed_for_width(if inverted { !shifted & mask } else { shifted & mask }, register_width)
        }
        "imm" if context.encoding_name().starts_with("MSR_SI") => pstate_immediate(context).to_string(),
        "imm" if fields.len() > 1 && fields.iter().any(|field| field.starts_with("tsz")) && !has("imm3") => {
            return Some(element_index(context, operand, value));
        }
        "imm" if context.mnemonic() == "CLREX" && value == 15 => return Some(Value::Default("15".to_owned())),
        "imm" | "simm" | "uimm6" if memory_tagging(context) => {
            // MTE offsets and tag-granule adjustments count 16-byte granules.
            let granules = if name == "uimm6" { value as i64 } else { sign_extend(value, width) };
            return Some(default_if_zero(granules * 16));
        }
        "imm" if context.encoding_name().ends_with("_exception") && !context.encoding_name().starts_with("TENTER") => {
            if value == 0 {
                "0".to_owned()
            } else {
                format!("{value:#x}")
            }
        }
        "imm" if context.is_sve() && fields == ["imm8"] && context.has_operand("<shift>") => {
            return Some(sve_shifted_immediate(context, value));
        }
        "imm" if context.is_sve() && fields == ["imm4"] && context.has_operand("<pattern>") => {
            let multiplier = value + 1;
            if multiplier == 1 {
                return Some(Value::Default("1".to_owned()));
            }
            multiplier.to_string()
        }
        "imm" if context.is_sve() && context.has_text("VL") && context.has_text("MUL") => {
            // Multi-register loads and stores step by whole groups of vectors.
            let registers = sve_register_count(context);
            return Some(default_if_zero(sign_extend(value, width) * registers));
        }
        "imm" if context.is_sve() && context.mnemonic().starts_with("LD1R") && fields == ["imm6"] => {
            return Some(default_if_zero((value * context.sve_memory_element()) as i64));
        }
        "imm"
            if context.is_sve()
                && (context.mnemonic().starts_with("LD1RQ") || context.mnemonic().starts_with("LD1RO")) =>
        {
            let block = if context.mnemonic().starts_with("LD1RQ") { 16 } else { 32 };
            return Some(default_if_zero(sign_extend(value, width) * block));
        }
        "imm"
            if context.is_sve() && fields == ["imm5"] && context.has_text(".S")
                || context.is_sve() && fields == ["imm5"] && context.has_text(".D") =>
        {
            // Vector plus immediate addressing: an unsigned multiple of the memory element size.
            if context.mnemonic().starts_with("LD")
                || context.mnemonic().starts_with("ST")
                || context.mnemonic().starts_with("PRF")
            {
                let element = if context.mnemonic().starts_with("PRF") {
                    prefetch_element(context.mnemonic())
                } else {
                    context.sve_memory_element()
                };
                return Some(default_if_zero((value * element) as i64));
            }
            sign_extend(value, width).to_string()
        }
        "imm" if context.mnemonic() == "FMOV" && width == 8 => fp_immediate(value),
        "imm" if has("a") && has("h") => {
            // MOVI (64-bit): each bit of a:b:c:d:e:f:g:h expands to a byte. LLVM prints it with `%#016llx`.
            let mut expanded = 0u64;
            for bit in 0..8 {
                if value & (1 << bit) != 0 {
                    expanded |= 0xff << (bit * 8);
                }
            }
            if expanded == 0 { "0000000000000000".to_owned() } else { format!("{expanded:#016x}") }
        }
        "imm8" if context.mnemonic() == "FMOV" => fp_immediate(value),
        "pimm" => return Some(default_if_zero((value * context.transfer_size()) as i64)),
        "simm" if fields == ["S", "imm9"] => return Some(default_if_zero(sign_extend(value, width) * 8)),
        "simm" if !context.is_sve() => return Some(default_if_zero(sign_extend(value, width))),
        "imm" if fields == ["imm7"] && context.encoding_name().contains("ldst") => {
            return Some(default_if_zero(sign_extend(value, width) * context.transfer_size() as i64));
        }
        "imm" if context.mnemonic().starts_with("TB") => value.to_string(),
        "imm" if context.is_sve() && (has("imm5") || has("imm6")) && fields.len() == 1 => {
            sign_extend(value, width).to_string()
        }
        "imm" | "immr" | "imms" | "uimm" | "imm8" => {
            if let Some(text) = ranked_choice(context, operand) {
                return Some(Value::Text(text));
            }
            value.to_string()
        }
        _ => return None,
    };
    Some(Value::Text(text))
}

fn signed_for_width(value: u64, width: u32) -> String {
    if width == 32 { (value as u32 as i32).to_string() } else { (value as i64).to_string() }
}

/// `VFPExpandImm` for an 8-bit floating-point immediate, printed with eight decimals like LLVM.
fn fp_immediate(imm8: u64) -> String {
    let sign = if imm8 & 0x80 != 0 { -1.0 } else { 1.0 };
    let exponent = ((imm8 >> 4) & 0x7) as i32;
    let exponent = if exponent & 0x4 != 0 { exponent - 7 } else { exponent + 1 };
    let fraction = 1.0 + (imm8 & 0xf) as f64 / 16.0;
    format!("{:.8}", sign * fraction * 2f64.powi(exponent))
}

/// SVE predicate constraint patterns; unnamed values print as immediates.
fn sve_pattern(operand: &Operand, value: u64) -> Value {
    let name = match value {
        0..=13 => operand.choices.get(value as usize).map(|choice| choice.to_ascii_lowercase()),
        29 => Some("mul4".to_owned()),
        30 => Some("mul3".to_owned()),
        31 => return Value::Default("all".to_owned()),
        _ => None,
    };
    Value::Text(name.unwrap_or_else(|| format!("#{value}")))
}

/// SVE immediates encoded with the element size, such as shift amounts in `tszh:tszl:imm3`.
fn sve_constant(context: &Context, operand: &Operand, value: u64, width: u32) -> Value {
    let fields = context.field_names(operand);
    if fields == ["imm13"] {
        let Some(element) = sve_logical_element(value) else { return Value::Invalid };
        let (n, immr, imms) = (value >> 12, (value >> 6) & 0x3f, value & 0x3f);
        return match decode_bit_masks(n, imms, immr, true, element as u32) {
            Some(mask) => Value::Text(format!("{mask:#x}")),
            None => Value::Invalid,
        };
    }
    if fields == ["imm8"] && matches!(context.mnemonic(), "FDUP" | "FMOV") {
        return Value::Text(fp_immediate(value));
    }
    if fields.first().is_some_and(|f| f.starts_with("tsz")) && fields.last() == Some(&"imm3") {
        let tsize_width = width - 3;
        let tsize = value >> 3;
        if tsize == 0 {
            return Value::Invalid;
        }
        let _ = tsize_width;
        let element = 8u64 << (63 - tsize.leading_zeros());
        let mnemonic = context.mnemonic();
        let left = mnemonic.starts_with("LSL") || mnemonic.contains("SHL") || mnemonic.starts_with("SLI");
        return Value::Text(if left { value - element } else { 2 * element - value }.to_string());
    }
    if let Some(text) = ranked_choice(context, operand) {
        return Value::Text(text);
    }
    if right_shift(context.mnemonic()) && fields.last().is_some_and(|field| field.starts_with("imm")) {
        // Narrowing right shifts by an amount up to the element size, encoded as size - amount.
        return Value::Text(((1u64 << width) - value).to_string());
    }
    Value::Text(value.to_string())
}

/// SVE `#<imm>{, LSL #8}` immediates, which LLVM prints with the shift folded into the value.
fn sve_shifted_immediate(context: &Context, imm8: u64) -> Value {
    let shifted = context.field("sh") == Some(1);
    if shifted && imm8 == 0 {
        return Value::Text("0".to_owned());
    }
    let element_bits = 8u32 << context.field("size").unwrap_or(0);
    let signed = matches!(context.mnemonic(), "DUP" | "CPY" | "MOV");
    let shift = if shifted { 8 } else { 0 };
    let text = if signed {
        let value = sign_extend(imm8, 8) << shift;
        sign_extend(value as u64, element_bits).to_string()
    } else {
        let mask = if element_bits >= 64 { u64::MAX } else { (1u64 << element_bits) - 1 };
        ((imm8 << shift) & mask).to_string()
    };
    Value::Text(text)
}

/// Bytes per element of an SVE prefetch (PRFB, PRFH, PRFW, PRFD).
fn prefetch_element(mnemonic: &str) -> u64 {
    match mnemonic {
        "PRFH" => 2,
        "PRFW" => 4,
        "PRFD" => 8,
        _ => 1,
    }
}

/// SVE prefetch operations: values 6, 7, 14 and 15 are unnamed.
fn sve_prefetch(operand: &Operand, value: u64) -> Value {
    let index = match value {
        0..=5 => Some(value),
        8..=13 => Some(value - 2),
        _ => None,
    };
    match index.and_then(|index| operand.choices.get(index as usize)) {
        Some(name) => Value::Text(name.to_ascii_lowercase()),
        None => Value::Text(format!("#{value}")),
    }
}

/// How many vectors an SVE structure or multi-vector load or store transfers.
fn sve_register_count(context: &Context) -> i64 {
    for (name, count) in [("<Zt4>", 4), ("<Zt3>", 3), ("<Zt2>", 2)] {
        if context.has_operand(name) {
            return count;
        }
    }
    let mnemonic = context.mnemonic();
    let digit = mnemonic.trim_start_matches(|c: char| !c.is_ascii_digit()).chars().next();
    match digit.and_then(|d| d.to_digit(10)) {
        Some(count @ 2..=4) if mnemonic.starts_with("LD") || mnemonic.starts_with("ST") => count as i64,
        _ => 1,
    }
}

/// SVE narrowing operations encode the wide source element size; the destination has half-width elements.
fn narrowing(mnemonic: &str) -> bool {
    mnemonic.ends_with("NB") || mnemonic.ends_with("NT") || mnemonic.ends_with('N')
}

/// RPRFM's operation: option<2>:option<0>:S:Rt<2:0>.
fn range_prefetch_operation(context: &Context) -> u64 {
    let option = context.field("option").unwrap_or(0);
    let s = context.field("S").unwrap_or(0);
    let rt = context.field("Rt").unwrap_or(0);
    (((option >> 2) & 1) << 5) | ((option & 1) << 4) | (s << 3) | (rt & 7)
}

/// The immediate of MSR (immediate): the CRm bits the PSTATE field leaves free (all four for DAIFSet and
/// DAIFClr, one bit for most others).
fn pstate_immediate(context: &Context) -> u64 {
    let (op1, crm, op2) =
        (context.field("op1").unwrap_or(0), context.field("CRm").unwrap_or(0), context.field("op2").unwrap_or(0));
    let lookup = |crm: u64| {
        let key = ((op1 << 7) | (crm << 3) | op2) as u16;
        spec::PSTATE_FIELDS.binary_search_by_key(&key, |&(k, _)| k).ok().map(|index| spec::PSTATE_FIELDS[index].1)
    };
    let name = lookup(crm);
    let shared = (0..16).filter(|&other| lookup(other) == name).count() as u64;
    crm & (shared.next_power_of_two() - 1)
}

/// Memory tagging loads, stores and address arithmetic, whose offsets are in 16-byte granules.
fn memory_tagging(context: &Context) -> bool {
    let name = context.encoding_name();
    name.contains("ldsttags") || name.contains("immtags") || name.starts_with("STGP")
}

/// `<Tb>` and `<Ta>` that share `<T>`'s fields and have as many spellings correspond to it one to one: the
/// specification lists the pairs in the same order (SVE widening, narrowing and multi-vector forms).
fn parallel_choice(context: &Context, operand: &Operand, name: &str) -> Option<Value> {
    if !matches!(name, "Tb" | "Ta") || !is_literal(operand.choices) {
        return None;
    }
    let primary = context.decoded.syntax.operands.iter().find(|other| other.name == "<T>")?;
    if primary.fields != operand.fields || primary.choices.len() != operand.choices.len() {
        return None;
    }
    let Value::Text(text) = arrangement(context, primary, "T")? else { return Some(Value::Invalid) };
    let index = primary.choices.iter().position(|choice| choice.eq_ignore_ascii_case(&text))?;
    Some(Value::Text(operand.choices[index].to_ascii_lowercase()))
}

/// Whether another operand indexes elements with bits above `tsz` (DUP, DUPQ and PSEL by index).
fn indexed_by_tsz(context: &Context, operand: &Operand) -> bool {
    context.decoded.syntax.operands.iter().any(|other| {
        matches!(other.name, "<imm>" | "<index>")
            && other.fields.len() > operand.fields.len()
            && operand.fields.iter().all(|field| other.fields.contains(field))
    })
}

/// The element size in bits of an SVE logical immediate `N:immr:imms`, or `None` when reserved.
fn sve_logical_element(imm13: u64) -> Option<u64> {
    let combined = ((imm13 >> 12) << 6) | (!imm13 & 0x3f);
    let length = 63u32.checked_sub(combined.leading_zeros())?;
    (length >= 3).then(|| 1u64 << length)
}

/// FP8 by-element forms, whose index takes the top bit of Rm.
fn fp8_by_element(context: &Context) -> bool {
    context.decoded.syntax.operands.iter().any(|operand| {
        operand.name == "<index>"
            && operand.fields.iter().any(|&i| context.decoded.encoding.fields[i as usize].name == "Rm")
    })
}
