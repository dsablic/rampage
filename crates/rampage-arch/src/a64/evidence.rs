use super::Decoded;
use crate::mrs::{self, Operand};
use crate::{MemoryOperand, OperandEvidence, OperandKind};

pub(super) fn operands(decoded: &Decoded) -> Option<Vec<OperandEvidence>> {
    let name = decoded.encoding.name;
    if name.ends_with("_ldst_pos") || name.ends_with("_ldst_unscaled") {
        return memory_operands(decoded);
    }
    let arithmetic = name.ends_with("_addsub_imm");
    let logical = name.ends_with("_log_imm");
    let wide_move = name.ends_with("_movewide")
        && (name.starts_with("MOVZ_") || name.starts_with("MOVN_"))
        && mrs::mnemonic(decoded.syntax) == "MOV";
    if !arithmetic && !logical && !wide_move {
        return None;
    }
    let width = if decoded.field("sf")? == 1 { 64 } else { 32 };
    let immediate = if arithmetic {
        decoded.field("imm12")? << (decoded.field("sh")? * 12)
    } else if logical {
        super::logical_immediate(decoded.word, width as u8)?
    } else {
        let value = decoded.field("imm16")? << (decoded.field("hw")? * 16);
        if name.starts_with("MOVN_") { !value } else { value }
    };
    let mut evidence = Vec::new();
    for operand in decoded.syntax.operands {
        // Optional shift modifiers are omitted at zero by the native renderer. A nonzero modifier
        // keeps its explicit position, but is not itself an enum/offset selector.
        if operand.name == "<shift>" && arithmetic {
            if decoded.field("sh")? != 0 {
                evidence.push(OperandEvidence::unsupported(evidence.len() as u8));
            }
            continue;
        }
        let index = evidence.len() as u8;
        if let Some(width) = register_width(operand) {
            evidence.push(register(index, width));
        } else if operand.name == "<imm>" {
            let mut operand = OperandEvidence::immediate(index, immediate, width);
            if arithmetic && name.starts_with("ADD_") && width == 64 {
                operand.memory = Some(MemoryOperand {
                    base: Some(base_name(decoded.field("Rn")?)),
                    index: None,
                    displacement: i64::try_from(immediate).ok()?,
                    scale: 1,
                    access_size: None,
                    relative: false,
                });
            }
            evidence.push(operand);
        } else {
            // No evidence for syntax forms whose explicit positions have not been established.
            return None;
        }
    }
    Some(evidence)
}

fn memory_operands(decoded: &Decoded) -> Option<Vec<OperandEvidence>> {
    if decoded.field("VR")? != 0 {
        return None;
    }
    if !matches!(
        mrs::mnemonic(decoded.syntax),
        "LDR"
            | "LDRB"
            | "LDRH"
            | "LDRSB"
            | "LDRSH"
            | "LDRSW"
            | "STR"
            | "STRB"
            | "STRH"
            | "LDUR"
            | "LDURB"
            | "LDURH"
            | "LDURSB"
            | "LDURSH"
            | "LDURSW"
            | "STUR"
            | "STURB"
            | "STURH"
    ) {
        return None;
    }
    // These bounded native syntax families have Rt followed by one bracketed base-plus-offset
    // operand. The Rn and displacement placeholders belong to that same explicit operand.
    let [target, base, offset] = decoded.syntax.operands else { return None };
    let width = register_width(target)?;
    if base.name != "<Xn|SP>" || !matches!(offset.name, "<pimm>" | "<simm>") {
        return None;
    }
    let access_size = 1u16 << decoded.field("size")?;
    let displacement = if decoded.encoding.name.ends_with("_ldst_pos") {
        i64::try_from(decoded.field("imm12")?.checked_mul(u64::from(access_size))?).ok()?
    } else {
        mrs::sign_extend(decoded.field("imm9")?, 9)
    };
    let memory = OperandEvidence {
        index: 1,
        kind: OperandKind::Memory,
        immediate: None,
        signed_value: None,
        width_bits: Some(access_size * 8),
        memory: Some(MemoryOperand {
            base: Some(base_name(decoded.field("Rn")?)),
            index: None,
            displacement,
            scale: 1,
            access_size: Some(access_size),
            relative: false,
        }),
    };
    Some(vec![register(0, width), memory])
}

fn register_width(operand: &Operand) -> Option<u16> {
    if operand.fields.len() != 1 {
        return None;
    }
    match operand.name.as_bytes().get(1) {
        Some(b'W') => Some(32),
        Some(b'X') => Some(64),
        _ => None,
    }
}

fn register(index: u8, width: u16) -> OperandEvidence {
    OperandEvidence {
        index,
        kind: OperandKind::Register,
        immediate: None,
        signed_value: None,
        width_bits: Some(width),
        memory: None,
    }
}

fn base_name(number: u64) -> String {
    if number == 31 { "sp".to_owned() } else { format!("x{number}") }
}
