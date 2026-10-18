//! Bounded, pure text assembly; this module never executes or installs the resulting bytes.
//!
//! V1 accepts one instruction per nonempty line, case-insensitive mnemonics/registers, comma-separated
//! operands, and decimal or `0x` integer literals (A64 immediates may have `#`). There are no labels,
//! comments, expressions, memory operands, prefixes, directives, macros, or symbol resolution.
//! x86/x64: NOP, RET, MOV reg/reg or reg/imm, CMP reg/reg or reg/imm, JMP/CALL/Jcc absolute numeric
//! targets. Registers are 16/32/64-bit GPRs (64-bit and r8-r15 require x64). Branches always use rel32.
//! A64: NOP, RET [Xn], B/BL/B.cond numeric targets, MOV same-width registers (not SP), MOV/MOVZ
//! unsigned 16-bit immediate [LSL #0/16/32/48], CMP reg/SP, unsigned 12-bit immediate [LSL #0/12].
//! MOV immediate is exactly one MOVZ, never a synthesized sequence. A64 is little-endian only.

use crate::{Arch, Target, a64};
use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Formatter, Instruction, IntelFormatter, OpKind, Register};
use serde::Serialize;

pub const MAX_SOURCE_BYTES: usize = 16 * 1024;
pub const MAX_INSTRUCTIONS: usize = 64;
pub const MAX_OUTPUT_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assembly {
    pub bytes: Vec<u8>,
    pub canonical_disassembly: Vec<String>,
    pub instruction_count: usize,
    pub evidence_profile: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize)]
#[error("assembly line {line}: {message}")]
pub struct AsmError {
    /// One-based source line; zero denotes a batch/target error.
    pub line: usize,
    pub message: String,
}

fn error(message: impl Into<String>) -> AsmError {
    AsmError { line: 0, message: message.into() }
}

/// Assemble a complete bounded batch, returning no partial result on failure.
pub fn assemble(target: &Target, address: u64, text: &str) -> Result<Assembly, AsmError> {
    if !matches!(target.arch, Arch::X86 | Arch::X86_64 | Arch::Aarch64) {
        return Err(error(format!("unsupported assembly architecture {}", target.arch)));
    }
    if target.big_endian {
        return Err(error("big-endian instruction assembly is unsupported"));
    }
    if text.len() > MAX_SOURCE_BYTES {
        return Err(error("source exceeds 16 KiB"));
    }
    if !text.is_ascii() {
        return Err(error("assembly source must be ASCII"));
    }
    if target.arch == Arch::Aarch64 && address & 3 != 0 {
        return Err(error("A64 instruction address must be four-byte aligned"));
    }
    let mut result = Assembly {
        bytes: Vec::new(),
        canonical_disassembly: Vec::new(),
        instruction_count: 0,
        evidence_profile: if target.arch == Arch::Aarch64 {
            "a64-generated-fields-decoder-checked-v1"
        } else {
            "iced-encoder-semantic-decoder-checked-v1"
        },
    };
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let encoded = (|| {
            if result.instruction_count >= MAX_INSTRUCTIONS {
                return Err(error("source exceeds 64 instructions"));
            }
            let at = address.checked_add(result.bytes.len() as u64).ok_or_else(|| error("address overflow"))?;
            let source = line.to_ascii_lowercase();
            let (mnemonic, operands) = parse_line(&source)?;
            let (bytes, canonical) = if target.arch == Arch::Aarch64 {
                encode_a64(at, mnemonic, &operands)?
            } else {
                encode_x86(target.arch, at, mnemonic, &operands)?
            };
            let end = at.checked_add(bytes.len() as u64).ok_or_else(|| error("next instruction address overflow"))?;
            if target.arch == Arch::X86 && (at > u64::from(u32::MAX) || end > u64::from(u32::MAX)) {
                return Err(error("x86 address/next IP exceeds 32 bits"));
            }
            if result.bytes.len() + bytes.len() > MAX_OUTPUT_BYTES {
                return Err(error("output exceeds 4096 bytes"));
            }
            Ok((bytes, canonical))
        })();
        let (bytes, canonical) = encoded.map_err(|mut err: AsmError| {
            err.line = index + 1;
            err
        })?;
        result.bytes.extend(bytes);
        result.canonical_disassembly.push(canonical);
        result.instruction_count += 1;
    }
    if result.instruction_count == 0 {
        return Err(error("source must contain at least one instruction"));
    }
    Ok(result)
}

fn parse_line(source: &str) -> Result<(&str, Vec<&str>), AsmError> {
    let split = source.find(char::is_whitespace).unwrap_or(source.len());
    let mnemonic = &source[..split];
    if !mnemonic.bytes().all(|byte| byte.is_ascii_alphabetic() || byte == b'.') {
        return Err(error("invalid mnemonic; labels and directives are unsupported"));
    }
    let tail = source[split..].trim();
    let operands: Vec<_> = if tail.is_empty() { Vec::new() } else { tail.split(',').map(str::trim).collect() };
    if operands.iter().any(|operand| operand.is_empty()) || operands.len() > 3 {
        return Err(error("invalid operand list"));
    }
    Ok((mnemonic, operands))
}

fn integer(source: &str) -> Result<i128, AsmError> {
    let source = source.strip_prefix('#').unwrap_or(source);
    let (negative, magnitude) = match source.strip_prefix('-') {
        Some(magnitude) => (true, magnitude),
        None => (false, source),
    };
    let (radix, digits) = magnitude.strip_prefix("0x").map_or((10, magnitude), |digits| (16, digits));
    if digits.is_empty() || !digits.bytes().all(|byte| (byte as char).is_digit(radix)) {
        return Err(error("expected a decimal or 0x integer literal; symbols/expressions are unsupported"));
    }
    let magnitude = i128::from_str_radix(digits, radix).map_err(|_| error("integer literal overflow"))?;
    Ok(if negative { -magnitude } else { magnitude })
}

fn unsigned(source: &str, bits: u32) -> Result<u64, AsmError> {
    let value = integer(source)?;
    if value < 0 || value >= 1i128 << bits {
        return Err(error(format!("operand must fit an unsigned {bits}-bit value")));
    }
    Ok(value as u64)
}

fn immediate(source: &str, bits: u32) -> Result<u64, AsmError> {
    let value = integer(source)?;
    if value < -(1i128 << (bits - 1)) || value >= 1i128 << bits {
        return Err(error(format!("immediate does not fit {bits} bits")));
    }
    Ok((value & ((1i128 << bits) - 1)) as u64)
}

fn x86_register(source: &str, arch: Arch) -> Option<(Register, u32)> {
    use Register::*;
    const REGS: [[Register; 16]; 3] = [
        [AX, CX, DX, BX, SP, BP, SI, DI, R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W],
        [EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D],
        [RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15],
    ];
    const NAMES: [[&str; 16]; 3] = [
        ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"],
        [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d",
            "r14d", "r15d",
        ],
        ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"],
    ];
    for (width_index, names) in NAMES.iter().enumerate() {
        if let Some(index) = names.iter().position(|name| *name == source) {
            if arch == Arch::X86 && (width_index == 2 || index >= 8) {
                return Option::None;
            }
            return Some((REGS[width_index][index], [16, 32, 64][width_index]));
        }
    }
    Option::None
}

fn x86_branch(mnemonic: &str, arch: Arch) -> Option<Code> {
    use Code::*;
    let index = match mnemonic {
        "jo" => 0,
        "jno" => 1,
        "jb" | "jc" | "jnae" => 2,
        "jae" | "jnb" | "jnc" => 3,
        "je" | "jz" => 4,
        "jne" | "jnz" => 5,
        "jbe" | "jna" => 6,
        "ja" | "jnbe" => 7,
        "js" => 8,
        "jns" => 9,
        "jp" | "jpe" => 10,
        "jnp" | "jpo" => 11,
        "jl" | "jnge" => 12,
        "jge" | "jnl" => 13,
        "jle" | "jng" => 14,
        "jg" | "jnle" => 15,
        "jmp" => 16,
        "call" => 17,
        _ => return None,
    };
    let codes = if arch == Arch::X86_64 {
        [
            Jo_rel32_64,
            Jno_rel32_64,
            Jb_rel32_64,
            Jae_rel32_64,
            Je_rel32_64,
            Jne_rel32_64,
            Jbe_rel32_64,
            Ja_rel32_64,
            Js_rel32_64,
            Jns_rel32_64,
            Jp_rel32_64,
            Jnp_rel32_64,
            Jl_rel32_64,
            Jge_rel32_64,
            Jle_rel32_64,
            Jg_rel32_64,
            Jmp_rel32_64,
            Call_rel32_64,
        ]
    } else {
        [
            Jo_rel32_32,
            Jno_rel32_32,
            Jb_rel32_32,
            Jae_rel32_32,
            Je_rel32_32,
            Jne_rel32_32,
            Jbe_rel32_32,
            Ja_rel32_32,
            Js_rel32_32,
            Jns_rel32_32,
            Jp_rel32_32,
            Jnp_rel32_32,
            Jl_rel32_32,
            Jge_rel32_32,
            Jle_rel32_32,
            Jg_rel32_32,
            Jmp_rel32_32,
            Call_rel32_32,
        ]
    };
    Some(codes[index])
}

fn encode_x86(arch: Arch, at: u64, mnemonic: &str, operands: &[&str]) -> Result<(Vec<u8>, String), AsmError> {
    use Code::*;
    let bitness = if arch == Arch::X86_64 { 64 } else { 32 };
    let iced_error = |err: iced_x86::IcedError| error(err.to_string());
    let instruction = match (mnemonic, operands) {
        ("nop", []) => Instruction::with(Nopd),
        ("ret", []) => Instruction::with(if bitness == 64 { Retnq } else { Retnd }),
        ("mov" | "cmp", [left, right]) => {
            let (destination, width) =
                x86_register(left, arch).ok_or_else(|| error("unsupported destination register"))?;
            let mov = mnemonic == "mov";
            if let Some((source, source_width)) = x86_register(right, arch) {
                if width != source_width {
                    return Err(error("register operand widths must match"));
                }
                let code = match (mov, width) {
                    (true, 16) => Mov_r16_rm16,
                    (true, 32) => Mov_r32_rm32,
                    (true, _) => Mov_r64_rm64,
                    (false, 16) => Cmp_r16_rm16,
                    (false, 32) => Cmp_r32_rm32,
                    (false, _) => Cmp_r64_rm64,
                };
                Instruction::with2(code, destination, source).map_err(iced_error)?
            } else if mov {
                let value = immediate(right, width)?;
                match width {
                    16 => Instruction::with2(Mov_r16_imm16, destination, value as u32),
                    32 => Instruction::with2(Mov_r32_imm32, destination, value as u32),
                    _ => Instruction::with2(Mov_r64_imm64, destination, value),
                }
                .map_err(iced_error)?
            } else {
                let value = if width == 64 {
                    let value = integer(right)?;
                    if value < i128::from(i32::MIN) || value > i128::from(i32::MAX) {
                        return Err(error("64-bit CMP immediate must fit signed 32 bits"));
                    }
                    value as i32 as u32
                } else {
                    immediate(right, width)? as u32
                };
                let code = match width {
                    16 => Cmp_rm16_imm16,
                    32 => Cmp_rm32_imm32,
                    _ => Cmp_rm64_imm32,
                };
                if width == 64 {
                    Instruction::with2(code, destination, value as i32).map_err(iced_error)?
                } else {
                    Instruction::with2(code, destination, value).map_err(iced_error)?
                }
            }
        }
        (_, [target]) if x86_branch(mnemonic, arch).is_some() => {
            let target = unsigned(target, bitness)?;
            let length = if matches!(mnemonic, "jmp" | "call") { 5 } else { 6 };
            let next = at.checked_add(length).ok_or_else(|| error("branch next IP overflow"))?;
            let displacement = i128::from(target) - i128::from(next);
            if displacement < i128::from(i32::MIN) || displacement > i128::from(i32::MAX) {
                return Err(error("relative branch target exceeds signed rel32 range"));
            }
            Instruction::with_branch(x86_branch(mnemonic, arch).unwrap(), target).map_err(iced_error)?
        }
        _ => return Err(error("unsupported x86 mnemonic or operand form")),
    };
    let mut encoder = Encoder::new(bitness);
    encoder.encode(&instruction, at).map_err(iced_error)?;
    let bytes = encoder.take_buffer();
    let decoded = Decoder::with_ip(bitness, &bytes, at, DecoderOptions::NONE).decode();
    if decoded.is_invalid() || decoded.len() != bytes.len() || !same_x86_operands(&instruction, &decoded) {
        return Err(error("encoder/decoder semantic verification failed"));
    }
    let mut canonical = String::new();
    IntelFormatter::new().format(&decoded, &mut canonical);
    Ok((bytes, canonical))
}

fn same_x86_operands(expected: &Instruction, actual: &Instruction) -> bool {
    if expected.code() != actual.code() || expected.op_count() != actual.op_count() {
        return false;
    }
    (0..expected.op_count()).all(|index| {
        let kind = expected.op_kind(index);
        kind == actual.op_kind(index)
            && match kind {
                OpKind::Register => expected.op_register(index) == actual.op_register(index),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    expected.near_branch_target() == actual.near_branch_target()
                }
                OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64 => expected.immediate(index) == actual.immediate(index),
                _ => false,
            }
    })
}

#[derive(Clone, Copy)]
struct A64Field {
    name: &'static str,
    start: u8,
    width: u8,
    value: u64,
}

fn field(name: &'static str, start: u8, width: u8, value: u64) -> A64Field {
    A64Field { name, start, width, value }
}

fn a64_register(source: &str, allow_sp: bool, allow_zero: bool) -> Result<(u64, u32), AsmError> {
    match source {
        "sp" if allow_sp => return Ok((31, 64)),
        "wsp" if allow_sp => return Ok((31, 32)),
        "xzr" if allow_zero => return Ok((31, 64)),
        "wzr" if allow_zero => return Ok((31, 32)),
        _ => {}
    }
    let (prefix, digits) = source.split_at(source.len().min(1));
    if !matches!(prefix, "w" | "x") || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(error("unsupported A64 register"));
    }
    let number = digits.parse::<u64>().map_err(|_| error("register number overflow"))?;
    if number > 30 || digits != number.to_string() {
        return Err(error("A64 numbered registers must be 0..30; use SP/ZR only where allowed"));
    }
    Ok((number, if prefix == "x" { 64 } else { 32 }))
}

fn shift(operand: Option<&&str>) -> Result<u64, AsmError> {
    let Some(operand) = operand else { return Ok(0) };
    let value = operand.strip_prefix("lsl").ok_or_else(|| error("only LSL immediate shift is supported"))?;
    if !value.starts_with(char::is_whitespace) {
        return Err(error("expected LSL followed by an immediate"));
    }
    unsigned(value.trim(), 8)
}

fn condition(source: &str) -> Option<u64> {
    Some(match source {
        "eq" => 0,
        "ne" => 1,
        "cs" | "hs" => 2,
        "cc" | "lo" => 3,
        "mi" => 4,
        "pl" => 5,
        "vs" => 6,
        "vc" => 7,
        "hi" => 8,
        "ls" => 9,
        "ge" => 10,
        "lt" => 11,
        "gt" => 12,
        "le" => 13,
        "al" => 14,
        "nv" => 15,
        _ => return None,
    })
}

fn a64_displacement(target: &str, at: u64, bits: u32) -> Result<u64, AsmError> {
    let target = unsigned(target, 64)?;
    if target & 3 != 0 {
        return Err(error("A64 branch target must be four-byte aligned"));
    }
    let offset = (i128::from(target) - i128::from(at)) / 4;
    if offset < -(1i128 << (bits - 1)) || offset >= 1i128 << (bits - 1) {
        return Err(error(format!("A64 branch target exceeds signed imm{bits} range")));
    }
    Ok((offset & ((1i128 << bits) - 1)) as u64)
}

fn encode_a64(at: u64, mnemonic: &str, operands: &[&str]) -> Result<(Vec<u8>, String), AsmError> {
    let (name, base, fields) = match (mnemonic, operands) {
        ("nop", []) => ("NOP_HI_hints", 0xd503201f, vec![]),
        ("ret", [] | [_]) => {
            let (register, width) = a64_register(operands.first().copied().unwrap_or("x30"), false, false)?;
            if width != 64 {
                return Err(error("RET requires an X register"));
            }
            ("RET_64R_branch_reg", 0xd65f0000, vec![field("Rn", 5, 5, register)])
        }
        ("b" | "bl", [target]) => {
            let link = mnemonic == "bl";
            (
                if link { "BL_only_branch_imm" } else { "B_only_branch_imm" },
                if link { 0x94000000 } else { 0x14000000 },
                vec![field("imm26", 0, 26, a64_displacement(target, at, 26)?)],
            )
        }
        (_, [target]) if mnemonic.starts_with("b.") => {
            let condition = condition(&mnemonic[2..]).ok_or_else(|| error("unknown A64 condition"))?;
            (
                "B_only_condbranch",
                0x54000000,
                vec![field("imm19", 5, 19, a64_displacement(target, at, 19)?), field("cond", 0, 4, condition)],
            )
        }
        ("mov", [destination, source]) if source.starts_with(['x', 'w']) => {
            let (rd, width) = a64_register(destination, false, true)?;
            let (rm, source_width) = a64_register(source, false, true)?;
            if width != source_width {
                return Err(error("register operand widths must match"));
            }
            (
                if width == 64 { "ORR_64_log_shift" } else { "ORR_32_log_shift" },
                if width == 64 { 0xaa000000 } else { 0x2a000000 },
                vec![
                    field("Rd", 0, 5, rd),
                    field("Rn", 5, 5, 31),
                    field("Rm", 16, 5, rm),
                    field("shift", 22, 2, 0),
                    field("imm6", 10, 6, 0),
                ],
            )
        }
        ("mov" | "movz", [destination, value] | [destination, value, _]) => {
            let (rd, width) = a64_register(destination, false, true)?;
            let shift = shift(operands.get(2))?;
            if shift % 16 != 0 || shift >= u64::from(width) {
                return Err(error("MOVZ shift must be 0/16 for W or 0/16/32/48 for X"));
            }
            (
                if width == 64 { "MOVZ_64_movewide" } else { "MOVZ_32_movewide" },
                if width == 64 { 0xd2800000 } else { 0x52800000 },
                vec![
                    field("Rd", 0, 5, rd),
                    field("imm16", 5, 16, unsigned(value, 16)?),
                    field("hw", 21, 2, shift / 16),
                ],
            )
        }
        ("cmp", [register, value] | [register, value, _]) => {
            let (rn, width) = a64_register(register, true, false)?;
            let shift = shift(operands.get(2))?;
            if !matches!(shift, 0 | 12) {
                return Err(error("CMP immediate shift must be 0 or 12"));
            }
            (
                if width == 64 { "SUBS_64S_addsub_imm" } else { "SUBS_32S_addsub_imm" },
                if width == 64 { 0xf1000000 } else { 0x71000000 },
                vec![
                    field("Rd", 0, 5, 31),
                    field("Rn", 5, 5, rn),
                    field("imm12", 10, 12, unsigned(value, 12)?),
                    field("sh", 22, 1, shift / 12),
                ],
            )
        }
        _ => return Err(error("unsupported A64 mnemonic or operand form")),
    };
    let word = encode_a64_fields(name, base, &fields)?;
    let canonical = a64::format_word(word, at, a64::LabelStyle::Absolute)
        .ok_or_else(|| error("A64 generated decoder could not format instruction"))?;
    Ok((word.to_le_bytes().to_vec(), canonical))
}

fn encode_a64_fields(name: &str, base: u32, fields: &[A64Field]) -> Result<u32, AsmError> {
    let encoding = a64::lookup(base)
        .filter(|encoding| encoding.name == name)
        .ok_or_else(|| error("A64 encoding binding does not match generated table"))?;
    if base & encoding.mask != encoding.value {
        return Err(error("A64 base violates required fixed bits"));
    }
    let mut word = base;
    let mut written = 0u32;
    for value in fields {
        let metadata = encoding
            .fields
            .iter()
            .find(|field| field.name == value.name)
            .filter(|field| field.start == value.start && field.width == value.width)
            .ok_or_else(|| error(format!("A64 field metadata mismatch for {}", value.name)))?;
        if value.value >= 1u64 << metadata.width {
            return Err(error("A64 field value overflow"));
        }
        let mask = ((1u32 << metadata.width) - 1) << metadata.start;
        let bits = (value.value as u32) << metadata.start;
        if written & mask != 0 || (bits ^ encoding.value) & mask & encoding.mask != 0 {
            return Err(error("A64 field overlaps another field or required fixed bits"));
        }
        written |= mask;
        word = (word & !mask) | bits;
    }
    let decoded = a64::decode_word(word)
        .filter(|decoded| decoded.encoding.name == name)
        .ok_or_else(|| error("A64 encoded word failed generated decoder verification"))?;
    if word & encoding.mask != encoding.value
        || fields.iter().any(|value| decoded.field(value.name) != Some(value.value))
    {
        return Err(error("A64 decoded operands differ from requested fields"));
    }
    Ok(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x64_independent_known_vectors_and_operand_semantics() {
        let cases: &[(&str, &[u8])] = &[
            ("nop", &[0x90]),
            ("ret", &[0xc3]),
            ("mov rax, 0x1122334455667788", &[0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]),
            ("mov r9, r10", &[0x4d, 0x8b, 0xca]),
            ("cmp rbx, -1", &[0x48, 0x81, 0xfb, 0xff, 0xff, 0xff, 0xff]),
            ("jmp 0x1010", &[0xe9, 0x0b, 0, 0, 0]),
            ("call 0xff0", &[0xe8, 0xeb, 0xff, 0xff, 0xff]),
            ("je 0x1010", &[0x0f, 0x84, 0x0a, 0, 0, 0]),
        ];
        for (source, bytes) in cases {
            let output = assemble(&Target::new(Arch::X86_64), 0x1000, source).unwrap();
            assert_eq!(&output.bytes, bytes, "{source}");
            assert_eq!(output.instruction_count, 1);
        }
        let output = assemble(&Target::new(Arch::X86_64), 0x1000, "cmp rbx, -1").unwrap();
        let decoded = Decoder::with_ip(64, &output.bytes, 0x1000, DecoderOptions::NONE).decode();
        assert_eq!(decoded.op0_register(), Register::RBX);
        assert_eq!(decoded.immediate32to64(), -1);
    }

    #[test]
    fn x86_modes_widths_and_sequence_addresses() {
        let target = Target::new(Arch::X86);
        assert_eq!(assemble(&target, 0, "mov ax, 0x1234").unwrap().bytes, [0x66, 0xb8, 0x34, 0x12]);
        assert_eq!(assemble(&target, 0, "mov eax, 1").unwrap().bytes, [0xb8, 1, 0, 0, 0]);
        let result = assemble(&target, 0x1000, "mov eax, 1\nmov eax, 2\njmp 0x1000").unwrap();
        assert_eq!(&result.bytes[10..], [0xe9, 0xf1, 0xff, 0xff, 0xff]);
        assert_eq!(result.instruction_count, 3);
        for source in ["mov rax, 1", "mov r8d, 1", "mov eax, ax", "mov al, 1", "mov eax, 0x100000000"] {
            assert!(assemble(&target, 0, source).is_err(), "{source}");
        }
    }

    #[test]
    fn a64_independent_words_and_alias_semantics() {
        let cases = [
            ("nop", 0xd503201fu32),
            ("ret", 0xd65f03c0),
            ("ret x1", 0xd65f0020),
            ("b 0x1010", 0x14000004),
            ("bl 0xff0", 0x97fffffc),
            ("b.eq 0x1010", 0x54000080),
            ("mov x0, x1", 0xaa0103e0),
            ("mov w2, w3", 0x2a0303e2),
            ("mov x0, #0x1234", 0xd2824680),
            ("movz w1, #1, lsl #16", 0x52a00021),
            ("movz x2, #0xabcd, lsl #48", 0xd2f579a2),
            ("cmp x0, #1", 0xf100041f),
            ("cmp wsp, #4095, lsl #12", 0x717fffff),
        ];
        for (source, word) in cases {
            let result = assemble(&Target::new(Arch::Aarch64), 0x1000, source).unwrap();
            assert_eq!(result.bytes, word.to_le_bytes(), "{source}");
            assert_eq!(result.instruction_count, 1);
        }
        let decoded = a64::decode_word(0xaa0103e0).unwrap();
        assert_eq!(decoded.field("Rn"), Some(31));
        assert_eq!(decoded.field("Rm"), Some(1));
        assert_eq!(decoded.field("Rd"), Some(0));
        let decoded = a64::decode_word(0xf100041f).unwrap();
        assert_eq!(decoded.field("Rd"), Some(31));
        assert_eq!(decoded.field("imm12"), Some(1));
    }

    #[test]
    fn a64_rejects_unrepresentable_or_ambiguous_forms() {
        let target = Target::new(Arch::Aarch64);
        for source in [
            "mov x0, 0x10000",
            "mov x0, -1",
            "mov sp, x0",
            "mov x0, sp",
            "mov x0, w1",
            "movz w0, 1, lsl #32",
            "movz x0, 1, lsl #8",
            "mov x31, 1",
            "mov x01, 1",
            "cmp xzr, 1",
            "cmp x0, 4096",
            "cmp x0, -1",
            "ret w0",
            "b 0x1001",
            "b 0x8001000",
            "b.eq 0x101000",
            "b.unknown 0",
            "add x0, x1, x2",
        ] {
            assert!(assemble(&target, 0x1000, source).is_err(), "{source}");
        }
        assert!(assemble(&target, 1, "nop").is_err());
        let mut big = target.clone();
        big.big_endian = true;
        assert!(assemble(&big, 0, "nop").is_err());
    }

    #[test]
    fn a64_bindings_reject_metadata_drift_and_fixed_bit_changes() {
        assert!(encode_a64_fields("BL_only_branch_imm", 0x14000000, &[]).is_err());
        assert!(encode_a64_fields("B_only_branch_imm", 0x14000000, &[field("imm26", 1, 25, 0)]).is_err());
        assert!(encode_a64_fields("B_only_branch_imm", 0x14000000, &[field("imm26", 0, 26, 1 << 26)]).is_err());
        assert!(encode_a64_fields("MOVZ_32_movewide", 0x52800000, &[field("hw", 21, 2, 2)]).is_err());
        assert!(
            encode_a64_fields("B_only_branch_imm", 0x14000000, &[field("imm26", 0, 26, 0), field("imm26", 0, 26, 0)],)
                .is_err()
        );
    }

    #[test]
    fn signed_branch_boundaries_and_no_address_wrap() {
        let x64 = Target::new(Arch::X86_64);
        assert!(assemble(&x64, 0, "jmp 0x80000004").is_ok());
        assert!(assemble(&x64, 0, "jmp 0x80000005").is_err());
        assert!(assemble(&x64, 0x80000000, "jmp 5").is_ok());
        assert!(assemble(&x64, 0x80000000, "jmp 4").is_err());
        assert!(assemble(&x64, u64::MAX, "nop").is_err());
        assert!(assemble(&Target::new(Arch::X86), 0xffff_ffff, "nop").is_err());
        let a64 = Target::new(Arch::Aarch64);
        assert!(assemble(&a64, 0x08000000, "b 0").is_ok());
        assert!(assemble(&a64, 0x08000004, "b 0").is_err());
        assert!(assemble(&a64, 0, "b 0x07fffffc").is_ok());
        assert!(assemble(&a64, 0, "b 0x08000000").is_err());
        assert!(assemble(&a64, 0x100000, "b.eq 0").is_ok());
        assert!(assemble(&a64, 0x100004, "b.eq 0").is_err());
    }

    #[test]
    fn batches_are_bounded_atomic_and_report_source_lines() {
        let target = Target::new(Arch::X86_64);
        assert!(assemble(&target, 0, &"nop\n".repeat(64)).is_ok());
        let error = assemble(&target, 0, &"nop\n".repeat(65)).unwrap_err();
        assert_eq!(error.line, 65);
        assert!(assemble(&target, 0, &" ".repeat(MAX_SOURCE_BYTES + 1)).is_err());
        for source in [
            "",
            " \n\t",
            "nop; ret",
            "start: nop",
            "jmp symbol",
            ".byte 0x90",
            "include x",
            "mov rax, [rbx]",
            "nop\n\nmov rax, 0x10000000000000000",
            "nop\nret\n.exec x",
        ] {
            assert!(assemble(&target, 0, source).is_err(), "{source}");
        }
        assert_eq!(assemble(&target, 0, "nop\n\ninvalid").unwrap_err().line, 3);
        for arch in Arch::ALL {
            if !matches!(arch, Arch::X86 | Arch::X86_64 | Arch::Aarch64) {
                assert!(assemble(&Target::new(arch), 0, "nop").is_err());
            }
        }
    }
}
