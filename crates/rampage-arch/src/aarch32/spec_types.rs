//! What the generated A32 and T32 tables use: the shared table types, and the Arm pseudocode helpers their
//! conditions call.

pub use crate::mrs::*;

/// `SInt`: the two's-complement value of the low `width` bits.
pub fn sign_extend(value: u64, width: u32) -> i64 {
    let shift = 64 - width;
    ((value << shift) as i64) >> shift
}

/// `A32ExpandImm`: an 8-bit value rotated right by twice the 4-bit rotation.
pub fn a32_expand_imm(imm12: u64) -> u64 {
    u64::from((imm12 as u32 & 0xff).rotate_right(2 * (imm12 as u32 >> 8)))
}

/// `T32ExpandImm`: a byte replicated in one of four patterns, or a rotated 8-bit value with its top bit set.
pub fn t32_expand_imm(imm12: u64) -> u64 {
    let imm8 = imm12 & 0xff;
    let value = if imm12 >> 10 == 0 {
        match (imm12 >> 8) & 3 {
            0 => imm8,
            1 => imm8 << 16 | imm8,
            2 => imm8 << 24 | imm8 << 8,
            _ => imm8 * 0x0101_0101,
        }
    } else {
        u64::from((0x80 | (imm12 as u32 & 0x7f)).rotate_right(imm12 as u32 >> 7))
    };
    value & 0xffff_ffff
}

/// Whether `value` is an A32 modified immediate, which a shorter-looking encoding (MOV rather than MOVW) can hold.
pub fn a32_encoding_exists(value: u64, _width: u32) -> bool {
    let value = value as u32;
    (0..16).any(|rotation| value.rotate_left(2 * rotation) <= 0xff)
}

/// Whether `value` is a T32 modified immediate: an ADD or MOV can hold it, so ADDW and MOVW must be named.
pub fn t32_encoding_exists(value: u64, _width: u32) -> bool {
    let value = value as u32;
    // The byte patterns 00XY00XY, XYXYXYXY and XY00XY00.
    let (low, second) = (value & 0xff, value >> 8 & 0xff);
    let replicated = (low != 0 && (value == low << 16 | low || value == low * 0x0101_0101))
        || (second != 0 && value == (second << 24 | second << 8));
    value <= 0xff || replicated || (8..32).any(|rotation| (0x80..=0xff).contains(&value.rotate_left(rotation)))
}
