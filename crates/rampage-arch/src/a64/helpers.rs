//! Arm pseudocode helpers (from the Arm ARM shared pseudocode library) used by decode conditions and operand
//! formatting.

use super::spec::SYSTEM_OPERATIONS;
use super::spec_types::SysKind;

fn ones(width: u32) -> u64 {
    if width >= 64 { u64::MAX } else { (1 << width) - 1 }
}

fn highest_set_bit(value: u64) -> Option<u32> {
    (value != 0).then(|| 63 - value.leading_zeros())
}

fn rotate_right(value: u64, amount: u32, width: u32) -> u64 {
    let amount = amount % width;
    if amount == 0 {
        return value;
    }
    ((value >> amount) | (value << (width - amount))) & ones(width)
}

fn replicate(element: u64, element_width: u32, width: u32) -> u64 {
    let mut result = 0;
    let mut position = 0;
    while position < width {
        result |= element << position;
        position += element_width;
    }
    result & ones(width)
}

/// `DecodeBitMasks(immN, imms, immr, immediate, M)`, returning the `wmask` of a logical immediate, or `None`
/// for reserved encodings.
pub fn decode_bit_masks(n: u64, imms: u64, immr: u64, immediate: bool, width: u32) -> Option<u64> {
    let length = highest_set_bit((n << 6) | (!imms & 0x3f))?;
    if length < 1 {
        return None;
    }
    let levels = ones(length);
    if immediate && imms & levels == levels {
        return None;
    }
    let s = (imms & levels) as u32;
    let r = (immr & levels) as u32;
    let element_width = 1 << length;
    if element_width > width {
        return None;
    }
    let element = rotate_right(ones(s + 1), r, element_width);
    Some(replicate(element, element_width, width))
}

/// `MoveWidePreferred`: whether an ORR immediate is better shown as MOV (wide immediate).
pub fn move_wide_preferred(sf: u64, n: u64, imms: u64, immr: u64) -> bool {
    let s = imms as i64;
    let r = immr as i64;
    let width = if sf == 1 { 64 } else { 32 };
    if sf == 1 && n != 1 {
        return false;
    }
    if sf == 0 && (n != 0 || imms & 0x20 != 0) {
        return false;
    }
    if s < 16 {
        return (-r).rem_euclid(16) <= 15 - s;
    }
    if s >= width - 15 {
        return r % 16 <= s - (width - 15);
    }
    false
}

/// `BFXPreferred`: whether a bitfield move is better shown as UBFX or SBFX.
pub fn bfx_preferred(sf: u64, unsigned: u64, imms: u64, immr: u64) -> bool {
    if imms < immr {
        return false;
    }
    if imms == (sf << 5) | 0x1f {
        return false;
    }
    if immr == 0 {
        if sf == 0 && (imms == 0b000111 || imms == 0b001111) {
            return false;
        }
        if sf == 1 && unsigned == 0 && (imms == 0b000111 || imms == 0b001111 || imms == 0b011111) {
            return false;
        }
    }
    true
}

/// `SVEMoveMaskPreferred`: whether an SVE DUPM is better shown as MOV.
pub fn sve_move_mask_preferred(imm13: u64) -> bool {
    let Some(imm) = decode_bit_masks(imm13 >> 12, imm13 & 0x3f, (imm13 >> 6) & 0x3f, true, 64) else {
        return false;
    };
    let bits = |high: u32, low: u32| (imm >> low) & ones(high - low + 1);
    let is_zero = |high, low| bits(high, low) == 0;
    let is_ones = |high: u32, low: u32| bits(high, low) == ones(high - low + 1);
    let words_equal = bits(63, 32) == bits(31, 0);
    let halves_equal = bits(31, 16) == bits(15, 0);
    if bits(7, 0) != 0 {
        if is_zero(63, 7) || is_ones(63, 7) {
            return false;
        }
        if words_equal && (is_zero(31, 7) || is_ones(31, 7)) {
            return false;
        }
        if words_equal && halves_equal && (is_zero(15, 7) || is_ones(15, 7)) {
            return false;
        }
        if words_equal && halves_equal && bits(15, 8) == bits(7, 0) {
            return false;
        }
    } else {
        if is_zero(63, 15) || is_ones(63, 15) {
            return false;
        }
        if words_equal && (is_zero(31, 7) || is_ones(31, 7)) {
            return false;
        }
        if words_equal && halves_equal {
            return false;
        }
    }
    true
}

/// Looks up the system instruction encoded by `op1:CRn:CRm:op2`, returning its kind and operation name.
pub fn system_operation(
    op1: u64,
    crn: u64,
    crm: u64,
    op2: u64,
    accept: impl Fn(SysKind) -> bool,
) -> Option<(SysKind, &'static str)> {
    let key = ((op1 << 11) | (crn << 7) | (crm << 3) | op2) as u16;
    let start = SYSTEM_OPERATIONS.partition_point(|&(k, _, _)| k < key);
    SYSTEM_OPERATIONS[start..]
        .iter()
        .take_while(|&&(k, _, _)| k == key)
        .find(|&&(_, kind, _)| accept(kind))
        .map(|&(_, kind, name)| (kind, name))
}

/// `SysOp`: classifies a SYS encoding.
pub fn sys_op(op1: u64, crn: u64, crm: u64, op2: u64) -> Option<SysKind> {
    let accept = |kind| {
        matches!(
            kind,
            SysKind::At
                | SysKind::Brb
                | SysKind::Dc
                | SysKind::Gic
                | SysKind::Gsb
                | SysKind::Ic
                | SysKind::Plbi
                | SysKind::Tlbi
        )
    };
    system_operation(op1, crn, crm, op2, accept).map(|(kind, _)| kind)
}

/// `SysOp128`: classifies a SYSP encoding.
pub fn sys_op128(op1: u64, crn: u64, crm: u64, op2: u64) -> Option<SysKind> {
    system_operation(op1, crn, crm, op2, |kind| kind == SysKind::Tlbip).map(|(kind, _)| kind)
}

/// `SysLOp`: classifies a SYSL encoding.
pub fn sysl_op(op1: u64, crn: u64, crm: u64, op2: u64) -> Option<SysKind> {
    system_operation(op1, crn, crm, op2, |kind| kind == SysKind::Gicr).map(|(kind, _)| kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_immediates_decode() {
        // and x0, x1, #0xff: N=1, immr=0, imms=7
        assert_eq!(decode_bit_masks(1, 7, 0, true, 64), Some(0xff));
        // orr w0, wzr, #0x55555555: N=0, immr=0, imms=0b111100
        assert_eq!(decode_bit_masks(0, 0b111100, 0, true, 32), Some(0x5555_5555));
        // Reserved: all-ones element
        assert_eq!(decode_bit_masks(1, 0x3f, 0, true, 64), None);
    }

    #[test]
    fn move_wide_preference() {
        // orr x0, xzr, #0xffff (N=1, imms=15, immr=0) is a MOVZ candidate.
        assert!(move_wide_preferred(1, 1, 15, 0));
        // orr x0, xzr, #0x5555555555555555 is not.
        assert!(!move_wide_preferred(1, 0, 0b111100, 0));
    }
}
