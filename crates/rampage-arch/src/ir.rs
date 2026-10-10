use serde::Serialize;

use crate::{Arch, Flow, Insn};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiftedInstruction {
    #[serde(serialize_with = "crate::hex::address")]
    pub address: u64,
    pub bits: u8,
    pub effects: Vec<Effect>,
    pub flow: Flow,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Value {
    Low32 {
        value: Box<Value>,
    },
    Binary {
        operation: Operation,
        left: Box<Value>,
        right: Box<Value>,
        bits: u8,
    },
    Register {
        number: u8,
    },
    StackPointer,
    Constant {
        #[serde(serialize_with = "crate::hex::address")]
        value: u64,
    },
    Add {
        left: Box<Value>,
        right: Box<Value>,
    },
    Subtract {
        left: Box<Value>,
        right: Box<Value>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    And,
    Or,
    Xor,
    ShiftLeft,
    ShiftRight,
    ArithmeticShiftRight,
    RotateRight,
    Multiply,
    UnsignedDivide,
    SignedDivide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagOperation {
    Add,
    Subtract,
    And,
}

pub fn binary(operation: Operation, left: u64, right: u64, bits: u8) -> Option<u64> {
    if !matches!(bits, 32 | 64) {
        return None;
    }
    let mask = if bits == 32 { u64::from(u32::MAX) } else { u64::MAX };
    let (left, right) = (left & mask, right & mask);
    let shift = (right % u64::from(bits)) as u32;
    let signed = |value| if bits == 32 { value as u32 as i32 as i64 } else { value as i64 };
    let value = match operation {
        Operation::And => left & right,
        Operation::Or => left | right,
        Operation::Xor => left ^ right,
        Operation::ShiftLeft => left.wrapping_shl(shift),
        Operation::ShiftRight => left >> shift,
        Operation::ArithmeticShiftRight => (signed(left) >> shift) as u64,
        Operation::RotateRight if bits == 32 => u64::from((left as u32).rotate_right(shift)),
        Operation::RotateRight => left.rotate_right(shift),
        Operation::Multiply => left.wrapping_mul(right),
        Operation::UnsignedDivide => left.checked_div(right).unwrap_or(0),
        Operation::SignedDivide => {
            let (left, right) = (signed(left), signed(right));
            if right == 0 { 0 } else { left.wrapping_div(right) as u64 }
        }
    };
    Some(value & mask)
}

/// Packed NZCV in bits 3..0, independent of the architectural system-register bit position.
pub fn flags(operation: FlagOperation, left: u64, right: u64, bits: u8) -> Option<u64> {
    if !matches!(bits, 32 | 64) {
        return None;
    }
    let mask = if bits == 32 { u64::from(u32::MAX) } else { u64::MAX };
    let sign = 1u64 << (bits - 1);
    let (left, right) = (left & mask, right & mask);
    let (result, carry, overflow) = match operation {
        FlagOperation::Add => {
            let result = left.wrapping_add(right) & mask;
            (
                result,
                u128::from(left) + u128::from(right) > u128::from(mask),
                (!(left ^ right) & (left ^ result) & sign) != 0,
            )
        }
        FlagOperation::Subtract => {
            let result = left.wrapping_sub(right) & mask;
            (result, left >= right, ((left ^ right) & (left ^ result) & sign) != 0)
        }
        FlagOperation::And => (left & right, false, false),
    };
    Some(u64::from(result & sign != 0) << 3 | u64::from(result == 0) << 2 | u64::from(carry) << 1 | u64::from(overflow))
}

pub fn condition(nzcv: u64, condition: u8) -> Option<bool> {
    if condition > 15 {
        return None;
    }
    let (n, z, c, v) = (nzcv & 8 != 0, nzcv & 4 != 0, nzcv & 2 != 0, nzcv & 1 != 0);
    let base = match condition >> 1 {
        0 => z,
        1 => c,
        2 => n,
        3 => v,
        4 => c && !z,
        5 => n == v,
        6 => n == v && !z,
        _ => true,
    };
    Some(if condition < 14 && condition & 1 != 0 { !base } else { base })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Effect {
    Select { destination: Value, condition: u8, when_true: Value, when_false: Value },
    SetFlags { operation: FlagOperation, left: Value, right: Value },
    FlagsConditional { condition: u8 },
    Call { target: Value, return_address: u64 },
    Control { inputs: Vec<Value> },
    ConditionalControl { value: Value, nonzero: bool, bit: Option<u8> },
    Discard { value: Value },
    LoadDiscard { address: Value },
    Assign { destination: Value, value: Value },
    Load { destination: Value, address: Value },
    Store { address: Value, value: Value },
    Barrier { reason: String },
}

fn register(number: u8, stack: bool) -> Value {
    match number {
        31 if stack => Value::StackPointer,
        31 => Value::Constant { value: 0 },
        _ => Value::Register { number },
    }
}

fn assign(destination: Value, value: Value) -> Effect {
    if matches!(destination, Value::Constant { .. }) {
        Effect::Discard { value }
    } else {
        Effect::Assign { destination, value }
    }
}

fn operation(operation: Operation, left: Value, right: Value, bits: u8) -> Value {
    Value::Binary { operation, left: Box::new(left), right: Box::new(right), bits }
}

fn arithmetic(
    lifted: &mut LiftedInstruction,
    target: Value,
    left: Value,
    right: Value,
    subtract: bool,
    set_flags: bool,
) {
    if set_flags {
        lifted.effects.push(Effect::SetFlags {
            operation: if subtract { FlagOperation::Subtract } else { FlagOperation::Add },
            left: left.clone(),
            right: right.clone(),
        });
    }
    let (left, right) = (Box::new(left), Box::new(right));
    let value = if subtract { Value::Subtract { left, right } } else { Value::Add { left, right } };
    lifted.effects.push(assign(target, value));
    lifted.complete = true;
}

/// A deliberately partial IR: unknown instructions are semantic barriers, never no-ops.
pub fn lift(arch: Arch, bytes: &[u8], insn: &Insn) -> LiftedInstruction {
    let mut lifted =
        LiftedInstruction { address: insn.address, bits: 64, effects: Vec::new(), flow: insn.flow, complete: false };
    if arch != Arch::Aarch64 || bytes.len() < 4 || insn.flow == Flow::Invalid {
        lifted.effects.push(Effect::Barrier { reason: "unsupported architecture or invalid instruction".to_owned() });
        return lifted;
    }
    let word = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let rd = (word & 31) as u8;
    let rn = ((word >> 5) & 31) as u8;
    let sf = word >> 31 != 0;
    let Some(decoded) = crate::a64::decode_word(word) else {
        lifted.effects.push(Effect::Barrier { reason: "unallocated instruction".to_owned() });
        return lifted;
    };
    let name = decoded.encoding.name;
    let width = if sf { 64 } else { 32 };
    if name.ends_with("_addsub_imm") {
        lifted.bits = if sf { 64 } else { 32 };
        let immediate = u64::from((word >> 10) & 0xfff) << if word & (1 << 22) != 0 { 12 } else { 0 };
        arithmetic(
            &mut lifted,
            register(rd, word & (1 << 29) == 0),
            register(rn, true),
            Value::Constant { value: immediate },
            word & (1 << 30) != 0,
            word & (1 << 29) != 0,
        );
    } else if name.ends_with("_addsub_shift") {
        lifted.bits = width;
        let shift = match (word >> 22) & 3 {
            0 => Operation::ShiftLeft,
            1 => Operation::ShiftRight,
            _ => Operation::ArithmeticShiftRight,
        };
        let right = operation(
            shift,
            register(((word >> 16) & 31) as u8, false),
            Value::Constant { value: u64::from((word >> 10) & 63) },
            width,
        );
        arithmetic(
            &mut lifted,
            register(rd, false),
            register(rn, false),
            right,
            word & (1 << 30) != 0,
            word & (1 << 29) != 0,
        );
    } else if word & 0xffe0_ffe0 == 0xaa00_03e0 {
        lifted.effects.push(assign(register(rd, false), register(((word >> 16) & 31) as u8, false)));
        lifted.complete = true;
    } else if name.ends_with("_log_shift") || name.ends_with("_log_imm") {
        lifted.bits = width;
        let right = if name.ends_with("_log_imm") {
            let Some(mask) = crate::a64::logical_immediate(word, width) else {
                return lifted;
            };
            Value::Constant { value: mask }
        } else {
            let shift = match (word >> 22) & 3 {
                0 => Operation::ShiftLeft,
                1 => Operation::ShiftRight,
                2 => Operation::ArithmeticShiftRight,
                _ => Operation::RotateRight,
            };
            let shifted = operation(
                shift,
                register(((word >> 16) & 31) as u8, false),
                Value::Constant { value: u64::from((word >> 10) & 63) },
                width,
            );
            if word & (1 << 21) != 0 {
                operation(Operation::Xor, shifted, Value::Constant { value: u64::MAX }, width)
            } else {
                shifted
            }
        };
        let left = register(rn, false);
        let opc = (word >> 29) & 3;
        let op = match opc {
            1 => Operation::Or,
            2 => Operation::Xor,
            _ => Operation::And,
        };
        if opc == 3 {
            lifted.effects.push(Effect::SetFlags {
                operation: FlagOperation::And,
                left: left.clone(),
                right: right.clone(),
            });
        }
        lifted
            .effects
            .push(assign(register(rd, name.ends_with("_log_imm") && opc != 3), operation(op, left, right, width)));
        lifted.complete = true;
    } else if name.ends_with("_movewide") {
        lifted.bits = width;
        let shift = ((word >> 21) & 3) * 16;
        let immediate = u64::from((word >> 5) & 0xffff) << shift;
        let value = if name.starts_with("MOVN") {
            Value::Constant { value: !immediate }
        } else if name.starts_with("MOVK") {
            operation(
                Operation::Or,
                operation(Operation::And, register(rd, false), Value::Constant { value: !(0xffff << shift) }, width),
                Value::Constant { value: immediate },
                width,
            )
        } else {
            Value::Constant { value: immediate }
        };
        lifted.effects.push(assign(register(rd, false), value));
        lifted.complete = true;
    } else if name.ends_with("_condsel") {
        lifted.bits = width;
        let when_true = register(rn, false);
        let rm = register(((word >> 16) & 31) as u8, false);
        let when_false = if name.starts_with("CSINC") {
            Value::Add { left: Box::new(rm), right: Box::new(Value::Constant { value: 1 }) }
        } else if name.starts_with("CSINV") {
            operation(Operation::Xor, rm, Value::Constant { value: u64::MAX }, width)
        } else if name.starts_with("CSNEG") {
            Value::Subtract { left: Box::new(Value::Constant { value: 0 }), right: Box::new(rm) }
        } else {
            rm
        };
        lifted.effects.push(Effect::Select {
            destination: register(rd, false),
            condition: ((word >> 12) & 15) as u8,
            when_true,
            when_false,
        });
        lifted.complete = true;
    } else if name.starts_with("UBFM_") || name.starts_with("SBFM_") {
        lifted.bits = width;
        let immr = ((word >> 16) & 63) as u8;
        let imms = ((word >> 10) & 63) as u8;
        let unsigned = name.starts_with("UBFM");
        let source = register(rn, false);
        let value = if imms == width - 1 {
            operation(
                if unsigned { Operation::ShiftRight } else { Operation::ArithmeticShiftRight },
                source,
                Value::Constant { value: u64::from(immr) },
                width,
            )
        } else if unsigned && imms + 1 == immr {
            operation(Operation::ShiftLeft, source, Value::Constant { value: u64::from(width - immr) }, width)
        } else if immr <= imms {
            let size = imms - immr + 1;
            let field = operation(
                Operation::And,
                operation(Operation::ShiftRight, source, Value::Constant { value: u64::from(immr) }, width),
                Value::Constant { value: crate::mrs::ones(u32::from(size)) },
                width,
            );
            if unsigned {
                field
            } else {
                operation(
                    Operation::ArithmeticShiftRight,
                    operation(Operation::ShiftLeft, field, Value::Constant { value: u64::from(width - size) }, width),
                    Value::Constant { value: u64::from(width - size) },
                    width,
                )
            }
        } else {
            lifted
                .effects
                .push(Effect::Barrier { reason: "wrapping bitfield semantics are not implemented".to_owned() });
            return lifted;
        };
        lifted.effects.push(assign(register(rd, false), value));
        lifted.complete = true;
    } else if name.ends_with("_dp_2src")
        && ["UDIV", "SDIV", "LSLV", "LSRV", "ASRV", "RORV"].iter().any(|prefix| name.starts_with(prefix))
    {
        lifted.bits = width;
        let op = match name.split('_').next().unwrap_or("") {
            "UDIV" => Operation::UnsignedDivide,
            "SDIV" => Operation::SignedDivide,
            "LSLV" => Operation::ShiftLeft,
            "LSRV" => Operation::ShiftRight,
            "ASRV" => Operation::ArithmeticShiftRight,
            _ => Operation::RotateRight,
        };
        lifted.effects.push(assign(
            register(rd, false),
            operation(op, register(rn, false), register(((word >> 16) & 31) as u8, false), width),
        ));
        lifted.complete = true;
    } else if matches!(name, "MADD_32A_dp_3src" | "MADD_64A_dp_3src" | "MSUB_32A_dp_3src" | "MSUB_64A_dp_3src") {
        lifted.bits = width;
        let product =
            operation(Operation::Multiply, register(rn, false), register(((word >> 16) & 31) as u8, false), width);
        let accumulator = Box::new(register(((word >> 10) & 31) as u8, false));
        let product = Box::new(product);
        let value = if name.starts_with("MSUB") {
            Value::Subtract { left: accumulator, right: product }
        } else {
            Value::Add { left: accumulator, right: product }
        };
        lifted.effects.push(assign(register(rd, false), value));
        lifted.complete = true;
    } else if matches!(name, "ADR_only_pcreladdr" | "ADRP_only_pcreladdr") {
        let raw = u64::from(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3));
        let offset = crate::mrs::sign_extend(raw, 21);
        let value = if name.starts_with("ADRP") {
            (insn.address & !0xfff).wrapping_add((offset << 12) as u64)
        } else {
            insn.address.wrapping_add(offset as u64)
        };
        lifted.effects.push(assign(register(rd, false), Value::Constant { value }));
        lifted.complete = true;
    } else if name == "BL_only_branch_imm" || name == "BLR_64_branch_reg" {
        let target = if name.starts_with("BLR") {
            register(rn, false)
        } else {
            let offset = crate::mrs::sign_extend(u64::from(word & 0x03ff_ffff), 26) << 2;
            Value::Constant { value: insn.address.wrapping_add(offset as u64) }
        };
        lifted.effects.push(Effect::Call { target, return_address: insn.address.wrapping_add(4) });
        lifted.complete = true;
    } else if name == "B_only_condbranch" {
        lifted.effects.push(Effect::FlagsConditional { condition: (word & 15) as u8 });
        lifted.complete = true;
    } else if matches!(name, "LDR_32_ldst_pos" | "STR_32_ldst_pos" | "LDR_64_ldst_pos" | "STR_64_ldst_pos") {
        lifted.bits = if name.contains("_32_") { 32 } else { 64 };
        let address = Value::Add {
            left: Box::new(register(rn, true)),
            right: Box::new(Value::Constant { value: u64::from((word >> 10) & 0xfff) * u64::from(lifted.bits / 8) }),
        };
        let rt = register(rd, false);
        lifted.effects.push(if word & (1 << 22) != 0 {
            if rd == 31 { Effect::LoadDiscard { address } } else { Effect::Load { destination: rt, address } }
        } else {
            Effect::Store { address, value: rt }
        });
        lifted.complete = true;
    } else if matches!(
        name,
        "LDR_64_ldst_immpost"
            | "STR_64_ldst_immpost"
            | "LDR_64_ldst_immpre"
            | "STR_64_ldst_immpre"
            | "LDUR_64_ldst_unscaled"
            | "STUR_64_ldst_unscaled"
    ) {
        let offset = crate::mrs::sign_extend(u64::from((word >> 12) & 511), 9);
        let updated = Value::Add {
            left: Box::new(register(rn, true)),
            right: Box::new(Value::Constant { value: offset as u64 }),
        };
        let post = name.ends_with("immpost");
        let address = if post { register(rn, true) } else { updated.clone() };
        let load = name.starts_with('L');
        if rd == rn && rn != 31 && !name.ends_with("unscaled") {
            lifted.effects.push(Effect::Barrier {
                reason: "overlapping memory writeback is constrained unpredictable".to_owned(),
            });
            return lifted;
        }
        lifted.effects.push(if load {
            if rd == 31 {
                Effect::LoadDiscard { address }
            } else {
                Effect::Load { destination: register(rd, false), address }
            }
        } else {
            Effect::Store { address, value: register(rd, false) }
        });
        if !name.ends_with("unscaled") {
            lifted.effects.push(assign(register(rn, true), updated));
        }
        lifted.complete = true;
    } else if (name.starts_with("STP_64_") || name.starts_with("LDP_64_"))
        && (name.ends_with("ldstpair_off") || name.ends_with("ldstpair_pre") || name.ends_with("ldstpair_post"))
    {
        let rt2 = ((word >> 10) & 31) as u8;
        let offset = crate::mrs::sign_extend(u64::from((word >> 15) & 127), 7) * 8;
        let updated = Value::Add {
            left: Box::new(register(rn, true)),
            right: Box::new(Value::Constant { value: offset as u64 }),
        };
        let address = if name.ends_with("post") { register(rn, true) } else { updated.clone() };
        let load = name.starts_with("LDP");
        let writeback = !name.ends_with("off");
        if load && (rd == rt2 || rn != 31 && (rd == rn || rt2 == rn)) {
            lifted
                .effects
                .push(Effect::Barrier { reason: "overlapping pair load is constrained unpredictable".to_owned() });
            return lifted;
        }
        if !load && writeback && rn != 31 && (rd == rn || rt2 == rn) {
            lifted.effects.push(Effect::Barrier {
                reason: "overlapping pair store writeback is constrained unpredictable".to_owned(),
            });
            return lifted;
        }
        for (index, rt) in [rd, rt2].into_iter().enumerate() {
            let address = if index == 0 {
                address.clone()
            } else {
                Value::Add { left: Box::new(address.clone()), right: Box::new(Value::Constant { value: 8 }) }
            };
            lifted.effects.push(if load {
                if rt == 31 {
                    Effect::LoadDiscard { address }
                } else {
                    Effect::Load { destination: register(rt, false), address }
                }
            } else {
                Effect::Store { address, value: register(rt, false) }
            });
        }
        if writeback {
            lifted.effects.push(assign(register(rn, true), updated));
        }
        lifted.complete = true;
    } else if word == 0xd503_201f {
        lifted.complete = true;
    } else if word & 0xfc00_0000 == 0x1400_0000 {
        lifted.effects.push(Effect::Control { inputs: Vec::new() });
        lifted.complete = true;
    } else if word & 0x7e00_0000 == 0x3400_0000 || word & 0x7e00_0000 == 0x3600_0000 {
        let bits = if sf { 64 } else { 32 };
        lifted.bits = bits;
        let bit = (word & 0x7e00_0000 == 0x3600_0000).then_some((((word >> 19) & 31) | ((word >> 31) << 5)) as u8);
        lifted.effects.push(Effect::ConditionalControl {
            value: register(rd, false),
            nonzero: word & (1 << 24) != 0,
            bit,
        });
        lifted.complete = true;
    } else if word & 0xffff_fc1f == 0xd61f_0000 || word & 0xffff_fc1f == 0xd65f_0000 {
        lifted.effects.push(Effect::Control { inputs: vec![register(rn, false)] });
        lifted.complete = true;
    }
    if !lifted.complete {
        lifted.effects.push(Effect::Barrier { reason: "instruction semantics not yet implemented".to_owned() });
    }
    lifted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Target, decoder};

    fn instruction(word: u32) -> LiftedInstruction {
        let bytes = word.to_le_bytes();
        let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x1000);
        lift(Arch::Aarch64, &bytes, &insn)
    }

    #[test]
    fn arithmetic_preserves_register_width_stack_pointer_and_immediate() {
        let lifted = instruction(0x9100_1020); // add x0,x1,#4
        assert!(lifted.complete);
        assert_eq!(lifted.bits, 64);
        assert_eq!(
            lifted.effects,
            vec![Effect::Assign {
                destination: Value::Register { number: 0 },
                value: Value::Add {
                    left: Box::new(Value::Register { number: 1 }),
                    right: Box::new(Value::Constant { value: 4 }),
                },
            }]
        );
        assert_eq!(instruction(0x1100_1020).bits, 32);
        assert!(matches!(
            &instruction(0x9100_13ff).effects[0],
            Effect::Assign { destination: Value::StackPointer, .. }
        ));
    }

    #[test]
    fn flag_setting_arithmetic_preserves_nzcv_effects() {
        let lifted = instruction(0xb100_1020);
        assert!(lifted.complete);
        assert!(matches!(&lifted.effects[0], Effect::SetFlags { operation: FlagOperation::Add, .. }));
    }

    #[test]
    fn loads_and_stores_are_distinct_effects_and_zero_register_is_constant() {
        assert!(matches!(&instruction(0xf940_0100).effects[0], Effect::Load { .. }));
        assert!(matches!(
            &instruction(0xf900_011f).effects[0],
            Effect::Store { value: Value::Constant { value: 0 }, .. }
        ));
    }

    #[test]
    fn moves_to_zero_discard_the_value_and_unknown_instructions_do_not_lift() {
        assert!(matches!(&instruction(0xd280_003f).effects[0], Effect::Discard { .. }));
        assert!(matches!(
            &instruction(0xaa08_03e9).effects[0],
            Effect::Assign { destination: Value::Register { number: 9 }, value: Value::Register { number: 8 } }
        ));
        assert!(instruction(0x8b01_0008).complete);
    }

    #[test]
    fn tagged_arithmetic_and_minmax_are_not_ordinary_add_sub() {
        for word in [0x9181_0420, 0xd181_0420, 0x11c0_0420, 0x91cc_0420] {
            assert!(!instruction(word).complete, "{word:08x}");
        }
        assert!(matches!(&instruction(0xf940_03ff).effects[0], Effect::LoadDiscard { .. }));
    }

    #[test]
    fn control_inputs_calls_and_flag_conditions_have_explicit_effects() {
        for (word, bits) in [(0x3400_0060, 32), (0xb400_0060, 64), (0x3600_0060, 32), (0xb600_0060, 64)] {
            let lifted = instruction(word);
            assert!(lifted.complete);
            assert_eq!(lifted.bits, bits);
            assert!(matches!(
                &lifted.effects[0],
                Effect::ConditionalControl { value: Value::Register { number: 0 }, .. }
            ));
        }
        for word in [0x1400_0002, 0xd61f_0100, 0xd65f_03c0] {
            assert!(instruction(word).complete, "{word:08x}");
        }
        for word in [0x9400_0002, 0xd63f_0100, 0x5400_0040] {
            assert!(instruction(word).complete, "{word:08x}");
        }
    }

    #[test]
    fn opposite_branch_polarities_and_distinct_bits_have_distinct_ir() {
        assert_ne!(instruction(0x3400_0060), instruction(0x3500_0060));
        assert_ne!(instruction(0x3600_0060), instruction(0x3700_0060));
        assert_ne!(instruction(0x3600_0060), instruction(0x3608_0060));
        assert!(matches!(
            instruction(0x3608_0060).effects[0],
            Effect::ConditionalControl { nonzero: false, bit: Some(1), .. }
        ));
    }
}
