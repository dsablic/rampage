//! A reference executor for lifted straight-line integer effects, shared by the deterministic and native tests.
#![allow(dead_code)]

use rampage_arch::ir::{self, Effect, LiftedInstruction, Value};
use rampage_arch::{Arch, Target, decoder};

pub fn lift(word: u32) -> LiftedInstruction {
    let bytes = word.to_le_bytes();
    let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x1000);
    ir::lift(Arch::Aarch64, &bytes, &insn)
}

pub fn value(expr: &Value, registers: &[u64; 31]) -> u64 {
    match expr {
        Value::Constant { value } => *value,
        Value::Register { number } => registers[*number as usize],
        Value::StackPointer => panic!("fixture does not use SP"),
        Value::Low32 { value: expr } => value(expr, registers) & 0xffff_ffff,
        Value::Add { left, right } => value(left, registers).wrapping_add(value(right, registers)),
        Value::Subtract { left, right } => value(left, registers).wrapping_sub(value(right, registers)),
        Value::Binary { operation, left, right, bits } => {
            ir::binary(*operation, value(left, registers), value(right, registers), *bits).unwrap()
        }
        Value::Unary { operation, value: expr, bits } => ir::unary(*operation, value(expr, registers), *bits).unwrap(),
    }
}

/// Arm AddWithCarry computed independently of `ir::flags`, returning the result and packed NZCV.
pub fn add_with_carry(x: u64, y: u64, carry: bool, bits: u8) -> (u64, u64) {
    let mask = if bits == 32 { u64::from(u32::MAX) } else { u64::MAX };
    let (x, y) = (x & mask, y & mask);
    let signed = |value: u64| if bits == 32 { i128::from(value as u32 as i32) } else { i128::from(value as i64) };
    let unsigned_sum = u128::from(x) + u128::from(y) + u128::from(carry);
    let signed_sum = signed(x) + signed(y) + i128::from(carry);
    let result = unsigned_sum as u64 & mask;
    let n = result >> (bits - 1) & 1;
    let z = u64::from(result == 0);
    let c = u64::from(u128::from(result) != unsigned_sum);
    let v = u64::from(signed(result) != signed_sum);
    (result, n << 3 | z << 2 | c << 1 | v)
}

fn write(registers: &mut [u64; 31], destination: &Value, value: u64, bits: u8) {
    let mask = if bits == 32 { u64::from(u32::MAX) } else { u64::MAX };
    match destination {
        Value::Register { number } => registers[*number as usize] = value & mask,
        Value::Constant { value: 0 } => {}
        _ => panic!("unexpected destination: {destination:?}"),
    }
}

/// Executes every effect of one complete instruction in order; `nzcv` is packed in bits 3..0.
pub fn execute(lifted: &LiftedInstruction, registers: &mut [u64; 31], nzcv: &mut u64) {
    assert!(lifted.complete, "{lifted:?}");
    let bits = lifted.bits;
    for effect in &lifted.effects {
        match effect {
            Effect::Assign { destination, value: expr } => {
                let result = value(expr, registers);
                write(registers, destination, result, bits);
            }
            Effect::Discard { .. } => {}
            Effect::Select { destination, condition, when_true, when_false } => {
                let arm = if ir::condition(*nzcv, *condition).unwrap() { when_true } else { when_false };
                let result = value(arm, registers);
                write(registers, destination, result, bits);
            }
            Effect::SetFlags { operation, left, right } => {
                *nzcv = ir::flags(*operation, value(left, registers), value(right, registers), bits).unwrap();
            }
            Effect::CarryArithmetic { destination, left, right, subtract, set_flags } => {
                let right = value(right, registers);
                let right = if *subtract { !right } else { right };
                let (result, flags) = add_with_carry(value(left, registers), right, *nzcv & 2 != 0, bits);
                write(registers, destination, result, bits);
                if *set_flags {
                    *nzcv = flags;
                }
            }
            Effect::ConditionalFlags { condition, operation, left, right, nzcv: otherwise } => {
                *nzcv = if ir::condition(*nzcv, *condition).unwrap() {
                    ir::flags(*operation, value(left, registers), value(right, registers), bits).unwrap()
                } else {
                    u64::from(*otherwise)
                };
            }
            _ => panic!("unsupported fixture effect: {effect:?}"),
        }
    }
}

/// Boundary results recorded from native AArch64 execution: word, x0..x3, NZCV in, destination result, NZCV out.
/// The native tests re-check every row on hardware; the deterministic tests replay them anywhere.
pub const EXPECTED: &[(u32, [u64; 4], u64, u64, u64)] = &[
    (0xba02_0020, [0, u64::MAX, 0, 0], 0b0010, 0, 0b0110),
    (0xba02_0020, [0, 0x7fff_ffff_ffff_ffff, 0, 0], 0b0010, 0x8000_0000_0000_0000, 0b1001),
    (0xba02_0020, [0, 1, 2, 0], 0b1101, 3, 0b0000),
    (0xfa02_0020, [0, 0, 0, 0], 0b0000, u64::MAX, 0b1000),
    (0xfa02_0020, [0, 0, 0, 0], 0b0010, 0, 0b0110),
    (0xfa02_0020, [0, 0x8000_0000_0000_0000, 0, 0], 0b0000, 0x7fff_ffff_ffff_ffff, 0b0011),
    (0x3a02_0020, [0, 0xffff_ffff, 0, 0], 0b0010, 0, 0b0110),
    (0x3a02_0020, [0, 0x7fff_ffff, 0, 0], 0b0010, 0x8000_0000, 0b1001),
    (0x5a02_0020, [u64::MAX, 0, 0, 0], 0b0000, 0xffff_ffff, 0b0000),
    (0xda02_03e0, [0, 0, 1, 0], 0b0010, u64::MAX, 0b0010),
    (0xda02_03e0, [0, 0, 1, 0], 0b0000, 0xffff_ffff_ffff_fffe, 0b0000),
    (0xba02_003f, [7, u64::MAX, 1, 0], 0b0000, 0, 0b0110),
    (0x9a01_0021, [0, 5, 0, 0], 0b0010, 0xb, 0b0010),
    (0xfa42_0025, [0, 3, 3, 0], 0b0100, 0, 0b0110),
    (0xfa42_0025, [0, 3, 3, 0], 0b0000, 0, 0b0101),
    (0x7a5f_882f, [0, 0x1f, 0, 0], 0b0010, 0, 0b0110),
    (0x7a5f_882f, [0, 0x1f, 0, 0], 0b0110, 0, 0b1111),
    (0x3a42_6029, [0, 0x7fff_ffff, 1, 0], 0b0001, 0, 0b1001),
    (0x3a42_6029, [0, 0x7fff_ffff, 1, 0], 0b0000, 0, 0b1001),
    (0x3a40_f820, [0, 0, 0, 0], 0b1111, 0, 0b0100),
    (0xb378_3c20, [u64::MAX, 0x1234_5678, 0, 0], 0b0000, 0xffff_ffff_ff56_78ff, 0b0000),
    (0xb345_3420, [u64::MAX, 0xffff_ffff_ffff_fc1f, 0, 0], 0b0000, 0xffff_ffff_ffff_ffe0, 0b0000),
    (0x3304_0c20, [0xffff_ffff_0000_0000, 0xff, 0, 0], 0b0000, 0xf000_0000, 0b0000),
    (0xb37f_f820, [1, u64::MAX, 0, 0], 0b0000, u64::MAX, 0b0000),
    (0x9374_4c20, [0, 0x8_0000, 0, 0], 0b0000, 0xffff_ffff_8000_0000, 0b0000),
    (0xd37d_1820, [0, 0xff, 0, 0], 0b0000, 0x3f8, 0b0000),
    (0x1301_0020, [0, 1, 0, 0], 0b0000, 0x8000_0000, 0b0000),
    (0x937f_f820, [0, 0x8000_0000_0000_0001, 0, 0], 0b0000, 2, 0b0000),
    (0xb37c_1fe0, [u64::MAX, 0, 0, 0], 0b0000, 0xffff_ffff_ffff_f00f, 0b0000),
    (0x9b22_7c20, [0, 0xffff_ffff, 0x8000_0000, 0], 0b0000, 0x8000_0000, 0b0000),
    (0x9ba2_7c20, [0, 0xffff_ffff, 0x8000_0000, 0], 0b0000, 0x7fff_ffff_8000_0000, 0b0000),
    (0x9b22_8c20, [0, 0x1_ffff_fffe, 3, 1], 0b0000, 7, 0b0000),
    (0x9ba2_0c20, [0, u64::MAX, u64::MAX, u64::MAX], 0b0000, 0xffff_fffe_0000_0000, 0b0000),
    (0x9b42_7c20, [0, u64::MAX, u64::MAX, 0], 0b0000, 0, 0b0000),
    (0x9bc2_7c20, [0, u64::MAX, u64::MAX, 0], 0b0000, 0xffff_ffff_ffff_fffe, 0b0000),
    (0x9b42_7c20, [0, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0], 0b0000, 0x4000_0000_0000_0000, 0b0000),
    (0x93c2_4420, [0, 0x123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 0], 0b0000, 0xe6f7_ff6e_5d4c_3b2a, 0b0000),
    (0x1382_7c20, [0, 0x8000_0001, 0x8000_0000, 0], 0b0000, 3, 0b0000),
    (0x93c1_2420, [0, 0x1ff, 0, 0], 0b0000, 0xff80_0000_0000_0000, 0b0000),
    (0x93c2_0020, [0, 1, 2, 0], 0b0000, 2, 0b0000),
    (0xdac0_1020, [0, 0, 0, 0], 0b0000, 0x40, 0b0000),
    (0x5ac0_1020, [0, 0xffff_ffff_0000_0001, 0, 0], 0b0000, 0x1f, 0b0000),
    (0xdac0_1420, [0, u64::MAX, 0, 0], 0b0000, 0x3f, 0b0000),
    (0xdac0_1420, [0, 1, 0, 0], 0b0000, 0x3e, 0b0000),
    (0x5ac0_1420, [0, 0xffff_c000, 0, 0], 0b0000, 0x11, 0b0000),
    (0x5ac0_1420, [0, 0, 0, 0], 0b0000, 0x1f, 0b0000),
    (0xdac0_0020, [0, 1, 0, 0], 0b0000, 0x8000_0000_0000_0000, 0b0000),
    (0x5ac0_0020, [0, 0x1_0000_0003, 0, 0], 0b0000, 0xc000_0000, 0b0000),
    (0xdac0_0c20, [0, 0x123_4567_89ab_cdef, 0, 0], 0b0000, 0xefcd_ab89_6745_2301, 0b0000),
    (0x5ac0_0820, [0, 0x123_4567_89ab_cdef, 0, 0], 0b0000, 0xefcd_ab89, 0b0000),
    (0xdac0_0420, [0, 0x123_4567_89ab_cdef, 0, 0], 0b0000, 0x2301_6745_ab89_efcd, 0b0000),
    (0x5ac0_0420, [0, 0x123_4567_89ab_cdef, 0, 0], 0b0000, 0xab89_efcd, 0b0000),
    (0xdac0_0820, [0, 0x123_4567_89ab_cdef, 0, 0], 0b0000, 0x6745_2301_efcd_ab89, 0b0000),
    (0xda81_1420, [0, 5, 0, 0], 0b0100, 0xffff_ffff_ffff_fffb, 0b0100),
    (0x1a81_a420, [0, 0xffff_ffff, 0, 0], 0b1000, 0, 0b1000),
    (0xda9f_b3e0, [9, 0, 0, 0], 0b1001, u64::MAX, 0b1001),
];

/// Lifts and executes `word` with x0..x3 and packed NZCV, returning x0..x3 and the resulting NZCV.
pub fn run(word: u32, inputs: [u64; 4], nzcv: u64) -> ([u64; 4], u64) {
    let mut registers = [0; 31];
    registers[..4].copy_from_slice(&inputs);
    let mut flags = nzcv;
    execute(&lift(word), &mut registers, &mut flags);
    (registers[..4].try_into().unwrap(), flags)
}
