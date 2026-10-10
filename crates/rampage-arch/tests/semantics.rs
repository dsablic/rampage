use rampage_arch::ir::{self, Effect, FlagOperation, LiftedInstruction, Value};
use rampage_arch::{Arch, Target, decoder};

fn lift(word: u32) -> LiftedInstruction {
    let bytes = word.to_le_bytes();
    let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x1000);
    ir::lift(Arch::Aarch64, &bytes, &insn)
}

fn value(value: &Value, registers: &[u64; 31], sp: u64) -> u64 {
    match value {
        Value::Constant { value } => *value,
        Value::Register { number } => registers[*number as usize],
        Value::StackPointer => sp,
        Value::Add { left, right } => self::value(left, registers, sp).wrapping_add(self::value(right, registers, sp)),
        Value::Subtract { left, right } => {
            self::value(left, registers, sp).wrapping_sub(self::value(right, registers, sp))
        }
        Value::Low32 { value } => self::value(value, registers, sp) & 0xffff_ffff,
        Value::Binary { operation, left, right, bits } => {
            ir::binary(*operation, self::value(left, registers, sp), self::value(right, registers, sp), *bits).unwrap()
        }
    }
}

#[test]
fn llvm_checked_integer_operations_have_executable_semantics() {
    let mut registers = [0; 31];
    registers[0] = 0xffff_ffff_1234_5678;
    registers[1] = 16;
    registers[2] = 3;
    registers[3] = 5;
    for (word, expected) in [
        (0x8b02_0c20, 40),
        (0x6b82_0820, 16),
        (0x8ac2_0c20, 0),
        (0x3200_1c20, 255),
        (0x92a2_4680, 0xffff_ffff_edcb_ffff),
        (0xf2d5_79a0, 0xffff_abcd_1234_5678),
        (0x9b02_0c20, 53),
        (0x1b02_8c20, 0xffff_ffd5),
        (0x9ac2_0820, 5),
        (0x1ac2_0c20, 5),
        (0x9ac2_2020, 128),
    ] {
        let lifted = lift(word);
        assert!(lifted.complete, "{word:08x}");
        let result = lifted
            .effects
            .iter()
            .find_map(|effect| match effect {
                Effect::Assign { value: rhs, .. } => Some(value(rhs, &registers, 0)),
                _ => None,
            })
            .unwrap();
        let mask = if lifted.bits == 32 { 0xffff_ffff } else { u64::MAX };
        assert_eq!(result & mask, expected, "{word:08x}");
    }
}

#[test]
fn shifts_divide_and_nzcv_handle_boundaries() {
    use ir::Operation::*;
    assert_eq!(ir::binary(ShiftLeft, 1, 64, 64), Some(1));
    assert_eq!(ir::binary(ArithmeticShiftRight, 0x8000_0000, 31, 32), Some(0xffff_ffff));
    assert_eq!(ir::binary(SignedDivide, i64::MIN as u64, u64::MAX, 64), Some(i64::MIN as u64));
    assert_eq!(ir::binary(UnsignedDivide, 7, 0, 64), Some(0));
    assert_eq!(ir::flags(FlagOperation::Add, u64::MAX, 1, 64), Some(6));
    assert_eq!(ir::flags(FlagOperation::Add, 0x7fff_ffff, 1, 32), Some(9));
    assert_eq!(ir::flags(FlagOperation::Subtract, 0, 1, 32), Some(8));
    assert_eq!(ir::flags(FlagOperation::Subtract, 0x8000_0000, 1, 32), Some(3));
    for flags in 0..16 {
        for condition in 0..14u8 {
            assert_eq!(ir::condition(flags, condition), ir::condition(flags, condition ^ 1).map(|value| !value));
        }
    }
}

#[test]
fn stack_pair_writeback_and_scalar_offsets_keep_addresses_and_sources() {
    for word in [0xf840_87e0, 0xf81f_83e0, 0xa9bf_7bfd, 0xa8c1_7bfd] {
        assert!(lift(word).complete, "{word:08x}");
    }
    let stp = lift(0xa9bf_7bfd);
    let mut registers = [0; 31];
    registers[29] = 99;
    registers[30] = 123;
    assert!(matches!(&stp.effects[0], Effect::Store { address, value: rhs }
        if value(address, &registers, 0x1000) == 0xff0 && value(rhs, &registers, 0x1000) == 99));
    assert!(matches!(&stp.effects[1], Effect::Store { address, value: rhs }
        if value(address, &registers, 0x1000) == 0xff8 && value(rhs, &registers, 0x1000) == 123));
    assert!(matches!(&stp.effects[2], Effect::Assign { destination: Value::StackPointer, value: rhs }
        if value(rhs, &registers, 0x1000) == 0xff0));
}

#[test]
fn shifted_zero_destinations_discard_and_overlapping_store_writeback_is_a_barrier() {
    for word in [0x8b01_001f, 0x4b01_001f] {
        assert!(matches!(lift(word).effects.last(), Some(Effect::Discard { .. })));
    }
    for word in [0xf800_8400, 0xf800_8c00] {
        assert!(!lift(word).complete);
        assert!(matches!(lift(word).effects[0], Effect::Barrier { .. }));
    }
}
