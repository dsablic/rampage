mod support;

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
        Value::Unary { operation, value, bits } => {
            ir::unary(*operation, self::value(value, registers, sp), *bits).unwrap()
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

#[test]
fn conditional_selects_preserve_condition_and_false_arm_transform() {
    let mut registers = [0; 31];
    registers[1] = 7;
    registers[2] = 11;
    for (word, condition, expected_false) in
        [(0x9a82_0020, 0, 11), (0x1a82_1420, 1, 12), (0xda82_b020, 11, !11u64), (0x5a82_c420, 12, 0xffff_fff5)]
    {
        let lifted = lift(word);
        assert!(lifted.complete);
        let Effect::Select { condition: actual, when_true, when_false, .. } = &lifted.effects[0] else {
            panic!("not select")
        };
        assert_eq!(*actual, condition);
        assert_eq!(value(when_true, &registers, 0), 7);
        let mask = if lifted.bits == 32 { 0xffff_ffff } else { u64::MAX };
        assert_eq!(value(when_false, &registers, 0) & mask, expected_false);
    }
}

#[test]
fn common_bitfield_aliases_have_correct_width_and_sign_semantics() {
    let mut registers = [0; 31];
    registers[1] = 0xffff_ffff_8000_00f3;
    for (word, expected) in [
        (0xd37d_f020, registers[1] << 3),
        (0x5307_7c20, 0x0100_0001),
        (0x934b_fc20, 0xffff_ffff_fff0_0000),
        (0xd345_3420, 7),
        (0x9340_1c20, 0xffff_ffff_ffff_fff3),
    ] {
        let lifted = lift(word);
        assert!(lifted.complete, "{word:08x}");
        let Effect::Assign { value: expr, .. } = &lifted.effects[0] else { panic!("missing assignment") };
        let mask = if lifted.bits == 32 { 0xffff_ffff } else { u64::MAX };
        assert_eq!(value(expr, &registers, 0) & mask, expected, "{word:08x}");
    }
}

#[test]
fn extended_arithmetic_handles_sign_zero_stack_and_discard_operands() {
    let mut registers = [0; 31];
    registers[1] = 0xffff_ffff_8000_00ff;
    registers[2] = 0xffff_ffff_ffff_ffff;
    for (word, expected) in [(0x8b21_4fe0, 0x4_0000_17f8), (0xcb21_63ff, 0x8000_0f01), (0x0b22_8420, 0x8000_00fd)] {
        let lifted = lift(word);
        assert!(lifted.complete, "{word:08x}");
        let Effect::Assign { value: expr, .. } = &lifted.effects[0] else { panic!("missing assignment") };
        let mask = if lifted.bits == 32 { 0xffff_ffff } else { u64::MAX };
        assert_eq!(value(expr, &registers, 0x1000) & mask, expected, "{word:08x}");
    }
    let lifted = lift(0xab21_cbff);
    assert!(matches!(lifted.effects[0], Effect::SetFlags { .. }));
    assert!(matches!(lifted.effects[1], Effect::Discard { .. }));
    assert!(!lift(0x8b21_57e0).complete);
}

#[test]
fn scalar_memory_tracks_access_width_result_extension_and_full_width_writeback() {
    let mut registers = [0; 31];
    registers[1] = 0x2000;
    registers[2] = u64::MAX;
    for (word, bits, result_bits, signed, expected_address) in [
        (0x3940_0fe0, 8, 32, false, 0x1000_0000_0003),
        (0x3980_0c20, 8, 64, true, 0x2003),
        (0x79c0_07e0, 16, 32, true, 0x1000_0000_0002),
        (0xb840_47e0, 32, 32, false, 0x1000_0000_0000),
        (0xb89f_cfe0, 32, 64, true, 0x0fff_ffff_fffc),
        (0x385f_f020, 8, 32, false, 0x1fff),
        (0x78a2_d820, 16, 64, true, 0x1ffe),
        (0xf862_7820, 64, 64, false, 0x1ff8),
        (0x1800_0040, 32, 32, false, 0x1008),
        (0x9800_0040, 32, 64, true, 0x1008),
    ] {
        let lifted = lift(word);
        assert!(lifted.complete, "{word:08x}");
        assert_eq!(lifted.bits, 64);
        assert!(
            matches!(&lifted.effects[0], Effect::MemoryLoad { address, bits: actual_bits,
            result_bits: actual_result, signed: actual_signed, .. } if *actual_bits == bits
            && *actual_result == result_bits && *actual_signed == signed
            && value(address, &registers, 0x1000_0000_0000) == expected_address),
            "{word:08x}"
        );
    }
    let post = lift(0xb840_47e0);
    assert!(matches!(&post.effects[1], Effect::Assign { destination: Value::StackPointer, value: expr }
        if value(expr, &registers, 0x1000_0000_0000) == 0x1000_0000_0004));
    for (word, expected_bits) in [(0x7900_07e0, 16), (0x3822_4820, 8)] {
        assert!(matches!(lift(word).effects[0], Effect::MemoryStore { bits, .. } if bits == expected_bits));
    }
    assert_eq!(ir::extend(0x80, 8, 32, true), Some(0xffff_ff80));
    assert_eq!(ir::extend(0x8000, 16, 64, true), Some(0xffff_ffff_ffff_8000));
    assert_eq!(ir::extend(u64::MAX, 8, 64, false), Some(255));
}

#[test]
fn word_pairs_scale_offsets_and_signed_pair_results_independently_of_sp() {
    let registers = [0; 31];
    let stp = lift(0x29bf_07e0);
    assert!(stp.complete);
    assert_eq!(stp.bits, 64);
    for (effect, expected) in stp.effects[..2].iter().zip([0xffff_fff8, 0xffff_fffc]) {
        assert!(matches!(effect, Effect::MemoryStore { address, bits: 32, .. }
            if value(address, &registers, 0x1_0000_0000) == expected));
    }
    let ldp = lift(0x28c1_0fe2);
    assert!(matches!(ldp.effects[0], Effect::MemoryLoad { bits: 32, result_bits: 32, signed: false, .. }));
    assert!(matches!(&ldp.effects[2], Effect::Assign { destination: Value::StackPointer, value: expr }
        if value(expr, &registers, 0x1_0000_0000) == 0x1_0000_0008));
    let signed = lift(0x697f_0fe2);
    assert!(signed.complete);
    assert!(
        signed
            .effects
            .iter()
            .all(|effect| matches!(effect, Effect::MemoryLoad { bits: 32, result_bits: 64, signed: true, .. }))
    );
}

fn execute_pair_load(lifted: &LiftedInstruction, registers: &mut [u64; 31], sp: u64) -> Vec<(u64, u8, u8, bool)> {
    let loaded_values = [0xffff_ffff_8000_0001, u64::MAX];
    let mut accesses = Vec::new();
    for effect in &lifted.effects {
        let loads = match effect {
            Effect::MemoryLoadPair { destinations, addresses, bits, result_bits, signed } => destinations
                .iter()
                .zip(addresses)
                .map(|(destination, address)| {
                    (destination.clone(), value(address, registers, sp), *bits, *result_bits, *signed)
                })
                .collect::<Vec<_>>(),
            Effect::MemoryLoad { destination, address, bits, result_bits, signed } => {
                vec![(destination.clone(), value(address, registers, sp), *bits, *result_bits, *signed)]
            }
            Effect::Load { destination, address } => {
                vec![(destination.clone(), value(address, registers, sp), 64, 64, false)]
            }
            Effect::LoadDiscard { address } => {
                vec![(Value::Constant { value: 0 }, value(address, registers, sp), 64, 64, false)]
            }
            _ => panic!("unexpected pair effect: {effect:?}"),
        };
        for (destination, address, bits, result_bits, signed) in loads {
            let loaded = loaded_values[accesses.len()];
            accesses.push((address, bits, result_bits, signed));
            match destination {
                Value::Register { number } => {
                    registers[number as usize] = ir::extend(loaded, bits, result_bits, signed).unwrap();
                }
                Value::Constant { value: 0 } => {}
                _ => panic!("pair load must not write SP: {destination:?}"),
            }
        }
    }
    accesses
}

#[test]
fn llvm_checked_no_writeback_pair_overlaps_keep_both_original_addresses() {
    // Encodings checked with clang's LLVM integrated assembler (-cc1as -show-encoding).
    for (word, base, destinations, offset, bits, result_bits, signed) in [
        (0xa940_0400, 0, [Some(0), Some(1)], 0, 64, 64, false), // ldp x0, x1, [x0]
        (0xa940_0420, 1, [Some(0), Some(1)], 0, 64, 64, false), // ldp x0, x1, [x1]
        (0xa960_0400, 0, [Some(0), Some(1)], -512, 64, 64, false),
        (0xa95f_8400, 0, [Some(0), Some(1)], 504, 64, 64, false),
        (0x2940_0400, 0, [Some(0), Some(1)], 0, 32, 32, false), // ldp w0, w1, [x0]
        (0x2940_0420, 1, [Some(0), Some(1)], 0, 32, 32, false), // ldp w0, w1, [x1]
        (0x2960_0400, 0, [Some(0), Some(1)], -256, 32, 32, false),
        (0x295f_8400, 0, [Some(0), Some(1)], 252, 32, 32, false),
        (0x6940_0400, 0, [Some(0), Some(1)], 0, 32, 64, true), // ldpsw x0, x1, [x0]
        (0x6940_0420, 1, [Some(0), Some(1)], 0, 32, 64, true), // ldpsw x0, x1, [x1]
        (0x6960_0400, 0, [Some(0), Some(1)], -256, 32, 64, true),
        (0x695f_8400, 0, [Some(0), Some(1)], 252, 32, 64, true),
        (0xa940_fc00, 0, [Some(0), None], 8, 64, 64, false), // ldp x0, xzr, [x0, #8]
        (0xa97f_801f, 0, [None, Some(0)], -8, 64, 64, false), // ldp xzr, x0, [x0, #-8]
        (0x2940_fc00, 0, [Some(0), None], 4, 32, 32, false),
        (0x297f_801f, 0, [None, Some(0)], -4, 32, 32, false),
        (0x6940_fc00, 0, [Some(0), None], 4, 32, 64, true),
        (0x697f_801f, 0, [None, Some(0)], -4, 32, 64, true),
    ] {
        let lifted = lift(word);
        assert!(lifted.complete, "{word:08x}");
        assert_eq!(lifted.bits, 64, "{word:08x}");
        for original_base in [0u64, 0x1_0000_0000, u64::MAX - 3] {
            let mut registers = [7; 31];
            registers[base] = original_base;
            let first_address = original_base.wrapping_add(offset as u64);
            assert_eq!(
                execute_pair_load(&lifted, &mut registers, 0x2000),
                [
                    (first_address, bits, result_bits, signed),
                    (first_address.wrapping_add(u64::from(bits / 8)), bits, result_bits, signed),
                ],
                "{word:08x}, base={original_base:x}"
            );
            let expected_values =
                if result_bits == 32 { [0x8000_0001, 0xffff_ffff] } else { [0xffff_ffff_8000_0001, u64::MAX] };
            for (destination, expected) in destinations.into_iter().zip(expected_values) {
                if let Some(number) = destination {
                    assert_eq!(registers[number], expected, "{word:08x}");
                }
            }
            assert_eq!(registers[2], 7, "{word:08x}");
        }
    }
}

#[test]
fn llvm_checked_pair_register_31_roles_and_overlapping_stores_are_unchanged() {
    for (word, offset, bits, result_bits, signed) in [
        (0xa960_03ff, -512, 64, 64, false), // ldp xzr, x0, [sp, #-512]
        (0xa95f_ffe0, 504, 64, 64, false),  // ldp x0, xzr, [sp, #504]
        (0x2960_03ff, -256, 32, 32, false),
        (0x295f_ffe0, 252, 32, 32, false),
        (0x6960_03ff, -256, 32, 64, true),
        (0x695f_ffe0, 252, 32, 64, true),
    ] {
        let lifted = lift(word);
        assert!(lifted.complete, "{word:08x}");
        let mut registers = [7; 31];
        let first_address = 0x1_0000_0000u64.wrapping_add(offset as u64);
        assert_eq!(
            execute_pair_load(&lifted, &mut registers, 0x1_0000_0000),
            [
                (first_address, bits, result_bits, signed),
                (first_address + u64::from(bits / 8), bits, result_bits, signed),
            ],
            "{word:08x}"
        );
        assert_eq!(registers[1], 7);
    }
    for (word, base, offset, bits) in [
        (0xa920_0400, 0, -512, 64), // stp x0, x1, [x0, #-512]
        (0x291f_8420, 1, 252, 32),  // stp w0, w1, [x1, #252]
    ] {
        let lifted = lift(word);
        assert!(lifted.complete, "{word:08x}");
        assert_eq!(lifted.effects.len(), 2);
        let mut registers = [0; 31];
        registers[0] = 0x1_0000_0000;
        registers[1] = 0x2_0000_0000;
        for (index, effect) in lifted.effects.iter().enumerate() {
            let (address, source) = match effect {
                Effect::Store { address, value } if bits == 64 => (address, value),
                Effect::MemoryStore { address, value, bits: actual_bits } if *actual_bits == bits => (address, value),
                _ => panic!("unexpected store: {effect:?}"),
            };
            assert_eq!(value(source, &registers, 0), registers[index], "{word:08x}");
            assert_eq!(
                value(address, &registers, 0),
                registers[base].wrapping_add(offset as u64).wrapping_add(index as u64 * u64::from(bits / 8)),
                "{word:08x}"
            );
        }
    }
}

#[test]
fn constrained_unpredictable_pair_overlaps_and_invalid_encodings_remain_barriers() {
    for word in [
        0xa9c1_0400,
        0xa9c1_0420,
        0xa8c1_0400,
        0xa8c1_0420, // x pair pre/post base overlaps
        0x29c1_0400,
        0x29c1_0420,
        0x28c1_0400,
        0x28c1_0420, // w pair pre/post base overlaps
        0x69c1_0400,
        0x69c1_0420,
        0x68c1_0400,
        0x68c1_0420, // signed pair pre/post base overlaps
        0xa940_0000,
        0x2940_0000,
        0x6940_0000, // duplicate destinations without writeback
        0xa940_7fff,
        0x2940_7fff,
        0x6940_7fff, // duplicate zero destinations with SP base
        0xa981_0400,
        0xa881_0420,
        0x2981_0400,
        0x2881_0420, // overlapping store writeback
        0xe940_0400,
        0x0000_0000, // unallocated encodings
    ] {
        let lifted = lift(word);
        assert!(!lifted.complete, "{word:08x}");
        assert!(matches!(lifted.effects.as_slice(), [Effect::Barrier { .. }]), "{word:08x}");
    }
}

#[test]
fn unsupported_scalar_neighbours_and_reserved_widths_remain_barriers() {
    // ctz/cnt/abs (FEAT_CSSC), rmif, setf8, and 32-bit bitfield/extract shapes with 6-bit amounts.
    for word in [0xdac0_1820, 0xdac0_1c20, 0xdac0_2020, 0xba00_0420, 0x3a00_082d, 0x3320_0020, 0x1382_8020] {
        let lifted = lift(word);
        assert!(!lifted.complete, "{word:08x}");
        assert!(matches!(lifted.effects.as_slice(), [Effect::Barrier { .. }]), "{word:08x}");
    }
}

#[test]
fn carry_and_conditional_compare_effects_keep_their_operands_and_immediates() {
    let lifted = lift(0xfa02_03e0); // ngcs x0, x2
    assert!(matches!(
        &lifted.effects[..],
        [Effect::CarryArithmetic {
            left: Value::Constant { value: 0 },
            right: Value::Register { number: 2 },
            subtract: true,
            set_flags: true,
            ..
        }]
    ));
    let lifted = lift(0x7a5f_882f); // ccmp w1, #31, #15, hi
    assert_eq!(lifted.bits, 32);
    assert!(matches!(
        &lifted.effects[..],
        [Effect::ConditionalFlags {
            condition: 8,
            operation: FlagOperation::Subtract,
            right: Value::Constant { value: 31 },
            nzcv: 15,
            ..
        }]
    ));
}

#[test]
fn natively_recorded_integer_family_boundaries_replay_through_the_lifted_effects() {
    for &(word, inputs, nzcv, result, expected_nzcv) in support::EXPECTED {
        let mut expected = inputs;
        if let Some(register) = expected.get_mut((word & 31) as usize) {
            *register = result;
        }
        assert_eq!(support::run(word, inputs, nzcv), (expected, expected_nzcv), "{word:08x} {inputs:x?} {nzcv:04b}");
    }
}
