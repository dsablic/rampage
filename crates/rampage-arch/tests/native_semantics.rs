#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use rampage_arch::ir::{self, Effect, FlagOperation, Operation, Value};
    use rampage_arch::{Arch, Target, decoder};

    fn value(expr: &Value, registers: &[u64; 31]) -> u64 {
        match expr {
            Value::Constant { value } => *value,
            Value::Register { number } => registers[*number as usize],
            Value::StackPointer => unreachable!("fixture does not use SP"),
            Value::Low32 { value: expr } => value(expr, registers) & 0xffff_ffff,
            Value::Add { left, right } => value(left, registers).wrapping_add(value(right, registers)),
            Value::Subtract { left, right } => value(left, registers).wrapping_sub(value(right, registers)),
            Value::Binary { operation, left, right, bits } => {
                ir::binary(*operation, value(left, registers), value(right, registers), *bits).unwrap()
            }
        }
    }

    #[test]
    fn lifted_shifted_arithmetic_and_multiply_match_native_instructions() {
        let mut seed = 7u64;
        for _ in 0..256 {
            let mut registers = [0; 31];
            for register in &mut registers[1..4] {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                *register = seed;
            }
            let (left, right, accumulator) = (registers[1], registers[2], registers[3]);
            let (add, multiply, logical): (u64, u64, u64);
            unsafe {
                std::arch::asm!("add {add}, {left}, {right}, lsl #3", "madd {multiply}, {left}, {right}, {accumulator}",
                    "and {logical}, {left}, {right}, ror #3", left = in(reg) left, right = in(reg) right,
                    accumulator = in(reg) accumulator, add = out(reg) add, multiply = out(reg) multiply,
                    logical = out(reg) logical, options(nomem, nostack));
            }
            for (word, expected) in [(0x8b02_0c20u32, add), (0x9b02_0c20, multiply), (0x8ac2_0c20, logical)] {
                let bytes = word.to_le_bytes();
                let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x1000);
                let lifted = ir::lift(Arch::Aarch64, &bytes, &insn);
                assert!(lifted.complete);
                let Effect::Assign { value: expr, .. } = &lifted.effects[0] else { panic!("missing assignment") };
                assert_eq!(value(expr, &registers), expected, "{word:08x}");
            }
        }
    }

    #[test]
    fn conditional_select_and_bitfield_aliases_match_native_execution() {
        let mut seed = 11u64;
        for _ in 0..128 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let left = seed;
            let right = seed.rotate_left(17);
            let (selected, bitfield, signed_byte): (u64, u64, u64);
            let nzcv: u64;
            unsafe {
                std::arch::asm!("cmp {left}, {right}", "mrs {flags}, nzcv", "csel {selected}, {left}, {right}, eq",
                    "ubfx {bitfield}, {left}, #5, #9", "sxtb {signed_byte}, {left:w}",
                    left = in(reg) left, right = in(reg) right, flags = out(reg) nzcv,
                    selected = out(reg) selected, bitfield = out(reg) bitfield, signed_byte = out(reg) signed_byte,
                    options(nomem, nostack));
            }
            let mut registers = [0; 31];
            registers[1] = left;
            registers[2] = right;
            for (word, expected) in [(0xd345_3420u32, bitfield), (0x9340_1c20, signed_byte), (0x9a82_0020, selected)] {
                let bytes = word.to_le_bytes();
                let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x1000);
                let lifted = ir::lift(Arch::Aarch64, &bytes, &insn);
                let actual = match &lifted.effects[0] {
                    Effect::Assign { value: expr, .. } => value(expr, &registers),
                    Effect::Select { condition, when_true, when_false, .. } => value(
                        if ir::condition(nzcv >> 28, *condition).unwrap() { when_true } else { when_false },
                        &registers,
                    ),
                    _ => panic!("unsupported fixture"),
                };
                assert_eq!(actual, expected, "{word:08x}");
            }
        }
    }

    #[test]
    fn arithmetic_and_nzcv_agree_with_native_aarch64_execution() {
        let cases = [0, 1, 7, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, i64::MAX as u64, i64::MIN as u64, u64::MAX];
        for left in cases {
            for right in cases {
                let (sum, sum_flags, difference, difference_flags): (u64, u64, u64, u64);
                unsafe {
                    std::arch::asm!("adds {sum}, {left}, {right}", "mrs {sum_flags}, nzcv",
                        "subs {difference}, {left}, {right}", "mrs {difference_flags}, nzcv",
                        left = in(reg) left, right = in(reg) right, sum = out(reg) sum,
                        sum_flags = out(reg) sum_flags, difference = out(reg) difference,
                        difference_flags = out(reg) difference_flags, options(nomem, nostack));
                }
                assert_eq!(sum, left.wrapping_add(right));
                assert_eq!(difference, left.wrapping_sub(right));
                assert_eq!(ir::flags(FlagOperation::Add, left, right, 64), Some(sum_flags >> 28));
                assert_eq!(ir::flags(FlagOperation::Subtract, left, right, 64), Some(difference_flags >> 28));
                let (product, quotient, signed_quotient, shifted): (u64, u64, u64, u64);
                unsafe {
                    std::arch::asm!("mul {product}, {left}, {right}", "udiv {quotient}, {left}, {right}",
                        "sdiv {signed_quotient}, {left}, {right}", "asr {shifted}, {left}, {right}",
                        left = in(reg) left, right = in(reg) right, product = out(reg) product,
                        quotient = out(reg) quotient, signed_quotient = out(reg) signed_quotient,
                        shifted = out(reg) shifted, options(nomem, nostack));
                }
                assert_eq!(ir::binary(Operation::Multiply, left, right, 64), Some(product));
                assert_eq!(ir::binary(Operation::UnsignedDivide, left, right, 64), Some(quotient));
                assert_eq!(ir::binary(Operation::SignedDivide, left, right, 64), Some(signed_quotient));
                assert_eq!(ir::binary(Operation::ArithmeticShiftRight, left, right, 64), Some(shifted));
                let (sum32, flags32, signed32, rotate32): (u64, u64, u64, u64);
                unsafe {
                    std::arch::asm!("adds {sum:w}, {left:w}, {right:w}", "mrs {flags}, nzcv",
                        "sdiv {signed:w}, {left:w}, {right:w}", "ror {rotate:w}, {left:w}, {right:w}",
                        left = in(reg) left, right = in(reg) right, sum = out(reg) sum32,
                        flags = out(reg) flags32, signed = out(reg) signed32, rotate = out(reg) rotate32,
                        options(nomem, nostack));
                }
                assert_eq!(sum32, left.wrapping_add(right) & 0xffff_ffff);
                assert_eq!(ir::flags(FlagOperation::Add, left, right, 32), Some(flags32 >> 28));
                assert_eq!(ir::binary(Operation::SignedDivide, left, right, 32), Some(signed32));
                assert_eq!(ir::binary(Operation::RotateRight, left, right, 32), Some(rotate32));
            }
        }
    }

    #[test]
    fn every_condition_code_matches_native_nzcv_tests() {
        for flags in 0..16u64 {
            let mut observed = [0u64; 16];
            unsafe {
                std::arch::asm!(
                    "mrs {saved}, nzcv", "msr nzcv, {flags}",
                    "cset {value}, eq", "str {value}, [{output}, #0]",
                    "cset {value}, ne", "str {value}, [{output}, #8]",
                    "cset {value}, hs", "str {value}, [{output}, #16]",
                    "cset {value}, lo", "str {value}, [{output}, #24]",
                    "cset {value}, mi", "str {value}, [{output}, #32]",
                    "cset {value}, pl", "str {value}, [{output}, #40]",
                    "cset {value}, vs", "str {value}, [{output}, #48]",
                    "cset {value}, vc", "str {value}, [{output}, #56]",
                    "cset {value}, hi", "str {value}, [{output}, #64]",
                    "cset {value}, ls", "str {value}, [{output}, #72]",
                    "cset {value}, ge", "str {value}, [{output}, #80]",
                    "cset {value}, lt", "str {value}, [{output}, #88]",
                    "cset {value}, gt", "str {value}, [{output}, #96]",
                    "cset {value}, le", "str {value}, [{output}, #104]",
                    "csel {value}, {one}, xzr, al", "str {value}, [{output}, #112]",
                    "csel {value}, {one}, xzr, nv", "str {value}, [{output}, #120]",
                    "msr nzcv, {saved}",
                    saved = out(reg) _, value = out(reg) _, flags = in(reg) flags << 28,
                    output = in(reg) observed.as_mut_ptr(), one = in(reg) 1u64,
                    options(nostack),
                );
            }
            for (condition, value) in observed.into_iter().enumerate() {
                assert_eq!(
                    ir::condition(flags, condition as u8),
                    Some(value != 0),
                    "flags={flags} condition={condition}"
                );
            }
        }
    }

    #[test]
    fn extended_arithmetic_matches_native_width_and_sign_rules() {
        for right in [0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x8000_0000, u64::MAX] {
            let (byte, word, narrow): (u64, u64, u64);
            let left = 0xffff_ffff_1234_5678u64;
            unsafe {
                std::arch::asm!(
                    "add {byte}, {left}, {right:w}, sxtb #1",
                    "add {word}, {left}, {right:w}, uxtw #3",
                    "sub {narrow:w}, {left:w}, {right:w}, sxth #2",
                    left = in(reg) left, right = in(reg) right, byte = out(reg) byte,
                    word = out(reg) word, narrow = out(reg) narrow,
                    options(nomem, nostack),
                );
            }
            let mut registers = [0; 31];
            registers[1] = left;
            registers[2] = right;
            for (word, expected) in [(0x8b22_8420u32, byte), (0x8b22_4c20, word), (0x4b22_a820, narrow)] {
                let bytes = word.to_le_bytes();
                let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x1000);
                let lifted = ir::lift(Arch::Aarch64, &bytes, &insn);
                assert!(lifted.complete);
                let Effect::Assign { value: expr, .. } = &lifted.effects[0] else { panic!("missing assignment") };
                let mask = if lifted.bits == 32 { 0xffff_ffff } else { u64::MAX };
                assert_eq!(value(expr, &registers) & mask, expected, "{word:08x}");
            }
        }
    }

    #[test]
    fn scalar_load_extension_matches_native_memory_reads() {
        let bytes = [0x80u8, 0xff, 0x00, 0x80, 0xff, 0xff, 0xff, 0xff];
        let (unsigned_byte, signed_byte32, signed_half64, signed_word64): (u64, u64, u64, u64);
        unsafe {
            std::arch::asm!(
                "ldrb {unsigned:w}, [{base}]", "ldrsb {byte:w}, [{base}]",
                "ldrsh {half}, [{base}]", "ldrsw {word}, [{base}]",
                base = in(reg) bytes.as_ptr(), unsigned = out(reg) unsigned_byte,
                byte = out(reg) signed_byte32, half = out(reg) signed_half64, word = out(reg) signed_word64,
                options(readonly, nostack),
            );
        }
        for (word, raw, expected) in [
            (0x3940_0020u32, 0x80, unsigned_byte),
            (0x39c0_0020, 0x80, signed_byte32),
            (0x7980_0020, 0xff80, signed_half64),
            (0xb980_0020, 0x8000_ff80, signed_word64),
        ] {
            let encoding = word.to_le_bytes();
            let instruction = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&encoding, 0x1000);
            let lifted = ir::lift(Arch::Aarch64, &encoding, &instruction);
            assert!(lifted.complete);
            let Effect::MemoryLoad { bits, result_bits, signed, .. } = lifted.effects[0] else {
                panic!("missing memory load");
            };
            assert_eq!(ir::extend(raw, bits, result_bits, signed), Some(expected), "{word:08x}");
        }
    }
}
