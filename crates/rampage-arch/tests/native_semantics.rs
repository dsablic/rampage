mod support;

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use super::support;
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
            Value::Unary { .. } => support::value(expr, registers),
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

    /// Runs one instruction natively with x0..x3 and packed NZCV, returning x0..x3 and the resulting NZCV.
    macro_rules! native {
        ($instruction:literal) => {
            |inputs: [u64; 4], nzcv: u64| -> ([u64; 4], u64) {
                let mut registers = inputs;
                let flags: u64;
                unsafe {
                    std::arch::asm!("msr nzcv, {input}", $instruction, "mrs {flags}, nzcv",
                        input = in(reg) nzcv << 28, flags = out(reg) flags,
                        inout("x0") registers[0], inout("x1") registers[1], inout("x2") registers[2],
                        inout("x3") registers[3], options(nomem, nostack));
                }
                (registers, flags >> 28)
            }
        };
    }

    type Native = fn([u64; 4], u64) -> ([u64; 4], u64);

    const BOUNDARIES: [u64; 10] = [
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x1_0000_0000,
        i64::MAX as u64,
        i64::MIN as u64,
        u64::MAX,
        0x0123_4567_89ab_cdef,
    ];

    /// Compares lifted and native execution over every pair of boundary values in x1/x2 (with x0 and x3 varied)
    /// and every packed NZCV state in `flags`.
    fn compare(cases: &[(u32, Native)], flags: std::ops::Range<u64>) {
        for &(word, native) in cases {
            let lifted = support::lift(word);
            assert!(lifted.complete, "{word:08x}: {lifted:?}");
            for &(_, inputs, nzcv, result, expected_nzcv) in support::EXPECTED.iter().filter(|row| row.0 == word) {
                let mut expected = inputs;
                if let Some(register) = expected.get_mut((word & 31) as usize) {
                    *register = result;
                }
                assert_eq!(native(inputs, nzcv), (expected, expected_nzcv), "recorded {word:08x} {inputs:x?}");
            }
            for (index, &left) in BOUNDARIES.iter().enumerate() {
                for &right in &BOUNDARIES {
                    let inputs = [
                        BOUNDARIES[(index + 3) % BOUNDARIES.len()] ^ 0xa5a5_5a5a_0ff0_f00f,
                        left,
                        right,
                        BOUNDARIES[(index + 7) % BOUNDARIES.len()],
                    ];
                    for nzcv in flags.clone() {
                        assert_eq!(
                            support::run(word, inputs, nzcv),
                            native(inputs, nzcv),
                            "{word:08x} inputs={inputs:x?} nzcv={nzcv:04b}"
                        );
                    }
                }
            }
        }
    }

    // Encodings below are checked with clang's LLVM integrated assembler (-cc1as -show-encoding).

    #[test]
    fn carry_arithmetic_matches_native_results_and_flags_for_every_carry_state() {
        compare(
            &[
                (0x9a02_0020, native!("adc x0, x1, x2")),
                (0xba02_0020, native!("adcs x0, x1, x2")),
                (0xda02_0020, native!("sbc x0, x1, x2")),
                (0xfa02_0020, native!("sbcs x0, x1, x2")),
                (0x1a02_0020, native!("adc w0, w1, w2")),
                (0x3a02_0020, native!("adcs w0, w1, w2")),
                (0x5a02_0020, native!("sbc w0, w1, w2")),
                (0x7a02_0020, native!("sbcs w0, w1, w2")),
                (0xda02_03e0, native!("ngc x0, x2")),
                (0x7a02_03e0, native!("ngcs w0, w2")),
                (0xba02_003f, native!("adcs xzr, x1, x2")),
                (0x9a01_0021, native!("adc x1, x1, x1")),
            ],
            0..16,
        );
    }

    #[test]
    fn conditional_compares_match_native_flags_on_both_condition_outcomes() {
        compare(
            &[
                (0xfa42_0025, native!("ccmp x1, x2, #5, eq")),
                (0xba42_b02a, native!("ccmn x1, x2, #10, lt")),
                (0x7a5f_882f, native!("ccmp w1, #31, #15, hi")),
                (0x3a40_f820, native!("ccmn w1, #0, #0, nv")),
                (0xfa47_e824, native!("ccmp x1, #7, #4, al")),
                (0x3a42_6029, native!("ccmn w1, w2, #9, vs")),
            ],
            0..16,
        );
    }

    #[test]
    fn wrapping_and_inserting_bitfields_match_native_execution() {
        compare(
            &[
                (0xb378_3c20, native!("bfi x0, x1, #8, #16")),
                (0xb345_3420, native!("bfxil x0, x1, #5, #9")),
                (0x3304_0c20, native!("bfi w0, w1, #28, #4")),
                (0x3300_7c20, native!("bfxil w0, w1, #0, #32")),
                (0xb37f_f820, native!("bfi x0, x1, #1, #63")),
                (0x9374_4c20, native!("sbfiz x0, x1, #12, #20")),
                (0xd37d_1820, native!("ubfiz x0, x1, #3, #7")),
                (0x1301_0020, native!("sbfiz w0, w1, #31, #1")),
                (0x531f_7420, native!("ubfiz w0, w1, #1, #30")),
                (0x937f_f820, native!("sbfiz x0, x1, #1, #63")),
                (0xb37c_1fe0, native!("bfc x0, #4, #8")),
            ],
            0..1,
        );
    }

    #[test]
    fn long_and_high_multiplies_match_native_execution() {
        compare(
            &[
                (0x9b22_7c20, native!("smull x0, w1, w2")),
                (0x9ba2_7c20, native!("umull x0, w1, w2")),
                (0x9b22_0c20, native!("smaddl x0, w1, w2, x3")),
                (0x9ba2_0c20, native!("umaddl x0, w1, w2, x3")),
                (0x9b22_8c20, native!("smsubl x0, w1, w2, x3")),
                (0x9ba2_8c20, native!("umsubl x0, w1, w2, x3")),
                (0x9b22_fc20, native!("smnegl x0, w1, w2")),
                (0x9b42_7c20, native!("smulh x0, x1, x2")),
                (0x9bc2_7c20, native!("umulh x0, x1, x2")),
            ],
            0..1,
        );
    }

    #[test]
    fn extracts_and_rotates_match_native_execution() {
        compare(
            &[
                (0x93c2_4420, native!("extr x0, x1, x2, #17")),
                (0x1382_7c20, native!("extr w0, w1, w2, #31")),
                (0x93c1_2420, native!("ror x0, x1, #9")),
                (0x1381_0020, native!("ror w0, w1, #0")),
                (0x93c2_0020, native!("extr x0, x1, x2, #0")),
            ],
            0..1,
        );
    }

    #[test]
    fn bit_counts_and_reversals_match_native_execution() {
        let cases: [(u32, Native); 11] = [
            (0xdac0_1020, native!("clz x0, x1")),
            (0x5ac0_1020, native!("clz w0, w1")),
            (0xdac0_1420, native!("cls x0, x1")),
            (0x5ac0_1420, native!("cls w0, w1")),
            (0xdac0_0020, native!("rbit x0, x1")),
            (0x5ac0_0020, native!("rbit w0, w1")),
            (0xdac0_0c20, native!("rev x0, x1")),
            (0x5ac0_0820, native!("rev w0, w1")),
            (0xdac0_0420, native!("rev16 x0, x1")),
            (0x5ac0_0420, native!("rev16 w0, w1")),
            (0xdac0_0820, native!("rev32 x0, x1")),
        ];
        compare(&cases, 0..1);
        let mut seed = 19u64;
        for _ in 0..256 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            for shift in [0, 7, 31, 32, 33, 63] {
                for value in [seed >> shift, !(seed >> shift)] {
                    for &(word, native) in &cases {
                        let inputs = [0, value, 0, 0];
                        assert_eq!(support::run(word, inputs, 0), native(inputs, 0), "{word:08x} {value:x}");
                    }
                }
            }
        }
    }

    #[test]
    fn conditional_select_aliases_match_native_execution_for_every_nzcv_state() {
        compare(
            &[
                (0xda81_1420, native!("cneg x0, x1, eq")),
                (0x1a81_a420, native!("cinc w0, w1, lt")),
                (0xda81_9020, native!("cinv x0, x1, hi")),
                (0x1a9f_07e0, native!("cset w0, ne")),
                (0xda9f_b3e0, native!("csetm x0, ge")),
            ],
            0..16,
        );
    }
}
