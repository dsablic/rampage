//! Carry, conditional-compare, high-multiply and unary AArch64 effects evaluated through SSA and constant dataflow.

use std::collections::BTreeMap;

use rampage_analysis::{
    dataflow,
    ssa::{self, InputBlock, Variable},
};
use rampage_arch::ir::{self, Effect, FlagOperation, LiftedInstruction, Value};
use rampage_arch::{Arch, Flow, Target, decoder};

fn setup(address: u64, effects: Vec<Effect>) -> LiftedInstruction {
    LiftedInstruction { address, bits: 64, flow: Flow::Next, complete: true, effects }
}

/// Runs `word` after fixing x0..x3 and the packed NZCV, returning x0..x3 and NZCV as dataflow constants.
fn evaluate(word: u32, inputs: [u64; 4], nzcv: u64) -> ([Option<u64>; 4], Option<u64>) {
    let assignments = (0..4u8)
        .map(|number| Effect::Assign {
            destination: Value::Register { number },
            value: Value::Constant { value: inputs[usize::from(number)] },
        })
        .collect();
    let zero = || Value::Constant { value: 0 };
    let bytes = word.to_le_bytes();
    let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x10);
    let lifted = ir::lift(Arch::Aarch64, &bytes, &insn);
    assert!(lifted.complete, "{word:08x}");
    let input = vec![InputBlock {
        address: 0,
        instructions: vec![
            setup(0, assignments),
            // 0 - 1 leaves Z clear, so the EQ conditional compare installs `nzcv` from its immediate.
            setup(
                4,
                vec![Effect::SetFlags {
                    operation: FlagOperation::Subtract,
                    left: zero(),
                    right: Value::Constant { value: 1 },
                }],
            ),
            setup(
                8,
                vec![Effect::ConditionalFlags {
                    condition: 0,
                    operation: FlagOperation::Subtract,
                    left: zero(),
                    right: zero(),
                    nzcv: nzcv as u8,
                }],
            ),
            lifted,
        ],
    }];
    let ssa = ssa::build(&input, &[], 0).unwrap();
    let constants: BTreeMap<_, _> = dataflow::analyze(&ssa)
        .unwrap()
        .constants
        .into_iter()
        .map(|constant| (constant.definition, constant.value))
        .collect();
    let mut registers = inputs.map(Some);
    let mut flags = Some(nzcv);
    for &id in &ssa.blocks[0].statements[3].definitions {
        let value = constants.get(&id).copied();
        match ssa.definitions[id].variable {
            Variable::Register { number } if number < 4 => registers[usize::from(number)] = value,
            Variable::Flags => flags = value,
            variable => panic!("unexpected definition of {variable:?}"),
        }
    }
    (registers, flags)
}

#[test]
fn carry_and_conditional_compare_lowering_reproduces_recorded_native_boundaries() {
    // Rows recorded from native AArch64 execution (see rampage-arch native_semantics).
    for (word, inputs, nzcv, result, expected_nzcv) in [
        (0xba02_0020u32, [0, u64::MAX, 0, 0], 0b0010, 0, 0b0110),
        (0xba02_0020, [0, 0x7fff_ffff_ffff_ffff, 0, 0], 0b0010, 0x8000_0000_0000_0000, 0b1001),
        (0xfa02_0020, [0, 0, 0, 0], 0b0000, u64::MAX, 0b1000),
        (0xfa02_0020, [0, 0x8000_0000_0000_0000, 0, 0], 0b0000, 0x7fff_ffff_ffff_ffff, 0b0011),
        (0x3a02_0020, [0, 0x7fff_ffff, 0, 0], 0b0010, 0x8000_0000, 0b1001),
        (0x5a02_0020, [u64::MAX, 0, 0, 0], 0b0000, 0xffff_ffff, 0b0000),
        (0xba02_003f, [7, u64::MAX, 1, 0], 0b0000, 0, 0b0110),
        (0x9a01_0021, [0, 5, 0, 0], 0b0010, 0xb, 0b0010),
        (0xfa42_0025, [0, 3, 3, 0], 0b0100, 0, 0b0110),
        (0xfa42_0025, [0, 3, 3, 0], 0b0000, 0, 0b0101),
        (0x7a5f_882f, [0, 0x1f, 0, 0], 0b0110, 0, 0b1111),
        (0x9bc2_7c20, [0, u64::MAX, u64::MAX, 0], 0b0000, 0xffff_ffff_ffff_fffe, 0b0000),
        (0x9b42_7c20, [0, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0], 0b0000, 0x4000_0000_0000_0000, 0b0000),
        (0x5ac0_1420, [0, 0xffff_c000, 0, 0], 0b0000, 0x11, 0b0000),
        (0xdac0_0420, [0, 0x123_4567_89ab_cdef, 0, 0], 0b0000, 0x2301_6745_ab89_efcd, 0b0000),
    ] {
        let mut expected = inputs.map(Some);
        if let Some(register) = expected.get_mut((word & 31) as usize) {
            *register = Some(result);
        }
        assert_eq!(evaluate(word, inputs, nzcv), (expected, Some(expected_nzcv)), "{word:08x} {inputs:x?}");
    }
}

#[test]
fn carry_results_stay_unknown_when_the_incoming_carry_is_unknown() {
    let bytes = 0xba02_0020u32.to_le_bytes();
    let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0);
    let input = vec![InputBlock { address: 0, instructions: vec![ir::lift(Arch::Aarch64, &bytes, &insn)] }];
    let ssa = ssa::build(&input, &[], 0).unwrap();
    let constants = dataflow::analyze(&ssa).unwrap().constants;
    for id in &ssa.blocks[0].statements[0].definitions {
        assert!(!constants.iter().any(|constant| constant.definition == *id));
    }
}

#[test]
fn new_operations_render_in_pseudocode() {
    let words = [0xba02_0020u32, 0xfa42_0025, 0x9b42_7c20, 0xdac0_1020, 0x5ac0_0420];
    let instructions = words
        .iter()
        .enumerate()
        .map(|(index, word)| {
            let bytes = word.to_le_bytes();
            let address = index as u64 * 4;
            let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, address);
            ir::lift(Arch::Aarch64, &bytes, &insn)
        })
        .collect();
    let ssa = ssa::build(&[InputBlock { address: 0, instructions }], &[], 0).unwrap();
    let text = rampage_analysis::pseudocode::render(&ssa, &[]).unwrap().text;
    for fragment in ["condition(", "flags_sub64(", "flags_add64(", "smulh64(", "clz64(", "rev16_32("] {
        assert!(text.contains(fragment), "{fragment} missing from {text}");
    }
}

#[cfg(target_arch = "aarch64")]
mod native {
    use super::evaluate;

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

    #[test]
    fn ssa_dataflow_of_flag_dependent_families_matches_native_execution() {
        let boundaries = [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, i64::MAX as u64, i64::MIN as u64, u64::MAX];
        let cases: [(u32, Native); 16] = [
            (0x9a02_0020, native!("adc x0, x1, x2")),
            (0xba02_0020, native!("adcs x0, x1, x2")),
            (0xda02_0020, native!("sbc x0, x1, x2")),
            (0xfa02_0020, native!("sbcs x0, x1, x2")),
            (0x3a02_0020, native!("adcs w0, w1, w2")),
            (0x7a02_0020, native!("sbcs w0, w1, w2")),
            (0x7a02_03e0, native!("ngcs w0, w2")),
            (0xba02_003f, native!("adcs xzr, x1, x2")),
            (0x9a01_0021, native!("adc x1, x1, x1")),
            (0xfa42_0025, native!("ccmp x1, x2, #5, eq")),
            (0x7a5f_882f, native!("ccmp w1, #31, #15, hi")),
            (0x3a42_6029, native!("ccmn w1, w2, #9, vs")),
            (0x9b42_7c20, native!("smulh x0, x1, x2")),
            (0x9bc2_7c20, native!("umulh x0, x1, x2")),
            (0x5ac0_1420, native!("cls w0, w1")),
            (0xdac0_0820, native!("rev32 x0, x1")),
        ];
        for (word, native) in cases {
            for left in boundaries {
                for right in boundaries {
                    let inputs = [0x0ff0_f00f_a5a5_5a5a, left, right, 3];
                    for nzcv in 0..16 {
                        let (registers, flags) = native(inputs, nzcv);
                        assert_eq!(
                            evaluate(word, inputs, nzcv),
                            (registers.map(Some), Some(flags)),
                            "{word:08x} {inputs:x?} {nzcv:04b}"
                        );
                    }
                }
            }
        }
    }
}
