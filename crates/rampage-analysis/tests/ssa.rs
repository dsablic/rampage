use rampage_analysis::ssa::{self, Expression, InputBlock, Ssa, Variable};
use rampage_arch::Flow;
use rampage_arch::ir::{Effect, LiftedInstruction, Value};

fn assign(at: u64, number: u8, value: Value, bits: u8) -> LiftedInstruction {
    LiftedInstruction {
        address: at,
        bits,
        flow: Flow::Next,
        complete: true,
        effects: vec![Effect::Assign { destination: Value::Register { number }, value }],
    }
}

fn block(address: u64, instructions: Vec<LiftedInstruction>) -> InputBlock {
    InputBlock { address, instructions }
}

fn evaluate(ssa: &Ssa, value: &Expression, predecessors: &[Option<usize>], depth: usize) -> Option<u64> {
    evaluate_inputs(ssa, value, predecessors, &[], depth)
}

fn evaluate_inputs(
    ssa: &Ssa,
    value: &Expression,
    predecessors: &[Option<usize>],
    inputs: &[u64],
    depth: usize,
) -> Option<u64> {
    if depth > 100 {
        return None;
    }
    match value {
        Expression::Constant { value } => Some(*value),
        Expression::Reference { definition } => {
            let definition = &ssa.definitions[*definition];
            if matches!(definition.expression, Expression::Input) {
                match definition.variable {
                    Variable::Register { number } => inputs.get(usize::from(number)).copied(),
                    Variable::StackPointer => inputs.get(31).copied(),
                    _ => None,
                }
            } else {
                evaluate_inputs(ssa, &definition.expression, predecessors, inputs, depth + 1)
            }
        }
        Expression::Add { left, right } => {
            Some(evaluate_inputs(ssa, left, predecessors, inputs, depth + 1)?.wrapping_add(evaluate_inputs(
                ssa,
                right,
                predecessors,
                inputs,
                depth + 1,
            )?))
        }
        Expression::Subtract { left, right } => {
            Some(evaluate_inputs(ssa, left, predecessors, inputs, depth + 1)?.wrapping_sub(evaluate_inputs(
                ssa,
                right,
                predecessors,
                inputs,
                depth + 1,
            )?))
        }
        Expression::Low32 { value } => {
            Some(evaluate_inputs(ssa, value, predecessors, inputs, depth + 1)? & 0xffff_ffff)
        }
        Expression::Extend { value, from_bits, to_bits, signed } => rampage_arch::ir::extend(
            evaluate_inputs(ssa, value, predecessors, inputs, depth + 1)?,
            *from_bits,
            *to_bits,
            *signed,
        ),
        Expression::Binary { operation, left, right, bits } => rampage_arch::ir::binary(
            *operation,
            evaluate_inputs(ssa, left, predecessors, inputs, depth + 1)?,
            evaluate_inputs(ssa, right, predecessors, inputs, depth + 1)?,
            *bits,
        ),
        Expression::Phi { inputs: phi_inputs } => {
            let input = phi_inputs.iter().find(|input| predecessors.contains(&input.predecessor))?;
            evaluate_inputs(
                ssa,
                &Expression::Reference { definition: input.definition },
                predecessors,
                inputs,
                depth + 1,
            )
        }
        _ => None,
    }
}

#[test]
fn diamond_phi_uses_each_predecessors_definition() {
    let blocks = vec![
        block(0x1000, vec![]),
        block(0x1010, vec![assign(0x1010, 0, Value::Constant { value: 7 }, 64)]),
        block(0x1020, vec![assign(0x1020, 0, Value::Constant { value: 11 }, 64)]),
        block(
            0x1030,
            vec![assign(
                0x1030,
                1,
                Value::Add {
                    left: Box::new(Value::Register { number: 0 }),
                    right: Box::new(Value::Constant { value: 3 }),
                },
                64,
            )],
        ),
    ];
    let ssa = ssa::build(&blocks, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap();
    let result = ssa.blocks[3].statements[0].definitions[0];
    for (predecessor, expected) in [(1, 10), (2, 14)] {
        assert_eq!(evaluate(&ssa, &ssa.definitions[result].expression, &[None, Some(predecessor)], 0), Some(expected));
    }
    assert!(ssa.blocks[3].phis.iter().any(|&id| ssa.definitions[id].variable == Variable::Register { number: 0 }));
}

#[test]
fn loop_header_phi_keeps_entry_and_backedge_values() {
    let blocks = vec![
        block(0x1000, vec![assign(0x1000, 0, Value::Constant { value: 0 }, 64)]),
        block(
            0x1010,
            vec![assign(
                0x1010,
                0,
                Value::Add {
                    left: Box::new(Value::Register { number: 0 }),
                    right: Box::new(Value::Constant { value: 1 }),
                },
                64,
            )],
        ),
    ];
    let ssa = ssa::build(&blocks, &[(0, 1), (1, 1)], 0).unwrap();
    let phi = ssa.blocks[1]
        .phis
        .iter()
        .map(|&id| &ssa.definitions[id])
        .find(|definition| definition.variable == Variable::Register { number: 0 })
        .unwrap();
    let Expression::Phi { inputs } = &phi.expression else { panic!("not a phi") };
    assert_eq!(inputs.iter().map(|input| input.predecessor).collect::<Vec<_>>(), [Some(0), Some(1)]);
    assert_eq!(inputs[1].definition, ssa.blocks[1].statements[0].definitions[0]);
}

#[test]
fn entry_backedges_include_the_external_input_edge() {
    let blocks = vec![block(0x1000, vec![assign(0x1000, 1, Value::Register { number: 0 }, 64)])];
    let ssa = ssa::build(&blocks, &[(0, 0)], 0).unwrap();
    let phi = &ssa.definitions[ssa.blocks[0].phis[0]];
    let Expression::Phi { inputs } = &phi.expression else { panic!("not a phi") };
    assert_eq!(inputs.iter().map(|input| input.predecessor).collect::<Vec<_>>(), [None, Some(0)]);
}

#[test]
fn narrow_arithmetic_wraps_and_zero_extends_architectural_registers() {
    for (left, subtract, expected) in [(u64::MAX, false, 0), (0, true, 0xffff_ffff)] {
        let pair = (Box::new(Value::Register { number: 0 }), Box::new(Value::Constant { value: 1 }));
        let value = if subtract {
            Value::Subtract { left: pair.0, right: pair.1 }
        } else {
            Value::Add { left: pair.0, right: pair.1 }
        };
        let blocks = vec![block(
            0x1000,
            vec![assign(0x1000, 0, Value::Constant { value: left }, 64), assign(0x1004, 0, value, 32)],
        )];
        let ssa = ssa::build(&blocks, &[], 0).unwrap();
        let id = ssa.blocks[0].statements[1].definitions[0];
        assert_eq!(evaluate(&ssa, &ssa.definitions[id].expression, &[None], 0), Some(expected));
    }
}

#[test]
fn unknown_instructions_and_calls_clobber_registers_and_memory() {
    for flow in [Flow::Next, Flow::Call(0x3000)] {
        let unknown =
            LiftedInstruction { address: 0x1004, bits: 64, effects: vec![], flow, complete: flow != Flow::Next };
        let blocks = vec![block(
            0x1000,
            vec![
                assign(0x1000, 0, Value::Constant { value: 7 }, 64),
                unknown,
                assign(0x1008, 1, Value::Register { number: 0 }, 64),
            ],
        )];
        let ssa = ssa::build(&blocks, &[], 0).unwrap();
        let id = ssa.blocks[0].statements[2].definitions[0];
        assert_eq!(evaluate(&ssa, &ssa.definitions[id].expression, &[None], 0), None);
        assert!(ssa.blocks[0].statements[1].barrier);
        assert!(
            ssa.blocks[0].statements[1].definitions.iter().any(|&id| ssa.definitions[id].variable == Variable::Memory)
        );
    }
}

#[test]
fn unreachable_predecessors_do_not_contribute_phi_inputs() {
    let blocks = vec![
        block(0x1000, vec![]),
        block(0x1010, vec![]),
        block(0x1020, vec![assign(0x1020, 1, Value::Register { number: 0 }, 64)]),
    ];
    let ssa = ssa::build(&blocks, &[(0, 2), (1, 2)], 0).unwrap();
    assert!(!ssa.blocks[1].reachable);
    assert_eq!(ssa.blocks[2].predecessors, [0]);
    assert!(ssa.blocks[1].statements.is_empty());
}

#[test]
fn malformed_edges_destinations_and_widths_are_errors() {
    let input = vec![block(0x1000, vec![])];
    assert!(ssa::build(&input, &[(0, 1)], 0).is_err());
    assert!(ssa::build(&input, &[], 1).is_err());
    assert!(ssa::build(&[], &[], 0).is_err());
    for insn in [
        assign(0x1000, 31, Value::Constant { value: 1 }, 64),
        assign(0x1000, 0, Value::Register { number: 99 }, 64),
        assign(0x1000, 0, Value::Constant { value: 1 }, 16),
    ] {
        assert!(ssa::build(&[block(0x1000, vec![insn])], &[], 0).is_err());
    }
    assert!(ssa::build(&vec![block(0, vec![]); 513], &[], 0).is_err());
}

#[test]
fn stores_define_memory_versions_and_loads_read_them() {
    let insns = vec![
        LiftedInstruction {
            address: 0x1000,
            bits: 64,
            complete: true,
            flow: Flow::Next,
            effects: vec![Effect::Store {
                address: Value::Constant { value: 0x3000 },
                value: Value::Constant { value: 7 },
            }],
        },
        LiftedInstruction {
            address: 0x1004,
            bits: 64,
            complete: true,
            flow: Flow::Next,
            effects: vec![Effect::Load {
                destination: Value::Register { number: 0 },
                address: Value::Constant { value: 0x3000 },
            }],
        },
    ];
    let ssa = ssa::build(&[block(0x1000, insns)], &[], 0).unwrap();
    let memory = ssa.blocks[0].statements[0].definitions[0];
    let load = ssa.blocks[0].statements[1].definitions[0];
    assert!(matches!(ssa.definitions[load].expression, Expression::Load { memory: id, .. } if id == memory));
}

#[test]
fn deep_ir_expressions_are_rejected_with_a_bounded_error() {
    let mut value = Value::Constant { value: 1 };
    for _ in 0..66 {
        value = Value::Add { left: Box::new(value), right: Box::new(Value::Constant { value: 1 }) };
    }
    assert!(ssa::build(&[block(0x1000, vec![assign(0x1000, 0, value, 64)])], &[], 0).is_err());
}

#[test]
fn generated_cyclic_cfgs_keep_unique_definitions_and_valid_references() {
    let mut seed = 7u64;
    for _ in 0..32 {
        let blocks: Vec<_> = (0..12)
            .map(|index| {
                block(
                    0x1000 + index * 4,
                    vec![assign(
                        0x1000 + index * 4,
                        (index % 4) as u8,
                        Value::Register { number: ((index + 1) % 4) as u8 },
                        64,
                    )],
                )
            })
            .collect();
        let mut edges: Vec<_> = (0..11).map(|index| (index, index + 1)).collect();
        for _ in 0..20 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            edges.push(((seed >> 32) as usize % 12, seed as usize % 12));
        }
        let ssa = ssa::build(&blocks, &edges, 0).unwrap();
        for (id, definition) in ssa.definitions.iter().enumerate() {
            assert_eq!(definition.id, id);
            if let Expression::Phi { inputs } = &definition.expression {
                for input in inputs {
                    assert!(input.definition < ssa.definitions.len());
                    assert_eq!(ssa.definitions[input.definition].variable, definition.variable);
                }
            }
        }
    }
}

#[test]
fn memory_phi_keeps_written_and_unwritten_paths_distinct() {
    let store = LiftedInstruction {
        address: 0x1010,
        bits: 64,
        complete: true,
        flow: Flow::Next,
        effects: vec![Effect::Store {
            address: Value::Constant { value: 0x3000 },
            value: Value::Constant { value: 7 },
        }],
    };
    let load = LiftedInstruction {
        address: 0x1030,
        bits: 64,
        complete: true,
        flow: Flow::Next,
        effects: vec![Effect::Load {
            destination: Value::Register { number: 0 },
            address: Value::Constant { value: 0x3000 },
        }],
    };
    let blocks =
        vec![block(0x1000, vec![]), block(0x1010, vec![store]), block(0x1020, vec![]), block(0x1030, vec![load])];
    let ssa = ssa::build(&blocks, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap();
    let phi = ssa.blocks[3]
        .phis
        .iter()
        .map(|&id| &ssa.definitions[id])
        .find(|definition| definition.variable == Variable::Memory)
        .unwrap();
    let Expression::Phi { inputs } = &phi.expression else { panic!("missing memory phi") };
    assert_eq!(inputs.len(), 2);
    assert!(
        inputs.iter().any(|input| matches!(&ssa.definitions[input.definition].expression, Expression::Store { .. }))
    );
    assert!(inputs.iter().any(|input| matches!(&ssa.definitions[input.definition].expression, Expression::Phi { .. })));
}

#[test]
fn output_definition_and_input_node_budgets_reject_amplification() {
    let unknown = LiftedInstruction { address: 0, bits: 64, complete: false, flow: Flow::Next, effects: vec![] };
    let error = ssa::build(&[block(0, vec![unknown; 20_000])], &[], 0).unwrap_err();
    assert!(error.contains("definition limit"));
    let control = LiftedInstruction {
        address: 0,
        bits: 64,
        complete: true,
        flow: Flow::Next,
        effects: vec![Effect::Control { inputs: vec![Value::Constant { value: 1 }; 80_001] }],
    };
    assert!(ssa::build(&[block(0, vec![control])], &[], 0).unwrap_err().contains("value-node limit"));
    let mut tree = Value::Constant { value: 1 };
    for _ in 0..16 {
        tree = Value::Add { left: Box::new(tree.clone()), right: Box::new(tree) };
    }
    assert!(ssa::build(&[block(0, vec![assign(0, 0, tree, 64)])], &[], 0).unwrap_err().contains("value-node limit"));
}

#[test]
fn discarded_loads_preserve_memory_access_width() {
    for bits in [32, 64] {
        let insn = LiftedInstruction {
            address: 0,
            bits,
            complete: true,
            flow: Flow::Next,
            effects: vec![Effect::LoadDiscard { address: Value::Constant { value: 0x3000 } }],
        };
        let ssa = ssa::build(&[block(0, vec![insn])], &[], 0).unwrap();
        assert_eq!(ssa.blocks[0].statements[0].bits, bits);
        assert!(
            matches!(ssa.blocks[0].statements[0].observations[0], Expression::Load { bits: width, .. } if width == bits)
        );
    }
}

#[test]
fn conditions_preserve_polarity_and_tested_bit() {
    for (nonzero, bit) in [(false, None), (true, None), (false, Some(1)), (true, Some(31))] {
        let insn = LiftedInstruction {
            address: 0,
            bits: 32,
            complete: true,
            flow: Flow::ConditionalJump(4),
            effects: vec![Effect::ConditionalControl { value: Value::Register { number: 0 }, nonzero, bit }],
        };
        let ssa = ssa::build(&[block(0, vec![insn])], &[], 0).unwrap();
        assert!(matches!(ssa.blocks[0].statements[0].observations[0],
            Expression::Condition { nonzero: polarity, bit: tested, .. } if polarity == nonzero && tested == bit));
    }
}

#[test]
fn aapcs64_calls_preserve_callee_saved_registers_but_clobber_caller_saved_values() {
    let instructions = vec![
        assign(0x1000, 0, Value::Constant { value: 7 }, 64),
        assign(0x1004, 19, Value::Constant { value: 11 }, 64),
        LiftedInstruction {
            address: 0x1008,
            bits: 64,
            flow: Flow::Call(0x3000),
            complete: true,
            effects: vec![Effect::Call { target: Value::Constant { value: 0x3000 }, return_address: 0x100c }],
        },
        assign(0x100c, 1, Value::Register { number: 0 }, 64),
        assign(0x1010, 2, Value::Register { number: 19 }, 64),
    ];
    let ssa = ssa::build(&[block(0x1000, instructions)], &[], 0).unwrap();
    let caller = ssa.blocks[0].statements[3].definitions[0];
    let callee = ssa.blocks[0].statements[4].definitions[0];
    assert_eq!(evaluate(&ssa, &ssa.definitions[caller].expression, &[None], 0), None);
    assert_eq!(evaluate(&ssa, &ssa.definitions[callee].expression, &[None], 0), Some(11));
    assert!(!ssa.blocks[0].statements[2].barrier);
    assert!(matches!(ssa.blocks[0].statements[2].observations[0], Expression::Call { return_address: 0x100c, .. }));
    let Expression::Call { result_buffer, stack_pointer, .. } = ssa.blocks[0].statements[2].observations[0] else {
        panic!("missing call");
    };
    assert_eq!(ssa.definitions[result_buffer].variable, Variable::Register { number: 8 });
    assert_eq!(ssa.definitions[stack_pointer].variable, Variable::StackPointer);
}

#[test]
fn llvm_checked_native_pair_loads_resolve_addresses_before_clobbering_the_base() {
    use rampage_arch::{Arch, Target, decoder, ir};

    // Literal encodings checked independently with LLVM's integrated assembler.
    for (word, base, destinations, offset, bits, result_bits, signed) in [
        (0xa940_0400u32, 0, [0, 1], 0, 64, 64, false),
        (0xa940_0420, 1, [0, 1], 0, 64, 64, false),
        (0xa960_0400, 0, [0, 1], -512, 64, 64, false),
        (0xa95f_8400, 0, [0, 1], 504, 64, 64, false),
        (0x2940_0400, 0, [0, 1], 0, 32, 32, false),
        (0x2940_0420, 1, [0, 1], 0, 32, 32, false),
        (0x2960_0400, 0, [0, 1], -256, 32, 32, false),
        (0x295f_8400, 0, [0, 1], 252, 32, 32, false),
        (0x6940_0400, 0, [0, 1], 0, 32, 64, true),
        (0x6940_0420, 1, [0, 1], 0, 32, 64, true),
        (0x6960_0400, 0, [0, 1], -256, 32, 64, true),
        (0x695f_8400, 0, [0, 1], 252, 32, 64, true),
        (0xa940_fc00, 0, [0, 31], 8, 64, 64, false),
        (0xa97f_801f, 0, [31, 0], -8, 64, 64, false),
        (0x2940_fc00, 0, [0, 31], 4, 32, 32, false),
        (0x297f_801f, 0, [31, 0], -4, 32, 32, false),
        (0x6940_fc00, 0, [0, 31], 4, 32, 64, true),
        (0x697f_801f, 0, [31, 0], -4, 32, 64, true),
        (0xa960_03ff, 31, [31, 0], -512, 64, 64, false),
        (0xa95f_ffe0, 31, [0, 31], 504, 64, 64, false),
        (0x2960_03ff, 31, [31, 0], -256, 32, 32, false),
        (0x295f_ffe0, 31, [0, 31], 252, 32, 32, false),
        (0x6960_03ff, 31, [31, 0], -256, 32, 64, true),
        (0x695f_ffe0, 31, [0, 31], 252, 32, 64, true),
    ] {
        let bytes = word.to_le_bytes();
        let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x1004);
        let lifted = ir::lift(Arch::Aarch64, &bytes, &insn);
        assert!(lifted.complete, "{word:08x}");
        for original_base in [0u64, 0x1_0000_0000, u64::MAX - 3] {
            let base_value = if base == 31 { Value::StackPointer } else { Value::Register { number: base } };
            let instructions = vec![
                LiftedInstruction {
                    address: 0x1000,
                    bits: 64,
                    flow: Flow::Next,
                    complete: true,
                    effects: vec![Effect::Assign {
                        destination: base_value.clone(),
                        value: Value::Constant { value: original_base },
                    }],
                },
                lifted.clone(),
                assign(0x1008, 2, base_value, 64),
            ];
            let ssa = ssa::build(&[block(0x1000, instructions)], &[], 0).unwrap();
            let statement = &ssa.blocks[0].statements[1];
            assert!(!statement.barrier, "{word:08x}");
            assert_eq!(statement.definitions.len() + statement.observations.len(), 2, "{word:08x}");
            let first_address = original_base.wrapping_add(offset as u64);
            let expected_addresses = [first_address, first_address.wrapping_add(u64::from(bits / 8))];
            let mut memories = Vec::new();
            for &id in &statement.definitions {
                let definition = &ssa.definitions[id];
                let Variable::Register { number } = definition.variable else { panic!("not a register load") };
                let index = destinations.iter().position(|&destination| destination == number).unwrap();
                let load = match &definition.expression {
                    Expression::Extend { value, from_bits, to_bits, signed: actual_signed } => {
                        assert_eq!((*from_bits, *to_bits, *actual_signed), (bits, result_bits, signed), "{word:08x}");
                        value.as_ref()
                    }
                    value @ Expression::Load { .. } => {
                        assert_eq!((bits, result_bits, signed), (64, 64, false));
                        value
                    }
                    _ => panic!("not a load: {:?}", definition.expression),
                };
                let Expression::Load { address, bits: actual_bits, memory } = load else { panic!("not a load") };
                assert_eq!(*actual_bits, bits, "{word:08x}");
                assert_eq!(evaluate(&ssa, address, &[None], 0), Some(expected_addresses[index]), "{word:08x}");
                memories.push(*memory);
            }
            for observation in &statement.observations {
                let index = destinations.iter().position(|&destination| destination == 31).unwrap();
                let Expression::Load { address, bits: actual_bits, memory } = observation else {
                    panic!("discarded load lost its memory access")
                };
                assert_eq!(*actual_bits, bits, "{word:08x}");
                assert_eq!(evaluate(&ssa, address, &[None], 0), Some(expected_addresses[index]), "{word:08x}");
                memories.push(*memory);
            }
            assert_eq!(memories[0], memories[1], "{word:08x}");
            let base_definition = if base == 31 {
                ssa.blocks[0].statements[0].definitions[0]
            } else {
                *statement
                    .definitions
                    .iter()
                    .find(|&&id| ssa.definitions[id].variable == Variable::Register { number: base })
                    .unwrap()
            };
            let after = ssa.blocks[0].statements[2].definitions[0];
            assert_eq!(ssa.definitions[after].expression, Expression::Reference { definition: base_definition });
        }
    }
}

#[test]
fn grouped_pair_loads_validate_inputs_and_count_both_definitions_in_the_budget() {
    let pair = |destinations, addresses, bits, result_bits| LiftedInstruction {
        address: 0x1000,
        bits: 64,
        flow: Flow::Next,
        complete: true,
        effects: vec![Effect::MemoryLoadPair { destinations, addresses, bits, result_bits, signed: false }],
    };
    let destinations = [Value::Register { number: 0 }, Value::Register { number: 1 }];
    let addresses = [Value::Register { number: 0 }, Value::Register { number: 0 }];
    for (bits, result_bits) in [(24, 64), (64, 32), (32, 8)] {
        assert!(
            ssa::build(
                &[block(0x1000, vec![pair(destinations.clone(), addresses.clone(), bits, result_bits)])],
                &[],
                0
            )
            .unwrap_err()
            .contains("invalid memory load widths")
        );
    }
    for invalid in [Value::Register { number: 31 }, Value::Constant { value: 1 }] {
        let insn = pair([Value::Register { number: 0 }, invalid], addresses.clone(), 64, 64);
        assert!(ssa::build(&[block(0x1000, vec![insn])], &[], 0).is_err());
    }
    let duplicate = pair([Value::Register { number: 0 }, Value::Register { number: 0 }], addresses.clone(), 64, 64);
    assert!(ssa::build(&[block(0x1000, vec![duplicate])], &[], 0).unwrap_err().contains("destinations must differ"));
    let bad_address =
        pair(destinations.clone(), [Value::Constant { value: 0 }, Value::Register { number: 99 }], 64, 64);
    assert!(ssa::build(&[block(0x1000, vec![bad_address])], &[], 0).is_err());
    let repeated = pair(destinations, addresses, 64, 64);
    assert!(ssa::build(&[block(0x1000, vec![repeated; 10_000])], &[], 0).unwrap_err().contains("definition limit"));
}

#[test]
fn native_pair_writeback_overlap_is_still_an_ssa_semantic_barrier() {
    use rampage_arch::{Arch, Target, decoder, ir};

    for word in [0xa9c1_0400u32, 0x28c1_0420, 0x69c1_0400, 0xa940_0000, 0xa981_0400] {
        let bytes = word.to_le_bytes();
        let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x1000);
        let lifted = ir::lift(Arch::Aarch64, &bytes, &insn);
        let ssa = ssa::build(&[block(0x1000, vec![lifted])], &[], 0).unwrap();
        let statement = &ssa.blocks[0].statements[0];
        assert!(statement.barrier, "{word:08x}");
        assert!(statement.observations.is_empty());
        assert!(statement.definitions.iter().any(|&id| ssa.definitions[id].variable == Variable::Memory));
        assert!(
            statement
                .definitions
                .iter()
                .all(|&id| matches!(ssa.definitions[id].expression, Expression::Unknown { .. }))
        );
    }
}

fn memory_instruction(address: u64, effect: Effect) -> LiftedInstruction {
    LiftedInstruction { address, bits: 64, flow: Flow::Next, complete: true, effects: vec![effect] }
}

fn stack_offset(offset: i64) -> Value {
    Value::Add { left: Box::new(Value::StackPointer), right: Box::new(Value::Constant { value: offset as u64 }) }
}

fn spill(address: u64, offset: i64, bits: u8, number: u8) -> LiftedInstruction {
    memory_instruction(
        address,
        Effect::MemoryStore { address: stack_offset(offset), value: Value::Register { number }, bits },
    )
}

fn reload(address: u64, offset: i64, bits: u8, result_bits: u8, signed: bool) -> LiftedInstruction {
    memory_instruction(
        address,
        Effect::MemoryLoad {
            destination: Value::Register { number: 2 },
            address: stack_offset(offset),
            bits,
            result_bits,
            signed,
        },
    )
}

fn has_load(value: &Expression) -> bool {
    match value {
        Expression::Load { .. } => true,
        Expression::Extend { value, .. } | Expression::Low32 { value } => has_load(value),
        _ => false,
    }
}

#[test]
fn nonconstant_spills_recover_the_stored_input_not_the_clobbered_register() {
    for (bits, result_bits, signed, expected) in [
        (8, 32, true, 0xffff_ff80),
        (16, 64, true, 0xffff_ffff_ffff_8080),
        (32, 64, false, 0x1234_8080),
        (64, 64, false, 0xabcd_0000_1234_8080),
    ] {
        let blocks = [block(
            0,
            vec![
                spill(0, -16, bits, 0),
                assign(4, 0, Value::Constant { value: 7 }, 64),
                reload(8, -16, bits, result_bits, signed),
            ],
        )];
        let mut ssa = ssa::build(&blocks, &[], 0).unwrap();
        for simplify in [false, true] {
            if simplify {
                ssa::simplify(&mut ssa).unwrap();
            }
            let result = ssa.blocks[0].statements[2].definitions[0];
            assert!(!has_load(&ssa.definitions[result].expression));
            assert_eq!(
                evaluate_inputs(&ssa, &ssa.definitions[result].expression, &[None], &[0xabcd_0000_1234_8080], 0),
                Some(expected)
            );
            let data = rampage_analysis::dataflow::analyze(&ssa).unwrap();
            assert_eq!(data.argument_registers, [0]);
            assert!(!data.constants.iter().any(|constant| constant.definition == result));
            assert!(data.forwarded_loads.is_empty());
            assert_eq!(data.stack_slots.len(), 1);
            assert_eq!((data.stack_slots[0].offset, data.stack_slots[0].bits), (-16, bits));
            assert_eq!(data.stack_slots[0].writes, [0]);
            assert_eq!(data.stack_slots[0].reads, [8]);
            assert!(matches!(ssa.blocks[0].statements[2].observations[0], Expression::Load { bits: width, .. }
                if width == bits));
        }
    }
}

#[test]
fn nonconstant_memory_phis_require_every_path_to_store_the_same_value_alias() {
    for (number, writes, expected) in [(0, true, true), (1, true, false), (0, false, false)] {
        let blocks = [
            block(0, vec![]),
            block(4, vec![spill(4, 0, 64, 0), assign(8, 0, Value::Constant { value: 7 }, 64)]),
            block(
                12,
                if writes { vec![assign(12, 3, Value::Register { number }, 64), spill(16, 0, 64, 3)] } else { vec![] },
            ),
            block(20, vec![reload(20, 0, 64, 64, false)]),
        ];
        let mut ssa = ssa::build(&blocks, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap();
        for simplified in [false, true] {
            if simplified {
                ssa::simplify(&mut ssa).unwrap();
            }
            let result = ssa.blocks[3].statements[0].definitions[0];
            assert_eq!(!has_load(&ssa.definitions[result].expression), expected);
            for predecessor in [1, 2] {
                assert_eq!(
                    evaluate_inputs(
                        &ssa,
                        &ssa.definitions[result].expression,
                        &[None, Some(predecessor)],
                        &[37, 91],
                        0,
                    ),
                    expected.then_some(37)
                );
            }
            rampage_analysis::dataflow::analyze(&ssa).unwrap();
        }
    }
}

#[test]
fn a_nontrivial_value_phi_can_be_spilled_without_expanding_its_expression() {
    let blocks = [
        block(0, vec![]),
        block(4, vec![assign(4, 3, Value::Register { number: 0 }, 64)]),
        block(8, vec![assign(8, 3, Value::Register { number: 1 }, 64)]),
        block(12, vec![spill(12, 0, 64, 3), reload(16, 0, 64, 64, false)]),
    ];
    let ssa = ssa::build(&blocks, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap();
    let result = ssa.blocks[3].statements[1].definitions[0];
    let Expression::Extend { value, .. } = &ssa.definitions[result].expression else { panic!("not a reload") };
    let Expression::Reference { definition } = value.as_ref() else { panic!("not a value alias") };
    assert!(matches!(ssa.definitions[*definition].expression, Expression::Phi { .. }));
    for (predecessor, expected) in [(1, 37), (2, 91)] {
        assert_eq!(
            evaluate_inputs(
                &ssa,
                &ssa.definitions[result].expression,
                &[None, Some(0), Some(predecessor)],
                &[37, 91],
                0
            ),
            Some(expected)
        );
    }
}

#[test]
fn nonconstant_reload_stops_at_overlaps_unknown_aliases_calls_and_barriers() {
    let call = LiftedInstruction {
        flow: Flow::Call(0x1000),
        ..memory_instruction(4, Effect::Call { target: Value::Constant { value: 0x1000 }, return_address: 8 })
    };
    for middle in [
        spill(4, 4, 32, 1),
        spill(4, -4, 64, 1),
        spill(4, 0, 32, 1),
        memory_instruction(
            4,
            Effect::MemoryStore {
                address: Value::Register { number: 1 },
                value: Value::Register { number: 0 },
                bits: 64,
            },
        ),
        memory_instruction(
            4,
            Effect::MemoryStore {
                address: Value::Constant { value: 0x3000 },
                value: Value::Register { number: 0 },
                bits: 64,
            },
        ),
        call,
        LiftedInstruction { address: 4, bits: 64, complete: false, flow: Flow::Next, effects: vec![] },
    ] {
        let ssa =
            ssa::build(&[block(0, vec![spill(0, 0, 64, 0), middle, reload(8, 0, 64, 64, false)])], &[], 0).unwrap();
        let result = ssa.blocks[0].statements[2].definitions[0];
        assert!(has_load(&ssa.definitions[result].expression));
        let data = rampage_analysis::dataflow::analyze(&ssa).unwrap();
        assert!(data.forwarded_loads.is_empty());
        assert!(!data.constants.iter().any(|constant| constant.definition == result));
    }
}

#[test]
fn finite_stack_adjustments_and_disjoint_stores_preserve_spilled_values() {
    let adjust = memory_instruction(0, Effect::Assign { destination: Value::StackPointer, value: stack_offset(-32) });
    let blocks =
        [block(0, vec![adjust, spill(4, 8, 64, 0)]), block(8, vec![spill(8, 16, 64, 1), reload(12, 8, 64, 64, false)])];
    let ssa = ssa::build(&blocks, &[(0, 1)], 0).unwrap();
    let result = ssa.blocks[1].statements[1].definitions[0];
    assert_eq!(evaluate_inputs(&ssa, &ssa.definitions[result].expression, &[None, Some(0)], &[37, 91], 0), Some(37));
    let data = rampage_analysis::dataflow::analyze(&ssa).unwrap();
    assert!(data.stack_slots.iter().any(|slot| slot.offset == -24 && slot.reads == [12] && slot.writes == [4]));
}

#[test]
fn arbitrary_memory_reads_and_reloaded_pointers_do_not_start_spill_inference_chains() {
    let pointer = Value::Register { number: 2 };
    let arbitrary =
        memory_instruction(0, Effect::Load { destination: Value::Register { number: 0 }, address: pointer });
    let ssa =
        ssa::build(&[block(0, vec![arbitrary, spill(4, 0, 64, 0), reload(8, 0, 64, 64, false)])], &[], 0).unwrap();
    let result = ssa.blocks[0].statements[2].definitions[0];
    assert!(has_load(&ssa.definitions[result].expression));
    let blocks = [block(
        0,
        vec![
            assign(0, 0, Value::StackPointer, 64),
            spill(4, 0, 64, 0),
            reload(8, 0, 64, 64, false),
            memory_instruction(
                12,
                Effect::MemoryStore {
                    address: Value::Register { number: 2 },
                    value: Value::Register { number: 1 },
                    bits: 64,
                },
            ),
            reload(16, 0, 64, 64, false),
        ],
    )];
    let ssa = ssa::build(&blocks, &[], 0).unwrap();
    let result = ssa.blocks[0].statements[4].definitions[0];
    assert!(has_load(&ssa.definitions[result].expression));
    assert!(rampage_analysis::dataflow::analyze(&ssa).unwrap().forwarded_loads.is_empty());
}

#[test]
fn legacy_recovered_stack_pointer_preserves_its_value_but_not_address_provenance() {
    let store =
        memory_instruction(4, Effect::Store { address: stack_offset(-16), value: Value::Register { number: 0 } });
    let load =
        memory_instruction(12, Effect::Load { address: stack_offset(-16), destination: Value::Register { number: 2 } });
    let mut ssa = ssa::build(
        &[block(
            0,
            vec![assign(0, 0, Value::StackPointer, 64), store, assign(8, 0, Value::Constant { value: 7 }, 64), load],
        )],
        &[],
        0,
    )
    .unwrap();
    let mut inputs = [0; 32];
    inputs[31] = 0x7fff_abcd_4000;
    for simplified in [false, true] {
        if simplified {
            ssa::simplify(&mut ssa).unwrap();
        }
        let statement = &ssa.blocks[0].statements[3];
        let result = statement.definitions[0];
        assert_eq!(statement.recovered_loads, [result]);
        let Expression::Reference { definition } = ssa.definitions[result].expression else {
            panic!("legacy reload should retain its direct value alias")
        };
        assert_eq!(ssa.definitions[definition].variable, Variable::StackPointer);
        assert_eq!(evaluate_inputs(&ssa, &ssa.definitions[result].expression, &[None], &inputs, 0), Some(inputs[31]));
        let data = rampage_analysis::dataflow::analyze(&ssa).unwrap();
        assert_eq!(data.stack_slots.len(), 1);
        assert_eq!(data.stack_slots[0].offset, -16);
        assert_eq!(data.stack_slots[0].writes, [4]);
        assert_eq!(data.stack_slots[0].reads, [12]);
        assert!(data.forwarded_loads.is_empty());
    }
}

#[test]
fn legacy_recovered_addresses_cannot_seed_later_dataflow_store_forwarding() {
    for alias in [
        None,
        Some(Value::Register { number: 2 }),
        Some(Value::Add {
            left: Box::new(Value::Register { number: 2 }),
            right: Box::new(Value::Constant { value: 0 }),
        }),
    ] {
        let mut instructions = vec![
            assign(0, 0, Value::StackPointer, 64),
            memory_instruction(4, Effect::Store { address: stack_offset(-16), value: Value::Register { number: 0 } }),
            memory_instruction(
                8,
                Effect::Load { address: stack_offset(-16), destination: Value::Register { number: 2 } },
            ),
        ];
        let number = if let Some(value) = alias {
            instructions.push(assign(12, 4, value, 64));
            4
        } else {
            2
        };
        let store_at = instructions.len() as u64 * 4;
        instructions.extend([
            memory_instruction(
                store_at,
                Effect::Store { address: Value::Register { number }, value: Value::Constant { value: 37 } },
            ),
            memory_instruction(
                store_at + 4,
                Effect::Load { address: Value::StackPointer, destination: Value::Register { number: 3 } },
            ),
        ]);
        let mut ssa = ssa::build(&[block(0, instructions)], &[], 0).unwrap();
        for simplified in [false, true] {
            if simplified {
                ssa::simplify(&mut ssa).unwrap();
            }
            let recovered = &ssa.blocks[0].statements[2];
            assert_eq!(recovered.recovered_loads, recovered.definitions);
            let last = ssa.blocks[0].statements.last().unwrap();
            let result = last.definitions[0];
            assert!(has_load(&ssa.definitions[result].expression));
            let data = rampage_analysis::dataflow::analyze(&ssa).unwrap();
            assert!(data.forwarded_loads.is_empty());
            assert!(!data.constants.iter().any(|constant| constant.definition == result));
            let slot = data.stack_slots.iter().find(|slot| slot.offset == 0).unwrap();
            assert!(slot.writes.is_empty());
            assert_eq!(slot.reads, [store_at + 4]);
        }
    }
}

#[test]
fn recovered_native_pair_results_do_not_taint_the_stack_pointer_writeback() {
    let words = [0xa9bf_07e0, 0xd280_0000, 0xd280_0001, 0xa8c1_0fe2, 0xf900_03e4, 0xf940_03e5];
    let instructions = words.iter().enumerate().map(|(index, &word)| native_a64(index as u64 * 4, word)).collect();
    let mut ssa = ssa::build(&[block(0, instructions)], &[], 0).unwrap();
    for simplified in [false, true] {
        if simplified {
            ssa::simplify(&mut ssa).unwrap();
        }
        let pair = &ssa.blocks[0].statements[3];
        assert_eq!(pair.recovered_loads.len(), 2);
        let writeback =
            *pair.definitions.iter().find(|&&id| ssa.definitions[id].variable == Variable::StackPointer).unwrap();
        assert!(!pair.recovered_loads.contains(&writeback));
        let data = rampage_analysis::dataflow::analyze(&ssa).unwrap();
        let slot = data.stack_slots.iter().find(|slot| slot.offset == 0).unwrap();
        assert_eq!(slot.writes, [16]);
        assert_eq!(slot.reads, [20]);
    }
}

#[test]
fn malformed_recovered_load_provenance_is_rejected_before_analysis_or_simplification() {
    for corruption in 0..5 {
        let mut ssa = ssa::build(&[block(0, vec![spill(0, 0, 64, 0), reload(4, 0, 64, 64, false)])], &[], 0).unwrap();
        let result = ssa.blocks[0].statements[1].definitions[0];
        match corruption {
            0 => ssa.blocks[0].statements[1].recovered_loads[0] = usize::MAX,
            1 => {
                let statement = &mut ssa.blocks[0].statements[1];
                statement.recovered_loads.push(result);
                statement.observations.push(statement.observations[0].clone());
            }
            2 => ssa.blocks[0].statements[1].recovered_loads[0] = ssa.blocks[0].statements[0].definitions[0],
            3 => ssa.blocks[0].statements[1].observations.clear(),
            _ => ssa.definitions[result].expression = Expression::Constant { value: 37 },
        }
        assert!(rampage_analysis::dataflow::analyze(&ssa).is_err());
        let count = ssa.definitions.len();
        assert!(ssa::simplify(&mut ssa).is_err());
        assert_eq!(ssa.definitions.len(), count);
    }
}

#[test]
fn cyclic_memory_stack_addresses_and_stored_values_remain_unresolved() {
    let cases = [
        (
            vec![block(0, vec![spill(0, 0, 64, 0)]), block(4, vec![reload(4, 0, 64, 64, false)])],
            vec![(0, 1), (1, 1)],
            1,
            0,
        ),
        (vec![block(0, vec![spill(0, 0, 64, 0), reload(4, 0, 64, 64, false)])], vec![(0, 0)], 0, 1),
        (
            vec![
                block(0, vec![]),
                block(4, vec![assign(4, 0, Value::Register { number: 0 }, 64)]),
                block(8, vec![spill(8, 0, 64, 0), reload(12, 0, 64, 64, false)]),
            ],
            vec![(0, 1), (1, 1), (1, 2)],
            2,
            1,
        ),
    ];
    for (blocks, edges, block, statement) in cases {
        let ssa = ssa::build(&blocks, &edges, 0).unwrap();
        let result = ssa.blocks[block].statements[statement].definitions[0];
        assert!(has_load(&ssa.definitions[result].expression));
        assert_eq!(evaluate_inputs(&ssa, &ssa.definitions[result].expression, &[None, Some(0)], &[37], 0), None);
        rampage_analysis::dataflow::analyze(&ssa).unwrap();
    }
}

#[test]
fn native_nonconstant_stack_pair_spills_preserve_inputs_after_source_clobbers() {
    use rampage_arch::{Arch, Target, decoder, ir};
    let words = [0xa9bf_07e0u32, 0xd280_0000, 0xd280_0001, 0xa8c1_0fe2];
    let instructions = words
        .iter()
        .enumerate()
        .map(|(index, &word)| {
            let bytes = word.to_le_bytes();
            let instruction = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, index as u64 * 4);
            let lifted = ir::lift(Arch::Aarch64, &bytes, &instruction);
            assert!(lifted.complete);
            lifted
        })
        .collect();
    let ssa = ssa::build(&[block(0, instructions)], &[], 0).unwrap();
    for (number, expected) in [(2, 37), (3, 91)] {
        let result = *ssa.blocks[0].statements[3]
            .definitions
            .iter()
            .find(|&&id| ssa.definitions[id].variable == Variable::Register { number })
            .unwrap();
        assert_eq!(evaluate_inputs(&ssa, &ssa.definitions[result].expression, &[None], &[37, 91], 0), Some(expected));
    }
    let data = rampage_analysis::dataflow::analyze(&ssa).unwrap();
    assert_eq!(data.stack_slots.iter().map(|slot| slot.offset).collect::<Vec<_>>(), [-16, -8]);
    assert!(data.stack_slots.iter().all(|slot| slot.writes == [0] && slot.reads == [12]));
}

#[test]
fn nonconstant_spills_require_matching_access_widths_and_entry_stack_provenance() {
    for (stored_bits, loaded_bits) in [(64, 32), (32, 64), (16, 8), (8, 16)] {
        let ssa =
            ssa::build(&[block(0, vec![spill(0, 0, stored_bits, 0), reload(4, 0, loaded_bits, 64, false)])], &[], 0)
                .unwrap();
        let result = ssa.blocks[0].statements[1].definitions[0];
        assert!(has_load(&ssa.definitions[result].expression));
    }
    for address in [Value::Constant { value: 0x3000 }, Value::Register { number: 1 }] {
        let store = memory_instruction(
            0,
            Effect::MemoryStore { address: address.clone(), value: Value::Register { number: 0 }, bits: 64 },
        );
        let load = memory_instruction(4, Effect::Load { address, destination: Value::Register { number: 2 } });
        let ssa = ssa::build(&[block(0, vec![store, load])], &[], 0).unwrap();
        let result = ssa.blocks[0].statements[1].definitions[0];
        assert!(has_load(&ssa.definitions[result].expression));
    }
}

#[test]
fn constant_register_spills_still_use_the_existing_store_evidence() {
    let blocks = [block(
        0,
        vec![assign(0, 0, Value::Constant { value: 37 }, 64), spill(4, 0, 64, 0), reload(8, 0, 64, 64, false)],
    )];
    let ssa = ssa::build(&blocks, &[], 0).unwrap();
    let result = ssa.blocks[0].statements[2].definitions[0];
    assert!(has_load(&ssa.definitions[result].expression));
    let data = rampage_analysis::dataflow::analyze(&ssa).unwrap();
    assert_eq!(data.forwarded_loads.len(), 1);
    assert_eq!(data.forwarded_loads[0].definition, result);
    assert_eq!(data.forwarded_loads[0].store_definitions, ssa.blocks[0].statements[1].definitions);
    assert_eq!(data.forwarded_loads[0].value, 37);
}

#[test]
fn nonconstant_spill_proofs_fail_closed_at_the_source_store_and_visit_limits() {
    for (paths, expected) in [(64, true), (65, false)] {
        let mut blocks = vec![block(0, vec![])];
        blocks.extend((1..=paths).map(|index| block(index as u64 * 4, vec![spill(index as u64 * 4, 0, 64, 0)])));
        blocks.push(block(0x1000, vec![reload(0x1000, 0, 64, 64, false)]));
        let edges: Vec<_> = (1..=paths).flat_map(|index| [(0, index), (index, paths + 1)]).collect();
        let ssa = ssa::build(&blocks, &edges, 0).unwrap();
        let result = ssa.blocks[paths + 1].statements[0].definitions[0];
        assert_eq!(!has_load(&ssa.definitions[result].expression), expected);
        rampage_analysis::dataflow::analyze(&ssa).unwrap();
    }
    let mut instructions = vec![assign(0, 3, Value::Register { number: 0 }, 64)];
    for index in 1..=18 {
        instructions.push(assign(
            index * 4,
            3,
            Value::Add {
                left: Box::new(Value::Register { number: 3 }),
                right: Box::new(Value::Register { number: 3 }),
            },
            64,
        ));
    }
    instructions.extend([spill(76, 0, 64, 3), reload(80, 0, 64, 64, false)]);
    let ssa = ssa::build(&[block(0, instructions)], &[], 0).unwrap();
    let result = ssa.blocks[0].statements.last().unwrap().definitions[0];
    assert!(has_load(&ssa.definitions[result].expression));
    assert!(ssa.definitions.len() < 100);
}

#[test]
fn legacy_stack_spills_alias_finite_computed_definitions_without_tree_substitution() {
    for bits in [32, 64] {
        let computed = assign(
            0,
            3,
            Value::Add { left: Box::new(Value::Register { number: 0 }), right: Box::new(Value::Constant { value: 5 }) },
            bits,
        );
        let store = LiftedInstruction {
            bits,
            ..memory_instruction(4, Effect::Store { address: stack_offset(0), value: Value::Register { number: 3 } })
        };
        let load = LiftedInstruction {
            bits,
            ..memory_instruction(
                12,
                Effect::Load { address: stack_offset(0), destination: Value::Register { number: 2 } },
            )
        };
        let ssa = ssa::build(
            &[block(0, vec![computed, store, assign(8, 3, Value::Constant { value: 9 }, 64), load])],
            &[],
            0,
        )
        .unwrap();
        let source = ssa.blocks[0].statements[0].definitions[0];
        let result = ssa.blocks[0].statements[3].definitions[0];
        let value = &ssa.definitions[result].expression;
        let reference = if let Expression::Low32 { value } = value { value.as_ref() } else { value };
        let reference = if let Expression::Extend { value, .. } = reference { value.as_ref() } else { reference };
        assert_eq!(*reference, Expression::Reference { definition: source });
        let expected = if bits == 32 { 3 } else { 0x1_0000_0003 };
        assert_eq!(evaluate_inputs(&ssa, value, &[None], &[0xffff_fffe], 0), Some(expected));
        rampage_analysis::dataflow::analyze(&ssa).unwrap();
    }
}

#[test]
fn finite_but_deep_stack_spill_paths_remain_unresolved() {
    let blocks: Vec<_> = (0..70)
        .map(|index| {
            block(
                index * 4,
                match index {
                    0 => vec![spill(0, 0, 64, 0)],
                    69 => vec![reload(276, 0, 64, 64, false)],
                    _ => vec![],
                },
            )
        })
        .collect();
    let edges: Vec<_> = (0..69).map(|index| (index, index + 1)).collect();
    let ssa = ssa::build(&blocks, &edges, 0).unwrap();
    let result = ssa.blocks[69].statements[0].definitions[0];
    assert!(has_load(&ssa.definitions[result].expression));
    rampage_analysis::dataflow::analyze(&ssa).unwrap();
}

fn native_a64(address: u64, word: u32) -> LiftedInstruction {
    use rampage_arch::{Arch, Target, decoder, ir};
    let bytes = word.to_le_bytes();
    let instruction = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, address);
    let lifted = ir::lift(Arch::Aarch64, &bytes, &instruction);
    assert!(lifted.complete);
    lifted
}

#[test]
fn scheduled_native_bound_branches_keep_the_comparisons_flag_definition() {
    for condition in [2, 3, 8, 9] {
        for (scheduled, preserved) in [(0x9100_0421, true), (0x3100_0421, false)] {
            let blocks = [block(
                0,
                vec![
                    native_a64(0, 0x7100_0c1f),
                    native_a64(4, scheduled),
                    native_a64(8, 0xd503_201f),
                    native_a64(12, 0x5400_0040 | condition),
                ],
            )];
            let mut ssa = ssa::build(&blocks, &[], 0).unwrap();
            ssa::simplify(&mut ssa).unwrap();
            let comparison = *ssa.blocks[0].statements[0]
                .definitions
                .iter()
                .find(|&&id| ssa.definitions[id].variable == Variable::Flags)
                .unwrap();
            let branch = &ssa.blocks[0].statements[3];
            assert_eq!(branch.flow, Flow::ConditionalJump(20));
            let Expression::FlagsCondition { flags, condition: actual } = branch.observations[0] else {
                panic!("missing branch flag dependency")
            };
            assert_eq!(u32::from(actual), condition);
            assert_eq!(flags == comparison, preserved);
        }
    }
}

#[test]
fn native_bound_branches_read_the_original_comparison_across_agreeing_predecessors() {
    for condition in [2, 3, 8, 9] {
        let blocks = [
            block(0, vec![native_a64(0, 0x7100_0c1f), native_a64(4, 0x3400_0061)]),
            block(8, vec![native_a64(8, 0x9100_0442), native_a64(12, 0x1400_0002)]),
            block(16, vec![native_a64(16, 0xd503_201f)]),
            block(20, vec![native_a64(20, 0x5400_0060 | condition)]),
        ];
        let mut ssa = ssa::build(&blocks, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap();
        let branch = &ssa.blocks[3].statements[0];
        let Expression::FlagsCondition { flags, .. } = branch.observations[0] else {
            panic!("missing branch flag dependency")
        };
        let Expression::Phi { inputs } = &ssa.definitions[flags].expression else {
            panic!("cross-block flags should use a phi before simplification")
        };
        assert_eq!(inputs.iter().map(|input| input.predecessor).collect::<Vec<_>>(), [Some(1), Some(2)]);
        ssa::simplify(&mut ssa).unwrap();
        let comparison = *ssa.blocks[0].statements[0]
            .definitions
            .iter()
            .find(|&&id| ssa.definitions[id].variable == Variable::Flags)
            .unwrap();
        let branch = &ssa.blocks[3].statements[0];
        assert_eq!(branch.flow, Flow::ConditionalJump(32));
        assert_eq!(
            branch.observations[0],
            Expression::FlagsCondition { flags: comparison, condition: condition as u8 }
        );
    }
}
