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
    if depth > 100 {
        return None;
    }
    match value {
        Expression::Constant { value } => Some(*value),
        Expression::Reference { definition } => {
            evaluate(ssa, &ssa.definitions[*definition].expression, predecessors, depth + 1)
        }
        Expression::Add { left, right } => Some(evaluate(ssa, left, predecessors, depth + 1)?.wrapping_add(evaluate(
            ssa,
            right,
            predecessors,
            depth + 1,
        )?)),
        Expression::Subtract { left, right } => Some(
            evaluate(ssa, left, predecessors, depth + 1)?.wrapping_sub(evaluate(ssa, right, predecessors, depth + 1)?),
        ),
        Expression::Low32 { value } => Some(evaluate(ssa, value, predecessors, depth + 1)? & 0xffff_ffff),
        Expression::Phi { inputs } => {
            let input = inputs.iter().find(|input| predecessors.contains(&input.predecessor))?;
            evaluate(ssa, &ssa.definitions[input.definition].expression, predecessors, depth + 1)
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
