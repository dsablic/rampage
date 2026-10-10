use rampage_analysis::{
    dataflow,
    ssa::{self, InputBlock},
};
use rampage_arch::{
    Flow,
    ir::{Effect, LiftedInstruction, Value},
};

fn assign(at: u64, destination: Value, value: Value) -> LiftedInstruction {
    LiftedInstruction {
        address: at,
        bits: 64,
        complete: true,
        flow: Flow::Next,
        effects: vec![Effect::Assign { destination, value }],
    }
}

#[test]
fn conflicting_stack_paths_are_not_reported_as_one_proven_slot() {
    let blocks = vec![
        InputBlock { address: 0, instructions: vec![] },
        InputBlock {
            address: 4,
            instructions: vec![assign(
                4,
                Value::StackPointer,
                Value::Subtract { left: Box::new(Value::StackPointer), right: Box::new(Value::Constant { value: 16 }) },
            )],
        },
        InputBlock { address: 8, instructions: vec![] },
        InputBlock {
            address: 12,
            instructions: vec![LiftedInstruction {
                address: 12,
                bits: 64,
                complete: true,
                flow: Flow::Next,
                effects: vec![Effect::Load {
                    destination: Value::Register { number: 0 },
                    address: Value::StackPointer,
                }],
            }],
        },
    ];
    let ssa = ssa::build(&blocks, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap();
    assert!(dataflow::analyze(&ssa).unwrap().stack_slots.is_empty());
}

#[test]
fn changing_loop_constants_reach_unknown_instead_of_iterating_forever() {
    let blocks = vec![
        InputBlock {
            address: 0,
            instructions: vec![assign(0, Value::Register { number: 0 }, Value::Constant { value: 0 })],
        },
        InputBlock {
            address: 4,
            instructions: vec![assign(
                4,
                Value::Register { number: 0 },
                Value::Add {
                    left: Box::new(Value::Register { number: 0 }),
                    right: Box::new(Value::Constant { value: 1 }),
                },
            )],
        },
    ];
    let ssa = ssa::build(&blocks, &[(0, 1), (1, 1)], 0).unwrap();
    let result = ssa.blocks[1].statements[0].definitions[0];
    assert!(!dataflow::analyze(&ssa).unwrap().constants.iter().any(|constant| constant.definition == result));
}

#[test]
fn flag_known_select_uses_the_correct_arm() {
    use rampage_arch::ir::FlagOperation;
    let input = vec![InputBlock {
        address: 0,
        instructions: vec![
            LiftedInstruction {
                address: 0,
                bits: 64,
                flow: Flow::Next,
                complete: true,
                effects: vec![Effect::SetFlags {
                    operation: FlagOperation::Subtract,
                    left: Value::Constant { value: 7 },
                    right: Value::Constant { value: 7 },
                }],
            },
            LiftedInstruction {
                address: 4,
                bits: 64,
                flow: Flow::Next,
                complete: true,
                effects: vec![Effect::Select {
                    destination: Value::Register { number: 0 },
                    condition: 0,
                    when_true: Value::Constant { value: 11 },
                    when_false: Value::Constant { value: 19 },
                }],
            },
        ],
    }];
    let ssa = ssa::build(&input, &[], 0).unwrap();
    let result = ssa.blocks[0].statements[1].definitions[0];
    assert!(
        dataflow::analyze(&ssa)
            .unwrap()
            .constants
            .iter()
            .any(|constant| constant.definition == result && constant.value == 11)
    );
}

#[test]
fn selects_wait_for_predecessor_flags_and_unconditional_conditions_ignore_unknown_flags() {
    use rampage_arch::ir::FlagOperation;
    for condition in [0, 14, 15] {
        let effects = if condition == 0 {
            vec![Effect::SetFlags {
                operation: FlagOperation::Subtract,
                left: Value::Constant { value: 7 },
                right: Value::Constant { value: 7 },
            }]
        } else {
            vec![]
        };
        let input = vec![
            InputBlock {
                address: 0,
                instructions: vec![LiftedInstruction {
                    address: 0,
                    bits: 64,
                    flow: Flow::Next,
                    complete: true,
                    effects,
                }],
            },
            InputBlock {
                address: 4,
                instructions: vec![LiftedInstruction {
                    address: 4,
                    bits: 64,
                    flow: Flow::Next,
                    complete: true,
                    effects: vec![Effect::Select {
                        destination: Value::Register { number: 0 },
                        condition,
                        when_true: Value::Constant { value: 11 },
                        when_false: Value::Constant { value: 19 },
                    }],
                }],
            },
        ];
        let ssa = ssa::build(&input, &[(0, 1)], 0).unwrap();
        let result = ssa.blocks[1].statements[0].definitions[0];
        assert!(
            dataflow::analyze(&ssa)
                .unwrap()
                .constants
                .iter()
                .any(|constant| constant.definition == result && constant.value == 11)
        );
    }
}

#[test]
fn return_candidates_keep_values_without_inventing_argument_reads() {
    let blocks = vec![InputBlock {
        address: 0,
        instructions: vec![
            assign(0, Value::Register { number: 0 }, Value::Constant { value: 7 }),
            LiftedInstruction {
                address: 4,
                bits: 64,
                flow: Flow::Return,
                complete: true,
                effects: vec![Effect::Return { target: Value::Register { number: 30 } }],
            },
        ],
    }];
    let ssa = ssa::build(&blocks, &[], 0).unwrap();
    let data = dataflow::analyze(&ssa).unwrap();
    assert!(data.argument_registers.is_empty());
    assert_eq!(data.integer_returns.len(), 1);
    assert_eq!(data.integer_returns[0].constant_values, [Some("0x7".to_owned()), None]);
}

#[test]
fn distinct_return_paths_keep_separate_candidates_and_barriers_keep_unknown_values() {
    let returned = |address| LiftedInstruction {
        address,
        bits: 64,
        flow: Flow::Return,
        complete: true,
        effects: vec![Effect::Return { target: Value::Register { number: 30 } }],
    };
    let blocks = vec![
        InputBlock { address: 0, instructions: vec![] },
        InputBlock {
            address: 4,
            instructions: vec![assign(4, Value::Register { number: 0 }, Value::Constant { value: 11 }), returned(8)],
        },
        InputBlock {
            address: 12,
            instructions: vec![
                assign(12, Value::Register { number: 0 }, Value::Constant { value: 19 }),
                LiftedInstruction { address: 16, bits: 64, flow: Flow::Next, complete: false, effects: vec![] },
                returned(20),
            ],
        },
    ];
    let data = dataflow::analyze(&ssa::build(&blocks, &[(0, 1), (0, 2)], 0).unwrap()).unwrap();
    assert_eq!(data.integer_returns.len(), 2);
    assert_eq!(data.integer_returns[0].constant_values[0].as_deref(), Some("0xb"));
    assert_eq!(data.integer_returns[1].constant_values, [None, None]);
}

#[test]
fn malformed_return_indices_and_placement_are_checked_errors() {
    use rampage_analysis::ssa::Expression;
    let instruction = LiftedInstruction {
        address: 0,
        bits: 64,
        flow: Flow::Return,
        complete: true,
        effects: vec![Effect::Return { target: Value::Register { number: 30 } }],
    };
    let mut ssa = ssa::build(&[InputBlock { address: 0, instructions: vec![instruction.clone()] }], &[], 0).unwrap();
    let Expression::Return { integer_values, .. } = &mut ssa.blocks[0].statements[0].observations[0] else {
        panic!("missing return");
    };
    integer_values[0] = usize::MAX;
    assert!(dataflow::analyze(&ssa).is_err());
    let mut misplaced = instruction.clone();
    misplaced.flow = Flow::Next;
    assert!(ssa::build(&[InputBlock { address: 0, instructions: vec![misplaced] }], &[], 0).is_err());
    let mut ssa = ssa::build(&[InputBlock { address: 0, instructions: vec![instruction] }], &[], 0).unwrap();
    ssa.definitions[0].expression = ssa.blocks[0].statements[0].observations[0].clone();
    assert!(dataflow::analyze(&ssa).is_err());
}
