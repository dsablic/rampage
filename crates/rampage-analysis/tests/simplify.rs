use rampage_analysis::{
    dataflow,
    ssa::{self, Expression, InputBlock},
};
use rampage_arch::{
    Flow,
    ir::{Effect, LiftedInstruction, Value},
};

fn assignment(address: u64, value: Value) -> LiftedInstruction {
    LiftedInstruction {
        address,
        bits: 64,
        flow: Flow::Next,
        complete: true,
        effects: vec![Effect::Assign { destination: Value::Register { number: 0 }, value }],
    }
}

#[test]
fn straight_line_phis_collapse_without_losing_definitions_or_values() {
    let blocks = vec![
        InputBlock { address: 0, instructions: vec![assignment(0, Value::Constant { value: 7 })] },
        InputBlock {
            address: 4,
            instructions: vec![assignment(
                4,
                Value::Add {
                    left: Box::new(Value::Register { number: 0 }),
                    right: Box::new(Value::Constant { value: 3 }),
                },
            )],
        },
    ];
    let mut ssa = ssa::build(&blocks, &[(0, 1)], 0).unwrap();
    let original = ssa.definitions.len();
    assert!(ssa::simplify(&mut ssa).unwrap() > 0);
    assert!(ssa.definitions.len() < original);
    assert!(ssa.blocks.iter().all(|block| block.phis.is_empty()));
    let result = ssa.blocks[1].statements[0].definitions[0];
    assert!(
        dataflow::analyze(&ssa)
            .unwrap()
            .constants
            .iter()
            .any(|constant| constant.definition == result && constant.value == 10)
    );
    assert_eq!(ssa::simplify(&mut ssa).unwrap(), 0);
}

#[test]
fn changing_loop_values_keep_phi_inputs() {
    let blocks = vec![
        InputBlock { address: 0, instructions: vec![assignment(0, Value::Constant { value: 7 })] },
        InputBlock {
            address: 4,
            instructions: vec![assignment(
                4,
                Value::Add {
                    left: Box::new(Value::Register { number: 0 }),
                    right: Box::new(Value::Constant { value: 1 }),
                },
            )],
        },
    ];
    let mut ssa = ssa::build(&blocks, &[(0, 1), (1, 1)], 0).unwrap();
    ssa::simplify(&mut ssa).unwrap();
    assert!(ssa.blocks[1].phis.iter().any(|&id| matches!(ssa.definitions[id].expression,
        Expression::Phi { ref inputs } if inputs.len() == 2)));
    let result = ssa.blocks[1].statements[0].definitions[0];
    assert!(!dataflow::analyze(&ssa).unwrap().constants.iter().any(|constant| constant.definition == result));
}

#[test]
fn different_diamond_definitions_remain_distinct_after_alias_remapping() {
    let blocks = vec![
        InputBlock { address: 0, instructions: vec![] },
        InputBlock { address: 4, instructions: vec![assignment(4, Value::Constant { value: 7 })] },
        InputBlock { address: 8, instructions: vec![assignment(8, Value::Constant { value: 11 })] },
        InputBlock { address: 12, instructions: vec![assignment(12, Value::Register { number: 0 })] },
    ];
    let mut ssa = ssa::build(&blocks, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap();
    ssa::simplify(&mut ssa).unwrap();
    let phi = ssa.blocks[3]
        .phis
        .iter()
        .find_map(|&id| match &ssa.definitions[id].expression {
            Expression::Phi { inputs } => Some(inputs),
            _ => None,
        })
        .unwrap();
    assert_eq!(phi.len(), 2);
    assert_ne!(phi[0].definition, phi[1].definition);
    assert_eq!(phi.iter().map(|input| input.predecessor).collect::<Vec<_>>(), [Some(1), Some(2)]);
    let result = ssa.blocks[3].statements[0].definitions[0];
    assert!(!dataflow::analyze(&ssa).unwrap().constants.iter().any(|constant| constant.definition == result));
}

#[test]
fn malformed_public_phis_are_rejected_before_mutation() {
    let blocks = vec![InputBlock { address: 0, instructions: vec![assignment(0, Value::Register { number: 0 })] }];
    let mut ssa = ssa::build(&blocks, &[], 0).unwrap();
    let id = ssa.blocks[0].phis[0];
    let Expression::Phi { inputs } = &mut ssa.definitions[id].expression else { panic!("missing phi") };
    inputs[0].definition = usize::MAX;
    let original = ssa.definitions.len();
    assert!(ssa::simplify(&mut ssa).is_err());
    assert_eq!(ssa.definitions.len(), original);
}

#[test]
fn forward_phi_chains_collapse_at_the_definition_limit() {
    use rampage_analysis::ssa::{Block, Definition, PhiInput, Ssa, Variable};
    let count = 20_000;
    let definitions = (0..count)
        .map(|id| Definition {
            id,
            variable: Variable::Register { number: 0 },
            expression: if id + 1 == count {
                Expression::Input
            } else {
                Expression::Phi { inputs: vec![PhiInput { predecessor: None, definition: id + 1 }] }
            },
        })
        .collect();
    let mut ssa = Ssa {
        entry: 0,
        definitions,
        blocks: vec![Block {
            address: 0,
            reachable: true,
            predecessors: vec![],
            phis: (0..count - 1).collect(),
            statements: vec![],
        }],
        limitations: vec![],
    };
    assert_eq!(ssa::simplify(&mut ssa).unwrap(), count - 1);
    assert_eq!(ssa.definitions.len(), 1);
    assert!(matches!(ssa.definitions[0].expression, Expression::Input));
}

#[test]
fn unchanged_loop_phis_collapse_and_return_references_remap() {
    let blocks = vec![
        InputBlock { address: 0, instructions: vec![assignment(0, Value::Constant { value: 11 })] },
        InputBlock {
            address: 4,
            instructions: vec![LiftedInstruction {
                address: 4,
                bits: 64,
                flow: Flow::Return,
                complete: true,
                effects: vec![Effect::Return { target: Value::Register { number: 30 } }],
            }],
        },
    ];
    let mut ssa = ssa::build(&blocks, &[(0, 1), (1, 1)], 0).unwrap();
    ssa::simplify(&mut ssa).unwrap();
    assert!(ssa.blocks[1].phis.is_empty());
    assert_eq!(dataflow::analyze(&ssa).unwrap().integer_returns[0].constant_values[0].as_deref(), Some("0xb"));
}
