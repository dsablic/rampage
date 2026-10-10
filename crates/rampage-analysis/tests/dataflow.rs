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
    assert!(dataflow::analyze(&ssa).stack_slots.is_empty());
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
    assert!(!dataflow::analyze(&ssa).constants.iter().any(|constant| constant.definition == result));
}
