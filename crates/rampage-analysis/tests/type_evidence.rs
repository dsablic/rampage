use rampage_analysis::{
    ssa::{self, InputBlock},
    type_evidence,
};
use rampage_arch::{
    Flow,
    ir::{Effect, LiftedInstruction, Operation, Value},
};

#[test]
fn address_integer_signed_and_return_roles_remain_separate_evidence() {
    let instructions = vec![
        LiftedInstruction {
            address: 0,
            bits: 64,
            flow: Flow::Next,
            complete: true,
            effects: vec![Effect::MemoryLoad {
                address: Value::Register { number: 0 },
                destination: Value::Register { number: 1 },
                bits: 8,
                result_bits: 64,
                signed: true,
            }],
        },
        LiftedInstruction {
            address: 4,
            bits: 64,
            flow: Flow::Next,
            complete: true,
            effects: vec![Effect::Assign {
                destination: Value::Register { number: 2 },
                value: Value::Binary {
                    operation: Operation::SignedDivide,
                    left: Box::new(Value::Register { number: 1 }),
                    right: Box::new(Value::Register { number: 0 }),
                    bits: 64,
                },
            }],
        },
        LiftedInstruction {
            address: 8,
            bits: 64,
            flow: Flow::Return,
            complete: true,
            effects: vec![Effect::Return { target: Value::Register { number: 30 } }],
        },
    ];
    let ssa = ssa::build(&[InputBlock { address: 0, instructions }], &[], 0).unwrap();
    let evidence = type_evidence::analyze(&ssa).unwrap();
    let address = evidence.definitions.iter().find(|fact| fact.address_operand && !fact.code_target).unwrap();
    assert!(address.signed_operand);
    assert!(address.integer_widths.contains(&64));
    assert!(evidence.definitions.iter().any(|fact| fact.code_target));
    assert!(evidence.definitions.iter().any(|fact| fact.integer_return_candidate));
    assert!(!evidence.definitions.iter().any(|fact| fact.unsigned_operand));
}

#[test]
fn malformed_type_evidence_inputs_are_checked_errors() {
    let mut ssa = ssa::build(&[InputBlock { address: 0, instructions: vec![] }], &[], 0).unwrap();
    ssa.entry = usize::MAX;
    assert!(type_evidence::analyze(&ssa).is_err());
}

#[test]
fn logical_shift_value_is_unsigned_but_count_is_not_an_address_or_code_target() {
    let shift = Value::Binary {
        operation: Operation::ShiftRight,
        left: Box::new(Value::Register { number: 0 }),
        right: Box::new(Value::Register { number: 1 }),
        bits: 64,
    };
    let instructions = vec![LiftedInstruction {
        address: 0,
        bits: 64,
        flow: Flow::IndirectJump,
        complete: true,
        effects: vec![Effect::IndirectBranch { target: shift }],
    }];
    let mut ssa = ssa::build(&[InputBlock { address: 0, instructions }], &[], 0).unwrap();
    ssa::simplify(&mut ssa).unwrap();
    let evidence = type_evidence::analyze(&ssa).unwrap();
    let count_id = ssa
        .definitions
        .iter()
        .find(|definition| definition.variable == (rampage_analysis::ssa::Variable::Register { number: 1 }))
        .unwrap()
        .id;
    let count = evidence.definitions.iter().find(|fact| fact.definition == count_id).unwrap();
    assert!(!count.address_operand && !count.code_target && !count.signed_operand && !count.unsigned_operand);
    assert!(evidence.definitions.iter().any(|fact| fact.code_target && fact.unsigned_operand));
}

#[test]
fn repeated_definition_expression_work_is_bounded() {
    let mut value = Value::Register { number: 0 };
    for _ in 0..60 {
        value = Value::Add { left: Box::new(value), right: Box::new(Value::Constant { value: 1 }) };
    }
    let input = [InputBlock {
        address: 0,
        instructions: vec![LiftedInstruction {
            address: 0,
            bits: 64,
            flow: Flow::Next,
            complete: true,
            effects: vec![Effect::Assign { destination: Value::Register { number: 1 }, value }],
        }],
    }];
    let mut ssa = ssa::build(&input, &[], 0).unwrap();
    let id = ssa.blocks[0].statements[0].definitions[0];
    ssa.blocks[0].statements[0].definitions = vec![id; 2000];
    assert!(type_evidence::analyze(&ssa).is_err());
}
