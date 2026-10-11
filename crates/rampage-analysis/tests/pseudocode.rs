use rampage_analysis::{
    pseudocode,
    ssa::{self, Expression, InputBlock},
};
use rampage_arch::{
    Flow,
    ir::{Effect, LiftedInstruction, Value},
};

fn block(at: u64, flow: Flow) -> InputBlock {
    InputBlock {
        address: at,
        instructions: vec![LiftedInstruction {
            address: at,
            bits: 64,
            flow,
            complete: true,
            effects: vec![Effect::Control { inputs: Vec::new() }],
        }],
    }
}

#[test]
fn backward_entry_and_missing_fallthrough_have_explicit_transfers() {
    let ssa = ssa::build(&[block(0x1000, Flow::Return), block(0x1008, Flow::Jump(0x1000))], &[(1, 0)], 1).unwrap();
    let output = pseudocode::render(&ssa, &[(1, 0)]).unwrap();
    assert!(output.text.contains("goto bb1;"));
    let ssa =
        ssa::build(&[block(0x1000, Flow::ConditionalJump(0x1008)), block(0x1008, Flow::Return)], &[(0, 1)], 0).unwrap();
    assert!(pseudocode::render(&ssa, &[(0, 1)]).unwrap().text.contains("goto unknown_fallthrough;"));
}

#[test]
fn invalid_indices_and_deep_expressions_return_errors() {
    let insn = LiftedInstruction {
        address: 0,
        bits: 64,
        flow: Flow::Next,
        complete: true,
        effects: vec![Effect::Assign {
            destination: Value::Register { number: 0 },
            value: Value::Constant { value: 1 },
        }],
    };
    let mut ssa = ssa::build(&[InputBlock { address: 0, instructions: vec![insn] }], &[], 0).unwrap();
    assert!(pseudocode::render(&ssa, &[(0, 1)]).is_err());
    ssa.definitions[0].id = 100;
    assert!(pseudocode::render(&ssa, &[]).is_err());
    ssa.definitions[0].id = 0;
    ssa.blocks[0].reachable = false;
    assert!(pseudocode::render(&ssa, &[]).is_err());
    ssa.blocks[0].reachable = true;
    let mut expr = Expression::Constant { value: 1 };
    for _ in 0..100 {
        expr = Expression::Low32 { value: Box::new(expr) };
    }
    ssa.definitions[0].expression = expr;
    assert!(pseudocode::render(&ssa, &[]).is_err());
}

#[test]
fn structured_loops_reexecute_header_phis_before_each_condition_test() {
    let mut header = block(4, Flow::ConditionalJump(12));
    header.instructions[0].effects =
        vec![Effect::ConditionalControl { value: Value::Register { number: 0 }, nonzero: false, bit: None }];
    let mut body = block(8, Flow::Jump(4));
    body.instructions[0].effects = vec![Effect::Assign {
        destination: Value::Register { number: 0 },
        value: Value::Subtract {
            left: Box::new(Value::Register { number: 0 }),
            right: Box::new(Value::Constant { value: 1 }),
        },
    }];
    let edges = [(0, 1), (1, 2), (1, 3), (2, 1)];
    let ssa = ssa::build(&[block(0, Flow::Next), header, body, block(12, Flow::Return)], &edges, 0).unwrap();
    let output = pseudocode::render_structured(&ssa, &edges).unwrap();
    assert!(output.structured);
    let loop_at = output.text.find("while (true)").unwrap();
    let phi_at = output.text[loop_at..].find("parallel_phi_bindings").unwrap();
    let break_at = output.text[loop_at..].find("break;").unwrap();
    assert!(phi_at < break_at);
    assert!(output.text.contains("predecessor = bb2;"));
    assert!(!output.text.contains("goto "));
}
