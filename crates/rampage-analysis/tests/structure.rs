use rampage_analysis::{
    ssa::{self, InputBlock},
    structure::{self, Region},
};
use rampage_arch::{
    Flow,
    ir::{Effect, LiftedInstruction, Value},
};

fn graph(flows: &[Flow], edges: &[(usize, usize)]) -> rampage_analysis::ssa::Ssa {
    let input: Vec<_> = flows
        .iter()
        .enumerate()
        .map(|(index, &flow)| InputBlock {
            address: index as u64 * 4,
            instructions: vec![LiftedInstruction {
                address: index as u64 * 4,
                bits: 64,
                complete: true,
                flow,
                effects: if matches!(flow, Flow::ConditionalJump(_)) {
                    vec![Effect::ConditionalControl { value: Value::Register { number: 0 }, nonzero: false, bit: None }]
                } else {
                    vec![Effect::Control { inputs: vec![] }]
                },
            }],
        })
        .collect();
    ssa::build(&input, edges, 0).unwrap()
}

#[test]
fn diamond_becomes_an_if_with_one_shared_join() {
    let edges = [(0, 1), (0, 2), (1, 3), (2, 3)];
    let ssa = graph(&[Flow::ConditionalJump(8), Flow::Jump(12), Flow::Next, Flow::Return], &edges);
    let structure = structure::analyze(&ssa, &edges).unwrap();
    let Region::Sequence { regions } = structure.body else { panic!("not sequence") };
    assert_eq!(regions.len(), 3);
    assert!(matches!(regions[1], Region::If { .. }));
    assert!(matches!(regions[2], Region::Block { block: 3 }));
}

#[test]
fn canonical_loop_keeps_header_execution_and_condition_polarity() {
    let edges = [(0, 1), (1, 2), (1, 3), (2, 1)];
    let ssa = graph(&[Flow::Next, Flow::ConditionalJump(12), Flow::Jump(4), Flow::Return], &edges);
    let Region::Sequence { regions } = structure::analyze(&ssa, &edges).unwrap().body else { panic!("not sequence") };
    assert!(matches!(regions[1], Region::Loop { header: 1, body_when_true: false, .. }));
    assert!(matches!(regions[2], Region::Block { block: 3 }));
}

#[test]
fn irreducible_unknown_and_external_paths_remain_unstructured() {
    let edges = [(0, 1), (0, 2), (1, 2), (2, 1)];
    let ssa = graph(&[Flow::ConditionalJump(8), Flow::Jump(8), Flow::Jump(4)], &edges);
    assert!(structure::analyze(&ssa, &edges).is_err());
    assert!(structure::analyze(&graph(&[Flow::IndirectJump], &[]), &[]).is_err());
    assert!(structure::analyze(&graph(&[Flow::ConditionalJump(100), Flow::Return], &[(0, 1)]), &[(0, 1)]).is_err());
}

#[test]
fn conditional_early_returns_keep_both_arms_without_an_invented_join() {
    let edges = [(0, 1), (0, 2)];
    let ssa = graph(&[Flow::ConditionalJump(8), Flow::Return, Flow::Return], &edges);
    let Region::Sequence { regions } = structure::analyze(&ssa, &edges).unwrap().body else { panic!("not sequence") };
    assert_eq!(regions.len(), 2);
    let Region::If { taken, not_taken, .. } = &regions[1] else { panic!("missing if") };
    assert!(matches!(taken.as_ref(), Region::Sequence { regions } if regions.len() == 1));
    assert!(matches!(not_taken.as_ref(), Region::Sequence { regions } if regions.len() == 1));
}

#[test]
fn loop_bodies_with_external_conditional_exits_are_not_hidden() {
    let edges = [(0, 2), (0, 1), (2, 0)];
    let ssa = graph(&[Flow::ConditionalJump(8), Flow::Return, Flow::ConditionalJump(0)], &edges);
    assert!(structure::analyze(&ssa, &edges).is_err());
    let edges = [(0, 1)];
    assert!(structure::analyze(&graph(&[Flow::Jump(100), Flow::Return], &edges), &edges).is_err());
}

#[test]
fn malformed_deep_conditions_are_rejected_before_cloning() {
    use rampage_analysis::ssa::Expression;
    let edges = [(0, 1), (0, 2)];
    let mut ssa = graph(&[Flow::ConditionalJump(8), Flow::Return, Flow::Return], &edges);
    let mut value = Expression::Constant { value: 1 };
    for _ in 0..100 {
        value = Expression::Low32 { value: Box::new(value) };
    }
    ssa.blocks[0].statements[0].observations =
        vec![Expression::Condition { value: Box::new(value), nonzero: false, bit: None }];
    assert!(structure::analyze(&ssa, &edges).is_err());
}

#[test]
fn a_call_that_never_returns_ends_its_path() {
    // if (c) abort(); return;
    let edges = [(0, 1), (0, 2)];
    let mut ssa = graph(&[Flow::ConditionalJump(8), Flow::Call(0x100), Flow::Return], &edges);
    assert!(structure::analyze(&ssa, &edges).is_err());
    ssa.blocks[1].statements[0].noreturn = true;
    let Region::Sequence { regions } = structure::analyze(&ssa, &edges).unwrap().body else { panic!("not sequence") };
    assert!(matches!(regions[1], Region::If { .. }));

    let unstructured = rampage_analysis::pseudocode::render(&ssa, &edges).unwrap().text;
    assert!(unstructured.contains("stop; // the call never returns"), "{unstructured}");
    assert!(!unstructured.contains("unknown_fallthrough"), "{unstructured}");
    let structured = rampage_analysis::pseudocode::render_structured(&ssa, &edges).unwrap().text;
    assert!(structured.contains("stop; // the call never returns"), "{structured}");
}
