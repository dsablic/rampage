use rampage_analysis::{
    control,
    ssa::{self, InputBlock},
};

fn graph(count: usize, edges: &[(usize, usize)]) -> rampage_analysis::ssa::Ssa {
    let blocks: Vec<_> =
        (0..count).map(|index| InputBlock { address: index as u64 * 4, instructions: vec![] }).collect();
    ssa::build(&blocks, edges, 0).unwrap()
}

#[test]
fn diamonds_have_entry_dominator_and_no_natural_loop() {
    let edges = [(0, 1), (0, 2), (1, 3), (2, 3)];
    let control = control::analyze(&graph(4, &edges), &edges).unwrap();
    assert_eq!(control.immediate_dominators, [None, Some(0), Some(0), Some(0)]);
    assert!(control.loops.is_empty());
}

#[test]
fn loop_members_backedges_and_exits_are_exact() {
    let edges = [(0, 1), (1, 2), (2, 1), (1, 3)];
    let control = control::analyze(&graph(4, &edges), &edges).unwrap();
    assert_eq!(control.loops.len(), 1);
    assert_eq!(control.loops[0].header, 1);
    assert_eq!(control.loops[0].blocks, [1, 2]);
    assert_eq!(control.loops[0].backedges, [2]);
    assert_eq!(control.loops[0].exits, [(1, 3)]);
    assert_eq!(control.immediate_dominators[2], Some(1));
}

#[test]
fn irreducible_cycles_are_not_claimed_as_natural_loops() {
    let edges = [(0, 1), (0, 2), (1, 2), (2, 1)];
    assert!(control::analyze(&graph(3, &edges), &edges).unwrap().loops.is_empty());
    let edges = [(0, 0)];
    assert_eq!(control::analyze(&graph(1, &edges), &edges).unwrap().loops[0].blocks, [0]);
}

#[test]
fn inconsistent_public_graphs_and_invalid_indices_are_errors() {
    let mut ssa = graph(2, &[(0, 1)]);
    assert!(control::analyze(&ssa, &[(0, 2)]).is_err());
    assert!(control::analyze(&ssa, &[]).is_err());
    ssa.blocks[1].reachable = false;
    assert!(control::analyze(&ssa, &[(0, 1)]).is_err());
    ssa.entry = 3;
    assert!(control::analyze(&ssa, &[]).is_err());
}
