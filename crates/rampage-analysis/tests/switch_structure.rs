use rampage_analysis::{
    discover::Switch,
    pseudocode,
    ssa::{self, Expression, InputBlock, Ssa, Variable},
    structure::{self, Region},
};
use rampage_arch::{
    Flow,
    ir::{Effect, FlagOperation, LiftedInstruction, Value},
};

const DISPATCH: u64 = 0x10;
const FOLLOW: u64 = 0x60;
const DEFAULT: u64 = 0x50;

fn instruction(address: u64, flow: Flow, effects: Vec<Effect>) -> LiftedInstruction {
    LiftedInstruction { address, bits: 32, complete: true, flow, effects }
}

/// `0: cmp w8, #N; 4: b.hi DEFAULT; 10: br x9; 20, 30, 40: cases; 50: default; 60: return`. `flows` gives the
/// terminal transfer of each case block.
fn function(cases: [Flow; 3], edges: &[(usize, usize)]) -> Ssa {
    function_with_split_guard(cases, edges, false)
}

fn function_with_split_guard(cases: [Flow; 3], edges: &[(usize, usize)], split: bool) -> Ssa {
    let control = || vec![Effect::Control { inputs: vec![] }];
    let mut guard = InputBlock {
        address: 0,
        instructions: vec![
            instruction(
                0,
                Flow::Next,
                vec![Effect::SetFlags {
                    operation: FlagOperation::Subtract,
                    left: Value::Register { number: 8 },
                    right: Value::Constant { value: 2 },
                }],
            ),
            instruction(4, Flow::ConditionalJump(DEFAULT), vec![Effect::FlagsConditional { condition: 8 }]),
        ],
    };
    let dispatch = InputBlock {
        address: DISPATCH,
        instructions: vec![instruction(
            DISPATCH,
            Flow::IndirectJump,
            vec![Effect::IndirectBranch { target: Value::Register { number: 9 } }],
        )],
    };
    let mut blocks = if split {
        guard.instructions[1] = instruction(4, Flow::Jump(8), control());
        let branch = InputBlock {
            address: 8,
            instructions: vec![
                instruction(8, Flow::Next, vec![]),
                instruction(12, Flow::ConditionalJump(DEFAULT), vec![Effect::FlagsConditional { condition: 8 }]),
            ],
        };
        vec![guard, branch, dispatch]
    } else {
        vec![guard, dispatch]
    };
    for (index, flow) in cases.into_iter().enumerate() {
        let address = 0x20 + 0x10 * index as u64;
        blocks.push(InputBlock { address, instructions: vec![instruction(address, flow, control())] });
    }
    blocks.push(InputBlock { address: DEFAULT, instructions: vec![instruction(DEFAULT, Flow::Next, control())] });
    blocks.push(InputBlock { address: FOLLOW, instructions: vec![instruction(FOLLOW, Flow::Return, control())] });
    ssa::build(&blocks, edges, 0).unwrap()
}

fn switch(table: &[u64]) -> Switch {
    let mut cases = table.to_vec();
    cases.sort_unstable();
    cases.dedup();
    Switch { jump: DISPATCH, cases, table: table.to_vec(), guard: 0 }
}

fn cases(region: &Region) -> Option<Vec<Vec<u64>>> {
    match region {
        Region::Sequence { regions } => regions.iter().find_map(cases),
        Region::If { taken, not_taken, .. } => cases(taken).or_else(|| cases(not_taken)),
        Region::Switch { cases, .. } => Some(cases.iter().map(|case| case.values.clone()).collect()),
        _ => None,
    }
}

const JOIN: Flow = Flow::Jump(FOLLOW);
const DENSE_EDGES: [(usize, usize); 9] = [(0, 5), (0, 1), (1, 2), (1, 3), (1, 4), (2, 6), (3, 6), (4, 6), (5, 6)];

#[test]
fn a_dense_switch_with_a_default_structures_inside_its_bound_check() {
    let ssa = function([JOIN; 3], &DENSE_EDGES);
    let switches = [switch(&[0x20, 0x30, 0x40])];
    let flat = pseudocode::render_with_switches(&ssa, &DENSE_EDGES, &switches).unwrap().text;
    assert!(flat.contains("switch (zext32(x8_"), "{flat}");
    for line in ["case 0: goto bb2;", "case 1: goto bb3;", "case 2: goto bb4;", "default: goto bb5;"] {
        assert!(flat.contains(line), "{flat}");
    }
    assert!(!flat.contains("unknown_target"), "{flat}");
    assert!(pseudocode::render(&ssa, &DENSE_EDGES).unwrap().text.contains("goto unknown_target;"));

    assert!(structure::analyze(&ssa, &DENSE_EDGES).is_err());
    let structure = structure::analyze_with_switches(&ssa, &DENSE_EDGES, &switches).unwrap();
    let Region::Sequence { regions } = &structure.body else { panic!("not sequence") };
    let Region::If { taken, not_taken, .. } = &regions[1] else { panic!("no bound check: {regions:?}") };
    assert!(
        matches!(taken.as_ref(), Region::Sequence { regions } if matches!(regions[..], [Region::Block { block: 5 }]))
    );
    let Region::Sequence { regions: inside } = not_taken.as_ref() else { panic!("not sequence") };
    assert!(matches!(inside[..], [Region::Block { block: 1 }, Region::Switch { dispatch: 1, .. }]), "{inside:?}");
    assert!(matches!(regions[2], Region::Block { block: 6 }));
    assert_eq!(cases(&structure.body), Some(vec![vec![0], vec![1], vec![2]]));

    let text = pseudocode::render_structured_with_switches(&ssa, &DENSE_EDGES, &switches).unwrap().text;
    let switch_at = text.find("switch (").unwrap();
    assert!(text[switch_at..].contains("case 1:\n"), "{text}");
    assert!(text.find("// bb6").unwrap() > text.rfind("break;").unwrap(), "{text}");
}

#[test]
fn a_sparse_switch_groups_entries_and_cases_that_skip_straight_to_the_follow() {
    // Entries 0 and 3 share bb2; 1, 4, 5, 6 go straight to the follow block; 2 to bb4.
    let edges = [(0, 5), (0, 1), (1, 2), (1, 4), (1, 6), (2, 6), (4, 6), (5, 6)];
    let ssa = function([JOIN, Flow::Return, JOIN], &edges);
    let switches = [switch(&[0x20, FOLLOW, 0x40, 0x20, FOLLOW, FOLLOW, FOLLOW])];
    let flat = pseudocode::render_with_switches(&ssa, &edges, &switches).unwrap().text;
    assert!(flat.contains("case 0: case 3: goto bb2;"), "{flat}");
    assert!(flat.contains("case 1: case 4 ... 6: goto bb6;"), "{flat}");
    let structure = structure::analyze_with_switches(&ssa, &edges, &switches).unwrap();
    assert_eq!(cases(&structure.body), Some(vec![vec![0, 3], vec![1, 4, 5, 6], vec![2]]));
}

#[test]
fn cases_that_all_return_need_no_follow_block() {
    let edges = [(0, 5), (0, 1), (1, 2), (1, 3), (1, 4), (5, 6)];
    let ssa = function([Flow::Return; 3], &edges);
    let switches = [switch(&[0x20, 0x30, 0x40])];
    let structure = structure::analyze_with_switches(&ssa, &edges, &switches).unwrap();
    assert_eq!(cases(&structure.body), Some(vec![vec![0], vec![1], vec![2]]));
}

#[test]
fn fall_through_shared_and_external_cases_stay_flat() {
    let switches = [switch(&[0x20, 0x30, 0x40])];
    // Case 0 falls through into case 1's body.
    let edges = [(0, 5), (0, 1), (1, 2), (1, 3), (1, 4), (2, 3), (3, 6), (4, 6), (5, 6)];
    let ssa = function([Flow::Next, JOIN, JOIN], &edges);
    let error = structure::analyze_with_switches(&ssa, &edges, &switches).unwrap_err();
    assert!(error.contains("fall through"), "{error}");
    assert!(pseudocode::render_with_switches(&ssa, &edges, &switches).unwrap().text.contains("case 0: goto bb2;"));
    // The default jumps into case 2's body.
    let mut edges = DENSE_EDGES.to_vec();
    edges[8] = (5, 4);
    let ssa = function([JOIN; 3], &edges);
    assert!(structure::analyze_with_switches(&ssa, &edges, &switches).is_err());
    // An entry leaves the function: a tail call.
    let ssa = function([JOIN; 3], &DENSE_EDGES);
    let external = [switch(&[0x20, 0x30, 0x40, 0x1000])];
    assert!(structure::analyze_with_switches(&ssa, &DENSE_EDGES, &external).is_err());
    let flat = pseudocode::render_with_switches(&ssa, &DENSE_EDGES, &external).unwrap().text;
    assert!(flat.contains("case 3: goto external_1000;"), "{flat}");
    // A table that disagrees with the graph's switch edges.
    let short = [switch(&[0x20, 0x30])];
    assert!(structure::analyze_with_switches(&ssa, &DENSE_EDGES, &short).is_err());
}

#[test]
fn a_guard_in_an_earlier_block_still_recovers_the_bounding_branch_and_default() {
    let mut edges: Vec<_> = DENSE_EDGES.iter().map(|&(from, to)| (from + 1, to + 1)).collect();
    edges.push((0, 1));
    let ssa = function_with_split_guard([JOIN; 3], &edges, true);
    let switches = [switch(&[0x20, 0x30, 0x40])];
    let flat = pseudocode::render_with_switches(&ssa, &edges, &switches).unwrap().text;
    assert!(flat.contains("default: goto bb6;"), "{flat}");
    let structured = structure::analyze_with_switches(&ssa, &edges, &switches).unwrap();
    assert_eq!(cases(&structured.body), Some(vec![vec![0], vec![1], vec![2]]));
}

#[test]
fn inverse_bounds_use_the_taken_dispatch_edge_not_the_default_edge() {
    let mut ssa = function([JOIN; 3], &DENSE_EDGES);
    let branch = ssa.blocks[0].statements.last_mut().unwrap();
    branch.flow = Flow::ConditionalJump(DISPATCH);
    let Expression::FlagsCondition { condition, .. } = &mut branch.observations[0] else { panic!("not flags") };
    *condition = 9;
    let switches = [switch(&[0x20, 0x30, 0x40])];
    let flat = pseudocode::render_with_switches(&ssa, &DENSE_EDGES, &switches).unwrap().text;
    assert!(flat.contains("default: goto bb5;"), "{flat}");
    let structured = structure::analyze_with_switches(&ssa, &DENSE_EDGES, &switches).unwrap();
    assert_eq!(cases(&structured.body), Some(vec![vec![0], vec![1], vec![2]]));
}

#[test]
fn an_unrelated_condition_does_not_invent_a_switch_default() {
    let mut ssa = function([JOIN; 3], &DENSE_EDGES);
    let unrelated = ssa.definitions.len();
    ssa.definitions.push(ssa::Definition { id: unrelated, variable: Variable::Flags, expression: Expression::Input });
    let branch = ssa.blocks[0].statements.last_mut().unwrap();
    let Expression::FlagsCondition { flags, .. } = &mut branch.observations[0] else { panic!("not flags") };
    *flags = unrelated;
    let flat = pseudocode::render_with_switches(&ssa, &DENSE_EDGES, &[switch(&[0x20, 0x30, 0x40])]).unwrap().text;
    assert!(!flat.contains("default: goto bb5;"), "{flat}");
}

#[test]
fn conflicting_branch_conditions_leave_the_default_unknown() {
    let mut ssa = function([JOIN; 3], &DENSE_EDGES);
    let unrelated = ssa.definitions.len();
    ssa.definitions.push(ssa::Definition { id: unrelated, variable: Variable::Flags, expression: Expression::Input });
    ssa.blocks[0]
        .statements
        .last_mut()
        .unwrap()
        .observations
        .insert(0, Expression::FlagsCondition { flags: unrelated, condition: 8 });
    let flat = pseudocode::render_with_switches(&ssa, &DENSE_EDGES, &[switch(&[0x20, 0x30, 0x40])]).unwrap().text;
    assert!(!flat.contains("default: goto bb5;"), "{flat}");
}
