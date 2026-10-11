use rampage_analysis::{
    dataflow,
    ssa::{self, InputBlock},
};
use rampage_arch::{
    Flow,
    ir::{Effect, LiftedInstruction, Value},
};

fn insn(address: u64, effect: Effect) -> LiftedInstruction {
    LiftedInstruction { address, bits: 64, flow: Flow::Next, complete: true, effects: vec![effect] }
}

fn offset(value: u64) -> Value {
    Value::Add { left: Box::new(Value::StackPointer), right: Box::new(Value::Constant { value }) }
}

fn store(address: u64, at: Value, bits: u8, value: u64) -> LiftedInstruction {
    insn(address, Effect::MemoryStore { address: at, bits, value: Value::Constant { value } })
}

fn load(address: u64, at: Value, bits: u8, result_bits: u8, signed: bool) -> LiftedInstruction {
    insn(
        address,
        Effect::MemoryLoad { address: at, bits, result_bits, signed, destination: Value::Register { number: 0 } },
    )
}

#[test]
fn exact_spill_reload_forwards_with_sign_and_zero_extension() {
    for (bits, result_bits, signed, value, expected) in [
        (8, 32, true, 0x180, 0xffff_ff80),
        (16, 64, true, 0x8000, 0xffff_ffff_ffff_8000),
        (32, 64, false, u64::MAX, 0xffff_ffff),
        (64, 64, false, u64::MAX, u64::MAX),
    ] {
        let input = [InputBlock {
            address: 0,
            instructions: vec![store(0, offset(0), bits, value), load(4, offset(0), bits, result_bits, signed)],
        }];
        let ssa = ssa::build(&input, &[], 0).unwrap();
        let result = ssa.blocks[0].statements[1].definitions[0];
        let data = dataflow::analyze(&ssa).unwrap();
        assert!(data.constants.iter().any(|constant| constant.definition == result && constant.value == expected));
        assert_eq!(data.forwarded_loads.len(), 1);
        assert_eq!(data.forwarded_loads[0].store_definitions, ssa.blocks[0].statements[0].definitions);
        assert_eq!(data.stack_slots[0].bits, bits);
        assert_eq!(data.stack_slots[0].reads, [4]);
    }
}

#[test]
fn disjoint_stores_preserve_evidence_but_unknown_and_overlapping_writes_do_not() {
    for (middle, resolves) in [
        (store(4, offset(8), 64, 19), true),
        (store(4, offset(4), 32, 19), false),
        (store(4, Value::Register { number: 1 }, 64, 19), false),
        (insn(4, Effect::Call { target: Value::Constant { value: 0x1000 }, return_address: 8 }), false),
    ] {
        let input = [InputBlock {
            address: 0,
            instructions: vec![store(0, offset(0), 64, 11), middle, load(8, offset(0), 64, 64, false)],
        }];
        let data = dataflow::analyze(&ssa::build(&input, &[], 0).unwrap()).unwrap();
        assert_eq!(!data.forwarded_loads.is_empty(), resolves);
    }
}

#[test]
fn memory_joins_require_each_path_to_agree_and_keep_both_sources() {
    for (other_value, other_store, expected) in [(11, true, true), (19, true, false), (11, false, false)] {
        let input = [
            InputBlock { address: 0, instructions: vec![] },
            InputBlock { address: 4, instructions: vec![store(4, offset(0), 64, 11)] },
            InputBlock {
                address: 8,
                instructions: if other_store { vec![store(8, offset(0), 64, other_value)] } else { vec![] },
            },
            InputBlock { address: 12, instructions: vec![load(12, offset(0), 64, 64, false)] },
        ];
        let ssa = ssa::build(&input, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap();
        let data = dataflow::analyze(&ssa).unwrap();
        assert_eq!(!data.forwarded_loads.is_empty(), expected);
        if expected {
            assert_eq!(data.forwarded_loads[0].store_definitions.len(), 2);
        }
    }
}

#[test]
fn a_store_after_a_reload_can_feed_a_later_reload_without_snapshot_bytes() {
    let input = [InputBlock {
        address: 0,
        instructions: vec![
            store(0, offset(0), 64, 11),
            load(4, offset(0), 64, 64, false),
            insn(8, Effect::MemoryStore { address: offset(8), bits: 64, value: Value::Register { number: 0 } }),
            load(12, offset(8), 64, 64, false),
        ],
    }];
    let data = dataflow::analyze(&ssa::build(&input, &[], 0).unwrap()).unwrap();
    assert_eq!(data.forwarded_loads.len(), 2);
    assert!(data.forwarded_loads.iter().all(|load| load.value == 11));
}

#[test]
fn cyclic_memory_and_mixed_address_domains_remain_unknown() {
    let input = [
        InputBlock { address: 0, instructions: vec![store(0, offset(0), 64, 11)] },
        InputBlock { address: 4, instructions: vec![load(4, offset(0), 64, 64, false)] },
    ];
    let data = dataflow::analyze(&ssa::build(&input, &[(0, 1), (1, 1)], 0).unwrap()).unwrap();
    assert!(data.forwarded_loads.is_empty());
    let input = [InputBlock {
        address: 0,
        instructions: vec![
            store(0, offset(0), 64, 11),
            store(4, Value::Constant { value: 0x1000 }, 64, 7),
            load(8, offset(0), 64, 64, false),
        ],
    }];
    assert!(dataflow::analyze(&ssa::build(&input, &[], 0).unwrap()).unwrap().forwarded_loads.is_empty());
}

#[test]
fn missing_or_duplicate_memory_phi_paths_are_errors_not_evidence() {
    use rampage_analysis::ssa::{Expression, Variable};
    let input = [
        InputBlock { address: 0, instructions: vec![] },
        InputBlock { address: 4, instructions: vec![store(4, offset(0), 64, 11)] },
        InputBlock { address: 8, instructions: vec![store(8, offset(0), 64, 19)] },
        InputBlock { address: 12, instructions: vec![load(12, offset(0), 64, 64, false)] },
    ];
    let mut ssa = ssa::build(&input, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap();
    let phi = *ssa.blocks[3].phis.iter().find(|&&id| ssa.definitions[id].variable == Variable::Memory).unwrap();
    let Expression::Phi { inputs } = &mut ssa.definitions[phi].expression else { panic!("missing phi") };
    inputs.pop();
    assert!(dataflow::analyze(&ssa).is_err());
    let Expression::Phi { inputs } = &mut ssa.definitions[phi].expression else { panic!("missing phi") };
    inputs.push(inputs[0].clone());
    assert!(dataflow::analyze(&ssa).is_err());
}

#[test]
fn shared_suffix_memoization_does_not_bypass_memory_path_depth() {
    let input: Vec<_> = (0..83)
        .map(|index| InputBlock {
            address: index * 4,
            instructions: if index == 0 {
                vec![store(0, offset(0), 64, 11)]
            } else if index == 82 {
                vec![load(328, offset(0), 64, 64, false)]
            } else {
                vec![]
            },
        })
        .collect();
    let mut edges: Vec<_> = (0..82).map(|index| (index, index + 1)).collect();
    edges.push((40, 82));
    let mut ssa = ssa::build(&input, &edges, 0).unwrap();
    assert!(dataflow::analyze(&ssa).unwrap().forwarded_loads.is_empty());
    for definition in &mut ssa.definitions {
        if let rampage_analysis::ssa::Expression::Phi { inputs } = &mut definition.expression {
            inputs.reverse();
        }
    }
    assert!(dataflow::analyze(&ssa).unwrap().forwarded_loads.is_empty());
}
