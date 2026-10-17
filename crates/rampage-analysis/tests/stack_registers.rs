use rampage_analysis::{
    dataflow::{self, DataFlow},
    ssa::{self, Expression, InputBlock, Variable},
};
use rampage_arch::{
    Arch, Flow, Target, decoder,
    ir::{self, Effect, LiftedInstruction, Value},
};

fn lifted(address: u64, words: &[u32]) -> InputBlock {
    let instructions = words
        .iter()
        .enumerate()
        .map(|(index, word)| {
            let bytes = word.to_le_bytes();
            let instruction = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, address + index as u64 * 4);
            let instruction = ir::lift(Arch::Aarch64, &bytes, &instruction);
            assert!(instruction.complete, "{word:08x}");
            instruction
        })
        .collect();
    InputBlock { address, instructions }
}

fn insn(address: u64, effect: Effect) -> LiftedInstruction {
    LiftedInstruction { address, bits: 64, flow: Flow::Next, complete: true, effects: vec![effect] }
}

fn copy(address: u64, destination: u8, source: u8) -> LiftedInstruction {
    insn(
        address,
        Effect::Assign {
            destination: Value::Register { number: destination },
            value: Value::Register { number: source },
        },
    )
}

fn store(address: u64, register: u8, bits: u8) -> LiftedInstruction {
    insn(
        address,
        Effect::MemoryStore { address: Value::StackPointer, value: Value::Register { number: register }, bits },
    )
}

fn reload(address: u64, register: u8) -> LiftedInstruction {
    insn(
        address,
        Effect::MemoryLoad {
            destination: Value::Register { number: register },
            address: Value::StackPointer,
            bits: 64,
            result_bits: 64,
            signed: false,
        },
    )
}

fn analyze(instructions: Vec<LiftedInstruction>) -> DataFlow {
    dataflow::analyze(&ssa::build(&[InputBlock { address: 0, instructions }], &[], 0).unwrap()).unwrap()
}

#[test]
fn raw_frame_pair_and_integer_spill_have_entry_relative_value_evidence() {
    let block = lifted(0x1000, &[0xa9be_7bfd, 0x9100_03fd, 0xf900_0bf3, 0xf940_0bf3, 0xa8c2_7bfd, 0xd65f_03c0]);
    let data = dataflow::analyze(&ssa::build(&[block], &[], 0).unwrap()).unwrap();
    assert_eq!(data.incomplete_instructions, 0);
    assert_eq!(data.stack_registers.len(), 3);
    let matches: Vec<_> = data
        .stack_registers
        .iter()
        .filter(|record| record.classification == "matching_register_reload")
        .map(|record| (record.register, record.offset, record.bits, record.stores.clone(), record.restores.clone()))
        .collect();
    assert_eq!(
        matches,
        [
            (19, -16, 64, vec![0x1008], vec![0x100c]),
            (29, -32, 64, vec![0x1000], vec![0x1010]),
            (30, -24, 64, vec![0x1000], vec![0x1010]),
        ]
    );
    for record in &data.stack_registers {
        assert_eq!(record.confidence, "ssa_proven");
        assert!(record.evidence.contains(&"entry_register_store"));
    }
}

#[test]
fn raw_copy_can_store_another_registers_entry_value_but_narrow_copies_cannot() {
    for (copy_word, expected) in [(0xaa13_03e9, true), (0x2a13_03e9, false)] {
        let block = lifted(0x1000, &[copy_word, 0xd280_0033, 0xf900_03e9, 0xf940_03f3, 0xd65f_03c0]);
        let data = dataflow::analyze(&ssa::build(&[block], &[], 0).unwrap()).unwrap();
        assert_eq!(
            data.stack_registers.iter().any(|record| {
                record.register == 19
                    && record.classification == "matching_register_reload"
                    && record.stores == [0x1008]
                    && record.restores == [0x100c]
            }),
            expected
        );
        assert!(!data.stack_registers.iter().any(|record| record.register == 9));
    }
}

#[test]
fn partial_stores_and_overwrites_never_claim_a_restore_pair() {
    for instructions in [
        vec![store(0, 19, 32), reload(4, 19)],
        vec![store(0, 19, 64), store(4, 20, 64), reload(8, 19)],
        vec![store(0, 19, 64), store(4, 20, 32), reload(8, 19)],
        vec![store(0, 19, 64), reload(4, 20)],
    ] {
        let data = analyze(instructions);
        assert!(!data.stack_registers.iter().any(|record| record.classification == "matching_register_reload"));
        let candidate = data.stack_registers.iter().find(|record| record.classification == "reload_candidate").unwrap();
        assert_eq!(candidate.confidence, "conditional");
        assert!(candidate.stores.is_empty());
        assert_eq!(candidate.restores.len(), 1);
        assert!(candidate.evidence.contains(&"entry_register_value_not_proven"));
    }
}

#[test]
fn branch_slot_reuse_requires_all_paths_to_retain_the_same_entry_register() {
    for (other_register, expected) in [(19, true), (20, false)] {
        let input = [
            InputBlock { address: 0, instructions: vec![store(0, 19, 64)] },
            InputBlock { address: 4, instructions: vec![] },
            InputBlock { address: 8, instructions: vec![store(8, other_register, 64)] },
            InputBlock { address: 12, instructions: vec![reload(12, 19)] },
        ];
        let data = dataflow::analyze(&ssa::build(&input, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap()).unwrap();
        let matched = data.stack_registers.iter().find(|record| record.classification == "matching_register_reload");
        assert_eq!(matched.is_some(), expected);
        if let Some(matched) = matched {
            assert_eq!(matched.stores, [0, 8]);
            assert_eq!(matched.restores, [12]);
        } else {
            let candidate =
                data.stack_registers.iter().find(|record| record.classification == "reload_candidate").unwrap();
            assert!(candidate.stores.is_empty());
        }
    }
}

#[test]
fn stored_value_phis_must_agree_even_when_the_carrier_register_matches() {
    for (other_register, expected) in [(19, true), (20, false)] {
        let input = [
            InputBlock { address: 0, instructions: vec![] },
            InputBlock { address: 4, instructions: vec![copy(4, 9, 19)] },
            InputBlock { address: 8, instructions: vec![copy(8, 9, other_register)] },
            InputBlock { address: 12, instructions: vec![store(12, 9, 64), reload(16, 19)] },
        ];
        let data = dataflow::analyze(&ssa::build(&input, &[(0, 1), (0, 2), (1, 3), (2, 3)], 0).unwrap()).unwrap();
        assert_eq!(
            data.stack_registers.iter().any(|record| record.classification == "matching_register_reload"),
            expected
        );
        assert_eq!(
            data.stack_registers.iter().any(|record| record.evidence.contains(&"entry_register_store")),
            expected
        );
    }
}

#[test]
fn unknown_stack_pointer_and_incomplete_semantics_do_not_create_frame_evidence() {
    let unknown_sp = insn(0, Effect::Assign { destination: Value::StackPointer, value: Value::Register { number: 0 } });
    let data = analyze(vec![unknown_sp, store(4, 19, 64), reload(8, 19)]);
    assert!(data.stack_registers.is_empty());
    let mut incomplete = copy(4, 9, 19);
    incomplete.complete = false;
    let data = analyze(vec![store(0, 19, 64), incomplete, reload(8, 19)]);
    assert_eq!(data.incomplete_instructions, 1);
    assert!(!data.stack_registers.iter().any(|record| record.classification == "matching_register_reload"));
    assert!(data.stack_registers.iter().all(|record| record.restores.is_empty()));
}

#[test]
fn calls_unknown_aliases_and_memory_cycles_stop_reload_matching() {
    for middle in [
        insn(4, Effect::Call { target: Value::Constant { value: 0x1000 }, return_address: 8 }),
        insn(
            4,
            Effect::MemoryStore {
                address: Value::Register { number: 1 },
                value: Value::Register { number: 20 },
                bits: 64,
            },
        ),
    ] {
        let data = analyze(vec![store(0, 19, 64), middle, reload(8, 19)]);
        assert!(!data.stack_registers.iter().any(|record| record.classification == "matching_register_reload"));
    }
    let input = [
        InputBlock { address: 0, instructions: vec![store(0, 19, 64)] },
        InputBlock { address: 4, instructions: vec![reload(4, 19)] },
    ];
    let data = dataflow::analyze(&ssa::build(&input, &[(0, 1), (1, 1)], 0).unwrap()).unwrap();
    assert!(!data.stack_registers.iter().any(|record| record.classification == "matching_register_reload"));
}

#[test]
fn provenance_copy_depth_is_bounded() {
    let mut instructions: Vec<_> = (0..40).map(|index| copy(index * 4, 19, 19)).collect();
    instructions.extend([store(160, 19, 64), reload(164, 19)]);
    let data = analyze(instructions);
    assert!(!data.stack_registers.iter().any(|record| record.classification == "entry_register_store"));
    assert!(!data.stack_registers.iter().any(|record| record.classification == "matching_register_reload"));
    assert!(data.stack_registers.iter().any(|record| record.classification == "reload_candidate"));
}

#[test]
fn out_of_range_store_and_load_references_are_errors() {
    for corrupt_store in [true, false] {
        let input = [InputBlock { address: 0, instructions: vec![store(0, 19, 64), reload(4, 19)] }];
        let mut ssa = ssa::build(&input, &[], 0).unwrap();
        let id = ssa.blocks[0].statements[usize::from(!corrupt_store)].definitions[0];
        if corrupt_store {
            let Expression::Store { value, .. } = &mut ssa.definitions[id].expression else { panic!("missing store") };
            **value = Expression::Reference { definition: usize::MAX };
        } else {
            let Expression::Load { memory, .. } = &mut ssa.blocks[0].statements[1].observations[0] else {
                panic!("missing retained load")
            };
            *memory = usize::MAX;
        }
        assert!(dataflow::analyze(&ssa).is_err());
    }
}

#[test]
fn conflicting_or_missing_memory_phi_inputs_are_not_restore_evidence() {
    let input = [
        InputBlock { address: 0, instructions: vec![store(0, 19, 64)] },
        InputBlock { address: 4, instructions: vec![] },
        InputBlock { address: 8, instructions: vec![reload(8, 19)] },
    ];
    let mut ssa = ssa::build(&input, &[(0, 1), (0, 2), (1, 2)], 0).unwrap();
    let phi = *ssa.blocks[2].phis.iter().find(|&&id| ssa.definitions[id].variable == Variable::Memory).unwrap();
    let Expression::Phi { inputs } = &mut ssa.definitions[phi].expression else { panic!("missing phi") };
    inputs.pop();
    assert!(dataflow::analyze(&ssa).is_err());
}

#[test]
fn recovered_pair_accesses_keep_their_definition_order_after_simplification() {
    let block = lifted(0x1000, &[0xa9be_7bfd, 0x9100_03fd, 0xa8c2_7bfd, 0xd65f_03c0]);
    let mut ssa = ssa::build(&[block], &[], 0).unwrap();
    ssa::simplify(&mut ssa).unwrap();
    let data = dataflow::analyze(&ssa).unwrap();
    assert!(
        data.stack_registers
            .iter()
            .any(|record| { record.register == 29 && record.offset == -32 && record.restores == [0x1008] })
    );
    assert!(
        data.stack_registers
            .iter()
            .any(|record| { record.register == 30 && record.offset == -24 && record.restores == [0x1008] })
    );
    let statement = &mut ssa.blocks[0].statements[2];
    assert_eq!(statement.recovered_loads.len(), 2);
    statement.recovered_loads.reverse();
    assert!(dataflow::analyze(&ssa).is_err());
}

#[test]
fn expression_node_budget_is_checked_before_register_provenance() {
    let input = [InputBlock { address: 0, instructions: vec![store(0, 19, 64), reload(4, 19)] }];
    let mut ssa = ssa::build(&input, &[], 0).unwrap();
    let id = ssa.blocks[0].statements[0].definitions[0];
    let Expression::Store { value, .. } = &mut ssa.definitions[id].expression else { panic!("missing store") };
    let mut tree = Expression::Constant { value: 0 };
    for _ in 0..16 {
        tree = Expression::Add { left: Box::new(tree.clone()), right: Box::new(tree) };
    }
    **value = tree;
    assert!(dataflow::analyze(&ssa).is_err());
}

#[test]
fn large_multi_effect_statement_keeps_first_and_last_recovered_load_mappings() {
    let mut effects: Vec<_> = (0..10_000)
        .map(|_| Effect::MemoryLoad {
            destination: Value::Register { number: 19 },
            address: Value::StackPointer,
            bits: 64,
            result_bits: 64,
            signed: false,
        })
        .collect();
    let Effect::MemoryLoad { destination, .. } = effects.last_mut().unwrap() else { panic!("missing load") };
    *destination = Value::Register { number: 20 };
    let input = [InputBlock {
        address: 0,
        instructions: vec![
            store(0, 19, 64),
            LiftedInstruction { address: 4, bits: 64, flow: Flow::Next, complete: true, effects },
        ],
    }];
    let ssa = ssa::build(&input, &[], 0).unwrap();
    assert_eq!(ssa.blocks[0].statements[1].recovered_loads.len(), 10_000);
    let data = dataflow::analyze(&ssa).unwrap();
    assert_eq!(data.stack_registers.len(), 2);
    let matched = data.stack_registers.iter().find(|record| record.register == 19).unwrap();
    assert_eq!(matched.classification, "matching_register_reload");
    assert_eq!(matched.stores, [0]);
    assert_eq!(matched.restores, [4]);
    let candidate = data.stack_registers.iter().find(|record| record.register == 20).unwrap();
    assert_eq!(candidate.classification, "reload_candidate");
    assert_eq!(candidate.confidence, "conditional");
    assert!(candidate.stores.is_empty());
    assert_eq!(candidate.restores, [4]);
}
