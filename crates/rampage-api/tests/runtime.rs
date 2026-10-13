use std::path::PathBuf;

use rampage_api::{EdgeKind, Project, tools};
use rampage_arch::Flow;
use rampage_loaders::Binary;

#[test]
fn runtime_snapshot_resolves_indirect_flow_in_listing_analysis_graph_and_tools() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let lines = project.disassemble(Some("0x1000"), 3).unwrap();
    assert_eq!(lines[2].flow, Flow::Jump(0x1010));
    let graph = project.function_graph(0x1000).unwrap();
    assert_eq!(graph.blocks.len(), 2);
    assert_eq!(graph.edges.len(), 1);
    let registry = tools::tools();
    let (text, failed) = tools::call(&registry, &project, "function_graph", serde_json::json!({"at": "0x1000"}));
    assert!(!failed);
    assert!(text.contains("0x1010"));
    assert!(project.summary().provenance.is_some());
    let summary = project.function_summary(0x1000).unwrap();
    assert_eq!(summary.graph.edges.len(), 1);
    assert!(summary.limitations[0].contains("not decompiled"));
    assert_eq!(summary.ir.len(), 4);
    assert!(summary.ir.iter().all(|instruction| instruction.complete));
}

#[test]
fn conditional_fallthrough_calls_close_discovery_and_jumps_keep_graph_edges() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-conditional.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    assert!(project.function_graph(0x1020).is_ok());
    let graph = project.function_graph(0x2000).unwrap();
    let branch = graph.blocks.iter().flat_map(|block| &block.lines).find(|line| line.address == 0x2008).unwrap();
    assert_eq!(branch.flow, Flow::Jump(0x2020));
    let target = graph.blocks.iter().position(|block| block.start == 0x2020).unwrap();
    assert!(graph.edges.iter().any(|edge| edge.to == target));
}

#[test]
fn summaries_report_reference_truncation_through_the_page_total() {
    let root = std::env::temp_dir().join(format!("rampage-summary-{}.json", std::process::id()));
    let mut bytes: Vec<u8> = (0..1001).flat_map(|_| 0x1001_0008u32.to_le_bytes()).collect();
    bytes.extend(0xd65f_03c0u32.to_le_bytes());
    let snapshot = serde_json::json!({
        "format": "rampage-snapshot-v1", "arch": "aarch64", "provenance": "summary limit fixture",
        "regions": [
            {"name": "code", "address": "0x1000", "permissions": "r-x", "bytes": rampage_arch::hex::bytes(&bytes)},
            {"name": "data", "address": "0x3000", "permissions": "r--", "bytes": "00".repeat(5000)}
        ],
        "seeds": ["0x1000"], "entry": "0x1000"
    });
    let mut file = std::fs::OpenOptions::new().create_new(true).write(true).open(&root).unwrap();
    serde_json::to_writer(&mut file, &snapshot).unwrap();
    drop(file);
    let project = Project::new(Binary::open(&root).unwrap());
    let summary = project.function_summary(0x1000).unwrap();
    assert_eq!(summary.references.total, 1001);
    assert_eq!(summary.references.items.len(), 1000);
    std::fs::remove_file(root).unwrap();
}

#[test]
fn graph_preserves_unresolved_flows_after_memory_writes_and_block_resets() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-memory-effects.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    for (function, branch) in [(0x1000, 0x1018), (0x2000, 0x2018)] {
        let graph = project.function_graph(function).unwrap();
        let line = graph.blocks.iter().flat_map(|block| &block.lines).find(|line| line.address == branch).unwrap();
        assert_eq!(line.flow, Flow::IndirectJump);
    }
}

#[test]
fn final_pass_call_targets_participate_in_shared_tail_discovery() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-shared-tail.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let functions = project.functions(&Default::default()).unwrap();
    assert!(functions.items.iter().any(|function| function.address == 0x5000));
    assert_eq!(project.function_graph(0x5000).unwrap().blocks.len(), 1);
}

#[test]
fn writable_pointer_at_a_join_never_gets_one_false_proven_target() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-join.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let graph = project.function_graph(0x1000).unwrap();
    let line = graph.blocks.iter().flat_map(|block| &block.lines).find(|line| line.address == 0x1018).unwrap();
    assert_eq!(line.flow, Flow::IndirectJump);
    let references = project.xrefs(rampage_api::XrefQuery::From(0x1000), None, None).unwrap();
    assert!(!references.items.iter().any(|reference| reference.from == 0x1018 && reference.to == 0x4000));
}

#[test]
fn summary_ssa_carries_diamond_definitions_into_the_join() {
    use rampage_analysis::ssa::{Expression, Variable};
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-ssa-diamond.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let summary = project.function_summary(0x1000).unwrap();
    assert_eq!(summary.lifted_instructions, summary.ir.len());
    let ssa = summary.ssa.unwrap();
    let join = ssa.blocks.iter().find(|block| block.address == 0x1010).unwrap();
    let phi = join
        .phis
        .iter()
        .map(|&id| &ssa.definitions[id])
        .find(|definition| definition.variable == Variable::Register { number: 1 })
        .unwrap();
    let Expression::Phi { inputs } = &phi.expression else { panic!("missing phi") };
    assert_eq!(inputs.len(), 2);
    let constants: Vec<_> = inputs.iter().map(|input| &ssa.definitions[input.definition].expression).collect();
    assert!(constants.contains(&&Expression::Constant { value: 7 }));
    assert!(constants.contains(&&Expression::Constant { value: 11 }));
    let text = summary.pseudocode.unwrap().text;
    assert!(text.contains("phi("));
    assert!(text.contains("if (") && text.contains("goto bb"));
    assert!(!text.contains("semantic barrier"));
    assert!(summary.structured_control.is_some());
    let structured = summary.structured_pseudocode.unwrap();
    assert!(structured.structured);
    assert!(structured.text.contains("} else {") && structured.text.contains("phi_from(predecessor"));
}

#[test]
fn a_bounded_switch_connects_its_jump_to_every_case_in_the_graph_and_ssa() {
    let adr = |rd: u32, from: u64, to: u64| {
        let offset = to.wrapping_sub(from) as u32;
        0x1000_0000 | (offset & 3) << 29 | (offset >> 2 & 0x7_ffff) << 5 | rd
    };
    // nop; nop; cmp w0, #3; b.hi 0x1038; nop; adr x9, table; adr x10, 0x1028; ldrb w11, [x9, w0, uxtw];
    // add x10, x10, x11, lsl #2; br x10; then four cases and the default, each a ret.
    let mut words = vec![0xd503_201f, 0xd503_201f, 0x7100_0c1f, 0x5400_0168, 0xd503_201f];
    words.extend([adr(9, 0x1014, 0x3000), adr(10, 0x1018, 0x1028), 0x3860_492b, 0x8b0b_094a, 0xd61f_0140]);
    words.extend([0xd65f_03c0; 5]);
    let code: Vec<u8> = words.iter().flat_map(|word: &u32| word.to_le_bytes()).collect();
    let path = std::env::temp_dir().join(format!("rampage-switch-graph-{}.json", std::process::id()));
    let snapshot = serde_json::json!({
        "format": "rampage-snapshot-v1", "arch": "aarch64", "provenance": "switch graph fixture",
        "regions": [
            {"name": "text", "address": "0x1000", "permissions": "r-x", "bytes": rampage_arch::hex::bytes(&code)},
            {"name": "table", "address": "0x3000", "permissions": "r--", "bytes": "00010203"}
        ],
        "seeds": ["0x1000"], "entry": "0x1000"
    });
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    serde_json::to_writer(&mut file, &snapshot).unwrap();
    drop(file);
    let result = Binary::open(&path);
    std::fs::remove_file(&path).unwrap();
    let summary = Project::new(result.unwrap()).function_summary(0x1000).unwrap();
    let graph = &summary.graph;
    let index = |address: u64| graph.blocks.iter().position(|block| block.start == address).unwrap();
    let dispatch = index(0x1010);
    let mut cases: Vec<_> = graph
        .edges
        .iter()
        .filter(|edge| edge.from == dispatch)
        .map(|edge| {
            assert_eq!(edge.kind, EdgeKind::Switch);
            graph.blocks[edge.to].start
        })
        .collect();
    cases.sort_unstable();
    assert_eq!(cases, [0x1028, 0x102c, 0x1030, 0x1034]);
    let ssa = summary.ssa.unwrap();
    assert!(ssa.blocks.iter().all(|block| block.reachable), "{:?}", ssa.blocks);
    let case = ssa.blocks.iter().find(|block| block.address == 0x1030).unwrap();
    assert_eq!(case.predecessors, [dispatch]);
}

#[test]
fn oversized_ssa_does_not_hide_the_structural_summary() {
    let path = std::env::temp_dir().join(format!("rampage-ssa-budget-{}.json", std::process::id()));
    let mut bytes = "1f2003d5".repeat(20_001);
    bytes.push_str("c0035fd6");
    let snapshot = serde_json::json!({
        "format": "rampage-snapshot-v1", "arch": "aarch64", "provenance": "SSA resource fixture",
        "regions": [{ "name": "text", "address": "0x1000", "permissions": "r-x", "bytes": bytes }],
        "seeds": ["0x1000"], "entry": "0x1000"
    });
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    serde_json::to_writer(&mut file, &snapshot).unwrap();
    drop(file);
    let project = Project::new(Binary::open(&path).unwrap());
    let summary = project.function_summary(0x1000).unwrap();
    assert_eq!(summary.ir.len(), 20_002);
    assert!(summary.ssa.is_none());
    assert!(summary.limitations.iter().any(|text| text.contains("SSA omitted") && text.contains("instruction limit")));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn barrier_amplification_omits_ssa_before_allocating_large_definition_tables() {
    let path = std::env::temp_dir().join(format!("rampage-ssa-definitions-{}.json", std::process::id()));
    let mut bytes = "0040201e".repeat(19_999);
    bytes.push_str("c0035fd6");
    let snapshot = serde_json::json!({
        "format": "rampage-snapshot-v1", "arch": "aarch64", "provenance": "SSA barrier resource fixture",
        "regions": [{ "name": "text", "address": "0x1000", "permissions": "r-x", "bytes": bytes }],
        "seeds": ["0x1000"], "entry": "0x1000"
    });
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    serde_json::to_writer(&mut file, &snapshot).unwrap();
    drop(file);
    let summary = Project::new(Binary::open(&path).unwrap()).function_summary(0x1000).unwrap();
    assert!(summary.ssa.is_none());
    assert!(summary.limitations.iter().any(|text| text.contains("definition limit")));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn arm64_stack_pairs_report_entry_relative_slots() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64-stack.snapshot.json");
    let summary = Project::new(Binary::open(path).unwrap()).function_summary(0x1000).unwrap();
    assert!(summary.ir.iter().all(|instruction| instruction.complete));
    let dataflow = summary.dataflow.unwrap();
    assert_eq!(dataflow.stack_slots.len(), 2);
    for (slot, offset) in dataflow.stack_slots.iter().zip([-16, -8]) {
        assert_eq!(slot.offset, offset);
        assert_eq!(slot.bits, 64);
        assert_eq!(slot.writes, [0x1000]);
        assert_eq!(slot.reads, [0x100c]);
    }
}

#[test]
fn signed_byte_spill_forwards_a_return_candidate_without_snapshot_memory() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64-byte-spill.snapshot.json");
    let summary = Project::new(Binary::open(path).unwrap()).function_summary(0x1000).unwrap();
    assert!(summary.ir.iter().all(|instruction| instruction.complete));
    let data = summary.dataflow.unwrap();
    assert_eq!(data.stack_slots.len(), 1);
    assert_eq!(data.stack_slots[0].offset, -13);
    assert_eq!(data.stack_slots[0].bits, 8);
    assert_eq!(data.stack_slots[0].writes, [0x1008]);
    assert_eq!(data.stack_slots[0].reads, [0x100c]);
    assert_eq!(data.forwarded_loads.len(), 1);
    assert_eq!(data.integer_returns[0].constant_values[0].as_deref(), Some("0xffffffffffffff80"));
    assert!(data.argument_registers.is_empty());
    let text = summary.pseudocode.unwrap().text;
    assert!(text.contains("load8(") && text.contains("sext8_to64("));
}

#[test]
fn spilled_indirect_target_is_image_validated_without_inserting_a_cfg_edge() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64-spilled-target.snapshot.json");
    let summary = Project::new(Binary::open(&path).unwrap()).function_summary(0x1000).unwrap();
    assert_eq!(summary.validated_indirect_targets.len(), 1);
    assert_eq!(summary.validated_indirect_targets[0].target, 0x2000);
    assert_eq!(summary.validated_indirect_targets[0].address, 0x1014);
    assert!(summary.graph.edges.is_empty());
    let mut binary = Binary::open(path).unwrap();
    binary.segments[1].perms.execute = false;
    let summary = Project::new(binary).function_summary(0x1000).unwrap();
    assert!(summary.validated_indirect_targets.is_empty());
    assert_eq!(summary.dataflow.unwrap().indirect_targets.len(), 1);
}

#[test]
fn indirect_target_instruction_must_fit_entirely_inside_code() {
    let mut bytes = vec![0u8; 0x1280];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    let put16 = |bytes: &mut [u8], at, value: u16| bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    let put32 = |bytes: &mut [u8], at, value: u32| bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    let put64 = |bytes: &mut [u8], at, value: u64| bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 183);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, 0x1000);
    put64(&mut bytes, 32, 64);
    put64(&mut bytes, 40, 0x1140);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 1);
    put16(&mut bytes, 58, 64);
    put16(&mut bytes, 60, 5);
    put16(&mut bytes, 62, 4);
    put32(&mut bytes, 64, 1);
    put32(&mut bytes, 68, 5);
    put64(&mut bytes, 72, 0x100);
    put64(&mut bytes, 80, 0x1000);
    put64(&mut bytes, 88, 0x1000);
    put64(&mut bytes, 96, 0x1004);
    put64(&mut bytes, 104, 0x1004);
    put64(&mut bytes, 112, 0x100);
    for (index, word) in
        [0xd100_43ffu32, 0xd284_0008, 0xf900_03e8, 0xf940_03e9, 0x9100_43ff, 0xd61f_0120].into_iter().enumerate()
    {
        put32(&mut bytes, 0x100 + index * 4, word);
    }
    put32(&mut bytes, 0x1100, 0xd65f_03c0);
    let names = b"\0.dispatch\0.target\0.data\0.shstrtab\0";
    bytes[0x1108..0x1108 + names.len()].copy_from_slice(names);
    for (index, name, flags, address, offset, size, kind) in [
        (1, 1, 6, 0x1000, 0x100, 24, 1),
        (2, 11, 6, 0x2000, 0x1100, 2, 1),
        (3, 19, 2, 0x2002, 0x1102, 2, 1),
        (4, 25, 0, 0, 0x1108, names.len() as u64, 3),
    ] {
        let at = 0x1140 + index * 64;
        put32(&mut bytes, at, name);
        put32(&mut bytes, at + 4, kind);
        put64(&mut bytes, at + 8, flags);
        put64(&mut bytes, at + 16, address);
        put64(&mut bytes, at + 24, offset);
        put64(&mut bytes, at + 32, size);
        put64(&mut bytes, at + 48, 1);
    }
    let path = std::env::temp_dir().join(format!("rampage-code-range-{}.elf", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let result = Binary::open(&path);
    std::fs::remove_file(&path).unwrap();
    let binary = result.unwrap();
    assert!(binary.read(0x2000, 4).is_some());
    assert_eq!(binary.code_from(0x2000).unwrap().len(), 2);
    let summary = Project::new(binary).function_summary(0x1000).unwrap();
    assert!(summary.validated_indirect_targets.is_empty());
}
