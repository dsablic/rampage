use std::path::PathBuf;

use rampage_api::{Project, tools};
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
