//! Owned JSON vectors, not Ghidra output or evidence of parity on a real binary.

use rampage_eval::parity_graph::{
    Address, ExportBinding, GraphMetric, GraphReceipt, GraphRequest, ImageIdentity, Side, compare_exports,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn digest(text: &str) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(text.as_bytes()))
}

fn request(rampage: &str, ghidra: &str, max_details: usize) -> GraphRequest {
    let image = ImageIdentity {
        image_sha256: digest("owned-vector-image"),
        architecture: "x86_64".into(),
        address_bits: 64,
        address_space: "ram".into(),
        image_base: Address(0),
        image_offset: 0,
        image_length: None,
    };
    let binding = |tool: &str, text: &str| ExportBinding {
        image: image.clone(),
        tool: tool.into(),
        version: "owned-test-vector".into(),
        exporter: format!("owned {tool} JSON vector"),
        exporter_sha256: digest(tool),
        export_sha256: digest(text),
        provenance: Some(json!({"origin": "synthetic-owned-test"})),
    };
    GraphRequest { rampage: binding("rampage", rampage), ghidra: binding("ghidra", ghidra), max_details }
}

fn compare(rampage: Value, ghidra: Value, limit: usize) -> GraphReceipt {
    let (rampage, ghidra) = (rampage.to_string(), ghidra.to_string());
    compare_exports(&request(&rampage, &ghidra, limit), &rampage, &ghidra).unwrap()
}

fn r_function(address: &str, blocks: Value, edges: Value, references: Value) -> Value {
    json!({"address": address, "blocks": blocks, "edges": edges, "references": references,
        "noreturn_calls": []})
}

fn g_function(address: &str, blocks: Value, calls: Value) -> Value {
    json!({"address": address, "noreturn": false, "blocks": blocks, "calls": calls})
}

fn g_block(start: &str, end: &str, successors: Value) -> Value {
    json!({"start": start, "end": end, "successors": successors})
}

fn single_r() -> Value {
    json!([r_function("0x10", json!(["0x10"]), json!([]), json!([]))])
}

fn single_g() -> Value {
    json!({"functions": [g_function("0x10", json!([g_block("0x10", "0x20", json!([]))]), json!([]))]})
}

#[test]
fn exact_address_matches_ignore_cfg_kinds_and_call_kinds_but_retain_binding() {
    let r = json!([r_function(
        "0x0010",
        json!(["0x10", "0x20"]),
        json!([["0x10", "0x20", "fallthrough"]]),
        json!([["0x14", "0x900", "call"]])
    )]);
    let g = json!({"functions": [g_function("0x10", json!([
        g_block("0x10", "0x20", json!([["0x20", "FALL_THROUGH"]])),
        g_block("0x20", "0x30", json!([]))]), json!([["0x14", "0x900", "UNCONDITIONAL_CALL"]]))]});
    let report = compare(r, g, 8);
    assert_eq!(report.functions.common, 1);
    assert_eq!(report.blocks.matched, 2);
    assert_eq!(report.edges.matched, 1);
    assert_eq!(report.calls.matched, 1);
    assert_eq!(report.call_graph.matched, 1);
    assert_eq!(report.blocks.precision, Some(1.0));
    assert_eq!(report.disagreements.total, 0);
    assert!(!report.reference_is_truth);
    assert_eq!(report.binding.rampage.provenance, Some(json!({"origin": "synthetic-owned-test"})));
    assert_eq!(serde_json::to_value(Address(0x10)).unwrap(), "0x10");
}

#[test]
fn missing_and_spurious_items_keep_denominators_and_bounded_details() {
    let r = json!([r_function(
        "0x10",
        json!(["0x10", "0x20", "0x30"]),
        json!([["0x10", "0x20", "branch"], ["0x10", "0x30", "branch"]]),
        json!([["0x12", "0x900", "call"], ["0x14", "0xa00", "call"]])
    )]);
    let g = json!({"functions": [g_function("0x10", json!([
        g_block("0x10", "0x20", json!([["0x20", "CONDITIONAL_JUMP"], ["0x40", "FALL_THROUGH"]])),
        g_block("0x20", "0x30", json!([])), g_block("0x40", "0x50", json!([]))]),
        json!([["0x12", "0x900", "UNCONDITIONAL_CALL"], ["0x16", "0xb00", "UNCONDITIONAL_CALL"]]))]});
    let report = compare(r, g, 2);
    assert_eq!((report.blocks.rampage, report.blocks.ghidra, report.blocks.matched), (3, 3, 2));
    assert_eq!((report.blocks.only_rampage, report.blocks.only_ghidra, report.blocks.union), (1, 1, 4));
    assert_eq!(report.blocks.precision, Some(2.0 / 3.0));
    assert_eq!(report.blocks.recall, Some(2.0 / 3.0));
    assert_eq!(report.blocks.jaccard, Some(0.5));
    assert_eq!((report.edges.matched, report.edges.rampage, report.edges.ghidra), (1, 2, 2));
    assert_eq!((report.calls.matched, report.calls.rampage, report.calls.ghidra), (1, 2, 2));
    assert_eq!((report.call_graph.matched, report.call_graph.union), (1, 3));
    assert_eq!(report.disagreeing_functions, 1);
    assert_eq!(report.disagreements.items.len(), 2);
    assert_eq!(report.disagreements.total, 12);
    assert_eq!(report.disagreements.omitted, 10);
    assert_eq!(report.disagreements.items[0].metric, GraphMetric::Blocks);
    assert_eq!(report.disagreements.items[0].side, Side::Rampage);
    assert_eq!(report.disagreements.items[0].source, Address(0x30));
    assert_eq!(report.raw_call_disagreements.only_rampage, 1);
    assert_eq!(report.raw_call_disagreements.only_ghidra, 1);
    assert_eq!(report.raw_call_disagreements.details.total, 2);
    assert_eq!(report.raw_call_disagreements.details.omitted, 0);
}

#[test]
fn unmatched_functions_are_coverage_not_item_denominators() {
    let mut r = single_r();
    r.as_array_mut().unwrap().push(r_function("0x30", json!(["0x30", "0x34"]), json!([]), json!([])));
    let mut g = single_g();
    g["functions"].as_array_mut().unwrap().push(g_function(
        "0x50",
        json!([g_block("0x50", "0x60", json!([]))]),
        json!([]),
    ));
    let report = compare(r, g, 1);
    assert_eq!((report.functions.rampage, report.functions.ghidra, report.functions.common), (2, 2, 1));
    assert_eq!((report.functions.only_rampage, report.functions.only_ghidra), (1, 1));
    assert_eq!((report.functions.unmatched.total, report.functions.unmatched.omitted), (2, 1));
    assert_eq!(report.functions.unmatched.items[0].function, Address(0x30));
    assert_eq!((report.blocks.rampage, report.blocks.ghidra, report.blocks.matched), (1, 1, 1));
}

#[test]
fn zero_denominators_are_null_and_zero_common_is_not_vacuous_agreement() {
    for (r, g) in
        [(json!([]), json!({"functions": []})), (single_r(), json!({"functions": []})), (json!([]), single_g())]
    {
        let report = compare(r, g, 0);
        assert_eq!(report.functions.common, 0);
        assert_eq!(report.blocks.precision, None);
        assert_eq!(report.blocks.recall, None);
        assert_eq!(report.blocks.jaccard, None);
        assert_eq!(serde_json::to_value(&report).unwrap()["calls"]["recall"], Value::Null);
        assert_eq!(report.identical_block_functions, 0);
        assert!(report.functions.unmatched.items.is_empty());
    }
    let report = compare(single_r(), single_g(), 0);
    assert_eq!(report.calls.precision, None);
    assert_eq!(report.edges.recall, None);
    assert_eq!(report.blocks.recall, Some(1.0));
    let mut g = single_g();
    g["functions"][0]["calls"] = json!([["0x12", "0x900", "UNCONDITIONAL_CALL"]]);
    let report = compare(single_r(), g, 0);
    assert_eq!(report.calls.precision, None);
    assert_eq!(report.calls.recall, Some(0.0));
    assert_eq!(report.calls.only_ghidra, 1);
    assert!(report.disagreements.total > 0);
    assert_eq!(report.disagreements.total, report.disagreements.omitted);
}

#[test]
fn source_instruction_pairs_differ_even_when_the_call_graph_matches() {
    let mut r = single_r();
    r[0]["references"] = json!([["0x12", "0x900", "call"], ["0x14", "0x900", "call"]]);
    let mut g = single_g();
    g["functions"][0]["calls"] = json!([["0x16", "0x900", "UNCONDITIONAL_CALL"]]);
    let report = compare(r, g, 20);
    assert_eq!(report.calls.matched, 0);
    assert_eq!((report.calls.rampage, report.calls.ghidra), (2, 1));
    assert_eq!(report.call_graph.matched, 1);
    assert_eq!((report.call_graph.rampage, report.call_graph.ghidra), (1, 1));
    let details: Vec<_> = report.disagreements.items.iter().filter(|item| item.metric == GraphMetric::Calls).collect();
    assert_eq!(details.len(), 3);
    assert_eq!(details[0].kind.as_deref(), Some("call"));
    assert_eq!(details[2].kind.as_deref(), Some("UNCONDITIONAL_CALL"));
}

#[test]
fn tail_calls_use_all_rampage_starts_but_not_self_jumps_or_arbitrary_jumps() {
    let r = json!([
        r_function(
            "0x10",
            json!(["0x10"]),
            json!([]),
            json!([["0x12", "0x10", "jump"], ["0x14", "0x30", "jump"], ["0x16", "0x900", "jump"]])
        ),
        r_function("0x30", json!(["0x30"]), json!([]), json!([]))
    ]);
    let mut g = single_g();
    g["functions"][0]["calls"] = json!([["0x14", "0x30", "UNCONDITIONAL_CALL"]]);
    let report = compare(r, g, 10);
    assert_eq!((report.calls.rampage, report.calls.ghidra, report.calls.matched), (1, 1, 1));
    assert_eq!(report.functions.only_rampage, 1);
}

#[test]
fn computed_call_prefix_filter_retains_exclusions_separately() {
    let mut r = single_r();
    r[0]["references"] = json!([["0x1c", "0x908", "call"]]);
    let mut g = single_g();
    g["functions"][0]["calls"] = json!([
        ["0x14", "0x900", "COMPUTED_CALL"],
        ["0x18", "0x904", "COMPUTED_CALL_TERMINATOR"],
        ["0x1c", "0x908", "COMPUTED_CALL"]
    ]);
    let report = compare(r, g, 1);
    assert_eq!(report.calls.matched, 1);
    assert_eq!(report.calls.recall, Some(1.0));
    assert_eq!(report.ghidra_computed_calls.total, 2);
    assert_eq!(report.ghidra_computed_calls.omitted, 1);
    assert_eq!(report.ghidra_computed_calls.items[0].source, Address(0x14));
    assert_eq!(report.disagreements.total, 0);
    assert_eq!(report.disagreeing_functions, 1);
    assert_eq!(report.raw_call_disagreements.only_rampage, 0);
    assert_eq!(report.raw_call_disagreements.only_ghidra, 2);
    assert_eq!(report.raw_call_disagreements.details.total, 2);
    assert_eq!(report.raw_call_disagreements.details.omitted, 1);
}

#[test]
fn ghidra_only_computed_call_is_a_raw_disagreement_not_a_scored_call() {
    for kind in ["COMPUTED_CALL", "COMPUTED_CALL_TERMINATOR"] {
        for limit in [0, 1] {
            let mut g = single_g();
            g["functions"][0]["calls"] = json!([["0x14", "0x900", kind]]);
            let report = compare(single_r(), g, limit);
            assert_eq!(report.disagreeing_functions, 1);
            assert_eq!(report.calls.rampage, 0);
            assert_eq!(report.calls.ghidra, 0);
            assert_eq!(report.calls.recall, None);
            assert_eq!(report.call_graph.ghidra, 0);
            assert_eq!(report.disagreements.total, 0);
            assert_eq!(report.ghidra_computed_calls.total, 1);
            let raw = &report.raw_call_disagreements;
            assert_eq!((raw.only_rampage, raw.only_ghidra), (0, 1));
            assert_eq!(raw.details.total, 1);
            assert_eq!(raw.details.omitted, 1 - limit);
            assert_eq!(raw.details.items.len(), limit);
            if limit == 1 {
                let item = &raw.details.items[0];
                assert_eq!(item.function, Address(0x10));
                assert_eq!(item.metric, GraphMetric::Calls);
                assert_eq!(item.side, Side::Ghidra);
                assert_eq!(item.source, Address(0x14));
                assert_eq!(item.target, Some(Address(0x900)));
                assert_eq!(item.kind.as_deref(), Some(kind));
            }
        }
    }
}

#[test]
fn shared_blocks_and_edges_are_pooled_per_function_owner() {
    let r = json!([
        r_function("0x10", json!(["0x10", "0x50"]), json!([["0x10", "0x50", "jump"]]), json!([])),
        r_function("0x30", json!(["0x30"]), json!([]), json!([]))
    ]);
    let g = json!({"functions": [
        g_function("0x10", json!([
            g_block("0x10", "0x20", json!([["0x50", "UNCONDITIONAL_JUMP"]])),
            g_block("0x50", "0x60", json!([]))]), json!([])),
        g_function("0x30", json!([
            g_block("0x30", "0x40", json!([["0x50", "UNCONDITIONAL_JUMP"]])),
            g_block("0x50", "0x60", json!([]))]), json!([]))]});
    let report = compare(r, g, 20);
    assert_eq!(report.blocks.matched, 3);
    assert_eq!(report.blocks.recall, Some(3.0 / 4.0));
    assert_eq!(report.edges.recall, Some(0.5));
}

#[test]
fn straight_line_splits_collapse_but_entry_and_self_loop_survive() {
    let r = json!([r_function("0x10", json!(["0x10"]), json!([]), json!([]))]);
    let g = json!({"functions": [g_function("0x10", json!([
        g_block("0x10", "0x14", json!([["0x14", "FALL_THROUGH"]])),
        g_block("0x14", "0x20", json!([]))]), json!([]))]});
    let report = compare(r, g, 20);
    assert_eq!(report.blocks.recall, Some(0.5));
    assert_eq!(report.chains.recall, Some(1.0));
    assert_eq!((report.chain_edges.rampage, report.chain_edges.ghidra), (0, 0));

    let r = json!([r_function("0x10", json!(["0x10"]), json!([["0x10", "0x10", "jump"]]), json!([]))]);
    let g = json!({"functions": [g_function("0x10", json!([
        g_block("0x10", "0x20", json!([["0x10", "UNCONDITIONAL_JUMP"]]))]), json!([]))]});
    let report = compare(r, g, 20);
    assert_eq!(report.chains.matched, 1);
    assert_eq!(report.chain_edges.matched, 1);
}

#[test]
fn preserves_high_u64_addresses_without_float_rounding_and_checks_declared_width() {
    let r = json!([r_function(
        "0xfffffffffffffffe",
        json!(["0xfffffffffffffffe"]),
        json!([]),
        json!([["0xfffffffffffffffe", "0xfffffffffffffffc", "call"]])
    )]);
    let g = json!({"functions": [g_function("0xfffffffffffffffe", json!([
        g_block("0xfffffffffffffffe", "0xffffffffffffffff", json!([]))]),
        json!([["0xfffffffffffffffe", "0xfffffffffffffffd", "UNCONDITIONAL_CALL"]]))]});
    let report = compare(r, g, 10);
    assert_eq!(report.blocks.matched, 1);
    assert_eq!((report.calls.rampage, report.calls.ghidra, report.calls.matched), (1, 1, 0));
    assert_eq!(report.disagreements.items[0].target, Some(Address(0xfffffffffffffffc)));
    let r = r_function("0x100000000", json!(["0x100000000"]), json!([]), json!([]));
    let r = json!([r]).to_string();
    let g = single_g().to_string();
    let mut binding = request(&r, &g, 1);
    binding.rampage.image.address_bits = 32;
    binding.ghidra.image.address_bits = 32;
    assert!(compare_exports(&binding, &r, &g).unwrap_err().to_string().contains("32-bit"));
}

#[test]
fn malformed_exports_missing_fields_bad_tuples_and_bad_addresses_fail() {
    let g = single_g().to_string();
    for bad in [
        "{",
        "{}",
        "null",
        "[{}]",
        r#"[{"address":"0x10","blocks":[],"edges":[],"references":[["0x10","0x20"]]}]"#,
        r#"[{"address":16,"blocks":[],"edges":[],"references":[]}]"#,
    ] {
        assert!(compare_exports(&request(bad, &g, 1), bad, &g).is_err(), "accepted {bad}");
    }
    for address in ["10", "0x", "-0x1", "0x-1", "0x+1", "0x 1", "0x10000000000000000", "ram:0x10"] {
        let r = json!([r_function(address, json!([]), json!([]), json!([]))]).to_string();
        assert!(compare_exports(&request(&r, &g, 1), &r, &g).is_err(), "accepted {address}");
    }
    let r = single_r().to_string();
    for bad in ["[]", "{}", "{\"functions\":[{}]}", "{\"functions\":null}"] {
        assert!(compare_exports(&request(&r, bad, 1), &r, bad).is_err());
    }
    let mut bad_block = single_g();
    bad_block["functions"][0]["blocks"][0]["start"] = json!("0x10000000000000000");
    let mut missing_calls = single_g();
    missing_calls["functions"][0].as_object_mut().unwrap().remove("calls");
    let mut bad_call = single_g();
    bad_call["functions"][0]["calls"] = json!([["0x10", 32, "UNCONDITIONAL_CALL"]]);
    for g in [bad_block, missing_calls, bad_call] {
        let g = g.to_string();
        assert!(compare_exports(&request(&r, &g, 1), &r, &g).is_err());
    }
}

#[test]
fn duplicate_numeric_function_or_block_addresses_and_conflicting_call_kinds_fail() {
    let mut duplicate_r = single_r();
    duplicate_r.as_array_mut().unwrap().push(r_function("0x0010", json!([]), json!([]), json!([])));
    let mut duplicate_r_block = single_r();
    duplicate_r_block[0]["blocks"] = json!(["0x10", "0X0010"]);
    let mut conflicting_r = single_r();
    conflicting_r.as_array_mut().unwrap().push(r_function("0x30", json!([]), json!([]), json!([])));
    conflicting_r[0]["references"] = json!([["0x12", "0x30", "call"], ["0x12", "0x30", "jump"]]);
    let mut duplicate_g = single_g();
    duplicate_g["functions"].as_array_mut().unwrap().push(g_function("0x0010", json!([]), json!([])));
    let mut duplicate_g_block = single_g();
    duplicate_g_block["functions"][0]["blocks"].as_array_mut().unwrap().push(g_block("0x0010", "0x20", json!([])));
    let mut conflicting_g = single_g();
    conflicting_g["functions"][0]["calls"] =
        json!([["0x12", "0x900", "COMPUTED_CALL"], ["0x12", "0x900", "UNCONDITIONAL_CALL"]]);
    for (r, g, expected) in [
        (duplicate_r, single_g(), "duplicate function"),
        (duplicate_r_block, single_g(), "duplicate block"),
        (conflicting_r, single_g(), "conflicting call"),
        (single_r(), duplicate_g, "duplicate function"),
        (single_r(), duplicate_g_block, "duplicate block"),
        (single_r(), conflicting_g, "conflicting call"),
    ] {
        let (r, g) = (r.to_string(), g.to_string());
        let error = compare_exports(&request(&r, &g, 1), &r, &g).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn repeated_edges_and_identical_call_pairs_are_sets_not_extra_denominators() {
    let r = json!([r_function(
        "0x10",
        json!(["0x10"]),
        json!([["0x10", "0x10", "jump"], ["0x10", "0x10", "conditional"]]),
        json!([["0x12", "0x900", "call"], ["0x12", "0x900", "call"]])
    )]);
    let g = json!({"functions": [g_function("0x10", json!([
        g_block("0x10", "0x20", json!([["0x10", "UNCONDITIONAL_JUMP"], ["0x10", "CONDITIONAL_JUMP"]]))]),
        json!([["0x12", "0x900", "UNCONDITIONAL_CALL"], ["0x12", "0x900", "UNCONDITIONAL_CALL"]]))]});
    let report = compare(r, g, 10);
    assert_eq!((report.edges.matched, report.edges.rampage, report.edges.ghidra), (1, 1, 1));
    assert_eq!((report.calls.matched, report.calls.rampage, report.calls.ghidra), (1, 1, 1));
}

#[test]
fn binding_rejects_changed_export_bytes_image_or_address_context_and_missing_identity() {
    let (r, g) = (single_r().to_string(), single_g().to_string());
    let binding = request(&r, &g, 2);
    assert!(compare_exports(&binding, &format!("{r}\n"), &g).is_err());
    assert!(compare_exports(&binding, &r, &format!("{g}\n")).is_err());
    for field in
        ["image_sha256", "architecture", "address_bits", "address_space", "image_base", "image_offset", "image_length"]
    {
        let mut changed = binding.clone();
        match field {
            "image_sha256" => changed.ghidra.image.image_sha256 = digest("different-image"),
            "architecture" => changed.ghidra.image.architecture = "aarch64".into(),
            "address_bits" => changed.ghidra.image.address_bits = 32,
            "address_space" => changed.ghidra.image.address_space = "other".into(),
            "image_base" => changed.ghidra.image.image_base = Address(0x1000),
            "image_offset" => changed.ghidra.image.image_offset = 4096,
            "image_length" => changed.ghidra.image.image_length = Some(8192),
            _ => unreachable!(),
        }
        assert!(compare_exports(&changed, &r, &g).is_err(), "accepted mismatched {field}");
    }
    let mut changed = binding.clone();
    changed.ghidra.version.clear();
    assert!(compare_exports(&changed, &r, &g).is_err());
    changed = binding.clone();
    changed.rampage.exporter_sha256 = "unobserved".into();
    assert!(compare_exports(&changed, &r, &g).is_err());
    changed = binding;
    changed.ghidra.tool = "rampage".into();
    assert!(compare_exports(&changed, &r, &g).is_err());
}
