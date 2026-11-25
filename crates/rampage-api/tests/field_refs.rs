//! References to structure fields reached through a base register plus an immediate offset: a literal-pool or
//! MOVW/MOVT base and `ldrb r0, [r1, #11]`. The fixture (tests/fixtures/firmware/raw-cortex-m-fields.c) keeps its
//! structure in SRAM, which the Raw project leaves unmapped.

use std::path::Path;
use std::sync::Arc;

use rampage_api::tools::{call_shared, tools};
use rampage_api::{Project, RawProjectRequest, Session};
use serde_json::{Value, json};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");
/// `link_state.state`, offset 11 into the structure at 0x20000100.
const STATE: &str = "0x2000010b";

fn project() -> Arc<Project> {
    let path = Path::new(FIXTURES).join("firmware/raw-cortex-m-fields.bin");
    let length = std::fs::metadata(&path).unwrap().len();
    let request: RawProjectRequest = serde_json::from_value(json!({
        "profile": "cortex-m3", "offset": 0, "length": length, "base_address": "0x8000000", "vector_table": true,
    }))
    .unwrap();
    Session::default().with_analysis_store(None).open_raw(&path, &request).unwrap()
}

fn call(project: &Arc<Project>, name: &str, input: Value) -> Value {
    let mut project = Arc::clone(project);
    let (text, error) = call_shared(&tools(), &mut project, name, input);
    assert!(!error, "{name}: {text}");
    serde_json::from_str(&text).unwrap()
}

/// The function containing the instruction at `address`, named as `xrefs` rows name it.
fn function_named(project: &Arc<Project>, address: &str) -> String {
    let rows = call(project, "xrefs", json!({ "from": address, "limit": 1 }));
    rows["items"][0]["from_function"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn reads_and_writes_of_a_field_list_their_base_and_access() {
    let project = project();
    let page = call(&project, "xrefs", json!({ "to": STATE, "limit": 100 }));
    let rows = page["items"].as_array().unwrap();
    // link_up and stepped read it, set_link writes it, poll_link reads it inside a loop after a join.
    assert_eq!(rows.len(), 4, "{page:#}");
    for row in rows {
        assert_eq!(row["kind"], "data", "{row}");
        let base = &row["base"];
        assert_eq!(base["width"], 1, "{row}");
        let address = u64::from_str_radix(base["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        assert_eq!(0x2000_0100 + 11, address + base["offset"].as_u64().unwrap(), "{row}");
        // The base was set by an earlier instruction of the same function.
        let site = base["site"].as_str().unwrap();
        assert_eq!(function_named(&project, site), row["from_function"].as_str().unwrap(), "{row}");
    }
    let accesses: Vec<&str> = rows.iter().map(|row| row["access"].as_str().unwrap()).collect();
    assert_eq!(accesses.iter().filter(|access| **access == "write").count(), 1, "{page:#}");
    assert_eq!(accesses.iter().filter(|access| **access == "read").count(), 3, "{page:#}");
    // Three take the pool address itself as the base; `stepped` adds 8 to it first.
    let offsets: Vec<u64> = rows.iter().map(|row| row["base"]["offset"].as_u64().unwrap()).collect();
    assert_eq!(offsets.iter().filter(|offset| **offset == 11).count(), 3, "{page:#}");
    assert_eq!(offsets.iter().filter(|offset| **offset == 3).count(), 1, "{page:#}");
    // The base came from a literal-pool load: the pool load itself is a data reference to its pool slot.
    for row in rows.iter().filter(|row| row["base"]["offset"] == 11) {
        let site = row["base"]["site"].as_str().unwrap();
        let from_site = call(&project, "xrefs", json!({ "from": site, "limit": 10 }));
        assert!(from_site["items"].as_array().unwrap().iter().all(|xref| xref["kind"] == "data"), "{from_site}");
    }

    // A MOVW/MOVT base reaches the halfword at +12.
    let count = call(&project, "xrefs", json!({ "to": "0x2000010c", "limit": 10 }));
    let count_rows = count["items"].as_array().unwrap();
    assert_eq!(count_rows.len(), 1, "{count:#}");
    assert_eq!(count_rows[0]["base"]["width"], 2);
    assert_eq!(count_rows[0]["base"]["address"], "0x20000100");
    assert_eq!(count_rows[0]["access"], "read");
}

#[test]
fn search_references_carry_the_same_evidence() {
    let project = project();
    let report = call(&project, "search", json!({ "mode": { "kind": "references", "target": STATE } }));
    let hits = report["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 4, "{report:#}");
    for hit in hits {
        assert_eq!(hit["reference_kinds"], json!(["data"]), "{hit}");
        assert_eq!(hit["base"]["width"], 1, "{hit}");
    }
}

/// A base overwritten before the access, loaded on only one path into it, SP-relative, or in unmapped code space
/// yields no reference; only the four real accesses reach the field.
#[test]
fn accesses_without_a_known_base_are_not_field_references() {
    let project = project();
    let page = call(&project, "xrefs", json!({ "to": STATE, "limit": 100 }));
    let readers: Vec<String> =
        page["items"].as_array().unwrap().iter().map(|row| row["from_function"].as_str().unwrap().to_owned()).collect();
    let all = call(&project, "list_functions", json!({ "limit": 100 }));
    let functions: Vec<&Value> = all["items"].as_array().unwrap().iter().collect();
    // Every function's references: none but the four accessors reach anywhere in the structure, and nothing reaches
    // the code-space address 0x40b or a stack slot.
    let mut field_rows = 0;
    for function in &functions {
        let address = function["address"].as_str().unwrap();
        let from = call(&project, "xrefs", json!({ "from": address, "limit": 100 }));
        for row in from["items"].as_array().unwrap() {
            let to = u64::from_str_radix(row["to"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            assert_ne!(to, 0x40b, "{row}");
            assert!(!(0x2000_0000..0x2000_1000).contains(&to) || (0x2000_0100..0x2000_0114).contains(&to), "{row}");
            if row.get("base").is_some() {
                field_rows += 1;
                assert!(row["base"]["address"].as_str().unwrap().starts_with("0x200001"), "{row}");
            }
        }
    }
    // link_up, set_link (state and mode), poll_link, stepped and link_count.
    assert_eq!(field_rows, 6, "{readers:?}");
    let distinct: std::collections::BTreeSet<&String> = readers.iter().collect();
    assert_eq!(distinct.len(), 4, "{readers:?}");
}
