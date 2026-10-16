//! Executes only an externally built owned Rust/WIT component through the production worker boundary.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use rampage_plugin::{MAX_COMPONENT_BYTES, PluginConfig, run_component};
use rampage_plugin_contract::{
    BinaryFact, FunctionFacts, GuestOutcome, SCHEMA_VERSION, TriageFact, TriageFacts, decode_response, validate_facts,
};

#[test]
#[ignore = "requires RAMPAGE_TRIAGE_COMPONENT and RAMPAGE_PLUGIN_WORKER from the owned component recipe"]
fn real_component_composes_an_empty_inventory_without_native_workflow_callbacks() {
    let path = std::env::var_os("RAMPAGE_TRIAGE_COMPONENT").expect("owned Rust/WIT component");
    let worker = PathBuf::from(std::env::var_os("RAMPAGE_PLUGIN_WORKER").expect("trusted worker executable"));
    let mut component = Vec::new();
    File::open(path).unwrap().take(MAX_COMPONENT_BYTES as u64 + 1).read_to_end(&mut component).unwrap();
    assert!(component.len() <= MAX_COMPONENT_BYTES);
    let facts = TriageFacts {
        schema_version: SCHEMA_VERSION,
        exhaustive: true,
        record_total: 2,
        per_section: 1,
        binary: BinaryFact {
            id: 1,
            format: "Elf".into(),
            arch: "x86_64".into(),
            entry: None,
            section_count: 0,
            segment_count: 0,
        },
        triage: TriageFact {
            id: 2,
            image_size: 0,
            entropy: 0.0,
            sha256: "0".repeat(64),
            md5: "0".repeat(32),
            hints: Vec::new(),
        },
        detections: Vec::new(),
        managed: None,
        capabilities: Vec::new(),
        imports: Vec::new(),
        strings: Vec::new(),
        functions: FunctionFacts::Available { rows: Vec::new() },
        signature_matches: Vec::new(),
    };
    validate_facts(&facts).unwrap();
    let input = serde_json::to_vec(&facts).unwrap();
    let output = run_component(&component, &input, &PluginConfig::new(worker), None).unwrap();
    let response = decode_response(&output, &facts).unwrap();
    let GuestOutcome::Report { body } = response.outcome else {
        panic!("the actual guest must compose a report for the valid empty inventory");
    };
    assert_eq!(body.sections.len(), 6);
    assert!(body.summary.iter().any(|line| line.contains("Elf")));
    let functions = body.sections.iter().find(|section| section.title == "Functions").unwrap();
    assert!(functions.findings.iter().any(|finding| finding.observation.contains("0 functions discovered")));
    assert!(body.limitations.iter().any(|line| line.contains("statically linked")));
}
