use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_loaders::{Binary, Export, Symbol, SymbolKind};

use super::*;

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fixture(base: u64, instructions: &str) -> (Fixture, Project) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let file = Fixture(std::env::temp_dir().join(format!(
        "entry-tool-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    )));
    std::fs::write(
        &file.0,
        serde_json::json!({
            "format":"rampage-snapshot-v1", "arch":"x86_64", "data_big_endian":false,
            "provenance":"owned entry tool transport evidence", "seeds":[format!("{base:#x}")],
            "regions":[{"name":"code","address":format!("{base:#x}"),"permissions":"r-x","bytes":instructions}]
        })
        .to_string(),
    )
    .unwrap();
    let project = Project::new(Binary::open(&file.0).unwrap());
    (file, project)
}

fn page(project: &Project, arguments: Value) -> Value {
    let (text, failed) = call(&tools(), project, "entry_diagnostics", arguments);
    assert!(!failed, "{text}");
    assert!(text.len() <= MAX_RESULT_CHARS, "{} bytes", text.len());
    assert!(project.cached_analysis().is_none());
    serde_json::from_str(&text).expect("every successful tool page is complete JSON")
}

#[test]
fn long_escaped_aliases_keep_one_complete_entry_with_explicit_transport_name_omissions() {
    let (_file, mut project) = fixture(0x1000, "b805000000c3");
    for index in 0..7 {
        project.binary.symbols.push(Symbol {
            name: format!("symbol_{index}{}", "\0".repeat(3900)),
            address: 0x1000,
            size: 6,
            kind: SymbolKind::Function,
        });
        project.binary.exports.push(Export { name: format!("export_{index}{}", "\0".repeat(3900)), address: 0x1000 });
    }
    let result = page(&project, serde_json::json!({"at":"0x1000"}));
    assert_eq!(result["entries_total"], 1);
    assert_eq!(result["entries"].as_array().unwrap().len(), 1);
    assert_eq!(result["more"], false);
    assert!(result["transport"]["names_omitted_total"].as_u64().unwrap() > 0);
    assert!(result["entries"][0]["origins"].as_array().unwrap().iter().all(|origin| origin["name"].is_null()));
    assert_eq!(result["usage"]["declaration_records"], 15);
    assert!(result["usage"]["name_bytes_copied"].as_u64().unwrap() > MAX_RESULT_CHARS as u64 / 2);
    assert_eq!(result["entries"][0]["assessment"], "locally_plausible");
    assert_eq!(result["entries"][0]["instruction_count"], 2);
}

#[test]
fn paged_samples_retain_every_entry_once_even_when_names_use_the_whole_result_budget() {
    let code = "b805000000c39090909090909090909090".repeat(32);
    let (_file, mut project) = fixture(0x1000, &code);
    for index in 0..32 {
        project.binary.symbols.push(Symbol {
            name: format!("entry_{index}_{}", "λ".repeat(1400)),
            address: 0x1000 + index * 16,
            size: 6,
            kind: SymbolKind::Function,
        });
    }
    let mut offset = 0;
    let mut addresses = Vec::new();
    let mut capped = false;
    loop {
        let result = page(&project, serde_json::json!({"offset":offset,"limit":64}));
        assert_eq!(result["entries_total"], 32);
        assert_eq!(result["usage"]["declaration_records"], 33);
        addresses.extend(result["entries"].as_array().unwrap().iter().map(|row| row["address"].clone()));
        capped |= result["byte_capped"] == true;
        if result["more"] == false {
            break;
        }
        let next = result["next_offset"].as_u64().unwrap() as usize;
        assert!(next > offset, "a whole row must fit on its next page");
        offset = next;
    }
    assert!(capped);
    let expected: Vec<_> = (0..32).map(|index| serde_json::json!(format!("{:#x}", 0x1000 + index * 16))).collect();
    assert_eq!(addresses, expected);
    let empty = page(&project, serde_json::json!({"offset":usize::MAX,"limit":1}));
    assert_eq!(empty["entries"], serde_json::json!([]));
    assert_eq!(empty["entries_total"], 32);
}

#[test]
fn high_addresses_and_flow_targets_survive_the_real_tool_json_round_trip_without_numeric_loss() {
    let base = (1u64 << 53) + 0x1000;
    let (_file, project) = fixture(base, "e8050000009090909090c3");
    let result = page(&project, serde_json::json!({"at":format!("{base:#x}")}));
    let entry = &result["entries"][0];
    assert_eq!(entry["address"], format!("{base:#x}"));
    assert_eq!(entry["last_flow"]["kind"], "call");
    assert_eq!(entry["last_flow"]["target"], format!("{:#x}", base + 10));
    assert_eq!(entry["stop"], "control_transfer");
}

#[test]
fn only_the_new_decompile_schema_exposes_exact_entry_and_entry_samples_refuse_discovery_arguments() {
    let catalog = tools();
    let decompile = catalog.iter().find(|tool| tool.name == "decompile").unwrap();
    assert!(decompile.input_schema["properties"].get("exact_entry").is_some());
    let summary = catalog.iter().find(|tool| tool.name == "function_summary").unwrap();
    assert!(summary.input_schema["properties"].get("exact_entry").is_none());
    let (_file, project) = fixture(0x1000, "c3");
    for arguments in
        [serde_json::json!({"include_discovery":true}), serde_json::json!({"limit":0}), serde_json::json!({"limit":65})]
    {
        let (_, failed) = call(&catalog, &project, "entry_diagnostics", arguments);
        assert!(failed);
        assert!(project.cached_analysis().is_none());
    }
}

#[test]
fn exact_fit_and_adjacent_first_rows_always_make_progress_instead_of_repeating_an_empty_page() {
    use rampage_analysis::entry_audit::{EntryAuditLimits, EntryOrigin, EntryOriginKind, sample_entry};
    for delta in [-1isize, 0, 1] {
        let (_file, project) = fixture(0x1000, "b805000000c3");
        let make_report = || {
            let mut report = sample_entry(&project.binary, 0x1000, EntryAuditLimits::default());
            report.entries[0].origins = (0..3)
                .map(|_| EntryOrigin {
                    kind: EntryOriginKind::Symbol,
                    name: Some("a".repeat(4000)),
                    name_omitted: false,
                    symbol_kind: Some(SymbolKind::Function),
                })
                .collect();
            report.usage.name_bytes_copied = 12000;
            report
        };
        let baseline = make_report();
        let row_bytes = serde_json::to_value(&baseline.entries[0]).unwrap().to_string().len();
        let mut envelope = entry_diagnostics_page(make_report(), 0, 64).unwrap();
        envelope["entries"] = serde_json::json!([]);
        let overhead = envelope.to_string().len() + 256;
        let extra = (MAX_RESULT_CHARS as isize - overhead as isize - row_bytes as isize + delta) as usize;
        let mut nul = extra / 5;
        let mut newline = extra % 5;
        let mut report = make_report();
        for origin in &mut report.entries[0].origins {
            let zeros = nul.min(4000);
            nul -= zeros;
            let newlines = newline.min(4000 - zeros);
            newline -= newlines;
            origin.name =
                Some(format!("{}{}{}", "\0".repeat(zeros), "\n".repeat(newlines), "a".repeat(4000 - zeros - newlines)));
        }
        assert_eq!((nul, newline), (0, 0));
        let encoded_row = serde_json::to_value(&report.entries[0]).unwrap().to_string().len();
        assert_eq!(encoded_row + overhead, (MAX_RESULT_CHARS as isize + delta) as usize);
        let page = entry_diagnostics_page(report, 0, 64).unwrap();
        assert_eq!(page["entries"].as_array().unwrap().len(), 1, "boundary delta {delta}");
        assert_eq!(page["more"], false, "a one-row report cannot promise a repeating empty continuation");
        assert!(page.to_string().len() <= MAX_RESULT_CHARS);
        assert!(project.cached_analysis().is_none());
    }
}
