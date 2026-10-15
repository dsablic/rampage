#![cfg(unix)]

use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rampage_api::derived_cache::{
    CachedFunctionInventory, FunctionInventoryCacheRow, InventoryCacheReadOutcome, capture_function_inventory,
    completed_function_inventory_rows, function_inventory_dependency_key, publish_function_inventory,
    read_function_inventory,
};
use rampage_api::{Project, ProjectWorkspacePhase, ProjectWorkspaceTaskControl};
use rampage_loaders::Binary;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "function-inventory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn source(&self) -> PathBuf {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/decode-x64.elf");
        let source = self.join("owned.elf");
        std::fs::copy(fixture, &source).unwrap();
        source
    }

    fn document(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.join(name);
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap().write_all(bytes).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn project(path: &Path) -> Arc<Project> {
    Arc::new(Project::new(Binary::open(path).unwrap()))
}

fn persistent_project(source: &Path, log: &Path, checked: bool) -> Arc<Project> {
    let annotations = if checked {
        rampage_api::annotations::Annotations::open_checked(log.to_owned())
    } else {
        rampage_api::annotations::Annotations::open(log.to_owned())
    }
    .unwrap();
    Arc::new(Project::with_annotations(Binary::open(source).unwrap(), annotations))
}

fn controlled<T>(work: impl FnOnce(&mut ProjectWorkspaceTaskControl<'_>) -> T) -> T {
    let cancellation = AtomicBool::new(false);
    let mut observer = |_| {};
    work(&mut ProjectWorkspaceTaskControl::new(&cancellation, &mut observer))
}

fn discover(project: &Project) {
    assert!(project.binary.validate_available_backing_source().unwrap());
    assert!(!project.analysis_cache_status().program);
    project.functions(&rampage_api::FunctionsQuery { limit: Some(0), ..Default::default() }).unwrap();
    assert!(project.binary.validate_available_backing_source().unwrap());
    assert!(project.analysis_cache_status().program);
}

fn publish(project: &Arc<Project>, output: &Path) {
    controlled(|control| {
        let prepared = capture_function_inventory(Arc::clone(project), control).unwrap();
        publish_function_inventory(&prepared, output, control).unwrap();
    });
}

fn hit(project: &Arc<Project>, path: &Path) -> CachedFunctionInventory {
    match controlled(|control| read_function_inventory(Arc::clone(project), path, control)).unwrap() {
        InventoryCacheReadOutcome::Hit(view) => view,
        _ => panic!("expected historical cache hit"),
    }
}

fn document_value(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn payload_checksum(document: &Value) -> String {
    let mut hash = Sha256::new();
    hash.update(b"FunctionInventoryCacheV0.payload\0");
    for field in ["source_sha256", "image_sha256", "context_sha256", "names_sha256", "decoder", "discovery", "naming"] {
        let text = document["key"][field].as_str().unwrap();
        hash.update((text.len() as u64).to_le_bytes());
        hash.update(text.as_bytes());
    }
    hash.update(document["total_functions"].as_u64().unwrap().to_le_bytes());
    hash.update([u8::from(document["truncated"].as_bool().unwrap())]);
    let rows = &document["rows"];
    hash.update((rows.as_array().unwrap().len() as u64).to_le_bytes());
    for row in rows.as_array().unwrap() {
        for field in ["address", "name"] {
            let text = row[field].as_str().unwrap();
            hash.update((text.len() as u64).to_le_bytes());
            hash.update(text.as_bytes());
        }
        for field in ["size", "block_count", "instruction_count"] {
            hash.update(row[field].as_u64().unwrap().to_le_bytes());
        }
    }
    rampage_arch::hex::bytes(&hash.finalize())
}

#[test]
fn cold_capture_and_missing_cache_never_initialize_analysis_or_create_a_file() {
    let scratch = Scratch::new();
    let project = project(&scratch.source());
    let output = scratch.join("absent.json");
    assert!(controlled(|control| capture_function_inventory(Arc::clone(&project), control)).is_err());
    assert!(matches!(
        controlled(|control| read_function_inventory(Arc::clone(&project), &output, control)).unwrap(),
        InventoryCacheReadOutcome::Miss,
    ));
    assert!(!project.analysis_cache_status().program);
    assert!(!project.analysis_cache_status().strings);
    assert!(!project.analysis_cache_status().triage);
    assert!(!output.exists());
}

#[test]
fn capture_counts_come_from_completed_program_and_reopen_remains_analysis_free() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let original = project(&source);
    discover(&original);
    let oracle = rampage_analysis::functions::analyze(&original.binary).unwrap();
    let prepared = controlled(|control| capture_function_inventory(Arc::clone(&original), control)).unwrap();
    assert!(!prepared.rows().is_empty());
    assert_eq!(prepared.total_functions(), oracle.functions.len() as u64);
    for (row, function) in prepared.rows().iter().zip(&oracle.functions) {
        assert_eq!(row.address, format!("{:#x}", function.address));
        assert_eq!(row.size, function.blocks.iter().map(|block| block.end - block.start).sum::<u64>());
        assert_eq!(row.block_count, function.blocks.len() as u64);
        assert_eq!(row.instruction_count, function.instruction_count as u64);
    }
    let output = scratch.join("cache.json");
    controlled(|control| publish_function_inventory(&prepared, &output, control)).unwrap();
    let fresh = project(&source);
    let view = hit(&fresh, &output);
    assert_eq!(view.rows(), prepared.rows());
    assert_eq!(view.provenance(), "cached_unverified_historical");
    assert!(!fresh.analysis_cache_status().program);
    view.validate_current_metadata(&fresh).unwrap();
    assert!(view.validate_current_metadata(&project(&source)).is_err());
}

#[test]
fn forged_matching_key_and_recomputed_checksum_still_cannot_create_authority() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let original = project(&source);
    discover(&original);
    let output = scratch.join("cache.json");
    publish(&original, &output);
    let mut document = document_value(&output);
    document["rows"][0]["address"] = json!("0x0");
    document["rows"][0]["name"] = json!("attacker_claimed_entry");
    document["rows"][0]["size"] = json!(u64::MAX);
    document["payload_sha256"] = json!(payload_checksum(&document));
    let forged = scratch.document("forged.json", &serde_json::to_vec(&document).unwrap());
    let fresh = project(&source);
    let view = hit(&fresh, &forged);
    assert_eq!(view.provenance(), "cached_unverified_historical");
    assert_eq!(view.rows()[0].address, "0x0");
    assert!(!fresh.analysis_cache_status().program);
    assert!(!fresh.analysis_cache_status().strings);
    assert!(!fresh.analysis_cache_status().triage);
    // Metadata validity deliberately does not validate cached geometry, entry eligibility, or provenance.
    view.validate_current_metadata(&fresh).unwrap();
}

#[test]
fn only_names_invalidate_the_inventory_not_comments_or_native_options() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let original = project(&source);
    discover(&original);
    let output = scratch.join("cache.json");
    publish(&original, &output);
    let fresh = project(&source);
    let view = hit(&fresh, &output);
    let address = u64::from_str_radix(&view.rows()[0].address[2..], 16).unwrap();
    let nonce = fresh.names_revision().unwrap();
    fresh.comment(address, Some("not an inventory dependency")).unwrap();
    fresh.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions::default()));
    assert!(Arc::ptr_eq(&nonce, &fresh.names_revision().unwrap()));
    hit(&fresh, &output);
    view.validate_current_metadata(&fresh).unwrap();
    fresh.rename(address, Some("inventory_renamed")).unwrap();
    assert!(!Arc::ptr_eq(&nonce, &fresh.names_revision().unwrap()));
    assert!(view.validate_current_metadata(&fresh).is_err());
    assert!(matches!(
        controlled(|control| read_function_inventory(Arc::clone(&fresh), &output, control)).unwrap(),
        InventoryCacheReadOutcome::Miss,
    ));
    let renamed_nonce = fresh.names_revision().unwrap();
    fresh.undo().unwrap();
    assert!(!Arc::ptr_eq(&renamed_nonce, &fresh.names_revision().unwrap()));
    hit(&fresh, &output);
    // Equal names after undo restore disk dependency consistency, not the old process-local view binding.
    assert!(view.validate_current_metadata(&fresh).is_err());
    assert!(!fresh.analysis_cache_status().program);
}

#[test]
fn first_comment_log_creation_and_empty_name_restart_preserve_the_current_view() {
    for checked in [false, true] {
        let scratch = Scratch::new();
        let source = scratch.source();
        let original = project(&source);
        discover(&original);
        let output = scratch.join("cache.json");
        publish(&original, &output);
        let log = scratch.join("annotations.jsonl");
        let fresh = persistent_project(&source, &log, checked);
        let view = hit(&fresh, &output);
        let address = u64::from_str_radix(&view.rows()[0].address[2..], 16).unwrap();
        let names_revision = fresh.names_revision().unwrap();
        assert!(!log.exists());
        fresh.comment(address, Some("first comment creates the log")).unwrap();
        assert!(log.exists());
        let before_replay = fresh.annotation_revision().unwrap();
        assert!(fresh.refresh_annotations().unwrap());
        assert_eq!(fresh.comment_at(address).as_deref(), Some("first comment creates the log"));
        assert!(!Arc::ptr_eq(&before_replay, &fresh.annotation_revision().unwrap()));
        assert!(Arc::ptr_eq(&names_revision, &fresh.names_revision().unwrap()));
        view.validate_current_metadata(&fresh).unwrap();

        let mut replacement_bytes = serde_json::to_vec(&rampage_api::annotations::Edit {
            field: rampage_api::annotations::Field::Comment,
            address,
            value: Some("comment after empty-name log restart".into()),
            previous: None,
        })
        .unwrap();
        replacement_bytes.push(b'\n');
        let replacement = scratch.document("replacement-log.jsonl", &replacement_bytes);
        std::fs::rename(replacement, &log).unwrap();
        let before_restart = fresh.annotation_revision().unwrap();
        assert!(fresh.refresh_annotations().unwrap());
        assert_eq!(fresh.comment_at(address).as_deref(), Some("comment after empty-name log restart"));
        assert!(!Arc::ptr_eq(&before_restart, &fresh.annotation_revision().unwrap()));
        assert!(Arc::ptr_eq(&names_revision, &fresh.names_revision().unwrap()));
        view.validate_current_metadata(&fresh).unwrap();
        assert!(!fresh.analysis_cache_status().program);
    }
}

#[test]
fn identical_name_replay_preserves_the_view_but_real_rename_aba_does_not() {
    for checked in [false, true] {
        let scratch = Scratch::new();
        let source = scratch.source();
        let original = project(&source);
        discover(&original);
        let rows = controlled(|control| completed_function_inventory_rows(&original, control)).unwrap();
        let address = u64::from_str_radix(&rows[0].address[2..], 16).unwrap();
        original.rename(address, Some("inventory_name_a")).unwrap();
        let output = scratch.join("cache.json");
        publish(&original, &output);
        let log = scratch.join("annotations.jsonl");
        let mut annotations = if checked {
            rampage_api::annotations::Annotations::open_checked(log)
        } else {
            rampage_api::annotations::Annotations::open(log)
        }
        .unwrap();
        annotations.set(rampage_api::annotations::Field::Name, address, Some("inventory_name_a".into())).unwrap();
        let fresh = Arc::new(Project::with_annotations(Binary::open(&source).unwrap(), annotations));
        let view = hit(&fresh, &output);
        let original_nonce = fresh.names_revision().unwrap();
        let before_replay = fresh.annotation_revision().unwrap();
        assert!(fresh.refresh_annotations().unwrap());
        assert_eq!(fresh.function_name(address), "inventory_name_a");
        assert!(!Arc::ptr_eq(&before_replay, &fresh.annotation_revision().unwrap()));
        assert!(Arc::ptr_eq(&original_nonce, &fresh.names_revision().unwrap()));
        view.validate_current_metadata(&fresh).unwrap();

        assert!(fresh.rename(address, Some("inventory_name_b")).unwrap().changed);
        let intermediate_nonce = fresh.names_revision().unwrap();
        assert!(!Arc::ptr_eq(&original_nonce, &intermediate_nonce));
        assert!(fresh.rename(address, Some("inventory_name_a")).unwrap().changed);
        let final_nonce = fresh.names_revision().unwrap();
        assert!(!Arc::ptr_eq(&original_nonce, &final_nonce));
        assert!(!Arc::ptr_eq(&intermediate_nonce, &final_nonce));
        assert_eq!(fresh.function_name(address), "inventory_name_a");
        assert!(view.validate_current_metadata(&fresh).is_err());
        assert!(fresh.refresh_annotations().unwrap());
        assert!(Arc::ptr_eq(&final_nonce, &fresh.names_revision().unwrap()));
        assert!(view.validate_current_metadata(&fresh).is_err());
        assert_eq!(hit(&fresh, &output).rows()[0].name, "inventory_name_a");
        assert!(!fresh.analysis_cache_status().program);
    }
}

#[test]
fn mutable_binary_context_is_a_dependency_even_when_original_file_hashes_match() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let original = project(&source);
    discover(&original);
    let output = scratch.join("cache.json");
    publish(&original, &output);
    for mutation in 0..6 {
        let mut binary = Binary::open(&source).unwrap();
        match mutation {
            0 => binary.segments[0].perms.execute = !binary.segments[0].perms.execute,
            1 => binary.segments[0].size += 1,
            2 => binary.thumb.push(0x10..0x20),
            3 => binary.function_starts.push(0x1234),
            4 => binary.big_endian = !binary.big_endian,
            _ => binary.segments[0].file_size += 1,
        }
        let fresh = Arc::new(Project::new(binary));
        assert!(matches!(
            controlled(|control| read_function_inventory(Arc::clone(&fresh), &output, control)).unwrap(),
            InventoryCacheReadOutcome::Miss,
        ));
        assert!(!fresh.analysis_cache_status().program);
    }
}

#[test]
fn actual_constructor_namer_is_keyed_even_if_public_symbols_are_restored() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let mut original_binary = Binary::open(&source).unwrap();
    original_binary.symbols.push(rampage_loaders::Symbol {
        address: u64::MAX,
        size: 0,
        name: "baseline_constructor_name".into(),
        kind: rampage_loaders::SymbolKind::Other,
    });
    let original = Arc::new(Project::new(original_binary));
    discover(&original);
    let output = scratch.join("cache.json");
    publish(&original, &output);
    let mut binary = Binary::open(&source).unwrap();
    binary.symbols.push(rampage_loaders::Symbol {
        address: u64::MAX,
        size: 0,
        name: "constructor_only_name".into(),
        kind: rampage_loaders::SymbolKind::Other,
    });
    let changed_index = binary.symbols.len() - 1;
    let mut altered = Project::new(binary);
    altered.binary.symbols[changed_index].name = "baseline_constructor_name".into();
    let altered = Arc::new(altered);
    assert!(matches!(
        controlled(|control| read_function_inventory(Arc::clone(&altered), &output, control)).unwrap(),
        InventoryCacheReadOutcome::Miss,
    ));
    assert!(!altered.analysis_cache_status().program);
}

#[test]
fn original_descriptor_rejects_identical_byte_inode_replacement_even_on_cache_miss() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let fresh = project(&source);
    let replacement = scratch.join("replacement.elf");
    std::fs::copy(&source, &replacement).unwrap();
    std::fs::rename(replacement, source).unwrap();
    assert!(matches!(
        controlled(|control| read_function_inventory(Arc::clone(&fresh), &scratch.join("missing"), control)).unwrap(),
        InventoryCacheReadOutcome::SourceChanged,
    ));
    assert!(!fresh.analysis_cache_status().program);
}

#[test]
fn owned_snapshot_is_not_mislabeled_as_an_original_mapped_source() {
    let scratch = Scratch::new();
    let document = json!({
        "format": "rampage-snapshot-v1", "arch": "x86_64", "provenance": "not a retained source descriptor",
        "regions": [{"name": "code", "address": "0x1000", "permissions": "r-x", "bytes": "90c3"}],
        "entry": "0x1000",
    });
    let binary = Binary::from_snapshot_bytes(serde_json::to_vec(&document).unwrap()).unwrap();
    let current = Arc::new(Project::new(binary));
    assert!(matches!(
        controlled(|control| read_function_inventory(Arc::clone(&current), &scratch.join("absent"), control)).unwrap(),
        InventoryCacheReadOutcome::SourceChanged,
    ));
    assert!(!current.analysis_cache_status().program);
    assert!(controlled(|control| capture_function_inventory(Arc::clone(&current), control)).is_err());
}

#[test]
fn canonical_hex_addresses_preserve_all_bits_without_claiming_entry_validity() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let original = project(&source);
    discover(&original);
    let output = scratch.join("cache.json");
    publish(&original, &output);
    let mut document = document_value(&output);
    document["rows"] = json!([{
        "address": "0xffffffffffffffff", "name": "unverified_address_above_js_safe_integer",
        "size": 0, "block_count": 0, "instruction_count": 0,
    }]);
    document["total_functions"] = json!(1);
    document["truncated"] = json!(false);
    document["payload_sha256"] = json!(payload_checksum(&document));
    let forged = scratch.document("wide.json", &serde_json::to_vec(&document).unwrap());
    let fresh = project(&source);
    assert_eq!(hit(&fresh, &forged).rows()[0].address, "0xffffffffffffffff");
    assert!(!fresh.analysis_cache_status().program);
    for (index, address) in ["0x00", "0xA", "0x10000000000000000", "18446744073709551615"].iter().enumerate() {
        document["rows"][0]["address"] = json!(address);
        // The checksum does not make a noncanonical address acceptable.
        document["payload_sha256"] = json!(payload_checksum(&document));
        let bad = scratch.document(&format!("bad-address-{index}"), &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            controlled(|control| read_function_inventory(Arc::clone(&fresh), &bad, control)).unwrap(),
            InventoryCacheReadOutcome::Rejected,
        ));
    }
}

#[test]
fn source_mutation_by_observer_after_read_is_rejected_not_adopted() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let original = project(&source);
    discover(&original);
    let output = scratch.join("cache.json");
    publish(&original, &output);
    let fresh = project(&source);
    let replacement = scratch.join("replacement.elf");
    std::fs::copy(&source, &replacement).unwrap();
    let cancellation = AtomicBool::new(false);
    let mut observer = |progress: rampage_api::ProjectWorkspaceProgress| {
        if progress.phase == ProjectWorkspacePhase::ResultValidation {
            std::fs::rename(&replacement, &source).unwrap();
        }
    };
    let outcome = read_function_inventory(
        Arc::clone(&fresh),
        &output,
        &mut ProjectWorkspaceTaskControl::new(&cancellation, &mut observer),
    )
    .unwrap();
    assert!(matches!(outcome, InventoryCacheReadOutcome::SourceChanged));
    assert!(!fresh.analysis_cache_status().program);
}

#[test]
fn source_mutation_immediately_before_dependency_key_never_reaches_mapped_reads() {
    for replace in [false, true] {
        let scratch = Scratch::new();
        let source = scratch.source();
        let original = project(&source);
        discover(&original);
        let output = scratch.join("cache.json");
        publish(&original, &output);
        let fresh = project(&source);
        let replacement = scratch.join("replacement.elf");
        if replace {
            std::fs::copy(&source, &replacement).unwrap();
        }
        let cancellation = AtomicBool::new(false);
        let mut identity_phases = 0;
        let mut mutated = false;
        let mut later_progress = false;
        let mut observer = |progress: rampage_api::ProjectWorkspaceProgress| {
            if mutated {
                later_progress = true;
            }
            if progress.phase == ProjectWorkspacePhase::ValidatingIdentity {
                identity_phases += 1;
                if identity_phases == 2 {
                    if replace {
                        std::fs::rename(&replacement, &source).unwrap();
                    } else {
                        OpenOptions::new().write(true).open(&source).unwrap().set_len(0).unwrap();
                    }
                    mutated = true;
                }
            }
        };
        let outcome = read_function_inventory(
            Arc::clone(&fresh),
            &output,
            &mut ProjectWorkspaceTaskControl::new(&cancellation, &mut observer),
        )
        .unwrap();
        assert_eq!(identity_phases, 2);
        assert!(mutated);
        assert!(!later_progress);
        assert!(matches!(outcome, InventoryCacheReadOutcome::SourceChanged));
        assert!(fresh.binary.validate_available_backing_source().is_err());
        let status = fresh.analysis_cache_status();
        assert!(!status.program && !status.strings && !status.triage);
    }
}

#[test]
fn hostile_profiles_unknown_duplicate_trailing_and_numeric_addresses_are_rejected() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let original = project(&source);
    discover(&original);
    let output = scratch.join("cache.json");
    publish(&original, &output);
    let good = document_value(&output);
    let compact = serde_json::to_string(&good).unwrap();
    let mut cases = vec![
        format!("{compact} null").into_bytes(),
        format!("{{\"version\":\"FunctionInventoryCacheV0\",{}", &compact[1..]).into_bytes(),
        format!("{}0{}", "[".repeat(9), "]".repeat(9)).into_bytes(),
        format!("[\"{}\"]", "x".repeat(4097)).into_bytes(),
        format!("[{}]", vec!["0"; 8193].join(",")).into_bytes(),
        format!("{}{}", " ".repeat(257), compact).into_bytes(),
        vec![b' '; 1024 * 1024 + 1],
    ];
    for mutate in 0..4 {
        let mut bad = good.clone();
        match mutate {
            0 => bad["native_mapped"] = json!(true),
            1 => bad["version"] = json!("FunctionInventoryCacheV999"),
            2 => bad["rows"][0]["address"] = json!(9007199254740993u64),
            _ => bad["key"]["discovery"] = json!("future-discovery"),
        }
        cases.push(serde_json::to_vec(&bad).unwrap());
    }
    let fresh = project(&source);
    for (index, bytes) in cases.iter().enumerate() {
        let bad = scratch.document(&format!("bad-{index}.json"), bytes);
        assert!(matches!(
            controlled(|control| read_function_inventory(Arc::clone(&fresh), &bad, control)).unwrap(),
            InventoryCacheReadOutcome::Rejected,
        ));
    }
    assert!(!fresh.analysis_cache_status().program);
}

#[test]
fn raw_escaped_names_obey_encoded_limits_before_typed_cache_deserialization() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let original = project(&source);
    discover(&original);
    let output = scratch.join("cache.json");
    publish(&original, &output);
    let mut template = document_value(&output);
    template["rows"] = json!([{
        "address": "0x1", "name": "placeholder", "size": 0, "block_count": 0, "instruction_count": 0,
    }]);
    template["total_functions"] = json!(1);
    template["truncated"] = json!(false);
    let raw_document = |encoded: &str, decoded: &str| {
        let mut document = template.clone();
        document["rows"][0]["name"] = json!(decoded);
        document["payload_sha256"] = json!(payload_checksum(&document));
        let compact = serde_json::to_string(&document).unwrap();
        let field = format!("\"name\":{}", serde_json::to_string(decoded).unwrap());
        let raw_field = format!("\"name\":\"{encoded}\"");
        assert!(compact.contains(&field));
        compact.replacen(&field, &raw_field, 1).into_bytes()
    };
    let fresh = project(&source);
    let encoded_boundary = format!("{}{}", r#"\"\\\u0041"#.repeat(409), r"\u0041");
    let decoded_boundary = format!("{}A", "\"\\A".repeat(409));
    let boundary = scratch.document("escaped-boundary.json", &raw_document(&encoded_boundary, &decoded_boundary));
    assert_eq!(hit(&fresh, &boundary).rows()[0].name, decoded_boundary);
    for (index, (encoded, decoded)) in [
        (format!("{encoded_boundary}a"), format!("{decoded_boundary}a")),
        (r"\u0041".repeat(683), "A".repeat(683)),
        (r"\ud83d\ude00".repeat(342), "\u{1f600}".repeat(342)),
    ]
    .iter()
    .enumerate()
    {
        let bad = scratch.document(&format!("escaped-over-budget-{index}.json"), &raw_document(encoded, decoded));
        assert!(matches!(
            controlled(|control| read_function_inventory(Arc::clone(&fresh), &bad, control)).unwrap(),
            InventoryCacheReadOutcome::Rejected,
        ));
    }
    for (index, encoded) in [r"\q", r"\u00xz", r"\u123", r"\ud800", r"\udc00"].iter().enumerate() {
        let bad = scratch.document(&format!("malformed-escape-{index}.json"), &raw_document(encoded, "unused"));
        assert!(matches!(
            controlled(|control| read_function_inventory(Arc::clone(&fresh), &bad, control)).unwrap(),
            InventoryCacheReadOutcome::Rejected,
        ));
    }
    assert_eq!(fresh.analysis_cache_status(), rampage_api::AnalysisCacheStatus::default());
}

#[test]
fn publication_after_link_cancellation_preserves_uncertain_commit_outcome() {
    let scratch = Scratch::new();
    let original = project(&scratch.source());
    discover(&original);
    let prepared = controlled(|control| capture_function_inventory(Arc::clone(&original), control)).unwrap();
    let output = scratch.join("cache.json");
    let cancellation = AtomicBool::new(false);
    let mut observer = |progress: rampage_api::ProjectWorkspaceProgress| {
        if progress.phase == ProjectWorkspacePhase::ValidatingCache {
            cancellation.store(true, Ordering::Relaxed);
        }
    };
    let publication = publish_function_inventory(
        &prepared,
        &output,
        &mut ProjectWorkspaceTaskControl::new(&cancellation, &mut observer),
    )
    .unwrap();
    assert_eq!(publication.status, rampage_api::DebuggerCapturePublicationStatus::PublishedUncertain);
    assert!(output.exists());
    assert!(!publication.warnings.is_empty());
}

#[test]
fn cancellation_after_staging_preserves_typed_retention_without_publishing_destination() {
    let scratch = Scratch::new();
    let original = project(&scratch.source());
    discover(&original);
    let prepared = controlled(|control| capture_function_inventory(Arc::clone(&original), control)).unwrap();
    let output = scratch.join("cache.json");
    let cancellation = AtomicBool::new(false);
    let mut observer = |progress: rampage_api::ProjectWorkspaceProgress| {
        if progress.phase == ProjectWorkspacePhase::PublicationStaged {
            cancellation.store(true, Ordering::Relaxed);
        }
    };
    let error = publish_function_inventory(
        &prepared,
        &output,
        &mut ProjectWorkspaceTaskControl::new(&cancellation, &mut observer),
    )
    .unwrap_err();
    match error {
        rampage_api::ApiError::DebuggerCaptureStagingRetained(retention) => {
            assert!(!retention.paths.is_empty());
            for path in retention.paths {
                assert!(path.starts_with(&scratch.0));
                assert!(path.exists());
            }
        }
        _ => panic!("staged cancellation lost typed resource retention"),
    }
    assert!(!output.exists());
}

#[test]
fn over_budget_names_are_rejected_without_discovery_or_additional_cache_name_clones() {
    let scratch = Scratch::new();
    let source = scratch.source();
    let mut binary = Binary::open(source).unwrap();
    binary.symbols.push(rampage_loaders::Symbol {
        address: u64::MAX,
        size: 0,
        name: "x".repeat(4097),
        kind: rampage_loaders::SymbolKind::Other,
    });
    let fresh = Arc::new(Project::new(binary));
    assert!(controlled(|control| function_inventory_dependency_key(&fresh, control)).is_err());
    // A missing cache is decided before source/name hashing, even when current key input is over budget.
    assert!(matches!(
        controlled(|control| read_function_inventory(Arc::clone(&fresh), &scratch.join("absent"), control)).unwrap(),
        InventoryCacheReadOutcome::Miss,
    ));
    assert!(!fresh.analysis_cache_status().program);
}

fn median(mut times: [Duration; 3]) -> Duration {
    times.sort();
    times[1]
}

fn measure_read(source: &Path, cache: &Path) -> (Duration, Vec<FunctionInventoryCacheRow>) {
    let started = Instant::now();
    let current = project(source);
    let loaded = started.elapsed();
    let cancellation = AtomicBool::new(false);
    let mut events = Vec::new();
    let mut observer = |progress: rampage_api::ProjectWorkspaceProgress| {
        events.push((progress.phase, started.elapsed()));
    };
    let outcome = read_function_inventory(
        Arc::clone(&current),
        cache,
        &mut ProjectWorkspaceTaskControl::new(&cancellation, &mut observer),
    )
    .unwrap();
    let view = match outcome {
        InventoryCacheReadOutcome::Hit(view) => view,
        _ => panic!("owned fixture full reopen did not produce usable historical rows"),
    };
    view.validate_current_metadata(&current).unwrap();
    assert!(!current.analysis_cache_status().program);
    assert!(!view.rows().is_empty());
    let elapsed = started.elapsed();
    let event = |phase| events.iter().find(|(actual, _)| *actual == phase).unwrap().1;
    let reading = event(ProjectWorkspacePhase::ReadingCache);
    let validating = event(ProjectWorkspacePhase::ValidatingCache);
    let hashing = events.iter().rev().find(|(phase, _)| *phase == ProjectWorkspacePhase::ValidatingIdentity).unwrap().1;
    let result = event(ProjectWorkspacePhase::ResultValidation);
    eprintln!(
        "cached_full_reopen={elapsed:?} load={loaded:?} private_read={:?} \
         raw_preflight_parse_checksum={:?} read_source_key={:?} final_validation={:?}",
        validating - reading,
        hashing - validating,
        result - hashing,
        elapsed - result,
    );
    (elapsed, view.rows().to_vec())
}

#[test]
#[ignore = "parent-only owned ELF baseline; requires function-inventory-oracle.sh --check, never runs target ELF"]
fn owned_elf_full_reopen_baseline() {
    let fixture_root = std::env::var_os("RAMPAGE_FUNCTION_INVENTORY_FIXTURES")
        .expect("owned fixture recipe required; no fallback to arbitrary executable");
    let fixture_root = PathBuf::from(fixture_root);
    let mut generated_go = false;
    for fixture in ["generated", "hello"] {
        let scratch = Scratch::new();
        let source = fixture_root.join(format!("{fixture}.elf"));
        let cache = scratch.join("inventory.json");
        let setup = project(&source);
        let discovery_started = Instant::now();
        discover(&setup);
        let setup_discovery = discovery_started.elapsed();
        let key_started = Instant::now();
        controlled(|control| function_inventory_dependency_key(&setup, control)).unwrap();
        let write_source_key = key_started.elapsed();
        let projection_started = Instant::now();
        let expected = controlled(|control| completed_function_inventory_rows(&setup, control)).unwrap();
        let projection = projection_started.elapsed();
        let capture_started = Instant::now();
        let prepared = controlled(|control| capture_function_inventory(Arc::clone(&setup), control)).unwrap();
        let capture_including_key = capture_started.elapsed();
        if fixture == "generated" {
            assert!((2301..=2500).contains(&prepared.total_functions()));
            assert!(expected.len() >= 1200);
            assert!(prepared.total_functions() > expected.len() as u64);
            assert!(prepared.truncated());
        }
        assert_eq!(expected, prepared.rows());
        let publication_started = Instant::now();
        controlled(|control| publish_function_inventory(&prepared, &cache, control)).unwrap();
        let publication = publication_started.elapsed();
        eprintln!(
            "fixture={fixture} setup_discovery={setup_discovery:?} write_source_key={write_source_key:?} \
             bounded_projection={projection:?} capture_including_key={capture_including_key:?} \
             private_publication={publication:?} rows={} total={} truncated={} rss=unavailable",
            expected.len(),
            prepared.total_functions(),
            prepared.truncated(),
        );
        let mut fresh_times = [Duration::ZERO; 3];
        let mut cached_times = [Duration::ZERO; 3];
        for attempt in 0..3 {
            let started = Instant::now();
            let current = project(&source);
            let load = started.elapsed();
            let discovery_started = Instant::now();
            discover(&current);
            let discovery = discovery_started.elapsed();
            let projection_started = Instant::now();
            let rows = controlled(|control| completed_function_inventory_rows(&current, control)).unwrap();
            let projection = projection_started.elapsed();
            fresh_times[attempt] = started.elapsed();
            assert_eq!(rows, expected);
            eprintln!(
                "fixture={fixture} attempt={attempt} fresh_full={:?} load={load:?} \
                 discovery={discovery:?} bounded_projection={projection:?}",
                fresh_times[attempt],
            );
            let (elapsed, cached_rows) = measure_read(&source, &cache);
            assert_eq!(cached_rows, expected);
            cached_times[attempt] = elapsed;
        }
        let fresh = median(fresh_times);
        let cached = median(cached_times);
        let go = cached.checked_mul(2).is_some_and(|twice| fresh >= twice);
        eprintln!(
            "fixture={fixture} fresh_median={fresh:?} cached_full_reopen_median={cached:?} \
             go_2x={go} disk_cache=uncontrolled attempts=3 no_retries=true",
        );
        if fixture == "generated" {
            generated_go = go;
        }
    }
    eprintln!("FunctionInventoryCacheV0 decision={}", if generated_go { "GO" } else { "NO-GO" });
}
