#![cfg(unix)]

use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{
    ModuleReferenceInput, ModuleReferenceQuery, ModuleReferenceStatus, Project, module_references,
    prepare_module_reference_view, validate_module_reference_inputs,
};
use rampage_loaders::Binary;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "module-references-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn module(&self, filename: &str, id: &str, bytes: &[u8]) -> ModuleReferenceInput {
        let path = self.0.join(filename);
        std::fs::write(&path, bytes).unwrap();
        ModuleReferenceInput { module_id: id.into(), project: Arc::new(Project::new(Binary::open(&path).unwrap())) }
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn word(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn dword(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn qword(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn terminated(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
    bytes[offset + value.len()] = 0;
}

fn pe() -> Vec<u8> {
    let mut bytes = vec![0; 0x2400];
    bytes[..2].copy_from_slice(b"MZ");
    dword(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    word(&mut bytes, 0x84, 0x8664);
    word(&mut bytes, 0x86, 2);
    word(&mut bytes, 0x94, 0xf0);
    word(&mut bytes, 0x96, 0x2022);
    word(&mut bytes, 0x98, 0x20b);
    dword(&mut bytes, 0xa8, 0x3000);
    qword(&mut bytes, 0xb0, 0x180000000);
    dword(&mut bytes, 0xb8, 0x1000);
    dword(&mut bytes, 0xbc, 0x200);
    dword(&mut bytes, 0xd0, 0x4000);
    dword(&mut bytes, 0xd4, 0x200);
    word(&mut bytes, 0xdc, 3);
    dword(&mut bytes, 0x104, 16);
    bytes[0x188..0x18e].copy_from_slice(b".rdata");
    dword(&mut bytes, 0x190, 0x2000);
    dword(&mut bytes, 0x194, 0x1000);
    dword(&mut bytes, 0x198, 0x2000);
    dword(&mut bytes, 0x19c, 0x200);
    dword(&mut bytes, 0x1ac, 0x40000040);
    bytes[0x1b0..0x1b5].copy_from_slice(b".text");
    dword(&mut bytes, 0x1b8, 0x200);
    dword(&mut bytes, 0x1bc, 0x3000);
    dword(&mut bytes, 0x1c0, 0x200);
    dword(&mut bytes, 0x1c4, 0x2200);
    dword(&mut bytes, 0x1d4, 0x60000020);
    bytes[0x2200] = 0xc3;
    bytes
}

fn consumer(library: &[u8], symbol: &[u8]) -> Vec<u8> {
    let mut bytes = pe();
    dword(&mut bytes, 0x110, 0x1100);
    dword(&mut bytes, 0x114, 40);
    dword(&mut bytes, 0x300, 0x1200);
    dword(&mut bytes, 0x30c, 0x1280);
    dword(&mut bytes, 0x310, 0x1240);
    qword(&mut bytes, 0x400, 0x1300);
    qword(&mut bytes, 0x440, 0x1300);
    terminated(&mut bytes, 0x480, library);
    terminated(&mut bytes, 0x502, symbol);
    bytes
}

fn provider(identity: &[u8], symbol: &[u8], target: u32) -> Vec<u8> {
    let mut bytes = pe();
    dword(&mut bytes, 0x108, 0x1500);
    dword(&mut bytes, 0x10c, 0x100);
    dword(&mut bytes, 0x70c, 0x1600);
    dword(&mut bytes, 0x710, 1);
    dword(&mut bytes, 0x714, 1);
    dword(&mut bytes, 0x718, 1);
    dword(&mut bytes, 0x71c, 0x1680);
    dword(&mut bytes, 0x720, 0x16a0);
    dword(&mut bytes, 0x724, 0x16c0);
    terminated(&mut bytes, 0x800, identity);
    dword(&mut bytes, 0x880, target);
    dword(&mut bytes, 0x8a0, 0x1700);
    terminated(&mut bytes, 0x900, symbol);
    bytes
}

fn consumer_many(count: usize, symbol: &[u8]) -> Vec<u8> {
    let mut bytes = consumer(b"provider.dll", b"unused");
    bytes.resize(0x50400, 0);
    dword(&mut bytes, 0xa8, 0x51000);
    dword(&mut bytes, 0xd0, 0x52000);
    dword(&mut bytes, 0x190, 0x50000);
    dword(&mut bytes, 0x198, 0x50000);
    dword(&mut bytes, 0x1bc, 0x51000);
    dword(&mut bytes, 0x1c4, 0x50200);
    dword(&mut bytes, 0x300, 0x10000);
    dword(&mut bytes, 0x310, 0x30000);
    let hint_rva = 0x51000 - symbol.len() as u32 - 3;
    let hint_offset = hint_rva as usize - 0xe00;
    terminated(&mut bytes, hint_offset + 2, symbol);
    for index in 0..count {
        qword(&mut bytes, 0xf200 + index * 8, u64::from(hint_rva));
        qword(&mut bytes, 0x2f200 + index * 8, u64::from(hint_rva));
    }
    bytes[0x50200] = 0xc3;
    bytes
}

fn pe32_with_address_overflow(mut bytes: Vec<u8>) -> Vec<u8> {
    let directories = bytes[0x108..0x188].to_vec();
    bytes[0xf8..0x178].copy_from_slice(&directories);
    word(&mut bytes, 0x84, 0x14c);
    word(&mut bytes, 0x98, 0x10b);
    dword(&mut bytes, 0xb4, 0xfffff000);
    dword(&mut bytes, 0xf4, 16);
    bytes
}

fn assert_cold(inputs: &[ModuleReferenceInput]) {
    for input in inputs {
        let caches = input.project.analysis_cache_status();
        assert!(!caches.program && !caches.strings && !caches.triage);
    }
}

#[test]
fn consumer_without_exports_binds_named_data_export_by_producer_metadata_not_filename() {
    let directory = Directory::new();
    let inputs = [
        directory.module("renamed-consumer", "consumer", &consumer(b"Provider.DLL", b"shared_data")),
        directory.module("not-provider.dll", "producer", &provider(b"provider.dll", b"shared_data", 0x1800)),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.rows.len(), 1);
    let row = &report.rows[0];
    assert_eq!(row.status, ModuleReferenceStatus::DeclaredLink);
    assert_eq!(row.source_module_id, "consumer");
    assert_eq!(row.source_slot, 0x180001240);
    assert_eq!(row.candidates[0].module_id, "producer");
    assert_eq!(row.candidates[0].address, Some(0x180001800));
    assert!(!row.candidates[0].executable_backing);
    assert_eq!(report.coverage[0].export_directory_present, Some(false));
    assert!(report.coverage[0].producer_identity.is_none());
    assert!(report.coverage[0].export_table_complete);
    assert!(row.producer_search_complete);
    assert!(report.complete);
    assert!(!report.proven_layout && !report.proven_runtime_flow);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["rows"][0]["source_slot"], "0x180001240");
    assert_eq!(json["rows"][0]["candidates"][0]["address"], "0x180001800");
    assert_cold(&inputs);
}

#[test]
fn identity_collision_is_ambiguous_even_when_only_one_provider_exports_the_symbol() {
    let directory = Directory::new();
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol")),
        directory.module("first", "first", &provider(b"Provider.DLL", b"symbol", 0x3000)),
        directory.module("second", "second", &provider(b"provider.dll", b"other", 0x3000)),
    ];
    let query = ModuleReferenceQuery { source_module_id: Some("consumer".into()), ..Default::default() };
    let report = module_references(&inputs, &query).unwrap();
    let row = &report.rows[0];
    assert_eq!(row.status, ModuleReferenceStatus::Ambiguous);
    assert_eq!(row.candidate_count, 2);
    assert!(row.candidates.iter().any(|candidate| candidate.identity_only && candidate.address.is_none()));
    assert_cold(&inputs);
}

#[test]
fn whole_library_identity_and_exact_symbol_bytes_do_not_use_paths_or_casefolding() {
    let directory = Directory::new();
    for (index, library, symbol) in [
        (0, b"folder/provider.dll".as_slice(), b"symbol".as_slice()),
        (1, b"provider.dll".as_slice(), b"Symbol".as_slice()),
    ] {
        let inputs = [
            directory.module(&format!("consumer-{index}"), "consumer", &consumer(library, symbol)),
            directory.module(&format!("provider-{index}"), "provider", &provider(b"provider.dll", b"symbol", 0x3000)),
        ];
        let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
        assert_eq!(report.rows[0].status, ModuleReferenceStatus::Unresolved);
        assert_cold(&inputs);
    }
}

#[test]
fn ordinal_imports_and_forwarded_exports_are_unsupported_metadata_not_runtime_edges() {
    let directory = Directory::new();
    let mut ordinal = consumer(b"provider.dll", b"#7");
    qword(&mut ordinal, 0x400, (1 << 63) | 7);
    qword(&mut ordinal, 0x440, (1 << 63) | 7);
    let mut forwarded = provider(b"provider.dll", b"symbol", 0x1580);
    terminated(&mut forwarded, 0x780, b"other.symbol");
    let inputs = [
        directory.module("ordinal", "ordinal", &ordinal),
        directory.module("named", "named", &consumer(b"provider.dll", b"symbol")),
        directory.module("provider", "provider", &forwarded),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.rows.len(), 2);
    assert!(report.rows.iter().all(|row| row.status == ModuleReferenceStatus::Unsupported));
    assert_eq!(report.rows[0].import_ordinal, Some(7));
    assert!(report.rows[0].import_name.is_none());
    assert_cold(&inputs);
}

#[test]
fn non_ascii_dll_identity_is_preserved_but_never_lossily_joined() {
    let directory = Directory::new();
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"\xff.dll", b"symbol")),
        directory.module("provider", "provider", &provider(b"\xff.dll", b"symbol", 0x3000)),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.rows[0].status, ModuleReferenceStatus::Unsupported);
    assert_eq!(report.rows[0].import_library.raw_hex, "ff2e646c6c");
    assert!(report.rows[0].import_library.display.is_none());
    assert_cold(&inputs);
}

#[test]
fn unsupported_snapshot_has_visible_coverage_and_no_original_source_claim() {
    let document = br#"{"format":"rampage-snapshot-v1","arch":"x86_64",
        "provenance":"owned unsupported-format fixture","regions":[
        {"name":"code","address":"0x1000","permissions":"r-x","bytes":"c3"}]}"#;
    let input = ModuleReferenceInput {
        module_id: "snapshot".into(),
        project: Arc::new(Project::new(Binary::from_snapshot_bytes(document.to_vec()).unwrap())),
    };
    let inputs = [input];
    let query = ModuleReferenceQuery { source_module_id: Some("snapshot".into()), ..Default::default() };
    let report = module_references(&inputs, &query).unwrap();
    assert!(report.rows.is_empty());
    assert_eq!(report.coverage.len(), 1);
    assert_eq!(report.coverage[0].known_source_slots, 0);
    assert!(report.coverage[0].metadata_origin.is_none());
    assert!(!report.coverage[0].source_revalidated_non_atomic);
    assert!(!report.complete);
    assert_cold(&inputs);
}

#[test]
#[ignore = "requires the central owned COFF consumer/provider fixture recipe; binaries are never executed"]
fn compiled_named_import_declaration_uses_export_directory_not_provider_filename() {
    let root = std::path::PathBuf::from(
        std::env::var_os("RAMPAGE_MODULE_LINKAGE_FIXTURES")
            .expect("select through tools/ci/module-linkage-oracle.sh --check"),
    );
    let consumer = Arc::new(Project::new(Binary::open(root.join("consumer.exe")).unwrap()));
    let provider = Arc::new(Project::new(Binary::open(root.join("renamed-provider.bin")).unwrap()));
    let expected_export = provider.binary.exports.iter().find(|entry| entry.name == "add").unwrap().address;
    let expected_slot = consumer
        .binary
        .import_slots
        .iter()
        .find(|slot| slot.name == "add" && slot.library.as_deref() == Some("owned-provider.dll"))
        .unwrap()
        .address;
    let inputs = [
        ModuleReferenceInput { module_id: "consumer".into(), project: consumer },
        ModuleReferenceInput { module_id: "renamed-provider".into(), project: provider },
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    let row = report
        .rows
        .iter()
        .find(|row| row.source_module_id == "consumer" && row.source_slot == expected_slot)
        .expect("real imported add slot");
    assert_eq!(row.status, ModuleReferenceStatus::DeclaredLink);
    assert_eq!(row.import_library.display.as_deref(), Some("owned-provider.dll"));
    assert_eq!(row.import_name.as_ref().unwrap().display.as_deref(), Some("add"));
    assert_eq!(row.candidates.len(), 1);
    assert_eq!(row.candidates[0].module_id, "renamed-provider");
    assert_eq!(row.candidates[0].address, Some(expected_export));
    assert!(row.candidates[0].executable_backing);
    assert_eq!(
        report.coverage.iter().find(|entry| entry.module_id == "consumer").unwrap().export_directory_present,
        Some(false)
    );
    assert!(!report.proven_runtime_flow && !report.proven_layout);
    assert_cold(&inputs);
}

#[test]
fn checked_query_bounds_and_duplicate_ids_fail_without_warming_analysis() {
    let directory = Directory::new();
    let input = directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol"));
    let inputs = [input.clone()];
    for query in [
        ModuleReferenceQuery { limit: Some(0), ..Default::default() },
        ModuleReferenceQuery { limit: Some(257), ..Default::default() },
        ModuleReferenceQuery { filter: Some("é".repeat(129)), ..Default::default() },
        ModuleReferenceQuery { source_module_id: Some("absent".into()), ..Default::default() },
    ] {
        assert!(module_references(&inputs, &query).is_err());
    }
    assert!(module_references(&[input.clone(), input], &ModuleReferenceQuery::default()).is_err());
    assert_cold(&inputs);
}

#[test]
fn prepared_view_retains_exact_arcs_and_rejects_changed_original_sources() {
    let directory = Directory::new();
    let input = directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol"));
    let inputs = [input];
    let view = prepare_module_reference_view(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert!(Arc::ptr_eq(&view.inputs()[0].project, &inputs[0].project));
    view.revalidate_sources().unwrap();
    let path = directory.0.join("consumer");
    let mut changed = std::fs::read(&path).unwrap();
    changed.push(0);
    std::fs::write(path, changed).unwrap();
    assert!(validate_module_reference_inputs(&inputs).is_err());
    assert!(view.revalidate_sources().is_err());
    assert!(module_references(&inputs, &ModuleReferenceQuery::default()).is_err());
    assert_cold(&inputs);
}

#[test]
fn missing_or_overbudget_provider_metadata_cannot_be_excluded_to_claim_uniqueness() {
    let directory = Directory::new();
    let mut malformed = provider(b"unknown.dll", b"symbol", 0x3000);
    dword(&mut malformed, 0x714, u32::MAX);
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol")),
        directory.module("good", "good", &provider(b"provider.dll", b"symbol", 0x3000)),
        directory.module("malformed", "malformed", &malformed),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.rows[0].status, ModuleReferenceStatus::Unsupported);
    assert!(!report.rows[0].producer_search_complete);
    assert!(!report.coverage[2].export_table_complete);
    assert_eq!(report.coverage[2].export_directory_present, Some(true));
    assert!(!report.complete);
    assert_cold(&inputs);
}

#[test]
fn unknown_empty_producer_identity_cannot_hide_a_possible_identity_collision() {
    let directory = Directory::new();
    let mut unknown = provider(b"", b"unused", 0x3000);
    dword(&mut unknown, 0x714, 0);
    dword(&mut unknown, 0x718, 0);
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol")),
        directory.module("good", "good", &provider(b"provider.dll", b"symbol", 0x3000)),
        directory.module("unknown", "unknown", &unknown),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.rows[0].status, ModuleReferenceStatus::Unsupported);
    assert!(!report.rows[0].producer_search_complete);
    assert_eq!(report.coverage[2].export_directory_present, Some(true));
    assert!(report.coverage[2].producer_identity.is_none());
    assert!(report.coverage[2].export_table_complete);
    assert_eq!(report.coverage[2].examined_exports, 0);
    assert!(!report.complete);
    assert_cold(&inputs);
}

#[test]
fn malformed_import_directory_has_no_invented_remainder_or_complete_unresolved_count() {
    let directory = Directory::new();
    let mut malformed = consumer(b"provider.dll", b"symbol");
    dword(&mut malformed, 0x114, 20);
    let inputs = [directory.module("malformed", "malformed", &malformed)];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert!(report.rows.is_empty());
    assert!(!report.coverage[0].import_table_complete);
    assert_eq!(report.coverage[0].known_source_slots, 0);
    assert!(!report.complete);
    assert_cold(&inputs);
}

#[test]
fn duplicate_named_exports_remain_ambiguous_with_bounded_candidates() {
    let directory = Directory::new();
    let mut duplicate = provider(b"provider.dll", b"symbol", 0x3000);
    dword(&mut duplicate, 0x718, 20);
    dword(&mut duplicate, 0x720, 0x1900);
    dword(&mut duplicate, 0x724, 0x1980);
    for index in 0..20 {
        dword(&mut duplicate, 0xb00 + index * 4, 0x1700);
    }
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol")),
        directory.module("duplicate", "duplicate", &duplicate),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    let row = &report.rows[0];
    assert_eq!(row.status, ModuleReferenceStatus::Ambiguous);
    assert_eq!(row.candidate_count, 20);
    assert!(row.candidates_truncated);
    assert!(row.candidates.len() < row.candidate_count);
    assert_cold(&inputs);
}

#[test]
fn row_retention_cap_is_explicit_and_source_slot_queries_do_not_lose_later_declarations() {
    let directory = Directory::new();
    let inputs = [
        directory.module("consumer", "consumer", &consumer_many(8193, b"x")),
        directory.module("provider", "provider", &provider(b"provider.dll", b"x", 0x3000)),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.matched, 8193);
    assert!(report.rows_truncated);
    assert!(!report.complete);
    let query = ModuleReferenceQuery { source_slot: Some(0x180040000), ..Default::default() };
    let selected = module_references(&inputs, &query).unwrap();
    assert_eq!(selected.rows.len(), 1);
    assert_eq!(selected.rows[0].status, ModuleReferenceStatus::DeclaredLink);
    assert!(!selected.rows_truncated);
    assert_cold(&inputs);
}

#[test]
fn encoded_byte_paging_retains_whole_maximum_names_and_always_makes_progress() {
    let directory = Directory::new();
    let name = vec![1; 4096];
    let inputs = [
        directory.module("consumer", "consumer", &consumer_many(64, &name)),
        directory.module("provider", "provider", &provider(b"provider.dll", &name, 0x3000)),
    ];
    let query = ModuleReferenceQuery { limit: Some(256), ..Default::default() };
    let first = module_references(&inputs, &query).unwrap();
    assert!(first.byte_capped && first.more);
    assert!(!first.rows.is_empty());
    assert_eq!(first.rows[0].import_name.as_ref().unwrap().raw_hex.len(), 8192);
    let encoded = serde_json::to_vec(&first).unwrap();
    assert!(encoded.len() <= 2 * 1024 * 1024);
    let query = ModuleReferenceQuery { offset: first.next_offset, ..query };
    let next = module_references(&inputs, &query).unwrap();
    assert!(!next.rows.is_empty());
    assert_ne!(first.rows[0].source_slot, next.rows[0].source_slot);
    assert_cold(&inputs);
}

#[test]
fn unsupported_elf_and_macho_keep_coverage_without_joining_legacy_import_inventory() {
    let directory = Directory::new();
    for (index, fixture) in ["hello-x64.elf", "hello-x64.macho"].iter().enumerate() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(fixture);
        let bytes = std::fs::read(path).unwrap();
        let inputs = [directory.module(&format!("unsupported-{index}"), "unsupported", &bytes)];
        let query = ModuleReferenceQuery { source_module_id: Some("unsupported".into()), ..Default::default() };
        let report = module_references(&inputs, &query).unwrap();
        assert!(report.rows.is_empty());
        assert_eq!(report.coverage.len(), 1);
        assert_eq!(report.coverage[0].known_source_slots, 0);
        assert!(report.coverage[0].metadata_origin.is_none());
        assert!(!report.coverage[0].source_revalidated_non_atomic);
        assert!(!report.complete);
        assert_cold(&inputs);
    }
}

#[test]
fn a_virtual_gap_in_import_name_metadata_never_becomes_a_known_source_slot() {
    let directory = Directory::new();
    let mut bytes = consumer(b"provider.dll", b"symbol");
    dword(&mut bytes, 0x30c, 0x900);
    let inputs = [directory.module("gap", "gap", &bytes)];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert!(report.rows.is_empty());
    assert_eq!(report.coverage[0].known_source_slots, 0);
    assert!(!report.coverage[0].import_table_complete);
    assert!(!report.complete);
    assert_cold(&inputs);
}

#[test]
fn overflowing_32_bit_image_addresses_are_unsupported_instead_of_widened_targets() {
    let directory = Directory::new();
    let bytes = pe32_with_address_overflow(consumer(b"provider.dll", b"symbol"));
    let inputs = [directory.module("width", "width", &bytes)];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert!(report.rows.is_empty());
    assert_eq!(report.coverage[0].known_source_slots, 0);
    assert!(report.coverage[0].metadata_origin.is_none());
    assert_eq!(report.coverage[0].export_directory_present, None);
    assert!(!report.complete);
    assert_cold(&inputs);
}

#[test]
fn module_count_and_ascii_identity_limits_are_checked_before_any_metadata_query() {
    let directory = Directory::new();
    let input = directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol"));
    for id in [String::new(), "x".repeat(65), "模块".into(), "line\nbreak".into()] {
        let mut invalid = input.clone();
        invalid.module_id = id;
        assert!(module_references(&[invalid], &ModuleReferenceQuery::default()).is_err());
    }
    let inputs: Vec<_> = (0..9)
        .map(|index| ModuleReferenceInput { module_id: format!("module-{index}"), project: Arc::clone(&input.project) })
        .collect();
    assert!(module_references(&inputs, &ModuleReferenceQuery::default()).is_err());
    assert_cold(&[input]);
}

#[test]
fn literal_hash_names_never_match_an_ordinal_only_export() {
    let directory = Directory::new();
    let mut ordinal_only = provider(b"provider.dll", b"ignored", 0x3000);
    dword(&mut ordinal_only, 0x710, 7);
    dword(&mut ordinal_only, 0x718, 0);
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"#7")),
        directory.module("provider", "provider", &ordinal_only),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.rows[0].status, ModuleReferenceStatus::Unresolved);
    assert!(report.rows[0].import_ordinal.is_none());
    assert_eq!(report.rows[0].import_name.as_ref().unwrap().display.as_deref(), Some("#7"));
    assert!(report.rows[0].candidates[0].identity_only);
    assert_cold(&inputs);
}

#[test]
fn non_utf8_symbol_names_can_join_by_exact_bytes_without_a_lossy_display_name() {
    let directory = Directory::new();
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"s\xff")),
        directory.module("provider", "provider", &provider(b"provider.dll", b"s\xff", 0x3000)),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.rows[0].status, ModuleReferenceStatus::DeclaredLink);
    let name = report.rows[0].import_name.as_ref().unwrap();
    assert_eq!(name.raw_hex, "73ff");
    assert!(name.display.is_none());
    assert_cold(&inputs);
}

#[test]
fn no_export_consumer_still_requires_complete_regular_and_delay_import_coverage() {
    let directory = Directory::new();
    let mut bytes = consumer(b"provider.dll", b"symbol");
    dword(&mut bytes, 0x170, 0x1a00);
    dword(&mut bytes, 0x174, 32);
    dword(&mut bytes, 0xc04, 0x1280);
    dword(&mut bytes, 0xc0c, 0x1240);
    dword(&mut bytes, 0xc10, 0x1200);
    let inputs = [
        directory.module("consumer", "consumer", &bytes),
        directory.module("provider", "provider", &provider(b"provider.dll", b"symbol", 0x3000)),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.coverage[0].export_directory_present, Some(false));
    assert!(!report.coverage[0].import_table_complete);
    assert_eq!(report.rows[0].status, ModuleReferenceStatus::Unsupported);
    assert!(!report.rows[0].producer_search_complete);
    assert!(report.matched_is_lower_bound);
    assert!(!report.complete);
    assert_cold(&inputs);
}

#[test]
fn unproven_export_directory_absence_cannot_exclude_an_unidentified_pe_candidate() {
    let directory = Directory::new();
    let unknown = pe32_with_address_overflow(provider(b"provider.dll", b"symbol", 0x3000));
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol")),
        directory.module("good", "good", &provider(b"provider.dll", b"symbol", 0x3000)),
        directory.module("unknown", "unknown", &unknown),
    ];
    let report = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(report.coverage[0].export_directory_present, Some(false));
    assert_eq!(report.coverage[2].export_directory_present, None);
    assert!(report.coverage[2].producer_identity.is_none());
    assert_eq!(report.coverage[2].examined_exports, 0);
    assert_eq!(report.rows[0].status, ModuleReferenceStatus::Unsupported);
    assert!(!report.rows[0].producer_search_complete);
    assert_cold(&inputs);
}

#[test]
fn third_non_exporting_pe_with_incomplete_imports_blocks_links_under_every_source_query() {
    let directory = Directory::new();
    for delayed in [false, true] {
        let mut third = consumer(b"irrelevant.dll", b"ignored");
        if delayed {
            dword(&mut third, 0x170, 0x1a00);
            dword(&mut third, 0x174, 32);
            dword(&mut third, 0xc04, 0x1280);
            dword(&mut third, 0xc0c, 0x1240);
            dword(&mut third, 0xc10, 0x1200);
        } else {
            dword(&mut third, 0x114, 20);
        }
        let suffix = if delayed { "delay" } else { "regular" };
        let inputs = [
            directory.module(&format!("consumer-{suffix}"), "consumer", &consumer_many(2, b"symbol")),
            directory.module(&format!("provider-{suffix}"), "provider", &provider(b"provider.dll", b"symbol", 0x3000)),
            directory.module(&format!("third-{suffix}"), "third", &third),
        ];
        for query in [
            ModuleReferenceQuery::default(),
            ModuleReferenceQuery { source_module_id: Some("consumer".into()), ..Default::default() },
            ModuleReferenceQuery { source_slot: Some(0x180030008), ..Default::default() },
            ModuleReferenceQuery { filter: Some("symbol".into()), ..Default::default() },
            ModuleReferenceQuery { offset: Some(1), limit: Some(1), ..Default::default() },
        ] {
            let report = module_references(&inputs, &query).unwrap();
            assert_eq!(report.coverage[2].export_directory_present, Some(false));
            assert!(!report.coverage[2].import_table_complete);
            assert!(report.rows.iter().any(|row| row.source_module_id == "consumer"));
            assert!(report.rows.iter().all(|row| row.status == ModuleReferenceStatus::Unsupported));
            assert!(report.rows.iter().all(|row| !row.producer_search_complete));
            assert!(!report.complete);
        }
        assert_cold(&inputs);
    }
}

#[test]
fn index_sort_exhaustion_invalidates_the_whole_matching_plan_without_losing_source_rows() {
    let directory = Directory::new();
    let mut duplicate = provider(b"provider.dll", b"symbol", 0x3000);
    dword(&mut duplicate, 0x718, 2);
    dword(&mut duplicate, 0x8a4, 0x1700);
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol")),
        directory.module("provider", "provider", &duplicate),
    ];
    let query = ModuleReferenceQuery { matching_work_limit: Some(6), ..Default::default() };
    let report = module_references(&inputs, &query).unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.matched, 1);
    assert!(!report.matched_is_lower_bound);
    assert_eq!(report.rows[0].status, ModuleReferenceStatus::Unsupported);
    assert!(!report.rows[0].producer_search_complete);
    assert!(report.rows[0].candidates_truncated);
    assert!(report.matching_work_exhausted);
    assert_eq!(report.matching_work_used, 0);
    assert!(!report.complete);
    assert_cold(&inputs);
}

#[test]
fn dll_comparison_exhaustion_keeps_observed_candidates_but_never_claims_uniqueness() {
    let directory = Directory::new();
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol")),
        directory.module("first", "first", &provider(b"provider.dll", b"symbol", 0x3000)),
        directory.module("second", "second", &provider(b"PROVIDER.DLL", b"other", 0x3000)),
    ];
    let query = ModuleReferenceQuery { matching_work_limit: Some(13), ..Default::default() };
    let report = module_references(&inputs, &query).unwrap();
    assert_eq!(report.rows.len(), 1);
    let row = &report.rows[0];
    assert_eq!(row.status, ModuleReferenceStatus::Unsupported);
    assert!(!row.producer_search_complete);
    assert_eq!(row.candidate_count, 1);
    assert_eq!(row.candidates.len(), 1);
    assert_eq!(row.candidates[0].module_id, "first");
    assert!(row.candidates[0].identity_only);
    assert!(row.candidates[0].address.is_none());
    assert!(row.candidates_truncated);
    assert!(report.matching_work_exhausted);
    assert_eq!(report.matching_work_used, 13);
    assert!(!report.complete);
    assert!(!report.matched_is_lower_bound);
    assert_cold(&inputs);
}

#[test]
fn fallible_merge_sort_orders_raw_names_and_stops_after_its_last_funded_comparison() {
    let directory = Directory::new();
    let mut bytes = provider(b"provider.dll", b"zebra", 0x3000);
    dword(&mut bytes, 0x718, 3);
    dword(&mut bytes, 0x8a4, 0x1720);
    dword(&mut bytes, 0x8a8, 0x1740);
    terminated(&mut bytes, 0x920, b"alpha");
    terminated(&mut bytes, 0x940, b"symbol");
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol")),
        directory.module("provider", "provider", &bytes),
    ];
    let query = ModuleReferenceQuery { matching_work_limit: Some(6), ..Default::default() };
    let exhausted = module_references(&inputs, &query).unwrap();
    assert_eq!(exhausted.matching_work_used, 6);
    assert!(exhausted.matching_work_exhausted);
    assert_eq!(exhausted.rows[0].status, ModuleReferenceStatus::Unsupported);
    assert!(!exhausted.rows[0].producer_search_complete);
    assert!(!exhausted.complete);
    let funded = module_references(&inputs, &ModuleReferenceQuery::default()).unwrap();
    assert_eq!(funded.rows[0].status, ModuleReferenceStatus::DeclaredLink);
    assert_eq!(funded.rows[0].candidates[0].address, Some(0x180003000));
    assert!(!funded.matching_work_exhausted);
    assert_cold(&inputs);
}

#[test]
fn matching_allowance_is_down_clamped_and_every_symbol_comparison_is_funded() {
    let directory = Directory::new();
    let inputs = [
        directory.module("consumer", "consumer", &consumer(b"provider.dll", b"symbol")),
        directory.module("provider", "provider", &provider(b"provider.dll", b"symbol", 0x3000)),
    ];
    for (allowance, complete, charged) in [(0, false, 0), (26, false, 20), (27, true, 27), (usize::MAX, true, 27)] {
        let query = ModuleReferenceQuery { matching_work_limit: Some(allowance), ..Default::default() };
        let report = module_references(&inputs, &query).unwrap();
        assert_eq!(report.matching_work_limit, allowance.min(32 * 1024 * 1024));
        assert_eq!(report.matching_work_used, charged);
        assert_eq!(report.matching_work_exhausted, !complete);
        assert_eq!(report.complete, complete);
        assert_eq!(report.rows[0].producer_search_complete, complete);
        let expected = if complete { ModuleReferenceStatus::DeclaredLink } else { ModuleReferenceStatus::Unsupported };
        assert_eq!(report.rows[0].status, expected);
        assert!(!report.matched_is_lower_bound);
    }
    assert_cold(&inputs);
}
