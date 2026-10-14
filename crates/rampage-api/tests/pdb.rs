#[path = "../../../tests/fixtures/pdb/support.rs"]
mod support;

use rampage_api::Project;
use rampage_api::annotations::Annotations;
use rampage_loaders::{Binary, Symbol, SymbolKind};
use support::{TempFiles, fixture, module_stream, rsds_offset, stream_offset};

fn project() -> Project {
    Project::new(Binary::open(fixture("fixture.exe")).unwrap())
}

#[test]
fn real_pdb_preview_apply_name_resolution_and_batch_undo() {
    let project = project();
    assert!(project.resolve("pdb_mix").is_err());
    let preview = project.import_pdb_names(&fixture("fixture.pdb"), false).unwrap();
    assert!(preview.applied.is_empty());
    assert!(project.annotation_list().names.is_empty());
    let mix = preview.preview.functions.iter().find(|function| function.name == "pdb_mix").unwrap().address;
    assert_eq!(mix, 0x140001000);
    let imported = project.import_pdb_names(&fixture("fixture.pdb"), true).unwrap();
    assert!(imported.applied.contains(&mix));
    let local = project.resolve("pdb_local").unwrap();
    assert!(imported.applied.contains(&local));
    assert_eq!(project.function_name(mix), "pdb_mix");
    assert_eq!(project.resolve("pdb_mix").unwrap(), mix);
    assert!(project.functions(&Default::default()).unwrap().items.iter().any(|row| row.name == "pdb_mix"));
    assert_eq!(project.undo().unwrap().len(), imported.applied.len());
    assert!(project.resolve("pdb_mix").is_err());
    assert!(project.resolve("pdb_local").is_err());
    assert_eq!(project.redo().unwrap().len(), imported.applied.len());
    assert_eq!(project.resolve("pdb_mix").unwrap(), mix);
    assert!(project.import_pdb_names(&fixture("fixture.pdb"), true).unwrap().applied.is_empty());
}

#[test]
fn real_pdb_preserves_symbol_export_entry_and_user_names() {
    let mut binary = Binary::open(fixture("fixture.exe")).unwrap();
    binary.symbols.push(Symbol {
        address: 0x140001000,
        name: "existing_mix".to_owned(),
        size: 0,
        kind: SymbolKind::Function,
    });
    let project = Project::new(binary);
    project.rename(0x140001020, Some("user_local")).unwrap();
    let imported = project.import_pdb_names(&fixture("fixture.pdb"), true).unwrap();
    assert!(imported.applied.is_empty());
    assert_eq!(project.function_name(0x140001000), "existing_mix");
    assert_eq!(project.function_name(0x140001020), "user_local");
    assert_eq!(project.function_name(0x140001030), "pdb_export");
    assert_eq!(project.function_name(project.binary.entry.unwrap()), "entry");
    assert!(imported.preserved.contains(&0x140001000));
    assert!(imported.preserved.contains(&0x140001020));
}

#[test]
fn mismatched_and_truncated_real_pdb_inputs_leave_all_annotations_unchanged() {
    let files = TempFiles::new();
    let mut image = std::fs::read(fixture("fixture.exe")).unwrap();
    let guid = rsds_offset(&image) + 4;
    image[guid] ^= 1;
    let path = files.write("mismatch.exe", &image);
    let project = Project::new(Binary::open(path).unwrap());
    assert!(project.import_pdb_names(&fixture("fixture.pdb"), true).is_err());
    assert!(project.annotation_list().names.is_empty());

    let bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let path = files.write("truncated.pdb", &bytes[..bytes.len() - 1]);
    let project = self::project();
    assert!(project.import_pdb_names(&path, true).is_err());
    assert!(project.annotation_list().names.is_empty());
}

#[test]
fn duplicate_function_names_in_real_pdb_do_not_partially_apply() {
    let files = TempFiles::new();
    let mut bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let module_start = stream_offset(&bytes, module_stream(&bytes), 0);
    let local = bytes[module_start..module_start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
    bytes[module_start + local..module_start + local + 10].copy_from_slice(b"pdb_mix\0\0\0");
    let path = files.write("ambiguous.pdb", &bytes);
    let project = project();
    let error = project.import_pdb_names(&path, true).unwrap_err();
    assert!(error.to_string().contains("ambiguous PDB name"), "{error}");
    assert!(project.annotation_list().names.is_empty());
}

#[test]
fn a_user_name_already_used_elsewhere_is_never_stolen() {
    let project = project();
    project.rename(0x140001020, Some("pdb_mix")).unwrap();
    let imported = project.import_pdb_names(&fixture("fixture.pdb"), true).unwrap();
    assert!(imported.applied.is_empty());
    assert_eq!(project.resolve("pdb_mix").unwrap(), 0x140001020);
    assert!(project.name_at(0x140001000).is_none());
}

#[test]
fn apply_refreshes_other_clients_names_under_the_annotation_log_lock() {
    let files = TempFiles::new();
    let log = files.write("names.rampage", b"");
    let importer = Project::with_annotations(
        Binary::open(fixture("fixture.exe")).unwrap(),
        Annotations::open(log.clone()).unwrap(),
    );
    let writer =
        Project::with_annotations(Binary::open(fixture("fixture.exe")).unwrap(), Annotations::open(log).unwrap());
    writer.rename(0x140001000, Some("other_client_mix")).unwrap();
    assert!(importer.name_at(0x140001000).is_none());
    let imported = importer.import_pdb_names(&fixture("fixture.pdb"), true).unwrap();
    assert!(imported.preserved.contains(&0x140001000));
    assert!(!imported.applied.contains(&0x140001000));
    assert_eq!(importer.function_name(0x140001000), "other_client_mix");
    assert_eq!(importer.undo().unwrap().len(), imported.applied.len());
    assert_eq!(importer.function_name(0x140001000), "other_client_mix");
}

#[test]
fn a_pdb_address_inside_a_function_is_not_an_importable_entry() {
    let files = TempFiles::new();
    let mut bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let module_start = stream_offset(&bytes, module_stream(&bytes), 0);
    let name = bytes[module_start..module_start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
    let procedure = module_start + name - 39;
    bytes[procedure + 32..procedure + 36].copy_from_slice(&33u32.to_le_bytes());
    let path = files.write("interior.pdb", &bytes);
    let project = project();
    let imported = project.import_pdb_names(&path, true).unwrap();
    assert!(imported.preserved.contains(&0x140001021));
    assert!(!imported.applied.contains(&0x140001021));
    assert!(project.name_at(0x140001021).is_none());
    assert!(project.resolve("pdb_local").is_err());
    assert_eq!(project.resolve("pdb_mix").unwrap(), 0x140001000);
}

#[test]
fn corrupt_wrapping_offset_and_hidden_record_flood_cannot_partially_apply_names() {
    let original = std::fs::read(fixture("fixture.pdb")).unwrap();
    let files = TempFiles::new();
    for corrupt in [
        support::corrupt_local_offset(&original, 3, 0xffffe020),
        support::corrupt_skipped_symbols(&original, false, 0x0007, 1_000_001),
    ] {
        let path = files.write("corrupt-not-compiler-generated.pdb", &corrupt);
        let project = project();
        project.rename(0x140001020, Some("preserved_user_local")).unwrap();
        for apply in [false, true] {
            assert!(project.import_pdb_names(&path, apply).is_err());
        }
        assert!(project.resolve("pdb_mix").is_err());
        let names = project.annotation_list().names;
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].text, "preserved_user_local");
    }
}

#[test]
fn corrupt_nonexecutable_or_unreadable_pe_cannot_apply_identity_matching_pdb_names() {
    let original = std::fs::read(fixture("fixture.exe")).unwrap();
    let files = TempFiles::new();
    for permission in [0x20000000, 0x40000000] {
        let path = files.write("corrupt-permissions.exe", &support::corrupt_text_permissions(&original, permission));
        let project = Project::new(Binary::open(path).unwrap());
        for apply in [false, true] {
            assert!(project.import_pdb_names(&fixture("fixture.pdb"), apply).is_err());
        }
        assert!(project.annotation_list().names.is_empty());
    }
}

#[test]
fn corrupt_constant_numeric_prefix_cannot_panic_or_partially_apply_function_names() {
    let original = std::fs::read(fixture("fixture.pdb")).unwrap();
    let corrupt = support::corrupt_local_constant_numeric_prefix(&original, 0x1107, 0xffff);
    let files = TempFiles::new();
    let path = files.write("corrupt-constant-prefix-not-compiler-generated.pdb", &corrupt);
    let project = project();
    project.rename(0x140001020, Some("preserved_user_local")).unwrap();
    for apply in [false, true] {
        let error = project.import_pdb_names(&path, apply).unwrap_err();
        assert!(error.to_string().contains("unsupported constant numeric prefix 0xffff"), "{error}");
    }
    assert!(project.resolve("pdb_mix").is_err());
    let names = project.annotation_list().names;
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].text, "preserved_user_local");
}

fn shared_import(project: &Project, input: serde_json::Value) -> (serde_json::Value, bool) {
    let (text, failed) = rampage_api::tools::call(&rampage_api::tools::tools(), project, "import_pdb_names", input);
    assert!(text.len() <= 60_000, "{}", text.len());
    (serde_json::from_str(&text).unwrap(), failed)
}

#[test]
fn shared_pdb_tool_defaults_to_preview_and_applies_the_whole_import_not_the_page() {
    use rampage_api::tools::{Effect, Group};
    use serde_json::json;

    let files = TempFiles::new();
    let log = files.write("shared-names.rampage", b"");
    let project = Project::with_annotations(
        Binary::open(fixture("fixture.exe")).unwrap(),
        Annotations::open(log.clone()).unwrap(),
    );
    let tools = rampage_api::tools::tools();
    let tool = tools.iter().find(|tool| tool.name == "import_pdb_names").unwrap();
    assert_eq!(tool.group, Group::Types);
    assert_eq!(tool.effect, Effect::Annotations);
    assert!(tool.reads_annotations);
    let before = std::fs::read(&log).unwrap();
    let (preview, failed) = shared_import(&project, json!({ "pdb": fixture("fixture.pdb"), "limit": 1 }));
    assert!(!failed, "{preview}");
    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["apply_requested"], false);
    assert_eq!(preview["whole_apply_succeeded"], false);
    assert_eq!(preview["applied_total"], 0);
    assert!(preview["identity"]["guid"].is_string());
    assert!(preview["identity"]["age"].as_u64().unwrap() > 0);
    assert_eq!(preview["details"].as_array().unwrap().len(), 1);
    assert_eq!(preview["more"], true);
    assert_eq!(preview["next_offset"], 1);
    assert_eq!(std::fs::read(&log).unwrap(), before);
    assert!(project.annotation_list().names.is_empty());
    assert!(project.resolve("pdb_mix").is_err());

    let (applied, failed) = shared_import(
        &project,
        json!({ "pdb": fixture("fixture.pdb"), "apply": true, "offset": usize::MAX, "limit": 1 }),
    );
    assert!(!failed, "{applied}");
    assert_eq!(applied["identity"], preview["identity"]);
    assert_eq!(applied["preview_total"], preview["preview_total"]);
    assert_eq!(applied["whole_apply_succeeded"], true);
    assert_eq!(applied["status"], "applied");
    assert_eq!(applied["applied_total"], 2);
    assert_eq!(applied["details"], json!([]));
    assert_eq!(applied["more"], false);
    assert_ne!(std::fs::read(&log).unwrap(), before);
    assert_eq!(project.resolve("pdb_mix").unwrap(), 0x140001000);
    assert_eq!(project.resolve("pdb_local").unwrap(), 0x140001020);
    let reopened =
        Project::with_annotations(Binary::open(fixture("fixture.exe")).unwrap(), Annotations::open(log).unwrap());
    assert_eq!(reopened.resolve("pdb_mix").unwrap(), 0x140001000);
    assert_eq!(reopened.resolve("pdb_local").unwrap(), 0x140001020);
    let (undo, failed) = rampage_api::tools::call(&tools, &project, "undo", json!({}));
    assert!(!failed, "{undo}");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&undo).unwrap().as_array().unwrap().len(), 2);
    assert!(project.annotation_list().names.is_empty());
    assert!(project.resolve("pdb_mix").is_err());
}

#[test]
fn shared_pdb_tool_rejects_identity_malformed_and_invalid_arguments_without_edits() {
    use serde_json::json;

    let files = TempFiles::new();
    let mut image = std::fs::read(fixture("fixture.exe")).unwrap();
    let guid = rsds_offset(&image) + 4;
    image[guid] ^= 1;
    let mismatch = Project::new(Binary::open(files.write("shared-mismatch.exe", &image)).unwrap());
    let (receipt, failed) = shared_import(&mismatch, json!({ "pdb": fixture("fixture.pdb"), "apply": true }));
    assert!(failed);
    assert_eq!(receipt["whole_apply_succeeded"], false);
    assert_eq!(receipt["applied_total"], 0);
    assert!(receipt["error"].as_str().unwrap().contains("GUID/age"), "{receipt}");
    assert!(mismatch.annotation_list().names.is_empty());

    let project = project();
    project.rename(0x140001020, Some("keep_user_local")).unwrap();
    let bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let malformed = files.write("shared-truncated.pdb", &bytes[..bytes.len() - 1]);
    for input in [
        json!({ "pdb": malformed, "apply": true }),
        json!({ "apply": true }),
        json!({ "pdb": fixture("fixture.pdb"), "apply": true, "limit": 0 }),
        json!({ "pdb": fixture("fixture.pdb"), "apply": true, "limit": 1001 }),
        json!({ "pdb": fixture("fixture.pdb"), "apply": "true" }),
        json!({ "pdb": fixture("fixture.pdb"), "apply": true, "auto_sidecar": true }),
    ] {
        let (receipt, failed) = shared_import(&project, input);
        assert!(failed, "{receipt}");
        assert_eq!(receipt["ok"], false);
        assert_eq!(receipt["status"], "rejected");
        assert_eq!(receipt["whole_apply_succeeded"], false);
        assert_eq!(receipt["applied_total"], 0);
        assert!(receipt["error"].is_string());
        assert!(project.resolve("pdb_mix").is_err());
        assert_eq!(project.annotation_list().names.len(), 1);
        assert_eq!(project.resolve("keep_user_local").unwrap(), 0x140001020);
    }
    assert_eq!(project.undo().unwrap().len(), 1);
    assert!(project.annotation_list().names.is_empty());
}

#[test]
fn shared_pdb_tool_preserves_another_clients_label_and_reports_full_counts() {
    use serde_json::json;

    let files = TempFiles::new();
    let log = files.write("shared-concurrent.rampage", b"");
    let importer = Project::with_annotations(
        Binary::open(fixture("fixture.exe")).unwrap(),
        Annotations::open(log.clone()).unwrap(),
    );
    let writer =
        Project::with_annotations(Binary::open(fixture("fixture.exe")).unwrap(), Annotations::open(log).unwrap());
    let (preview, failed) = shared_import(&importer, json!({ "pdb": fixture("fixture.pdb") }));
    assert!(!failed, "{preview}");
    writer.rename(0x140001000, Some("concurrent_mix")).unwrap();
    assert!(importer.name_at(0x140001000).is_none());
    let (receipt, failed) =
        shared_import(&importer, json!({ "pdb": fixture("fixture.pdb"), "apply": true, "offset": 1, "limit": 1 }));
    assert!(!failed, "{receipt}");
    assert_eq!(receipt["whole_apply_succeeded"], true);
    assert_eq!(receipt["preview_total"], preview["preview_total"]);
    assert_eq!(receipt["applied_total"], 1);
    assert_eq!(receipt["preserved_total"].as_u64().unwrap(), preview["preserved_total"].as_u64().unwrap() + 1);
    assert_eq!(importer.function_name(0x140001000), "concurrent_mix");
    assert_eq!(importer.resolve("pdb_local").unwrap(), 0x140001020);
    assert_eq!(importer.undo().unwrap().len(), 1);
    assert_eq!(importer.function_name(0x140001000), "concurrent_mix");
    assert!(importer.resolve("pdb_local").is_err());
}

#[test]
fn shared_pdb_tool_preserves_user_symbol_export_and_entry_names_without_an_undo_step() {
    use serde_json::json;

    let mut binary = Binary::open(fixture("fixture.exe")).unwrap();
    binary.symbols.push(Symbol {
        address: 0x140001000,
        name: "symbol_mix".to_owned(),
        size: 0,
        kind: SymbolKind::Function,
    });
    let project = Project::new(binary);
    project.rename(0x140001020, Some("user_local")).unwrap();
    let (receipt, failed) = shared_import(&project, json!({ "pdb": fixture("fixture.pdb"), "apply": true }));
    assert!(!failed, "{receipt}");
    assert_eq!(receipt["whole_apply_succeeded"], true);
    assert_eq!(receipt["applied_total"], 0);
    assert_eq!(receipt["preserved_total"], receipt["preview_total"]);
    assert!(
        receipt["details"]
            .as_array()
            .unwrap()
            .iter()
            .all(|detail| { detail["kind"] != "function" || detail["status"] == "preserved" })
    );
    assert_eq!(project.function_name(0x140001000), "symbol_mix");
    assert_eq!(project.function_name(0x140001020), "user_local");
    assert_eq!(project.function_name(0x140001030), "pdb_export");
    assert_eq!(project.function_name(project.binary.entry.unwrap()), "entry");
    let undo = project.undo().unwrap();
    assert_eq!(undo.len(), 1);
    assert_eq!(undo[0].value.as_deref(), Some("user_local"));
    assert_eq!(project.function_name(0x140001000), "symbol_mix");
    assert!(project.annotation_list().names.is_empty());
}
