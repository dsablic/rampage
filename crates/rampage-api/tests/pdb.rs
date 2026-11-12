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
fn duplicate_function_names_in_real_pdb_name_neither_function() {
    let files = TempFiles::new();
    let mut bytes = std::fs::read(fixture("fixture.pdb")).unwrap();
    let module_start = stream_offset(&bytes, module_stream(&bytes), 0);
    let local = bytes[module_start..module_start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
    bytes[module_start + local..module_start + local + 10].copy_from_slice(b"pdb_mix\0\0\0");
    let path = files.write("ambiguous.pdb", &bytes);
    let project = project();
    // A name two functions share names neither; the PDB's other names still apply, with a warning.
    let imported = project.import_pdb_names(&path, true).unwrap();
    assert!(imported.preview.warnings.iter().any(|warning| warning.starts_with("2 functions omitted")));
    assert!(!imported.preview.functions.iter().any(|function| function.name == "pdb_mix"));
    assert!(project.resolve("pdb_mix").is_err());
    assert!(imported.preview.functions.iter().any(|function| function.name == "pdb_entry"));
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod checked {
    use super::*;
    use std::path::Path;

    use rampage_api::{ApiError, PdbPreview};

    const MIX: u64 = 0x140001000;
    const LOCAL: u64 = 0x140001020;
    const OTHER: u64 = 0x140005000;

    fn logged(log: &Path) -> Project {
        Project::with_annotations(
            Binary::open(fixture("fixture.exe")).unwrap(),
            Annotations::open(log.to_owned()).unwrap(),
        )
    }

    fn seed_history(project: &Project) {
        project.comment(MIX, Some("keep this undo step")).unwrap();
        project.comment(LOCAL, Some("keep this redo step")).unwrap();
        assert_eq!(project.undo().unwrap()[0].address, LOCAL);
    }

    fn assert_unchanged_rejection<T>(
        project: &Project,
        log: &Path,
        work: impl FnOnce() -> Result<T, ApiError>,
    ) -> String {
        let before_log = std::fs::read(log).unwrap();
        let before_annotations = serde_json::to_value(project.annotation_list()).unwrap();
        let error = work().err().expect("stale preview must be refused").to_string();
        assert_eq!(std::fs::read(log).unwrap(), before_log, "{error}");
        assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before_annotations, "{error}");
        assert_eq!(project.redo().unwrap()[0].address, LOCAL, "stale errors must preserve redo");
        assert_eq!(project.undo().unwrap()[0].address, LOCAL);
        assert_eq!(project.undo().unwrap()[0].address, MIX, "stale errors must preserve the previous undo step");
        assert!(project.undo().unwrap().is_empty());
        error
    }

    fn changed_local_name(original: &[u8]) -> Vec<u8> {
        let mut bytes = original.to_vec();
        let start = stream_offset(original, module_stream(original), 0);
        let name = original[start..start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
        bytes[start + name..start + name + 10].copy_from_slice(b"new_local\0");
        bytes
    }

    #[test]
    fn checked_preview_is_read_only_and_apply_and_undo_use_the_approved_batch() {
        let files = TempFiles::new();
        let log = files.write("checked.rampage", b"");
        let project = logged(&log);
        project.comment(MIX, Some("earlier step")).unwrap();
        let before = std::fs::read(&log).unwrap();
        let receipt = project.preview_pdb_names(&fixture("fixture.pdb")).unwrap();
        assert_eq!(std::fs::read(&log).unwrap(), before);
        assert!(project.annotation_list().names.is_empty());
        assert_eq!(project.undo().unwrap()[0].value.as_deref(), Some("earlier step"));
        assert!(project.undo().unwrap().is_empty(), "preview must not add undo history");
        assert_eq!(receipt.approved().iter().map(|function| function.address).collect::<Vec<_>>(), [MIX, LOCAL]);
        assert_eq!(receipt.approved()[0].name, "pdb_mix");
        assert_eq!(receipt.approved()[1].name, "pdb_local");
        assert!(receipt.preserved().contains(&0x140001030));
        assert!(receipt.preserved().contains(&project.binary.entry.unwrap()));
        // Independently recorded SHA-256 values of the owned LLVM fixtures, not production hash helpers.
        assert_eq!(
            rampage_arch::hex::bytes(receipt.image_sha256()),
            "81f277669933189213eb1b4f04ace20115a8714d4153af053f5d9d75a7889495"
        );
        assert_eq!(
            rampage_arch::hex::bytes(receipt.pdb().sha256()),
            "618b154d83ecd8e0ec08056913371116e193d9d00569be07b6615183c9b3d644"
        );
        let applied = project.apply_pdb_names(&receipt).unwrap();
        assert_eq!(applied.applied, [MIX, LOCAL]);
        assert_eq!(applied.preserved, receipt.preserved());
        assert_eq!(applied.preview.functions, receipt.report().functions);
        assert_eq!(project.resolve("pdb_mix").unwrap(), MIX);
        assert_eq!(project.resolve("pdb_local").unwrap(), LOCAL);
        assert_eq!(project.undo().unwrap().len(), 2);
        assert!(project.annotation_list().names.is_empty());
        assert_eq!(project.redo().unwrap().len(), 2);
        assert!(project.apply_pdb_names(&receipt).unwrap().applied.is_empty());
        assert_eq!(project.undo().unwrap().len(), 2, "an empty checked apply must not create an undo step");
    }

    #[test]
    fn checked_preview_accepts_read_only_inputs_without_writing_or_creating_an_annotation_lock() {
        let files = TempFiles::new();
        let log = files.write("read-only.rampage", b"");
        let pdb = files.write("read-only.pdb", &std::fs::read(fixture("fixture.pdb")).unwrap());
        let project = logged(&log);
        for path in [&log, &pdb] {
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(path, permissions).unwrap();
        }
        let receipt = project.preview_pdb_names(&pdb).unwrap();
        assert_eq!(receipt.approved().len(), 2);
        assert!(std::fs::read(&log).unwrap().is_empty());
        let mut lock = log.as_os_str().to_owned();
        lock.push(".lock");
        assert!(!Path::new(&lock).exists());
        assert!(project.annotation_list().names.is_empty());
        assert!(project.undo().unwrap().is_empty());
    }

    #[test]
    fn another_project_cannot_apply_the_receipt_even_for_the_same_path_and_bytes() {
        let files = TempFiles::new();
        let origin = project();
        let receipt = origin.preview_pdb_names(&fixture("fixture.pdb")).unwrap();
        let log = files.write("other-project.rampage", b"");
        let other = logged(&log);
        seed_history(&other);
        let error = assert_unchanged_rejection(&other, &log, || other.apply_pdb_names(&receipt));
        assert!(error.contains("different project"), "{error}");
        assert!(origin.annotation_list().names.is_empty());
        assert!(origin.undo().unwrap().is_empty());
    }

    #[test]
    fn a_session_reload_of_identical_bytes_rejects_the_old_project_receipt_and_keeps_inherited_history() {
        let files = TempFiles::new();
        let bytes = std::fs::read(fixture("fixture.exe")).unwrap();
        let image = files.write("session.exe", &bytes);
        let log = files.write("session.exe.rampage", b"");
        let session = rampage_api::Session::default();
        let origin = session.open(&image, None).unwrap();
        seed_history(&origin);
        let receipt = origin.preview_pdb_names(&fixture("fixture.pdb")).unwrap();
        std::fs::rename(files.write("replacement.exe", &bytes), &image).unwrap();
        let reloaded = session.open(&image, None).unwrap();
        assert!(!std::sync::Arc::ptr_eq(&origin, &reloaded));
        let error = assert_unchanged_rejection(&reloaded, &log, || reloaded.apply_pdb_names(&receipt));
        assert!(error.contains("different project"), "{error}");
    }

    #[test]
    fn changed_pdb_names_with_the_same_guid_age_and_length_require_a_new_preview() {
        let files = TempFiles::new();
        let original = std::fs::read(fixture("fixture.pdb")).unwrap();
        let changed = changed_local_name(&original);
        let old_report = rampage_loaders::pdb::pdb_symbols_bytes(&original).unwrap();
        let new_report = rampage_loaders::pdb::pdb_symbols_bytes(&changed).unwrap();
        assert_eq!(old_report.identity, new_report.identity);
        assert_eq!(original.len(), changed.len());
        assert!(new_report.functions.iter().any(|function| function.name == "new_local"));
        let pdb = files.write("selected.pdb", &original);
        let log = files.write("changed-pdb.rampage", b"");
        let project = logged(&log);
        seed_history(&project);
        let receipt = project.preview_pdb_names(&pdb).unwrap();
        std::fs::write(&pdb, &changed).unwrap();
        let error = assert_unchanged_rejection(&project, &log, || project.apply_pdb_names(&receipt));
        assert!(error.contains("PDB bytes or provenance changed"), "{error}");
        assert!(receipt.approved().iter().any(|function| function.name == "pdb_local"));
        assert!(!receipt.report().functions.iter().any(|function| function.name == "new_local"));
    }

    #[test]
    fn checked_preview_omits_ambiguous_and_invalid_names_and_rejects_panic_prone_ones_without_touching_state() {
        let original = std::fs::read(fixture("fixture.pdb")).unwrap();
        let start = stream_offset(&original, module_stream(&original), 0);
        let name = original[start..start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
        let mut ambiguous = original.clone();
        ambiguous[start + name..start + name + 10].copy_from_slice(b"pdb_mix\0\0\0");
        let mut invalid = original.clone();
        invalid[start + name..start + name + 10].copy_from_slice(b"bad local\0");
        let numeric = support::corrupt_local_constant_numeric_prefix(&original, 0x1107, 0xffff);
        // Shared and non-identifier names are omitted with a warning, not offered.
        for (bytes, omitted) in [(ambiguous, "pdb_mix"), (invalid, "bad local")] {
            let files = TempFiles::new();
            let pdb = files.write("omitted.pdb", &bytes);
            let project = logged(&files.write("omitted-preview.rampage", b""));
            let receipt = project.preview_pdb_names(&pdb).unwrap();
            assert!(!receipt.report().functions.iter().any(|function| function.name == omitted));
            assert!(!receipt.report().warnings.is_empty());
        }
        let files = TempFiles::new();
        let pdb = files.write("invalid.pdb", &numeric);
        let log = files.write("invalid-preview.rampage", b"");
        let project = logged(&log);
        seed_history(&project);
        let error = assert_unchanged_rejection(&project, &log, || project.preview_pdb_names(&pdb));
        assert!(error.contains("unsupported constant numeric prefix"), "{error}");
    }

    #[test]
    fn replaced_identical_missing_truncated_oversized_and_symlink_pdbs_leave_state_and_history_untouched() {
        let original = std::fs::read(fixture("fixture.pdb")).unwrap();
        for mutation in ["replace", "missing", "truncate", "oversize", "symlink", "fifo"] {
            let files = TempFiles::new();
            let pdb = files.write("selected.pdb", &original);
            let log = files.write("stale-pdb.rampage", b"");
            let project = logged(&log);
            seed_history(&project);
            let receipt = project.preview_pdb_names(&pdb).unwrap();
            match mutation {
                "replace" => std::fs::rename(files.write("replacement.pdb", &original), &pdb).unwrap(),
                "missing" => std::fs::remove_file(&pdb).unwrap(),
                "truncate" => {
                    std::fs::OpenOptions::new().write(true).open(&pdb).unwrap().set_len(31).unwrap();
                }
                "oversize" => {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&pdb)
                        .unwrap()
                        .set_len(rampage_loaders::pdb::MAX_PDB_BYTES as u64 + 1)
                        .unwrap();
                }
                "symlink" => {
                    std::fs::remove_file(&pdb).unwrap();
                    std::os::unix::fs::symlink(fixture("fixture.pdb"), &pdb).unwrap();
                }
                "fifo" => {
                    std::fs::remove_file(&pdb).unwrap();
                    std::fs::rename(files.fifo("hostile.pdb"), &pdb).unwrap();
                }
                _ => unreachable!(),
            }
            assert_unchanged_rejection(&project, &log, || project.apply_pdb_names(&receipt));
        }
    }

    fn mutate_image(files: &TempFiles, path: &Path, original: &[u8], mutation: &str) {
        match mutation {
            "overwrite" => {
                let mut changed = original.to_vec();
                changed[0x400] ^= 1;
                std::fs::write(path, changed).unwrap();
            }
            "replace" => std::fs::rename(files.write("replacement.exe", original), path).unwrap(),
            "truncate" => {
                std::fs::OpenOptions::new().write(true).open(path).unwrap().set_len(1).unwrap();
            }
            "missing" => std::fs::remove_file(path).unwrap(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn changed_original_mappings_are_rejected_before_preview_or_apply_can_read_stale_mapped_bytes() {
        let original = std::fs::read(fixture("fixture.exe")).unwrap();
        for mutation in ["overwrite", "replace", "truncate", "missing"] {
            for after_preview in [false, true] {
                let files = TempFiles::new();
                let image = files.write("selected.exe", &original);
                let log = files.write("stale-image.rampage", b"");
                let project =
                    Project::with_annotations(Binary::open(&image).unwrap(), Annotations::open(log.clone()).unwrap());
                seed_history(&project);
                let receipt = after_preview.then(|| project.preview_pdb_names(&fixture("fixture.pdb")).unwrap());
                mutate_image(&files, &image, &original, mutation);
                if let Some(receipt) = receipt {
                    assert_unchanged_rejection(&project, &log, || project.apply_pdb_names(&receipt));
                } else {
                    assert_unchanged_rejection(&project, &log, || project.preview_pdb_names(&fixture("fixture.pdb")));
                }
            }
        }
    }

    #[test]
    fn new_labels_and_name_conflicts_shrink_checked_application_under_the_shared_log_lock() {
        for conflict_elsewhere in [false, true] {
            let files = TempFiles::new();
            let log = files.write("new-conflict.rampage", b"");
            let importer = logged(&log);
            let writer = logged(&log);
            let receipt = importer.preview_pdb_names(&fixture("fixture.pdb")).unwrap();
            if conflict_elsewhere {
                writer.rename(OTHER, Some("pdb_mix")).unwrap();
            } else {
                writer.rename(MIX, Some("concurrent_mix")).unwrap();
            }
            assert!(importer.name_at(MIX).is_none());
            let imported = importer.apply_pdb_names(&receipt).unwrap();
            assert_eq!(imported.applied, [LOCAL]);
            assert!(imported.preserved.contains(&MIX));
            assert_eq!(importer.resolve("pdb_local").unwrap(), LOCAL);
            assert_eq!(importer.undo().unwrap().len(), 1);
            assert!(importer.resolve("pdb_local").is_err());
            if conflict_elsewhere {
                assert_eq!(importer.resolve("pdb_mix").unwrap(), OTHER);
            } else {
                assert_eq!(importer.resolve("concurrent_mix").unwrap(), MIX);
            }
        }
    }

    #[test]
    fn clearing_preview_preserved_labels_or_conflicts_never_enlarges_the_approved_pairs() {
        for conflict_elsewhere in [false, true] {
            let files = TempFiles::new();
            let log = files.write("cleared-conflict.rampage", b"");
            let importer = logged(&log);
            let writer = logged(&log);
            let preserved = if conflict_elsewhere { OTHER } else { MIX };
            writer.rename(preserved, Some(if conflict_elsewhere { "pdb_mix" } else { "keep_mix" })).unwrap();
            importer.refresh_annotations().unwrap();
            let receipt = importer.preview_pdb_names(&fixture("fixture.pdb")).unwrap();
            assert_eq!(receipt.approved().iter().map(|function| function.address).collect::<Vec<_>>(), [LOCAL]);
            writer.rename(preserved, None).unwrap();
            let imported = importer.apply_pdb_names(&receipt).unwrap();
            assert_eq!(imported.applied, [LOCAL]);
            assert!(imported.preserved.contains(&MIX));
            assert!(importer.name_at(MIX).is_none());
            assert!(importer.resolve("pdb_mix").is_err());
            assert_eq!(importer.undo().unwrap().len(), 1);
            assert!(importer.annotation_list().names.is_empty());
        }
    }

    #[test]
    fn clearing_all_preview_preserved_pairs_keeps_an_empty_approval_empty_and_adds_no_undo_step() {
        let files = TempFiles::new();
        let log = files.write("empty-approval.rampage", b"");
        let importer = logged(&log);
        let writer = logged(&log);
        writer.rename(MIX, Some("keep_mix")).unwrap();
        writer.rename(OTHER, Some("pdb_local")).unwrap();
        importer.refresh_annotations().unwrap();
        importer.comment(MIX, Some("earlier step")).unwrap();
        let receipt = importer.preview_pdb_names(&fixture("fixture.pdb")).unwrap();
        assert!(receipt.approved().is_empty());
        writer.rename(MIX, None).unwrap();
        writer.rename(OTHER, None).unwrap();
        let before = std::fs::read(&log).unwrap();
        let imported = importer.apply_pdb_names(&receipt).unwrap();
        assert!(imported.applied.is_empty());
        assert_eq!(std::fs::read(&log).unwrap(), before);
        assert!(importer.annotation_list().names.is_empty());
        assert_eq!(importer.undo().unwrap()[0].value.as_deref(), Some("earlier step"));
        assert!(importer.undo().unwrap().is_empty());
    }

    #[test]
    fn selected_embedded_pe_uses_its_own_digest_and_original_outer_mapping() {
        let files = TempFiles::new();
        let image = std::fs::read(fixture("fixture.exe")).unwrap();
        let mut outer = vec![b'x'; 1001];
        outer.extend_from_slice(&image);
        let second_offset = outer.len() as u64;
        outer.extend_from_slice(&image);
        outer.extend_from_slice(b"outer trailing bytes");
        let path = files.write("embedded.bin", &outer);
        let log = files.write("embedded.rampage", b"");
        let importer = Project::with_annotations(
            Binary::open_at(&path, 1001, Some(image.len() as u64)).unwrap(),
            Annotations::open(log.clone()).unwrap(),
        );
        let receipt: PdbPreview<'_> = importer.preview_pdb_names(&fixture("fixture.pdb")).unwrap();
        assert_eq!(
            rampage_arch::hex::bytes(receipt.image_sha256()),
            "81f277669933189213eb1b4f04ace20115a8714d4153af053f5d9d75a7889495"
        );
        let other = Project::new(Binary::open_at(&path, second_offset, Some(image.len() as u64)).unwrap());
        assert!(other.apply_pdb_names(&receipt).is_err());
        assert_eq!(importer.apply_pdb_names(&receipt).unwrap().applied, [MIX, LOCAL]);
        assert_eq!(importer.undo().unwrap().len(), 2);
        seed_history(&importer);
        std::fs::rename(files.write("same-outer.bin", &outer), &path).unwrap();
        assert_unchanged_rejection(&importer, &log, || importer.apply_pdb_names(&receipt));
    }
}

#[test]
fn checked_preview_refuses_an_owned_input_without_original_backing_identity() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let error = project.preview_pdb_names(&fixture("fixture.pdb")).unwrap_err();
    assert!(error.to_string().contains("no mapped-file identity"), "{error}");
    assert!(project.annotation_list().names.is_empty());
    assert!(project.undo().unwrap().is_empty());
}

#[cfg(not(unix))]
#[test]
fn checked_preview_refuses_a_mapped_input_when_the_host_cannot_supply_original_backing_identity() {
    let project = project();
    let error = project.preview_pdb_names(&fixture("fixture.pdb")).unwrap_err();
    assert!(error.to_string().contains("identity unavailable"), "{error}");
    assert!(project.annotation_list().names.is_empty());
    assert!(project.undo().unwrap().is_empty());
}
