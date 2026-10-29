#![cfg(unix)]

use std::fs::{DirBuilder, File};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{
    DebuggerCapturePublicationStatus, Project, ProjectWorkspaceManifest, ProjectWorkspaceModuleInput,
    ProjectWorkspaceNavigation, ProjectWorkspacePhase, ProjectWorkspaceTaskControl, QualifiedProjectAddress, Session,
    capture_project_workspace, capture_project_workspace_controlled, capture_project_workspace_with_session,
    preview_project_workspace, preview_project_workspace_controlled, publish_project_workspace,
    publish_project_workspace_controlled,
};
use rampage_arch::Arch;
use rampage_decompiler::{DecompilerOptions, Platform};
use rampage_loaders::{Binary, ImageAt};
use serde_json::{Value, json};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "project-workspace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn ordinary(&self, name: &str, id: &str) -> ProjectWorkspaceModuleInput {
        let source_path = self.join(name);
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/decode-x64.elf");
        std::fs::copy(fixture, &source_path).unwrap();
        let project = Arc::new(Project::new(Binary::open(&source_path).unwrap()));
        ProjectWorkspaceModuleInput {
            id: id.to_owned(),
            label: "模块 / Módulo".to_owned(),
            source_path,
            image: None,
            project,
            navigation: navigation(id, 0x1000),
        }
    }

    fn snapshot(&self, name: &str, id: &str, provenance: &str, register: &str) -> ProjectWorkspaceModuleInput {
        let source_path = self.join(name);
        let document = json!({
            "format": "rampage-snapshot-v1", "arch": "x86_64", "provenance": provenance,
            "regions": [{"name": "code", "address": "0x1000", "permissions": "r-x", "bytes": "90c3"}],
            "entry": "0x1000", "registers": [{"thread_id": "0x1", "name": "rax", "value": register}],
        });
        std::fs::write(&source_path, serde_json::to_vec(&document).unwrap()).unwrap();
        let project = Arc::new(Project::new(Binary::open(&source_path).unwrap()));
        ProjectWorkspaceModuleInput {
            id: id.to_owned(),
            label: name.to_owned(),
            source_path,
            image: None,
            project,
            navigation: navigation(id, 0x1000),
        }
    }

    fn manifest_path(&self, manifest: &ProjectWorkspaceManifest) -> PathBuf {
        let path = self.join("workspace.json");
        std::fs::write(&path, serde_json::to_vec(manifest).unwrap()).unwrap();
        path
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn navigation(id: &str, address: u64) -> ProjectWorkspaceNavigation {
    ProjectWorkspaceNavigation {
        current: Some(QualifiedProjectAddress { module_id: id.to_owned(), address }),
        back: vec![QualifiedProjectAddress { module_id: id.to_owned(), address: address + 1 }],
        forward: Vec::new(),
    }
}

#[test]
fn capture_refuses_a_legacy_snapshot_that_cannot_be_restored_under_checked_source_limits() {
    let directory = Directory::new();
    let mut input = directory.snapshot("oversized-seeds.json", "snapshot", "owned raw-profile fixture", "0x1");
    let mut document: Value = serde_json::from_slice(&std::fs::read(&input.source_path).unwrap()).unwrap();
    document["seeds"] = json!(vec!["0x1000"; 4097]);
    std::fs::write(&input.source_path, serde_json::to_vec(&document).unwrap()).unwrap();
    input.project = Arc::new(Project::new(Binary::open(&input.source_path).unwrap()));
    let error = capture_project_workspace(&[input], "snapshot").unwrap_err().to_string();
    assert!(error.contains("raw structural or text budget"), "{error}");
    assert!(!directory.join("workspace.json").exists());
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn controlled_preview_cancels_before_opening_and_revalidates_observer_changes_before_returning() {
    use std::sync::atomic::AtomicBool;
    let directory = Directory::new();
    let cancellation = AtomicBool::new(true);
    let mut observer = |_| panic!("pre-cancelled preview must not notify or access a file");
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    let error = preview_project_workspace_controlled(&directory.join("missing.json"), &mut control).unwrap_err();
    assert!(error.to_string().contains("cancellation"));
    let input = directory.ordinary("owned.elf", "owned");
    let manifest = capture_project_workspace(&[input], "owned").unwrap();
    let path = directory.manifest_path(&manifest);
    let cancellation = AtomicBool::new(false);
    let mut phases = Vec::new();
    let mut observer = |event: rampage_api::ProjectWorkspaceProgress| {
        phases.push(event.phase);
        if event.phase == ProjectWorkspacePhase::ResultValidation {
            std::fs::write(&path, b"replaced manifest").unwrap();
        }
    };
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    assert!(preview_project_workspace_controlled(&path, &mut control).is_err());
    assert_eq!(phases, vec![ProjectWorkspacePhase::ReadingManifest, ProjectWorkspacePhase::ResultValidation]);
}

#[test]
fn controlled_capture_rejects_callback_truncation_and_annotation_aba_without_native_or_program_work() {
    use std::sync::atomic::AtomicBool;
    let directory = Directory::new();
    let input = directory.ordinary("owned.elf", "owned");
    let cancellation = AtomicBool::new(false);
    let mut observer = |event: rampage_api::ProjectWorkspaceProgress| {
        if event.phase == ProjectWorkspacePhase::ValidatingIdentity {
            std::fs::write(&input.source_path, b"truncated owned source").unwrap();
        }
    };
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    assert!(
        capture_project_workspace_controlled(std::slice::from_ref(&input), "owned", &Session::default(), &mut control)
            .is_err()
    );
    let input = directory.ordinary("other.elf", "other");
    let original = input.project.annotation_revision().unwrap();
    let mut observer = |event: rampage_api::ProjectWorkspaceProgress| {
        if event.phase == ProjectWorkspacePhase::ReadingAnnotations {
            input.project.comment(0x1000, Some("transient annotation")).unwrap();
            input.project.comment(0x1000, None).unwrap();
        }
    };
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    let error =
        capture_project_workspace_controlled(std::slice::from_ref(&input), "other", &Session::default(), &mut control)
            .unwrap_err()
            .to_string();
    assert!(error.contains("annotations changed"), "{error}");
    assert!(!Arc::ptr_eq(&original, &input.project.annotation_revision().unwrap()));
    assert_eq!(input.project.analysis_cache_status(), Default::default());
}

#[test]
fn loaded_metadata_validation_checks_original_sources_and_settings_without_initializing_analysis() {
    let directory = Directory::new();
    let input = directory.ordinary("owned.elf", "owned");
    let manifest = capture_project_workspace(&[input], "owned").unwrap();
    let path = directory.manifest_path(&manifest);
    let preview = preview_project_workspace(&path).unwrap();
    preview.validate_metadata().unwrap();
    let loaded = preview.open_reviewed(&Session::default()).unwrap();
    loaded.validate_metadata().unwrap();
    assert_eq!(loaded.modules()[0].project().analysis_cache_status(), Default::default());
    loaded.modules()[0].project().set_decompiler_options(None);
    assert!(loaded.validate_metadata().is_err(), "configuration identity change must revoke adoption");
}

#[test]
fn publication_cancellation_before_stage_writes_nothing_and_after_commit_keeps_actual_outcome() {
    use std::sync::atomic::AtomicBool;
    let directory = Directory::new();
    let input = directory.ordinary("owned.elf", "owned");
    let manifest = capture_project_workspace(&[input], "owned").unwrap();
    let output = directory.join("cancelled-workspace.json");
    let cancellation = AtomicBool::new(false);
    let mut observer = |event: rampage_api::ProjectWorkspaceProgress| {
        if event.phase == ProjectWorkspacePhase::Publishing {
            cancellation.store(true, Ordering::Relaxed);
        }
    };
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    assert!(publish_project_workspace_controlled(&manifest, &output, &mut control).is_err());
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    assert!(!output.exists());
    cancellation.store(false, Ordering::Relaxed);
    let mut observer = |event: rampage_api::ProjectWorkspaceProgress| {
        if event.phase == ProjectWorkspacePhase::ResultValidation {
            cancellation.store(true, Ordering::Relaxed);
        }
    };
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    let published = publish_project_workspace_controlled(&manifest, &output, &mut control).unwrap();
    assert_eq!(published.status, DebuggerCapturePublicationStatus::PublishedUncertain);
    assert_eq!(published.path, output);
    assert!(published.path.is_file());
    assert!(!published.retained_staging_paths.is_empty());
    assert!(published.warnings.iter().any(|warning| warning.contains("cancellation")));
}

#[test]
fn cancellation_after_real_staging_before_link_retains_exact_private_resources_without_a_destination() {
    use std::sync::atomic::AtomicBool;
    let directory = Directory::new();
    let input = directory.ordinary("owned.elf", "owned");
    let manifest = capture_project_workspace(&[input], "owned").unwrap();
    let output = directory.join("never-linked.json");
    let cancellation = AtomicBool::new(false);
    let mut staged = false;
    let mut observer = |event: rampage_api::ProjectWorkspaceProgress| {
        if event.phase == ProjectWorkspacePhase::PublicationStaged {
            staged = true;
            cancellation.store(true, Ordering::Relaxed);
        }
    };
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    let error = publish_project_workspace_controlled(&manifest, &output, &mut control).unwrap_err();
    assert!(staged);
    assert!(!output.exists());
    let rampage_api::ApiError::DebuggerCaptureStagingRetained(retained) = error else {
        panic!("real pre-link cancellation must preserve typed staging paths");
    };
    assert_eq!(retained.paths.len(), 1);
    assert!(retained.message.contains("cancellation"));
    assert_eq!(retained.paths[0].parent(), Some(directory.0.as_path()));
    let bytes = std::fs::read(&retained.paths[0]).unwrap();
    let staged_manifest: ProjectWorkspaceManifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(staged_manifest, manifest);
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 2);
}

fn write_value(directory: &Directory, value: &Value) -> PathBuf {
    let path = directory.join("edited.json");
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

#[test]
fn preview_never_resolves_or_opens_module_paths_and_cancel_has_no_side_effects() {
    let directory = Directory::new();
    let input = directory.ordinary("module", "opaque-a");
    let manifest = capture_project_workspace(&[input], "opaque-a").unwrap();
    let mut value = serde_json::to_value(manifest).unwrap();
    for hostile in ["/dev/zero", "/dev/null", "/no/such/module", directory.0.to_str().unwrap()] {
        value["modules"][0]["source_path"] = json!(hostile);
        let path = write_value(&directory, &value);
        let preview = preview_project_workspace(&path).unwrap();
        assert_eq!(preview.manifest().modules[0].source_path, Path::new(hostile));
        assert!(preview.annotation_review().contains("bounded checked"));
        drop(preview);
    }
    assert!(!directory.join("module.rampage").exists());
    assert!(!directory.join("module.rampage.lock").exists());
}

#[test]
fn strict_wire_rejects_unknown_duplicate_nested_and_oversized_documents() {
    let directory = Directory::new();
    let input = directory.ordinary("module", "a");
    let manifest = capture_project_workspace(&[input], "a").unwrap();
    let bytes = serde_json::to_string(&manifest).unwrap();
    let path = directory.join("bad.json");
    let malformed = [
        bytes.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        bytes.replacen("\"label\":", "\"surprise\":true,\"label\":", 1),
        bytes.replacen("\"id\":\"a\"", "\"id\":\"a\",\"id\":\"a\"", 1),
        format!("{}0{}", "[".repeat(9), "]".repeat(9)),
        " ".repeat(256 * 1024 + 1),
        "[0,".repeat(20000),
    ];
    for document in malformed {
        std::fs::write(&path, document).unwrap();
        assert!(preview_project_workspace(&path).is_err());
    }
    std::fs::write(&path, [0xff]).unwrap();
    assert!(preview_project_workspace(&path).is_err());
}

#[test]
fn preview_limits_ids_labels_navigation_paths_and_versions_without_source_access() {
    let directory = Directory::new();
    let input = directory.ordinary("module", "a");
    let manifest = capture_project_workspace(&[input], "a").unwrap();
    let base = serde_json::to_value(manifest).unwrap();
    let changes = [
        ("/version", json!(2)),
        ("/annotation_policy", json!("arbitrary_log_paths")),
        ("/active_module_id", json!("missing")),
        ("/modules/0/id", json!("ü")),
        ("/modules/0/id", json!("x".repeat(65))),
        ("/modules/0/label", json!("é".repeat(129))),
        ("/modules/0/source_path", json!("relative")),
        ("/modules/0/source_path", json!("/a/../b")),
        ("/modules/0/source_path", json!("/a/./b")),
        ("/modules/0/source_path", json!("/a//b")),
        ("/modules/0/source_path", json!(format!("/{}", "x".repeat(4096)))),
        ("/modules/0/navigation/current/module_id", json!("different")),
        ("/modules/0/navigation/back", json!(vec![json!({"module_id": "a", "address": "0x1"}); 257])),
    ];
    for (pointer, replacement) in changes {
        let mut value = base.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(preview_project_workspace(&write_value(&directory, &value)).is_err(), "{pointer}");
    }
    let mut duplicate = base.clone();
    duplicate["modules"] = json!([base["modules"][0], base["modules"][0]]);
    assert!(preview_project_workspace(&write_value(&directory, &duplicate)).is_err());
}

#[test]
fn identical_bytes_and_same_addresses_remain_independent_by_opaque_id_and_source_path() {
    let directory = Directory::new();
    let a = directory.ordinary("same-a", "opaque-a");
    let mut b = directory.ordinary("same-b", "opaque-b");
    b.label = a.label.clone();
    let manifest = capture_project_workspace(&[a, b], "opaque-b").unwrap();
    assert_eq!(manifest.modules[0].identity, manifest.modules[1].identity);
    let preview = preview_project_workspace(&directory.manifest_path(&manifest)).unwrap();
    let loaded = preview.open_reviewed(&Session::default()).unwrap();
    loaded.validate().unwrap();
    assert!(!Arc::ptr_eq(loaded.modules()[0].project(), loaded.modules()[1].project()));
    assert_eq!(loaded.active_module_id(), "opaque-b");
    assert_eq!(loaded.modules()[0].module().navigation.current.as_ref().unwrap().module_id, "opaque-a");
    assert_eq!(loaded.modules()[1].module().navigation.current.as_ref().unwrap().module_id, "opaque-b");
    let retained = Arc::clone(loaded.modules()[0].project());
    loaded.validate().unwrap();
    assert!(Arc::ptr_eq(&retained, loaded.modules()[0].project()));
    assert!(!directory.join("same-a.rampage").exists());
    assert!(!directory.join("same-b.rampage").exists());
}

#[test]
fn canonical_source_alias_is_refused_instead_of_implicitly_merged() {
    let directory = Directory::new();
    let a = directory.ordinary("module", "a");
    let b = ProjectWorkspaceModuleInput {
        id: "b".into(),
        label: "Other label".into(),
        source_path: a.source_path.clone(),
        image: None,
        project: Arc::clone(&a.project),
        navigation: navigation("b", 0x1000),
    };
    assert!(capture_project_workspace(&[a, b], "a").is_err());
}

#[test]
fn snapshot_registers_and_provenance_change_exact_document_not_capture_identity() {
    let directory = Directory::new();
    let a = directory.snapshot("a.json", "a", "first", "0x1");
    let b = directory.snapshot("b.json", "b", "other", "0x2");
    let manifest = capture_project_workspace(&[a, b], "a").unwrap();
    let a = &manifest.modules[0].identity;
    let b = &manifest.modules[1].identity;
    assert_eq!(a.capture_identity, b.capture_identity);
    assert_eq!(a.image_sha256, b.image_sha256);
    assert_ne!(a.snapshot_document_sha256, b.snapshot_document_sha256);
    assert_ne!(a.source_sha256, b.source_sha256);
    let mut changed = serde_json::to_value(&manifest).unwrap();
    changed["modules"][0]["identity"]["snapshot_document_sha256"] = json!("0".repeat(64));
    assert!(preview_project_workspace(&write_value(&directory, &changed)).is_err());
}

#[test]
fn reviewed_manifest_replacement_and_late_source_replacement_are_refused() {
    let directory = Directory::new();
    let input = directory.ordinary("module", "a");
    let source_path = input.source_path.clone();
    let manifest = capture_project_workspace(&[input], "a").unwrap();
    let path = directory.manifest_path(&manifest);
    let preview = preview_project_workspace(&path).unwrap();
    let replacement = directory.join("replacement.json");
    std::fs::write(&replacement, serde_json::to_vec(&manifest).unwrap()).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    assert!(preview.open_reviewed(&Session::default()).is_err());
    let preview = preview_project_workspace(&path).unwrap();
    std::fs::copy(&source_path, directory.join("new-source")).unwrap();
    std::fs::rename(directory.join("new-source"), &source_path).unwrap();
    // A replacement before explicit approval is allowed only when exact content and selected identity still match.
    let loaded = preview.open_reviewed(&Session::default()).unwrap();
    std::fs::copy(&source_path, directory.join("next-source")).unwrap();
    std::fs::rename(directory.join("next-source"), &source_path).unwrap();
    assert!(loaded.validate().is_err());
}

#[test]
fn owned_snapshot_keeps_original_source_descriptor_until_adoption() {
    let directory = Directory::new();
    let input = directory.snapshot("capture.json", "capture", "original", "0x1");
    let path = input.source_path.clone();
    let manifest = capture_project_workspace(&[input], "capture").unwrap();
    let loaded = preview_project_workspace(&directory.manifest_path(&manifest))
        .unwrap()
        .open_reviewed(&Session::default())
        .unwrap();
    let retained = Arc::clone(loaded.modules()[0].project());
    let document = retained.binary.file_bytes().to_vec();
    assert!(!retained.binary.validate_available_backing_source().unwrap());
    std::fs::copy(&path, directory.join("identical-copy.json")).unwrap();
    std::fs::rename(directory.join("identical-copy.json"), &path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), document);
    assert!(loaded.validate().is_err());
    assert!(Arc::ptr_eq(&retained, loaded.modules()[0].project()));
    assert_eq!(retained.binary.file_bytes(), document.as_slice());
}

#[test]
fn qualified_addresses_are_exact_hex_strings_above_javascript_precision_and_at_u64_max() {
    let directory = Directory::new();
    let mut input = directory.ordinary("module", "a");
    input.navigation = navigation("a", (1u64 << 53) + 1);
    input.navigation.forward.push(QualifiedProjectAddress { module_id: "a".into(), address: u64::MAX });
    let manifest = capture_project_workspace(&[input], "a").unwrap();
    let path = directory.manifest_path(&manifest);
    let document: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(document["modules"][0]["navigation"]["current"]["address"], "0x20000000000001");
    assert_eq!(document["modules"][0]["navigation"]["forward"][0]["address"], "0xffffffffffffffff");
    let preview = preview_project_workspace(&path).unwrap();
    let navigation = &preview.manifest().modules[0].navigation;
    assert_eq!(navigation.current.as_ref().unwrap().address, (1u64 << 53) + 1);
    assert_eq!(navigation.forward[0].address, u64::MAX);
    for address in [
        json!(9007199254740993u64),
        json!(-1),
        json!(false),
        Value::Null,
        json!([]),
        json!("0x10000000000000000"),
        json!("0x"),
        json!("0x01"),
        json!("0xF"),
        json!("-0x1"),
    ] {
        let mut malformed = document.clone();
        malformed["modules"][0]["navigation"]["current"]["address"] = address;
        assert!(preview_project_workspace(&write_value(&directory, &malformed)).is_err());
    }
}

#[test]
fn source_size_preflight_precedes_mapping_and_hashing_for_every_module() {
    let directory = Directory::new();
    let a = directory.ordinary("a", "a");
    let b = directory.ordinary("b", "b");
    let source_b = b.source_path.clone();
    let manifest = capture_project_workspace(&[a, b], "a").unwrap();
    let path = directory.manifest_path(&manifest);
    let preview = preview_project_workspace(&path).unwrap();
    let replacement = directory.join("oversized");
    File::create(&replacement).unwrap().set_len(128 * 1024 * 1024 + 1).unwrap();
    std::fs::rename(replacement, source_b).unwrap();
    assert!(preview.open_reviewed(&Session::default()).is_err());
    assert!(!directory.join("a.rampage").exists());
}

#[test]
fn aggregate_actual_source_sizes_are_preflighted_before_reading_any_stale_mapping() {
    let directory = Directory::new();
    let inputs = [directory.ordinary("a", "a"), directory.ordinary("b", "b"), directory.ordinary("c", "c")];
    for input in &inputs {
        let replacement = input.source_path.with_extension("sparse");
        File::create(&replacement).unwrap().set_len(90 * 1024 * 1024).unwrap();
        std::fs::rename(replacement, &input.source_path).unwrap();
    }
    let error = capture_project_workspace(&inputs, "a").unwrap_err();
    assert!(error.to_string().contains("aggregate source budget"));
    for input in &inputs {
        assert!(input.project.binary.validate_backing_source().is_err());
        assert!(!input.source_path.with_extension("rampage").exists());
    }
}

#[test]
fn stale_ordinary_session_cache_cannot_bypass_manifest_hashes() {
    let directory = Directory::new();
    let input = directory.ordinary("module", "a");
    let path = input.source_path.clone();
    let session = Session::default();
    let existing = session.open(&path, None).unwrap();
    let manifest = capture_project_workspace(&[input], "a").unwrap();
    let preview = preview_project_workspace(&directory.manifest_path(&manifest)).unwrap();
    let replacement = directory.join("changed");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0);
    std::fs::write(&replacement, bytes).unwrap();
    std::fs::rename(replacement, &path).unwrap();
    assert!(preview.open_reviewed(&session).is_err());
    assert!(existing.binary.validate_backing_source().is_err());
    assert!(!directory.join("module.rampage").exists());
}

#[test]
fn annotations_are_replayed_and_remain_persistent_in_the_returned_project() {
    let directory = Directory::new();
    let mut input = directory.ordinary("module", "a");
    let path = input.source_path.clone();
    let writer = Session::default().open(&path, None).unwrap();
    writer.comment(0x1000, Some("existing analyst evidence")).unwrap();
    input.project = writer;
    let manifest = capture_project_workspace(&[input], "a").unwrap();
    let log = directory.join("module.rampage");
    let before = std::fs::read(&log).unwrap();
    let loaded = preview_project_workspace(&directory.manifest_path(&manifest))
        .unwrap()
        .open_reviewed(&Session::default())
        .unwrap();
    let project = loaded.modules()[0].project();
    assert_eq!(project.comment_at(0x1000).as_deref(), Some("existing analyst evidence"));
    assert_eq!(std::fs::read(&log).unwrap(), before);
    project.comment(0x1000, Some("persisted after restore")).unwrap();
    project.undo().unwrap();
    assert_eq!(project.comment_at(0x1000).as_deref(), Some("existing analyst evidence"));
    let reopened = Session::default().open(&path, None).unwrap();
    assert_eq!(reopened.comment_at(0x1000).as_deref(), Some("existing analyst evidence"));
}

#[test]
fn checked_log_refuses_oversized_or_symlinked_logs_without_writes() {
    let directory = Directory::new();
    let input = directory.ordinary("module", "a");
    let manifest = capture_project_workspace(&[input], "a").unwrap();
    let preview = preview_project_workspace(&directory.manifest_path(&manifest)).unwrap();
    let log = directory.join("module.rampage");
    File::create(&log).unwrap().set_len(16 * 1024 * 1024 + 1).unwrap();
    assert!(preview.open_reviewed(&Session::default()).is_err());
    assert_eq!(std::fs::metadata(&log).unwrap().len(), 16 * 1024 * 1024 + 1);
    std::fs::remove_file(&log).unwrap();
    for malformed in
        [format!("{}\n", " ".repeat(2 * 1024 * 1024 + 1)), format!("{}0{}\n", "[".repeat(9), "]".repeat(9))]
    {
        std::fs::write(&log, &malformed).unwrap();
        assert!(preview.open_reviewed(&Session::default()).is_err());
        assert_eq!(std::fs::read(&log).unwrap(), malformed.as_bytes());
    }
    std::fs::remove_file(&log).unwrap();
    symlink("/dev/zero", &log).unwrap();
    assert!(preview.open_reviewed(&Session::default()).is_err());
    assert!(std::fs::symlink_metadata(&log).unwrap().file_type().is_symlink());
}

#[test]
fn failed_second_module_does_not_write_first_annotation_log_or_change_existing_project() {
    let directory = Directory::new();
    let mut a = directory.ordinary("a", "a");
    let b = directory.ordinary("b", "b");
    let session = Session::default();
    let existing = session.open(&a.source_path, None).unwrap();
    existing.comment(0x1000, Some("keep this bank")).unwrap();
    a.project = Arc::clone(&existing);
    let manifest = capture_project_workspace(&[a, b], "a").unwrap();
    let first_log = directory.join("a.rampage");
    let before = std::fs::read(&first_log).unwrap();
    std::fs::write(directory.join("b.rampage"), "not valid annotation JSON\n").unwrap();
    let preview = preview_project_workspace(&directory.manifest_path(&manifest)).unwrap();
    assert!(preview.open_reviewed(&session).is_err());
    assert_eq!(std::fs::read(&first_log).unwrap(), before);
    assert_eq!(existing.comment_at(0x1000).as_deref(), Some("keep this bank"));
    assert!(Arc::ptr_eq(&existing, &session.open(&directory.join("a"), None).unwrap()));
}

#[test]
fn configured_options_restore_without_analysis_and_auto_remains_distinct() {
    let directory = Directory::new();
    let a = directory.ordinary("a", "a");
    let b = directory.ordinary("b", "b");
    a.project.set_decompiler_options(Some(DecompilerOptions {
        platform: Platform::Windows,
        compiler: Some("windows".into()),
        arm_be8: false,
    }));
    let manifest = capture_project_workspace(&[a, b], "a").unwrap();
    assert!(manifest.modules[0].options.is_some());
    assert!(manifest.modules[1].options.is_none());
    let loaded = preview_project_workspace(&directory.manifest_path(&manifest))
        .unwrap()
        .open_reviewed(&Session::default())
        .unwrap();
    let options = loaded.modules()[0].project().configured_decompiler_options().unwrap().unwrap();
    assert_eq!(options.platform, Platform::Windows);
    assert_eq!(options.compiler.as_deref(), Some("windows"));
    assert!(loaded.modules()[1].project().configured_decompiler_options().unwrap().is_none());
    loaded.modules()[0].project().set_decompiler_options(Some(options));
    assert!(loaded.validate().is_err());
}

#[test]
fn in_memory_edits_and_unrecognized_annotation_paths_are_not_silently_discarded() {
    let directory = Directory::new();
    let input = directory.ordinary("module", "a");
    input.project.comment(0x1000, Some("not saved to a sidecar")).unwrap();
    assert!(capture_project_workspace(&[input], "a").is_err());
    let mut input = directory.ordinary("second", "b");
    let annotations = rampage_api::annotations::Annotations::open_checked(directory.join("custom.jsonl")).unwrap();
    input.project = Arc::new(Project::with_annotations(Binary::open(&input.source_path).unwrap(), annotations));
    input.project.comment(0x1000, Some("not in the recognized sidecar")).unwrap();
    assert!(capture_project_workspace(&[input], "b").is_err());
}

#[test]
fn ledger_entries_alone_count_as_analyst_state_when_saving() {
    let directory = Directory::new();
    let ledger = |text: &str| rampage_api::LedgerRequest {
        kind: Some(rampage_api::LedgerKind::Finding),
        text: Some(text.to_owned()),
        ..rampage_api::LedgerRequest::default()
    };
    let input = directory.ordinary("module", "a");
    input.project.record_finding(&ledger("only in memory")).unwrap();
    assert!(capture_project_workspace(&[input], "a").is_err());

    let mut input = directory.ordinary("second", "b");
    let writer = Session::default().open(&input.source_path, None).unwrap();
    writer.record_finding(&ledger("saved beside the binary")).unwrap();
    input.project = writer;
    let manifest = capture_project_workspace(&[input], "b").unwrap();
    let loaded = preview_project_workspace(&directory.manifest_path(&manifest))
        .unwrap()
        .open_reviewed(&Session::default())
        .unwrap();
    let list = loaded.modules()[0].project().list_findings(&rampage_api::LedgerQuery::default()).unwrap();
    assert_eq!(list.findings.iter().map(|entry| entry.text.as_str()).collect::<Vec<_>>(), ["saved beside the binary"]);
}

#[test]
fn fresh_restore_keeps_current_capture_annotation_directory_and_data_packs() {
    let directory = Directory::new();
    let mut input = directory.snapshot("capture.json", "capture", "capture", "0x1");
    let logs = directory.join("logs");
    DirBuilder::new().mode(0o700).create(&logs).unwrap();
    let session = Session::with_capture_annotations(logs.clone());
    input.project = session.open(&input.source_path, None).unwrap();
    input.project.comment(0x1000, Some("capture analyst state")).unwrap();
    let manifest = capture_project_workspace_with_session(&[input], "capture", &session).unwrap();
    let loaded =
        preview_project_workspace(&directory.manifest_path(&manifest)).unwrap().open_reviewed(&session).unwrap();
    assert_eq!(loaded.session().capture_annotations(), Some(logs.as_path()));
    assert!(Arc::ptr_eq(&session.packs(), &loaded.session().packs()));
    assert!(Arc::ptr_eq(&session.packs(), &loaded.modules()[0].project().packs()));
    assert_eq!(loaded.modules()[0].project().comment_at(0x1000).as_deref(), Some("capture analyst state"));
    let preview = preview_project_workspace(&directory.manifest_path(&manifest)).unwrap();
    assert!(preview.open_reviewed(&Session::default()).is_err());
    let other_logs = directory.join("other-logs");
    DirBuilder::new().mode(0o700).create(&other_logs).unwrap();
    let changed_settings = Session::with_capture_annotations(other_logs);
    assert!(preview.open_reviewed(&changed_settings).is_err());
    std::fs::rename(&logs, directory.join("original-logs")).unwrap();
    DirBuilder::new().mode(0o700).create(&logs).unwrap();
    assert!(preview.open_reviewed(&session).is_err());
    assert!(loaded.validate().is_err());
}

#[test]
fn snapshot_log_basename_in_an_unrelated_parent_does_not_prove_recognized_persistence() {
    let directory = Directory::new();
    let mut input = directory.snapshot("capture.json", "capture", "capture", "0x1");
    let identity = rampage_analysis::capture_identity::capture_identity(&input.project.binary).unwrap();
    let configured = directory.join("configured");
    let unrelated = directory.join("unrelated");
    DirBuilder::new().mode(0o700).create(&configured).unwrap();
    DirBuilder::new().mode(0o700).create(&unrelated).unwrap();
    let forged_log = unrelated.join(format!(".{}-{}.jsonl", identity.schema, identity.sha256));
    let annotations = rampage_api::annotations::Annotations::open_checked(forged_log).unwrap();
    input.project = Arc::new(Project::with_annotations(Binary::open(&input.source_path).unwrap(), annotations));
    input.project.comment(0x1000, Some("analyst edits in the wrong directory")).unwrap();
    let session = Session::with_capture_annotations(configured);
    assert!(capture_project_workspace_with_session(std::slice::from_ref(&input), "capture", &session).is_err());
    assert!(capture_project_workspace(&[input], "capture").is_err());
}

#[test]
fn embedded_selector_is_retained_and_not_conflated_with_whole_source() {
    let directory = Directory::new();
    let thin = directory.ordinary("thin", "thin");
    let thin_bytes = std::fs::read(&thin.source_path).unwrap();
    let source_path = directory.join("container");
    let mut bytes = vec![0u8; 4096];
    bytes.extend_from_slice(&thin_bytes);
    std::fs::write(&source_path, bytes).unwrap();
    let image = ImageAt::new(4096, Some(thin_bytes.len() as u64));
    let binary = Binary::open_image(&source_path, Some(image), Some(Arch::X86_64)).unwrap();
    let input = ProjectWorkspaceModuleInput {
        id: "embedded".into(),
        label: "Embedded".into(),
        source_path,
        image: Some(image),
        project: Arc::new(Project::new(binary)),
        navigation: navigation("embedded", 0x1000),
    };
    let manifest = capture_project_workspace(&[input], "embedded").unwrap();
    assert_ne!(manifest.modules[0].identity.source_sha256, manifest.modules[0].identity.image_sha256);
    let loaded = preview_project_workspace(&directory.manifest_path(&manifest))
        .unwrap()
        .open_reviewed(&Session::default())
        .unwrap();
    assert_eq!(loaded.modules()[0].project().binary.embedded.unwrap().offset, 4096);
}

#[test]
fn publication_is_private_no_clobber_and_revalidates_sources() {
    let directory = Directory::new();
    let input = directory.ordinary("module", "a");
    let manifest = capture_project_workspace(&[input], "a").unwrap();
    let path = directory.join("saved.json");
    let publication = publish_project_workspace(&manifest, &path).unwrap();
    assert_eq!(publication.status, DebuggerCapturePublicationStatus::Published);
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    let before = std::fs::read(&path).unwrap();
    assert!(publish_project_workspace(&manifest, &path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let preview = preview_project_workspace(&path).unwrap();
    assert_eq!(preview.document_sha256(), publication.document_sha256);
    std::fs::write(directory.join("replacement"), b"changed").unwrap();
    std::fs::rename(directory.join("replacement"), directory.join("module")).unwrap();
    assert!(publish_project_workspace(&manifest, &directory.join("another.json")).is_err());
    assert!(!directory.join("another.json").exists());
}

#[test]
fn directory_and_symlink_sources_are_not_resolved_as_bundles_on_approval() {
    let directory = Directory::new();
    let input = directory.ordinary("module", "a");
    let manifest = capture_project_workspace(&[input], "a").unwrap();
    let mut value = serde_json::to_value(&manifest).unwrap();
    symlink(directory.join("module"), directory.join("alias")).unwrap();
    for source in [directory.0.clone(), directory.join("alias"), PathBuf::from("/dev/zero")] {
        value["modules"][0]["source_path"] = json!(source);
        let preview = preview_project_workspace(&write_value(&directory, &value)).unwrap();
        assert!(preview.open_reviewed(&Session::default()).is_err());
    }
}
