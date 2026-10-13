use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_analysis::capture_identity::capture_identity;
use rampage_api::{ApiError, Project, Session};
use rampage_arch::Arch;
use rampage_loaders::{Binary, Format};
use serde_json::{Value, json};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-capture-session-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, snapshot: &Value) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, serde_json::to_vec(snapshot).unwrap()).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn snapshot() -> Value {
    json!({
        "format": "rampage-snapshot-v1",
        "arch": "aarch64",
        "provenance": "first controlled capture",
        "regions": [
            {"name": "code", "address": "0x1000", "permissions": "r-x", "bytes": "c0035fd61f2003d5"},
            {"name": "data", "address": "0x2000", "permissions": "rw-", "bytes": "0010000000000000"}
        ],
        "seeds": ["0x1000"],
        "entry": "0x1000",
        "modules": [{
            "name": "fixture", "path": "/not/opened/fixture", "uuid": "0123456789abcdef0123456789abcdef",
            "image_base": "0x0", "runtime_base": "0x1000"
        }],
        "registers": [{"thread_id": "0x1", "name": "pc", "value": "0x1000"}],
        "target": {"platform": "default", "compiler": "gcc"}
    })
}

fn identity(project: &Project) -> String {
    capture_identity(&project.binary).unwrap().sha256
}

fn sidecar(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".rampage");
    PathBuf::from(name)
}

#[test]
fn changed_capture_identity_never_reuses_a_project_or_its_annotations() {
    for change in [
        "bytes",
        "permissions",
        "address",
        "endianness",
        "instruction-endianness",
        "target",
        "compiler",
        "target-absence",
        "seeds",
        "entry",
        "module",
        "module-identity",
        "thumb",
    ] {
        let scratch = Scratch::new(change);
        let mut original = snapshot();
        if change == "thumb" {
            original["arch"] = json!("arm");
            original["regions"][0]["bytes"] = json!("1eff2fe11eff2fe1");
        }
        let path = scratch.write("capture.json", &original);
        let session = Session::default();
        let first = session.open(&path, None).unwrap();
        first.rename(0x1000, Some("first_capture")).unwrap();
        first.comment(0x1000, Some("first mapping only")).unwrap();
        let mut changed = original.clone();
        match change {
            "bytes" => changed["regions"][0]["bytes"] = json!("1f2003d5c0035fd6"),
            "permissions" => changed["regions"][0]["permissions"] = json!("rwx"),
            "address" => changed["regions"][1]["address"] = json!("0x3000"),
            "endianness" => changed["data_big_endian"] = json!(true),
            "instruction-endianness" => changed["big_endian"] = json!(true),
            "target" => changed["target"]["platform"] = json!("darwin"),
            "compiler" => changed["target"]["compiler"] = json!("apple"),
            "target-absence" => changed["target"] = json!(null),
            "seeds" => changed["seeds"] = json!(["0x1000", "0x1004"]),
            "entry" => changed["entry"] = json!("0x1004"),
            "module" => changed["modules"][0]["runtime_base"] = json!("0x2000"),
            "module-identity" => changed["modules"][0]["uuid"] = json!("other-opaque-identity"),
            "thumb" => changed["regions"][0]["thumb"] = json!(true),
            _ => unreachable!(),
        }
        scratch.write("capture.json", &changed);
        let second = session.open(&path, None).unwrap();
        assert!(!Arc::ptr_eq(&first, &second), "{change}");
        assert_ne!(identity(&first), identity(&second), "{change}");
        assert!(second.annotation_list().names.is_empty(), "{change}");
        assert_eq!(second.comment_at(0x1000), None, "{change}");
        assert_eq!(second.binary.file_bytes(), serde_json::to_vec(&changed).unwrap(), "{change}");
        first.comment(0x1004, Some("late edit on retired capture")).unwrap();
        second.refresh_annotations().unwrap();
        assert_eq!(second.comment_at(0x1004), None, "{change}");
        second.comment(0x1000, Some("second mapping only")).unwrap();
        let reopened = Session::default().open(&path, None).unwrap();
        assert_eq!(reopened.comment_at(0x1000).as_deref(), Some("second mapping only"), "{change}");
        assert!(reopened.annotation_list().names.is_empty(), "{change}");
        scratch.write("capture.json", &original);
        let restored = session.open(&path, None).unwrap();
        assert_eq!(restored.name_at(0x1000).as_deref(), Some("first_capture"), "{change}");
        assert_eq!(restored.comment_at(0x1000).as_deref(), Some("first mapping only"), "{change}");
        assert_eq!(restored.comment_at(0x1004).as_deref(), Some("late edit on retired capture"), "{change}");
    }
}

#[test]
fn equal_capture_at_a_new_path_shares_persistence_without_conflating_provenance() {
    let scratch = Scratch::new("equal");
    let first_path = scratch.write("first.json", &snapshot());
    let mut other = snapshot();
    other["provenance"] = json!("second controlled capture");
    other["regions"][0]["name"] = json!("other_code_label");
    other["modules"][0]["name"] = json!("other_module_label");
    other["modules"][0]["path"] = json!("/never/opened/other_module");
    other["modules"][0]["uuid"] = json!("01234567-89AB-CDEF-0123-456789ABCDEF");
    other["registers"][0]["value"] = json!("0x1004");
    other["regions"].as_array_mut().unwrap().reverse();
    let second_path = scratch.write("second.json", &other);
    let session = Session::default();
    let first = session.open(&first_path, None).unwrap();
    first.rename(0x1000, Some("shared_name")).unwrap();
    first.comment(0x1000, Some("shared capture annotation")).unwrap();
    let second = session.open(&second_path, Some(Arch::Aarch64)).unwrap();
    assert_eq!(identity(&first), identity(&second));
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(second.name_at(0x1000).as_deref(), Some("shared_name"));
    assert_eq!(second.comment_at(0x1000).as_deref(), Some("shared capture annotation"));
    assert_eq!(second.summary().provenance, Some("second controlled capture"));
    assert_eq!(first.summary().provenance, Some("first controlled capture"));
    assert_eq!(second.summary().snapshot_registers[0].value, "0x1004");
    assert_eq!(first.summary().snapshot_registers[0].value, "0x1000");
    assert_eq!(second.summary().snapshot_modules[0].path, "/never/opened/other_module");
    assert_eq!(second.summary().segments[0].name, "other_code_label");
    second.comment(0x1004, Some("edited through equal capture")).unwrap();
    let cached = session.open(&first_path, Some(Arch::Aarch64)).unwrap();
    assert!(Arc::ptr_eq(&first, &cached));
    assert_eq!(cached.comment_at(0x1004).as_deref(), Some("edited through equal capture"));
    assert!(!sidecar(&first_path).exists());
    assert!(!sidecar(&second_path).exists());
    drop(session);
    let fresh = Session::default();
    for (path, provenance) in [(&first_path, "first controlled capture"), (&second_path, "second controlled capture")] {
        let reopened = fresh.open(path, None).unwrap();
        assert_eq!(reopened.name_at(0x1000).as_deref(), Some("shared_name"));
        assert_eq!(reopened.comment_at(0x1004).as_deref(), Some("edited through equal capture"));
        assert_eq!(reopened.summary().provenance, Some(provenance));
    }
}

#[test]
fn changed_provenance_at_the_same_path_replaces_the_project_but_preserves_identity_scoped_annotations() {
    let scratch = Scratch::new("provenance");
    let path = scratch.write("capture.json", &snapshot());
    let session = Session::default();
    let first = session.open(&path, None).unwrap();
    first.comment(0x1000, Some("same analysis identity")).unwrap();
    let mut changed = snapshot();
    changed["provenance"] = json!("changed producer description");
    changed["registers"][0]["value"] = json!("0x2000");
    scratch.write("capture.json", &changed);
    let second = session.open(&path, None).unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(identity(&first), identity(&second));
    assert_eq!(second.summary().provenance, Some("changed producer description"));
    assert_eq!(second.summary().snapshot_registers[0].value, "0x2000");
    assert_eq!(second.comment_at(0x1000).as_deref(), Some("same analysis identity"));
    assert_eq!(first.summary().provenance, Some("first controlled capture"));
}

#[test]
fn explicit_annotation_directory_enables_cross_directory_reuse_without_global_discovery() {
    let scratch = Scratch::new("scope");
    for name in ["first", "second", "annotations"] {
        std::fs::create_dir(scratch.path(name)).unwrap();
    }
    let first_path = scratch.write("first/capture.json", &snapshot());
    let second_path = scratch.write("second/capture.json", &snapshot());
    let ordinary = Session::default().open(&first_path, None).unwrap();
    ordinary.comment(0x1000, Some("directory-local annotation")).unwrap();
    let elsewhere = Session::default().open(&second_path, None).unwrap();
    assert_eq!(elsewhere.comment_at(0x1000), None);
    let directory = scratch.path("annotations");
    let explicit = Session::with_capture_annotations(directory.clone()).open(&first_path, None).unwrap();
    assert_eq!(explicit.comment_at(0x1000), None);
    explicit.comment(0x1000, Some("explicit shared annotation")).unwrap();
    let reopened = Session::with_capture_annotations(directory).open(&second_path, None).unwrap();
    assert_eq!(reopened.comment_at(0x1000).as_deref(), Some("explicit shared annotation"));
    assert_eq!(std::fs::read_dir(scratch.path("second")).unwrap().count(), 1);
}

#[test]
fn legacy_snapshot_sidecar_is_reported_but_never_loaded_or_migrated() {
    let scratch = Scratch::new("legacy");
    let path = scratch.write("capture.json", &snapshot());
    let legacy = sidecar(&path);
    let legacy_bytes =
        b"{\"field\":\"comment\",\"address\":\"0x1000\",\"value\":\"unscoped legacy edit\",\"previous\":null}\n";
    std::fs::write(&legacy, legacy_bytes).unwrap();
    let first = Session::default().open(&path, None).unwrap();
    assert_eq!(first.comment_at(0x1000), None);
    assert!(first.summary().warnings.iter().any(|warning| warning.contains("legacy snapshot annotations")));
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 2);
    first.comment(0x1000, Some("identity-scoped edit")).unwrap();
    let mut changed = snapshot();
    changed["regions"][0]["permissions"] = json!("rwx");
    scratch.write("capture.json", &changed);
    let second = Session::default().open(&path, None).unwrap();
    assert_eq!(second.comment_at(0x1000), None);
    assert_eq!(std::fs::read(&legacy).unwrap(), legacy_bytes);
    let mut lock = legacy.as_os_str().to_owned();
    lock.push(".lock");
    assert!(!PathBuf::from(lock).exists());
}

#[test]
fn architecture_requests_are_revalidated_even_when_a_snapshot_is_cached() {
    let scratch = Scratch::new("arch");
    let path = scratch.write("capture.json", &snapshot());
    let session = Session::default();
    let first = session.open(&path, None).unwrap();
    first.comment(0x1000, Some("aarch64 only")).unwrap();
    assert!(Arc::ptr_eq(&first, &session.open(&path, Some(Arch::Aarch64)).unwrap()));
    assert!(matches!(session.open(&path, Some(Arch::X86_64)), Err(ApiError::Load { .. })));
    let mut changed = snapshot();
    changed["arch"] = json!("x86_64");
    changed["regions"][0]["bytes"] = json!("c390909090909090");
    scratch.write("capture.json", &changed);
    assert!(matches!(session.open(&path, Some(Arch::Aarch64)), Err(ApiError::Load { .. })));
    let second = session.open(&path, Some(Arch::X86_64)).unwrap();
    assert_eq!(second.binary.arch, Arch::X86_64);
    assert_eq!(second.comment_at(0x1000), None);
    assert!(Arc::ptr_eq(&second, &session.open(&path, None).unwrap()));
    scratch.write("capture.json", &snapshot());
    let restored = session.open(&path, None).unwrap();
    assert_eq!(restored.binary.arch, Arch::Aarch64);
    assert_eq!(restored.comment_at(0x1000).as_deref(), Some("aarch64 only"));
}

#[test]
fn malformed_or_missing_replacement_cannot_return_the_cached_capture() {
    let scratch = Scratch::new("invalid");
    let path = scratch.write("capture.json", &snapshot());
    let session = Session::default();
    let first = session.open(&path, None).unwrap();
    std::fs::write(&path, b"{\"format\":\"rampage-snapshot-v1\"").unwrap();
    assert!(matches!(session.open(&path, None), Err(ApiError::Load { .. })));
    assert!(matches!(session.open(&path, Some(Arch::Aarch64)), Err(ApiError::Load { .. })));
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(session.open(&path, None), Err(ApiError::Load { .. })));
    assert_eq!(first.summary().provenance, Some("first controlled capture"));
}

#[test]
fn capture_paths_stay_revalidated_across_ordinary_binary_replacements_and_architecture_changes() {
    for fixture in ["hello-arm64.macho", "hello-x64.elf"] {
        let scratch = Scratch::new("format-replacement");
        let path = scratch.write("capture.json", &snapshot());
        let session = Session::default();
        let first = session.open(&path, None).unwrap();
        first.comment(0x1000, Some("original snapshot only")).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(fixture);
        let replacement = scratch.path("replacement");
        std::fs::copy(source, &replacement).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let ordinary = session.open(&path, None).unwrap();
        assert_ne!(ordinary.binary.format, Format::Snapshot, "{fixture}");
        assert_eq!(ordinary.comment_at(0x1000), None, "{fixture}");
        assert!(Arc::ptr_eq(&ordinary, &session.open(&path, Some(ordinary.binary.arch)).unwrap()), "{fixture}");
        let last = *std::fs::read(&path).unwrap().last().unwrap();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.seek(SeekFrom::End(-1)).unwrap();
            file.write_all(&[last ^ 1]).unwrap();
        }
        let modified = session.open(&path, None).unwrap();
        assert!(!Arc::ptr_eq(&ordinary, &modified), "{fixture}");
        assert!(Arc::ptr_eq(&modified, &session.open(&path, None).unwrap()), "{fixture}");
        let mut changed = snapshot();
        changed["regions"][0]["permissions"] = json!("rwx");
        changed["provenance"] = json!("new snapshot after ordinary replacement");
        scratch.write("replacement", &changed);
        std::fs::rename(&replacement, &path).unwrap();
        assert!(matches!(session.open(&path, Some(Arch::X86_64)), Err(ApiError::Load { .. })), "{fixture}");
        let second = session.open(&path, None).unwrap();
        assert_eq!(second.binary.format, Format::Snapshot, "{fixture}");
        assert_eq!(second.binary.arch, Arch::Aarch64, "{fixture}");
        assert_eq!(second.summary().provenance, Some("new snapshot after ordinary replacement"), "{fixture}");
        assert!(!Arc::ptr_eq(&first, &second), "{fixture}");
        assert_eq!(second.comment_at(0x1000), None, "{fixture}");
        assert!(Arc::ptr_eq(&second, &session.open(&path, Some(Arch::Aarch64)).unwrap()), "{fixture}");
    }
}

#[test]
fn initial_ordinary_and_universal_caches_cannot_hide_snapshot_replacements_or_accept_stale_slices() {
    for fixture in ["hello-arm64.macho", "hello-x64.elf", "hello-universal.macho"] {
        let scratch = Scratch::new("initial-ordinary-replacement");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(fixture);
        let path = scratch.path("input");
        std::fs::copy(source, &path).unwrap();
        let session = Session::default();
        let ordinary = session.open(&path, None).unwrap();
        for &arch in &ordinary.binary.slices {
            session.open(&path, Some(arch)).unwrap();
        }
        ordinary.comment(0x1000, Some("ordinary annotations must not leak into snapshots")).unwrap();
        let replacement = scratch.write("replacement", &snapshot());
        let mut bytes = vec![b' '; 20_000];
        bytes.extend(std::fs::read(&replacement).unwrap());
        std::fs::write(&replacement, bytes).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert!(matches!(session.open(&path, Some(Arch::X86_64)), Err(ApiError::Load { .. })), "{fixture}");
        let capture = session.open(&path, None).unwrap();
        assert_eq!(capture.binary.format, Format::Snapshot, "{fixture}");
        assert_eq!(capture.binary.arch, Arch::Aarch64, "{fixture}");
        assert_eq!(capture.comment_at(0x1000), None, "{fixture}");
        assert!(!Arc::ptr_eq(&ordinary, &capture), "{fixture}");
        assert!(Arc::ptr_eq(&capture, &session.open(&path, Some(Arch::Aarch64)).unwrap()), "{fixture}");
    }
}

#[test]
fn ordinary_cache_cannot_hide_a_missing_or_invalid_snapshot_replacement() {
    for replacement in ["missing", "invalid", "empty"] {
        let scratch = Scratch::new("ordinary-invalid-replacement");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let path = scratch.path("input");
        std::fs::copy(source, &path).unwrap();
        let session = Session::default();
        session.open(&path, None).unwrap();
        std::fs::remove_file(&path).unwrap();
        match replacement {
            "missing" => {}
            "invalid" => {
                std::fs::write(&path, b"{\"format\":\"rampage-snapshot-v1\"").unwrap();
            }
            "empty" => {
                std::fs::write(&path, b"").unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(session.open(&path, None), Err(ApiError::Load { .. })), "{replacement}");
        assert!(matches!(session.open(&path, Some(Arch::X86_64)), Err(ApiError::Load { .. })), "{replacement}");
    }
}

#[test]
fn cached_snapshot_warnings_track_legacy_sidecar_creation_and_removal() {
    let scratch = Scratch::new("legacy-status");
    let path = scratch.write("capture.json", &snapshot());
    let session = Session::default();
    let first = session.open(&path, None).unwrap();
    first.comment(0x1000, Some("identity-scoped annotation survives warning changes")).unwrap();
    assert!(first.summary().warnings.is_empty());
    let legacy = sidecar(&path);
    std::fs::write(&legacy, b"unscoped legacy log remains ignored\n").unwrap();
    let warned = session.open(&path, None).unwrap();
    assert!(!Arc::ptr_eq(&first, &warned));
    assert!(warned.summary().warnings.iter().any(|warning| warning.contains("legacy snapshot annotations")));
    assert!(Arc::ptr_eq(&warned, &session.open(&path, None).unwrap()));
    std::fs::remove_file(legacy).unwrap();
    let cleared = session.open(&path, None).unwrap();
    assert!(!Arc::ptr_eq(&warned, &cleared));
    assert!(cleared.summary().warnings.is_empty());
    assert_eq!(cleared.comment_at(0x1000).as_deref(), Some("identity-scoped annotation survives warning changes"));
    assert!(Arc::ptr_eq(&cleared, &session.open(&path, None).unwrap()));
}

#[test]
fn explicit_snapshot_annotation_directory_must_exist_and_be_a_directory_even_on_cached_opens() {
    let scratch = Scratch::new("invalid-directory");
    let path = scratch.write("capture.json", &snapshot());
    let missing = scratch.path("missing");
    let session = Session::with_capture_annotations(missing.clone());
    assert!(matches!(session.open(&path, None), Err(ApiError::Invalid(_))));
    assert!(!missing.exists());
    std::fs::write(&missing, b"not a directory").unwrap();
    assert!(matches!(session.open(&path, None), Err(ApiError::Invalid(_))));
    std::fs::remove_file(&missing).unwrap();
    std::fs::create_dir(&missing).unwrap();
    let first = session.open(&path, None).unwrap();
    assert!(Arc::ptr_eq(&first, &session.open(&path, None).unwrap()));
    std::fs::remove_dir(&missing).unwrap();
    assert!(matches!(session.open(&path, None), Err(ApiError::Invalid(_))));
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);
}

#[test]
fn capture_logs_cannot_collide_with_ordinary_sidecars_named_after_the_capture_identity() {
    let scratch = Scratch::new("log-namespace");
    let capture_path = scratch.write("capture.json", &snapshot());
    let capture_identity = capture_identity(&Binary::open(&capture_path).unwrap()).unwrap();
    let basename = format!(".{}-{}", capture_identity.schema, capture_identity.sha256);
    let ordinary_path = scratch.path(&basename);
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    std::fs::copy(fixture, &ordinary_path).unwrap();
    let ordinary = Session::default().open(&ordinary_path, None).unwrap();
    ordinary.comment(0x1000, Some("ordinary annotation only")).unwrap();
    let ordinary_log = sidecar(&ordinary_path);
    let ordinary_log_bytes = std::fs::read(&ordinary_log).unwrap();
    let capture = Session::default().open(&capture_path, None).unwrap();
    assert_eq!(capture.comment_at(0x1000), None);
    capture.comment(0x1000, Some("capture annotation only")).unwrap();
    capture.comment(0x1004, Some("capture-only address")).unwrap();
    assert!(scratch.path(&format!("{basename}.jsonl")).is_file());
    assert_eq!(std::fs::read(&ordinary_log).unwrap(), ordinary_log_bytes);
    let reopened_ordinary = Session::default().open(&ordinary_path, None).unwrap();
    assert_eq!(reopened_ordinary.comment_at(0x1000).as_deref(), Some("ordinary annotation only"));
    assert_eq!(reopened_ordinary.comment_at(0x1004), None);
    reopened_ordinary.comment(0x1004, Some("ordinary-only address")).unwrap();
    let reopened_capture = Session::default().open(&capture_path, None).unwrap();
    assert_eq!(reopened_capture.comment_at(0x1000).as_deref(), Some("capture annotation only"));
    assert_eq!(reopened_capture.comment_at(0x1004).as_deref(), Some("capture-only address"));
}

#[test]
fn ordinary_binaries_keep_per_slice_sidecars_and_cached_project_behavior() {
    let scratch = Scratch::new("ordinary");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-universal.macho");
    let path = scratch.path("hello-universal.macho");
    std::fs::copy(fixture, &path).unwrap();
    let session = Session::with_capture_annotations(scratch.path("unused-directory"));
    let first = session.open(&path, None).unwrap();
    let address = first.binary.entry.unwrap();
    first.comment(address, Some("ordinary default slice")).unwrap();
    assert!(Arc::ptr_eq(&first, &session.open(&path, Some(first.binary.arch)).unwrap()));
    let other_arch = first.binary.slices.iter().copied().find(|&arch| arch != first.binary.arch).unwrap();
    let other = session.open(&path, Some(other_arch)).unwrap();
    assert_eq!(other.comment_at(address), None);
    let mut log = path.as_os_str().to_owned();
    log.push(format!(".{}.rampage", first.binary.arch));
    assert!(PathBuf::from(log).is_file());
    let reopened = Session::default().open(&path, Some(first.binary.arch)).unwrap();
    assert_eq!(reopened.comment_at(address).as_deref(), Some("ordinary default slice"));
    assert!(!scratch.path("unused-directory").exists());
    assert!(capture_identity(&Binary::open(&path).unwrap()).is_none());
}

#[test]
fn an_ordinary_binary_rewritten_on_disk_is_reloaded_with_its_annotations() {
    let scratch = Scratch::new("ordinary-rewrite");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin");
    let path = scratch.path("target.elf");
    std::fs::copy(fixtures.join("hello-x64.elf"), &path).unwrap();
    let session = Session::default();
    let first = session.open(&path, None).unwrap();
    first.comment(0x1000, Some("kept across reloads")).unwrap();
    assert!(Arc::ptr_eq(&first, &session.open(&path, None).unwrap()));

    let replacement = scratch.path("replacement");
    std::fs::copy(fixtures.join("hello-x64-dyn.elf"), &replacement).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    let replaced = session.open(&path, None).unwrap();
    assert!(!Arc::ptr_eq(&first, &replaced));
    assert_eq!(replaced.binary.file_bytes(), std::fs::read(&path).unwrap());
    assert_eq!(replaced.comment_at(0x1000).as_deref(), Some("kept across reloads"));
    assert!(Arc::ptr_eq(&replaced, &session.open(&path, None).unwrap()));

    // An in-place rewrite of the same length, as an editor or linker might make, is told by its modification time.
    let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
    let last = *std::fs::read(&path).unwrap().last().unwrap();
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[last ^ 1]).unwrap();
        file.set_modified(modified + std::time::Duration::from_secs(2)).unwrap();
    }
    let rewritten = session.open(&path, None).unwrap();
    assert!(!Arc::ptr_eq(&replaced, &rewritten));
    assert!(Arc::ptr_eq(&rewritten, &session.open(&path, Some(rewritten.binary.arch)).unwrap()));
}
