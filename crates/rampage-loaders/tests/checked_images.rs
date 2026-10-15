#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_loaders::{Binary, Format};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "checked-images-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn snapshot(seeds: usize) -> serde_json::Value {
    serde_json::json!({
        "format":"rampage-snapshot-v1", "arch":"x86_64", "data_big_endian":false,
        "seeds":vec!["0x1000"; seeds], "provenance":"owned checked-source fixture",
        "regions":[{"name":"code","address":"0x1000","permissions":"r-x","bytes":"c3"}]
    })
}

#[test]
fn checked_native_load_preserves_the_complete_image_and_original_descriptor() {
    let scratch = Scratch::new();
    let path = scratch.0.join("owned.elf");
    std::fs::copy(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf"), &path)
        .unwrap();
    let legacy = Binary::open(&path).unwrap();
    let checked = Binary::open_image_checked(&path, None, None).unwrap();
    assert_eq!(checked.image_bytes(), legacy.image_bytes());
    assert_eq!(checked.arch, legacy.arch);
    assert_eq!(checked.function_starts, legacy.function_starts);
    assert_eq!(serde_json::to_value(&checked.segments).unwrap(), serde_json::to_value(&legacy.segments).unwrap());
    assert_eq!(checked.backing_path(), Some(path.as_path()));
    checked.validate_backing_source().unwrap();
    let replacement = scratch.0.join("replacement");
    std::fs::copy(&path, &replacement).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    assert!(checked.validate_backing_source().is_err());
}

#[test]
fn checked_snapshot_array_admission_precedes_deserialization_without_changing_legacy_loading() {
    let scratch = Scratch::new();
    let path = scratch.0.join("owned.snapshot.json");
    std::fs::write(&path, serde_json::to_vec(&snapshot(4096)).unwrap()).unwrap();
    let checked = Binary::open_image_checked(&path, None, None).unwrap();
    assert_eq!(checked.format, Format::Snapshot);
    assert!(checked.backing_path().is_none());
    assert!(!checked.validate_available_backing_source().unwrap());
    std::fs::write(&path, serde_json::to_vec(&snapshot(4097)).unwrap()).unwrap();
    let error = Binary::open_image_checked(&path, None, None).unwrap_err().to_string();
    assert!(error.contains("raw structural or text budget"), "{error}");
    let legacy = Binary::open(&path).unwrap();
    assert_eq!(legacy.format, Format::Snapshot);
    assert!(legacy.validate_checked_source_profile().is_err());
}

#[test]
fn checked_snapshot_raw_text_and_document_caps_apply_before_copying_json() {
    let scratch = Scratch::new();
    let path = scratch.0.join("owned.snapshot.json");
    let mut text = snapshot(1);
    text["provenance"] = serde_json::json!("a".repeat(1024 * 1024 + 1));
    std::fs::write(&path, serde_json::to_vec(&text).unwrap()).unwrap();
    assert!(Binary::open_image_checked(&path, None, None).unwrap_err().to_string().contains("raw structural"));
    let mut file = std::fs::File::create(&path).unwrap();
    use std::io::Write;
    file.write_all(b"{").unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    drop(file);
    assert!(Binary::open_image_checked(&path, None, None).unwrap_err().to_string().contains("raw structural"));
}

#[test]
fn checked_open_refuses_special_sources_symlinks_directories_and_oversized_sources() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new();
    assert!(Binary::open_image_checked(&scratch.0, None, None).is_err());
    let path = scratch.0.join("oversized");
    std::fs::File::create(&path).unwrap().set_len(128 * 1024 * 1024 + 1).unwrap();
    assert!(Binary::open_image_checked(&path, None, None).unwrap_err().to_string().contains("128 MiB"));
    let alias = scratch.0.join("alias");
    symlink(&path, &alias).unwrap();
    assert!(Binary::open_image_checked(&alias, None, None).is_err());
    let fifo = scratch.0.join("pipe");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    assert!(Binary::open_image_checked(&fifo, None, None).is_err());
}
