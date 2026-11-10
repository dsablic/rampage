use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::Project;
use rampage_api::annotations::{Annotations, Field};
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-raw-pilot-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        if let Ok(entries) = std::fs::read_dir(&self.0) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn project() -> Arc<Project> {
    let options = RawCodeOptions {
        profile: RawProfile::Msp430,
        base: 0x1000,
        entry: None,
        seeds: vec![],
        vector_table: None,
        pointer_tables: false,
    };
    Arc::new(Project::new(Binary::from_raw_code(vec![0x30, 0x41], options).unwrap()))
}

#[test]
fn raw_is_not_a_capture_or_original_source_proof() {
    let project = project();
    assert!(rampage_analysis::capture_identity::capture_identity(&project.binary).is_none());
    assert!(project.binary.validate_backing_source().is_err());
    assert!(!project.binary.validate_available_backing_source().unwrap());
    assert_eq!(project.binary.raw_interpretation_identity().unwrap().unwrap().schema, "rampage-raw-interpretation-v4");
}

#[test]
fn raw_patch_v1_is_refused_without_changing_bytes_or_annotations() {
    let project = project();
    let bytes = project.binary.image_bytes().to_vec();
    let error = project.patch_bytes(0x1000, &[0x30, 0x41], &[0, 0], false).err().expect("Raw patch must refuse");
    assert!(error.to_string().contains("ELF64"), "{error}");
    assert_eq!(project.binary.image_bytes(), bytes);
    assert!(project.list_patches().unwrap().is_empty());
    assert!(project.annotation_list().names.is_empty());
}

#[test]
fn header_driven_open_never_infers_a_raw_profile_or_entry() {
    let owned = OwnedDirectory::new();
    let path = owned.0.join("code.bin");
    std::fs::write(&path, [0x30, 0x41]).unwrap();
    assert!(Binary::open(&path).is_err());
    let project = project();
    assert!(project.binary.entry.is_none());
    assert!(project.binary.function_starts.is_empty());
}

#[test]
fn supplying_a_persistent_annotation_log_cannot_enable_raw_sidecar_writes() {
    let owned = OwnedDirectory::new();
    let path = owned.0.join("notes.jsonl");
    let mut annotations = Annotations::open(path.clone()).unwrap();
    annotations.set(Field::Comment, 0x1000, Some("retained".into())).unwrap();
    let before = std::fs::read(&path).unwrap();
    let input = RawCodeOptions {
        profile: RawProfile::Msp430,
        base: 0x1000,
        entry: None,
        seeds: vec![],
        vector_table: None,
        pointer_tables: false,
    };
    let binary = Binary::from_raw_code(vec![0x30, 0x41], input).unwrap();
    let project = Project::with_annotations(binary, annotations);
    assert_eq!(project.comment_at(0x1000).as_deref(), Some("retained"));
    project.comment(0x1000, Some("memory only")).unwrap();
    assert_eq!(project.comment_at(0x1000).as_deref(), Some("memory only"));
    assert_eq!(std::fs::read(path).unwrap(), before);
}
