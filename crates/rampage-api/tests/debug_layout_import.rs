use std::path::PathBuf;

use rampage_api::Project;
use rampage_loaders::Binary;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf")
}

struct SourceCopy(PathBuf);

impl SourceCopy {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rampage-layout-source-{}-{index}.elf", std::process::id()));
        std::fs::copy(fixture(), &path).unwrap();
        Self(path)
    }
}

impl Drop for SourceCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn explicit_checked_preview_does_not_change_annotations_or_legacy_scalar_preview() {
    let project = Project::new(Binary::open(fixture()).unwrap());
    let legacy = project.import_debug_signatures(false).unwrap();
    let before = serde_json::to_string(&project.annotation_list()).unwrap();
    let preview = project.preview_debug_layouts().unwrap();
    assert!(preview.producer_report().is_some());
    assert_eq!(serde_json::to_string(&project.annotation_list()).unwrap(), before);
    assert!(project.undo().unwrap().is_empty());
    let after = project.import_debug_signatures(false).unwrap();
    assert_eq!(serde_json::to_string(&after.preview).unwrap(), serde_json::to_string(&legacy.preview).unwrap());
}

#[test]
fn a_reopened_project_cannot_rebind_a_checked_receipt() {
    let project = Project::new(Binary::open(fixture()).unwrap());
    let preview = project.preview_debug_layouts().unwrap();
    let reopened = Project::new(Binary::open(fixture()).unwrap());
    let error = reopened.apply_debug_layouts(&preview).unwrap_err().to_string();
    assert!(error.contains("different project"), "{error}");
    assert!(reopened.annotation_list().types.is_empty());
}

#[test]
fn source_replacement_is_refused_before_reading_the_retained_stale_mapping() {
    let source = SourceCopy::new();
    let project = Project::new(Binary::open(&source.0).unwrap());
    let preview = project.preview_debug_layouts().unwrap();
    std::fs::OpenOptions::new().write(true).open(&source.0).unwrap().set_len(0).unwrap();
    assert!(project.apply_debug_layouts(&preview).is_err());
    assert!(project.preview_debug_layouts().is_err());
    assert!(project.annotation_list().types.is_empty());
    assert!(project.annotation_list().signatures.is_empty());
}

#[test]
fn checked_name_batches_remain_refreshable_undoable_and_reopenable() {
    let log = std::env::temp_dir().join(format!("rampage-checked-name-batch-{}.jsonl", std::process::id()));
    let files = AnnotationFiles(log.clone());
    let project = Project::with_annotations(
        Binary::open(fixture()).unwrap(),
        rampage_api::annotations::Annotations::open_checked(log.clone()).unwrap(),
    );
    let entries: Vec<_> = (0..257)
        .map(|index| rampage_api::BatchEntry {
            at: format!("0x{:x}", 0x500000 + index),
            name: Some(format!("checked_label_{index}")),
            comment: None,
        })
        .collect();
    assert_eq!(project.annotate_batch(&entries).unwrap().changed, entries.len());
    project.refresh_annotations().unwrap();
    assert_eq!(project.resolve("checked_label_256").unwrap(), 0x500100);
    let reopened = Project::with_annotations(
        Binary::open(fixture()).unwrap(),
        rampage_api::annotations::Annotations::open_checked(log.clone()).unwrap(),
    );
    assert_eq!(reopened.resolve("checked_label_256").unwrap(), 0x500100);
    assert_eq!(project.undo().unwrap().len(), entries.len());
    project.refresh_annotations().unwrap();
    reopened.refresh_annotations().unwrap();
    assert!(project.resolve("checked_label_256").is_err());
    assert!(reopened.resolve("checked_label_256").is_err());
    assert_eq!(project.redo().unwrap().len(), entries.len());
    project.refresh_annotations().unwrap();
    assert_eq!(project.resolve("checked_label_256").unwrap(), 0x500100);
    drop(files);
}

#[test]
#[ignore = "requires RAMPAGE_DEBUG_LAYOUT_FIXTURES produced by the scoped owned-source fixture recipe"]
fn producer_backed_apply_uses_original_field_names_and_reopens_the_whole_dependency_batch() {
    let root = PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_LAYOUT_FIXTURES").expect("owned fixture directory"));
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let path = root.join(variant).join("flat.debug.elf");
        let log = std::env::temp_dir().join(format!("rampage-layout-roundtrip-{}-{variant}.jsonl", std::process::id()));
        let files = AnnotationFiles(log.clone());
        let project = Project::with_annotations(
            Binary::open(&path).unwrap(),
            rampage_api::annotations::Annotations::open_checked(log.clone()).unwrap(),
        );
        let preview = project.preview_debug_layouts().unwrap();
        let producer = preview.producer_report().unwrap();
        let layout = producer
            .layouts
            .iter()
            .find(|layout| layout.original_name.as_deref() == Some("debug_flat"))
            .expect("producer flat layout");
        assert_eq!(layout.producer_alignment, Some(8));
        assert!(layout.eligible_for_native_verification);
        assert!(!layout.strictly_applicable, "unknown producer leaf alignments must not become strict producer proof");
        assert!(!preview.approved().is_empty());
        assert!(!log.exists());
        let imported = project.apply_debug_layouts(&preview).unwrap();
        assert_eq!(imported.imported_types.len(), 1);
        for (name, field) in [
            ("debug_flat_read_first", "tag"),
            ("debug_flat_read_interior", "count"),
            ("debug_flat_read_flags", "flags"),
            ("debug_flat_read_weight", "weight"),
            ("debug_flat_read_pointer", "value"),
            ("debug_flat_read_final", "tail"),
            ("debug_flat_write_first", "tag"),
            ("debug_flat_write_interior", "count"),
            ("debug_flat_write_final", "tail"),
        ] {
            let address = project.resolve(name).unwrap();
            assert!(imported.applied.contains(&address), "{name} was not applied");
            let code = project.decompile(address).unwrap().code;
            assert!(code.contains(&format!("->{field}")), "{name}: {code}");
        }
        let reopened = Project::with_annotations(
            Binary::open(&path).unwrap(),
            rampage_api::annotations::Annotations::open_checked(log.clone()).unwrap(),
        );
        let address = reopened.resolve("debug_flat_read_interior").unwrap();
        assert!(reopened.decompile(address).unwrap().code.contains("->count"));
        assert!(reopened.apply_debug_layouts(&preview).is_err());
        let edits = project.undo().unwrap();
        assert_eq!(edits.len(), imported.applied.len() + imported.imported_types.len());
        assert!(project.annotation_list().types.is_empty() && project.annotation_list().signatures.is_empty());
        let removed = Project::with_annotations(
            Binary::open(&path).unwrap(),
            rampage_api::annotations::Annotations::open_checked(log.clone()).unwrap(),
        );
        assert!(removed.annotation_list().types.is_empty() && removed.annotation_list().signatures.is_empty());
        drop(files);
    }
}

struct AnnotationFiles(PathBuf);

impl Drop for AnnotationFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(PathBuf::from(format!("{}.lock", self.0.display())));
    }
}
