use std::path::{Path, PathBuf};

use rampage_api::Project;
use rampage_api::annotations::Annotations;
use rampage_loaders::Binary;

struct ReviewFiles(PathBuf);

impl ReviewFiles {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("rampage-reviewed-layout-{}-{next}.jsonl", std::process::id())))
    }
}

impl Drop for ReviewFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("jsonl.lock"));
    }
}

fn generated(variant: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_LAYOUT_FIXTURES").expect("owned fixture wrapper required"))
        .join(variant)
        .join("flat.debug.elf")
}

fn open(image: &Path, log: &Path) -> Project {
    Project::with_annotations(Binary::open(image).unwrap(), Annotations::open_checked(log.to_owned()).unwrap())
}

fn annotations(project: &Project) -> serde_json::Value {
    serde_json::to_value(project.annotation_list()).unwrap()
}

#[test]
fn preview_only_review_is_read_only_and_incorrect_approval_does_not_create_a_log() {
    let files = ReviewFiles::new();
    let image = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    let project = open(&image, &files.0);
    let before = annotations(&project);
    let review = project.review_debug_layouts().unwrap();
    assert!(review.imported.is_none());
    assert!(review.approved.is_empty());
    assert!(!files.0.exists());
    assert_eq!(annotations(&project), before);
    let incorrect = if review.review_sha256.starts_with('0') { "1".repeat(64) } else { "0".repeat(64) };
    assert!(project.apply_reviewed_debug_layouts(&incorrect).is_err());
    assert_eq!(annotations(&project), before);
    assert!(!files.0.exists());
    assert!(project.undo().unwrap().is_empty());
}

#[test]
#[ignore = "requires centrally compiled owned DWARF fixtures through the --check wrapper"]
fn reviewed_content_can_be_confirmed_after_reopen_without_rebinding_an_opaque_receipt() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let files = ReviewFiles::new();
        let image = generated(variant);
        let original = open(&image, &files.0);
        let review = original.review_debug_layouts().unwrap();
        assert!(!review.approved.is_empty());
        assert!(review.imported.is_none());
        assert!(!files.0.exists());
        let reopened = open(&image, &files.0);
        assert_eq!(reopened.review_debug_layouts().unwrap().review_sha256, review.review_sha256);
        let imported = reopened.apply_reviewed_debug_layouts(&review.review_sha256).unwrap();
        assert_eq!(imported.review_sha256, review.review_sha256);
        let result = imported.imported.unwrap();
        assert_eq!(result.applied, review.approved);
        assert_eq!(result.imported_types.len(), 1);
        let read = reopened.resolve("debug_flat_read_interior").unwrap();
        assert!(reopened.decompile(read).unwrap().code.contains("->count"));
        let persisted = open(&image, &files.0);
        assert!(persisted.decompile(read).unwrap().code.contains("->count"));
        assert!(reopened.apply_reviewed_debug_layouts(&review.review_sha256).is_err());
        assert_eq!(reopened.undo().unwrap().len(), result.applied.len() + result.imported_types.len());
        assert!(reopened.annotation_list().types.is_empty());
        assert!(reopened.annotation_list().signatures.is_empty());
    }
}

#[test]
#[ignore = "requires centrally compiled owned DWARF fixtures through the --check wrapper"]
fn changed_analyst_eligibility_requires_a_new_review_instead_of_widening_or_replacing_approval() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let files = ReviewFiles::new();
        let image = generated(variant);
        let project = open(&image, &files.0);
        let read = project.resolve("debug_flat_read_interior").unwrap();
        let initial = project.review_debug_layouts().unwrap();
        project.set_signature(read, Some("int4 analyst_read(void *input);")).unwrap();
        let before = annotations(&project);
        assert!(project.apply_reviewed_debug_layouts(&initial.review_sha256).is_err());
        assert_eq!(annotations(&project), before);
        assert!(project.annotation_list().types.is_empty());
        let preserved = project.review_debug_layouts().unwrap();
        assert!(preserved.preserved.contains(&read));
        assert!(!preserved.approved.contains(&read));
        project.set_signature(read, None).unwrap();
        let before = annotations(&project);
        assert!(project.apply_reviewed_debug_layouts(&preserved.review_sha256).is_err());
        assert_eq!(annotations(&project), before);
        assert!(project.annotation_list().types.is_empty());
        assert!(project.annotation_list().signatures.is_empty());
    }
}
