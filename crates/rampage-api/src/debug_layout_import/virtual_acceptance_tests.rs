use std::path::PathBuf;

use rampage_analysis::classes::HeaderClassification;
use serde_json::Value;

use super::*;

fn oracle() -> Value {
    serde_json::from_str(include_str!("../../../../tests/fixtures/debug-cpp-virtuals/oracle.json")).unwrap()
}

fn image(variant: &str, group: &str, control: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES").expect("owned virtual fixture wrapper"))
        .join(variant)
        .join(format!("{group}.{control}.elf"))
}

struct LogFiles(PathBuf);

impl LogFiles {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("virtual-api-{}-{next}.jsonl", std::process::id())))
    }
}

impl Drop for LogFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("jsonl.lock"));
    }
}

fn open(path: &std::path::Path, log: &std::path::Path) -> Project {
    Project::with_annotations(
        rampage_loaders::Binary::open(path).unwrap(),
        Annotations::open_checked(log.to_owned()).unwrap(),
    )
}

fn snapshot(project: &Project) -> Value {
    serde_json::to_value(project.annotation_list()).unwrap()
}

fn assert_source_links(project: &Project, review: &super::review::DebugLayoutReview, expected: &Value) {
    let expected_tables = expected["groups"]["records"]["tables"].as_array().unwrap();
    assert_eq!(review.virtual_evidence.tables.len(), expected_tables.len());
    let mut links = 0;
    for table in expected_tables {
        let symbol = table["symbol"].as_str().unwrap();
        let address = project.binary.symbol_by_name(symbol).unwrap().address;
        let actual = review.virtual_evidence.tables.iter().find(|actual| actual.raw.address == address).unwrap();
        assert_eq!(actual.raw.vtable_symbol, symbol);
        assert_eq!(actual.raw.header, HeaderClassification::UnverifiedPrefix);
        assert_eq!(actual.raw.raw_offset_word, 0);
        assert_eq!(actual.raw.offset_to_top, None);
        assert_eq!(actual.raw.rtti_candidate.address, 0);
        let words = table["words"].as_array().unwrap();
        assert_eq!(actual.raw.slots.len(), words.len() - 2);
        assert_eq!(actual.methods.len(), words.len() - 2);
        for (slot_index, linkage) in words.iter().skip(2).enumerate() {
            let linkage = linkage.as_str().unwrap();
            let entry = project.binary.symbol_by_name(linkage).unwrap().address;
            let slot = &actual.raw.slots[slot_index];
            assert_eq!(slot.raw_value, entry);
            assert_eq!(slot.target, Some(entry));
            let method = actual.methods.iter().find(|method| method.slot_index == slot_index as u64).unwrap();
            assert_eq!(method.declared_virtual_slot_index, slot_index as u64);
            assert_eq!(method.method_address, entry);
            assert_eq!(method.linkage_name, linkage);
            assert_eq!(method.verification, "native_checked_source_evidence");
            let raw = review
                .producer_report
                .as_ref()
                .unwrap()
                .signatures
                .iter()
                .find(|function| function.id == method.definition_id)
                .unwrap();
            let proof = raw.method.as_ref().unwrap();
            assert_eq!(proof.record_id, method.record_id);
            assert_eq!(proof.object_pointer_id, method.object_pointer_id);
            assert_eq!(proof.declaration_id, method.declaration_id);
            assert_eq!(proof.virtual_slot, Some(slot_index as u64));
            links += 1;
        }
    }
    assert_eq!(links, 4, "both independently emitted tables require two exact source-method associations");
}

#[test]
#[ignore = "requires centrally compiled owned virtual C++ fixtures through the --check wrapper"]
fn projected_storage_and_source_links_survive_apply_reopen_and_one_atomic_undo() {
    let expected = oracle();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let path = image(variant, "records", "debug");
        let log = LogFiles::new();
        let project = open(&path, &log.0);
        let entry = project.binary.symbol_by_name("_ZN13VirtualRecord9readCountEv").unwrap().address;
        let before_native = project.decompile(entry).unwrap();
        let before = snapshot(&project);
        let source_checks = super::source_evidence::source_validation_count();
        let review = project.review_debug_layouts().unwrap();
        assert_eq!(super::source_evidence::source_validation_count() - source_checks, 1);
        assert_eq!(snapshot(&project), before);
        assert!(!log.0.exists());
        assert!(project.undo().unwrap().is_empty());
        let retained_native = project.decompile(entry).unwrap();
        assert_eq!(retained_native.code, before_native.code, "preview cannot publish its temporary native type state");
        assert_eq!(retained_native.structure, before_native.structure);
        assert_source_links(&project, &review, &expected);
        assert_eq!(review.report.types.len(), 2);
        for ty in &review.report.types {
            assert_eq!((ty.layout.size, ty.layout.alignment), (16, 8));
            assert_eq!(ty.projections.len(), 1);
            assert_eq!(ty.layout.fields[0].name, "rampage_vptr");
            assert_eq!((ty.layout.fields[0].offset, ty.layout.fields[0].size), (0, 8));
            assert!(matches!(&ty.layout.fields[0].ty,
                LayoutType::Pointer { pointee, .. } if pointee.kind == ScalarKind::Void));
        }
        let evidence = serde_json::to_value(&review.virtual_evidence).unwrap();
        let imported = project.apply_reviewed_debug_layouts(&review.review_sha256).unwrap().imported.unwrap();
        assert_eq!(imported.applied.len(), 6);
        let annotations = project.annotation_list();
        assert_eq!(annotations.types.len(), 1);
        assert!(annotations.types[0].text.starts_with(TYPE_MAGIC_V2));
        let reopened = open(&path, &log.0);
        let source_checks = super::source_evidence::source_validation_count();
        let persisted = reopened.review_debug_layouts().unwrap();
        assert_eq!(super::source_evidence::source_validation_count() - source_checks, 1);
        assert!(persisted.approved.is_empty());
        assert_eq!(serde_json::to_value(&persisted.virtual_evidence).unwrap(), evidence);
        assert_source_links(&reopened, &persisted, &expected);
        for method in expected["groups"]["records"]["methods"].as_array().unwrap() {
            let symbol = method["symbol"].as_str().unwrap();
            let entry = project.binary.symbol_by_name(symbol).unwrap().address;
            let result = reopened.decompile(entry).unwrap();
            assert!(result.code.contains(&format!("->{}", method["field"].as_str().unwrap())), "{}", result.code);
            assert_eq!(u64::from(result.structure.signature.return_type.size), method["return_size"].as_u64().unwrap());
            assert_eq!(result.structure.signature.parameters.len(), if method["access"] == "write" { 2 } else { 1 });
        }
        assert_eq!(project.undo().unwrap().len(), imported.applied.len() + 1);
        assert_eq!(snapshot(&project), before);
        assert!(!reopened.refresh_annotations().unwrap() || reopened.annotation_list().types.is_empty());
        assert!(reopened.annotation_list().signatures.is_empty());
    }
}

#[test]
#[ignore = "requires centrally compiled owned virtual C++ fixtures through the --check wrapper"]
fn preserved_analyst_prototypes_do_not_become_source_proof_and_are_never_overwritten_by_it() {
    let expected = oracle();
    let path = image("dwarf5-o2", "records", "debug");
    let log = LogFiles::new();
    let project = open(&path, &log.0);
    for method in expected["groups"]["records"]["methods"].as_array().unwrap() {
        let entry = project.binary.symbol_by_name(method["symbol"].as_str().unwrap()).unwrap().address;
        project.set_signature(entry, Some("int4 analyst(void *opaque);")).unwrap();
    }
    let before = snapshot(&project);
    let bytes = std::fs::read(&log.0).unwrap();
    let source_checks = super::source_evidence::source_validation_count();
    let review = project.review_debug_layouts().unwrap();
    assert_eq!(super::source_evidence::source_validation_count() - source_checks, 1);
    assert!(review.approved.is_empty());
    assert_source_links(&project, &review, &expected);
    assert_eq!(snapshot(&project), before);
    assert_eq!(std::fs::read(&log.0).unwrap(), bytes);
    let imported = project.apply_reviewed_debug_layouts(&review.review_sha256).unwrap().imported.unwrap();
    assert!(imported.applied.is_empty() && imported.imported_types.is_empty());
    assert_eq!(snapshot(&project), before);
    assert!(!project.undo().unwrap().is_empty(), "the original analyst edit remains the next undo step");
}

#[test]
#[ignore = "requires centrally compiled owned virtual C++ fixtures through the --check wrapper"]
fn an_unvalidated_source_prototype_cannot_publish_native_checked_virtual_links() {
    let path = image("dwarf5-o2", "records", "debug");
    let project = Project::new(rampage_loaders::Binary::open(path).unwrap());
    let mut preview = project.preview_debug_layouts().unwrap();
    let producer = preview.producer.take().unwrap();
    let raw = producer
        .signatures
        .iter()
        .find(|function| function.method.as_ref().is_some_and(|m| m.virtual_slot.is_some()))
        .unwrap();
    let function = preview.report.functions.iter_mut().find(|function| function.address == raw.address).unwrap();
    function.declaration = format!("unknown_source_return method({} *self);", function.dependencies[0]);
    let before = snapshot(&project);
    let source_checks = super::source_evidence::source_validation_count();
    assert!(super::source_evidence::checked_virtual_source_evidence(&project, &producer, &preview).is_err());
    assert_eq!(super::source_evidence::source_validation_count() - source_checks, 1);
    assert_eq!(snapshot(&project), before);
    assert!(project.undo().unwrap().is_empty());
}
