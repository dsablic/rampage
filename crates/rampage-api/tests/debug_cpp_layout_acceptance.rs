use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rampage_api::annotations::Annotations;
use rampage_api::{DebugLayoutReview, Project};
use rampage_loaders::Binary;
use serde::Deserialize;

#[derive(Deserialize)]
struct Oracle {
    target: Target,
    constant_encoding: Encoding,
    layout: Layout,
    records: BTreeMap<String, Record>,
    groups: BTreeMap<String, Group>,
}

#[derive(Deserialize)]
struct Target {
    address_size: u64,
    max_binary_bytes: u64,
}

#[derive(Deserialize)]
struct Encoding {
    magic: String,
    version: u64,
    byte_order_tag: u64,
    byte_size: u64,
}

#[derive(Deserialize)]
struct Layout {
    size: u64,
    alignment: u64,
    fields: Vec<Field>,
}

#[derive(Deserialize)]
struct Field {
    name: String,
    offset: u64,
    size: u64,
    alignment: u64,
    kind: String,
}

#[derive(Deserialize)]
struct Record {
    tag: String,
    symbol: String,
}

#[derive(Deserialize)]
struct Group {
    #[serde(default)]
    methods: Vec<Method>,
}

#[derive(Deserialize)]
struct Method {
    symbol: String,
    object: String,
    field: String,
    access: String,
}

fn oracle() -> Oracle {
    serde_json::from_str(include_str!("../../../tests/fixtures/debug-cpp-layouts/oracle.json")).unwrap()
}

fn image(variant: &str, group: &str, control: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_CPP_LAYOUT_FIXTURES").expect("owned C++ fixture wrapper required"))
        .join(variant)
        .join(format!("{group}.{control}.elf"))
}

struct LogFiles(PathBuf);

impl LogFiles {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("rampage-cpp-layout-{}-{next}.jsonl", std::process::id())))
    }
}

impl Drop for LogFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("jsonl.lock"));
    }
}

fn open(path: &Path, log: &Path) -> Project {
    Project::with_annotations(Binary::open(path).unwrap(), Annotations::open_checked(log.to_owned()).unwrap())
}

fn annotations(project: &Project) -> serde_json::Value {
    serde_json::to_value(project.annotation_list()).unwrap()
}

fn source_constants(binary: &Binary, oracle: &Oracle) {
    assert!(binary.image_bytes().len() as u64 <= oracle.target.max_binary_bytes);
    let encoding = &oracle.constant_encoding;
    let mut expected = vec![
        u64::from_str_radix(encoding.magic.strip_prefix("0x").unwrap(), 16).unwrap(),
        encoding.version,
        oracle.target.address_size,
        encoding.byte_order_tag,
        oracle.layout.size,
        oracle.layout.alignment,
        oracle.layout.fields.len() as u64,
    ];
    for field in &oracle.layout.fields {
        expected.extend([field.offset, field.size, field.alignment]);
    }
    assert_eq!(expected.len() as u64 * 8, encoding.byte_size);
    for name in ["checked", "companion"] {
        let symbol = binary.symbol_by_name(&oracle.records[name].symbol).unwrap();
        assert_eq!(symbol.size, encoding.byte_size);
        let segment = binary.segment_containing(symbol.address).unwrap();
        assert!(segment.perms.read && !segment.perms.write && !segment.perms.execute);
        let bytes = binary.read(symbol.address, symbol.size).unwrap();
        assert!(bytes.as_chunks::<8>().1.is_empty());
        let measured: Vec<_> = bytes.as_chunks::<8>().0.iter().map(|word| u64::from_le_bytes(*word)).collect();
        assert_eq!(measured, expected, "independent compiler constants for {}", oracle.records[name].tag);
    }
}

fn method_address(project: &Project, method: &Method) -> u64 {
    project.binary.symbol_by_name(&method.symbol).expect("independent mangled method symbol").address
}

fn assert_layouts(review: &DebugLayoutReview, oracle: &Oracle) {
    for record in ["checked", "companion"] {
        let expected = &oracle.records[record];
        let native = review.report.types.iter().find(|ty| ty.original_name == expected.tag).expect("producer record");
        assert_eq!(u64::from(native.layout.size), oracle.layout.size);
        assert_eq!(u64::from(native.layout.alignment), oracle.layout.alignment);
        assert_eq!(native.layout.fields.len(), oracle.layout.fields.len());
        for (actual, field) in native.layout.fields.iter().zip(&oracle.layout.fields) {
            assert_eq!(actual.name, field.name);
            assert_eq!((u64::from(actual.offset), u64::from(actual.size)), (field.offset, field.size));
            match (&actual.ty, field.kind.as_str()) {
                (rampage_decompiler::layout::LayoutType::Scalar { scalar }, expected) => {
                    let category = match expected {
                        "signed" => rampage_decompiler::layout::ScalarKind::SignedInteger,
                        "unsigned" => rampage_decompiler::layout::ScalarKind::UnsignedInteger,
                        "float" => rampage_decompiler::layout::ScalarKind::Float,
                        _ => panic!("unexpected source scalar category {expected}"),
                    };
                    assert_eq!(scalar.kind, category);
                    assert_eq!(u64::from(scalar.alignment), field.alignment);
                }
                (rampage_decompiler::layout::LayoutType::Pointer { size, alignment, pointee, .. }, "pointer") => {
                    assert_eq!(u64::from(*size), field.size);
                    assert_eq!(u64::from(*alignment), field.alignment);
                    assert_eq!(pointee.kind, rampage_decompiler::layout::ScalarKind::SignedInteger);
                }
                _ => panic!("consumer changed source field category for {}", field.name),
            }
        }
    }
}

#[test]
#[ignore = "requires centrally compiled owned C++ fixtures through the --check wrapper"]
fn exact_class_and_struct_methods_use_one_producer_bound_this_parameter_and_actual_fields_after_reopen() {
    let oracle = oracle();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let path = image(variant, "records", "debug");
        let logs = LogFiles::new();
        let project = open(&path, &logs.0);
        source_constants(&project.binary, &oracle);
        let before = annotations(&project);
        let review = project.review_debug_layouts().unwrap();
        assert_layouts(&review, &oracle);
        assert_eq!(annotations(&project), before);
        assert!(!logs.0.exists());
        assert!(project.undo().unwrap().is_empty());
        let methods = &oracle.groups["records"].methods;
        for method in methods {
            let address = method_address(&project, method);
            assert!(review.approved.contains(&address), "{} was not admitted", method.symbol);
            let function = review.report.functions.iter().find(|function| function.address == address).unwrap();
            assert_eq!(function.original_name, method.symbol, "method identity is its exact linkage name");
            let record = method.object.strip_suffix(" *").unwrap();
            let dependency = review.report.types.iter().find(|ty| ty.original_name == record).unwrap();
            assert_eq!(function.dependencies.as_slice(), std::slice::from_ref(&dependency.layout.name));
            let producer = review.producer_report.as_ref().unwrap();
            let raw = producer.signatures.iter().find(|function| function.address == address).unwrap();
            let proof = raw.method.as_ref().expect("explicit method association, not a wrapper signature");
            let producer_record = producer.layouts.iter().find(|layout| layout.id == proof.record_id).unwrap();
            assert_eq!(producer_record.original_name.as_deref(), Some(record));
            assert_eq!(proof.linkage_name, method.symbol);
            assert_eq!(proof.object_pointer_id, raw.parameters[0].id);
            assert!(matches!(&raw.parameters[0].ty,
                rampage_loaders::debug::DebugLayoutValue::StructPointer { layout_id, .. }
                if *layout_id == proof.record_id));
            let return_type = match method.access.as_str() {
                "write" => "void ",
                "read-unsigned" => "uint4 ",
                "read" | "read-signed" => "int4 ",
                other => panic!("unexpected source access category {other}"),
            };
            assert!(function.declaration.starts_with(return_type), "{}", function.declaration);
        }
        let imported = project.apply_reviewed_debug_layouts(&review.review_sha256).unwrap().imported.unwrap();
        let reopened = open(&path, &logs.0);
        for method in methods {
            let address = method_address(&project, method);
            assert!(imported.applied.contains(&address));
            let native = project.decompile(address).unwrap();
            let persisted = reopened.decompile(address).unwrap();
            assert_eq!(persisted.code, native.code);
            assert_eq!(persisted.structure, native.structure);
            let parameters = &native.structure.signature.parameters;
            let writes = method.access == "write";
            assert_eq!(parameters.len(), if writes { 2 } else { 1 });
            assert!(!native.structure.signature.variadic);
            assert_eq!(u64::from(parameters[0].data_type.size), oracle.target.address_size);
            assert!(native.code.contains(&format!("->{}", method.field)), "{}", native.code);
            let compact: String = native.code.chars().filter(|character| !character.is_whitespace()).collect();
            if writes {
                let right = compact.split_once(&format!("->{}=", method.field)).expect("actual field store").1;
                assert!(!right.starts_with('='));
                assert!(right.split(';').next().unwrap().contains(&parameters[1].name));
                assert_eq!(native.structure.signature.return_type.size, 0);
            } else {
                assert!(compact.contains("return"));
                let int_width = oracle.layout.fields.iter().find(|field| field.name == "count").unwrap().size;
                assert_eq!(u64::from(native.structure.signature.return_type.size), int_width);
            }
        }
        project.undo().unwrap();
        assert_eq!(annotations(&project), before);
    }
}

#[test]
#[ignore = "requires centrally compiled owned C++ fixtures through the --check wrapper"]
fn cpp_method_approval_preserves_analyst_signatures_and_undo_keeps_their_edits() {
    let oracle = oracle();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let path = image(variant, "records", "debug");
        let logs = LogFiles::new();
        let project = open(&path, &logs.0);
        let method = &oracle.groups["records"].methods[0];
        let address = method_address(&project, method);
        project.set_signature(address, Some("int4 analyst_method(void *opaque);")).unwrap();
        let before = annotations(&project);
        let review = project.review_debug_layouts().unwrap();
        assert!(review.preserved.contains(&address));
        assert!(!review.approved.contains(&address));
        assert!(!review.approved.is_empty());
        let imported = project.apply_reviewed_debug_layouts(&review.review_sha256).unwrap().imported.unwrap();
        assert!(!imported.applied.contains(&address));
        assert!(project.decompile(address).unwrap().code.contains("opaque"));
        assert!(!project.undo().unwrap().is_empty());
        assert_eq!(annotations(&project), before);
    }
}

#[test]
#[ignore = "requires centrally compiled owned C++ fixtures through the --check wrapper"]
fn unsupported_cpp_records_and_symbols_only_controls_never_install_dependent_types_or_methods() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let controls = [
            ("records", "symbols"),
            ("unaligned", "debug"),
            ("const-method", "debug"),
            ("reference-argument", "debug"),
            ("byvalue", "debug"),
            ("virtual", "debug"),
            ("inherited", "debug"),
            ("static-method", "debug"),
        ];
        for (group, control) in controls {
            let path = image(variant, group, control);
            let logs = LogFiles::new();
            let project = open(&path, &logs.0);
            let before = annotations(&project);
            let review = project.review_debug_layouts().unwrap();
            assert!(review.approved.is_empty(), "{variant}/{group}/{control}: {:?}", review.approved);
            let imported = project.apply_reviewed_debug_layouts(&review.review_sha256).unwrap().imported.unwrap();
            assert!(imported.applied.is_empty() && imported.imported_types.is_empty());
            assert_eq!(annotations(&project), before);
            assert!(!logs.0.exists());
            assert!(project.undo().unwrap().is_empty());
        }
    }
}

#[test]
#[ignore = "requires centrally compiled owned C++ fixtures through the --check wrapper"]
fn a_changed_cpp_method_signature_cannot_reuse_the_previous_review_fingerprint() {
    let oracle = oracle();
    let path = image("dwarf5-o2", "records", "debug");
    let logs = LogFiles::new();
    let project = open(&path, &logs.0);
    let review = project.review_debug_layouts().unwrap();
    let method = &oracle.groups["records"].methods[0];
    let address = method_address(&project, method);
    project.set_signature(address, Some("int4 analyst_method(void *opaque);")).unwrap();
    let before = annotations(&project);
    assert!(project.apply_reviewed_debug_layouts(&review.review_sha256).is_err());
    assert_eq!(annotations(&project), before);
    assert_eq!(project.annotation_list().signatures.len(), 1);
    assert!(project.annotation_list().types.is_empty());
    let producer_entries: BTreeSet<_> = review.report.functions.iter().map(|function| function.address).collect();
    assert!(producer_entries.contains(&address));
}
