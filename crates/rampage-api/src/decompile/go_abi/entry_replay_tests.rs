use super::*;
use crate::annotations::{Annotations, Field};

fn project(arch: Arch) -> Project {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    let mut binary = rampage_loaders::Binary::open(fixture).unwrap();
    binary.arch = arch;
    Project::new(binary)
}

fn options() -> DecompilerOptions {
    DecompilerOptions { compiler: Some("golang".to_owned()), ..Default::default() }
}

#[test]
fn entry_generates_direct_alias_and_nested_canonical_dependencies_without_go_cache_access() {
    for arch in [Arch::X86_64, Arch::Aarch64] {
        let project = project(arch);
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Types, 0x8000_0000, Some("typedef go_results_2 analyst_pair;".to_owned())).unwrap();
        annotations
            .set(
                Field::Types,
                0x9000_0000,
                Some("struct analyst_box { analyst_pair pair; struct { go_results_3 triple; } nested; };".to_owned()),
            )
            .unwrap();
        annotations.set(Field::Global, 0xa000_0000, Some("go_results_4 shared_results;".to_owned())).unwrap();
        annotations
            .set(Field::Signature, 0xb000_0000, Some("go_results_5 analyst(analyst_box *box);".to_owned()))
            .unwrap();
        let generated = entry_types(&project, &annotations, &options()).unwrap();
        assert_eq!(generated, [result_type(2), result_type(3), result_type(4), result_type(5)]);
        assert_eq!(generated[0], "typedef struct { xunknown8 r0; xunknown8 r1; } go_results_2;");
        assert!(project.cached_analysis().is_none());
        assert!(project.go_prototypes.get().is_none());
    }
}

#[test]
fn entry_types_precede_analyst_dependencies_and_never_add_inferred_prototypes() {
    let project = project(Arch::X86_64);
    let address = project.binary.entry.unwrap();
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 1, Some("struct analyst_box { go_results_2 pair; };".to_owned())).unwrap();
    annotations
        .set(Field::Types, 2, Some("typedef struct{xunknown8 r0; xunknown8 r1;}go_results_2;".to_owned()))
        .unwrap();
    let actual = "go_results_2 analyst(analyst_box *box);";
    annotations.set(Field::Signature, address, Some(actual.to_owned())).unwrap();
    let poison = GoPrototypes {
        declarations: BTreeMap::from([(address, "void inferred_wrong(void);".to_owned())]),
        types: vec!["typedef int4 inferred_wrong_type;".to_owned()],
    };
    project.go_prototypes.set(poison).ok().unwrap();
    let generated = entry_types(&project, &annotations, &options()).unwrap();
    let operations = super::super::types::plan_entry(&project, &annotations, &generated, &BTreeMap::new()).unwrap();
    let parsed: Vec<_> = operations
        .iter()
        .filter_map(|operation| match operation {
            WorkerOperation::ParseTypes { declarations } => Some(declarations.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(parsed, [generated[0].as_str(), "struct analyst_box { go_results_2 pair; };"]);
    let prototypes: Vec<_> = operations
        .iter()
        .filter_map(|operation| match operation {
            WorkerOperation::Prototype { address: at, indirect, declaration } => {
                Some((*at, *indirect, declaration.as_str()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(prototypes, [(address, false, actual)]);
    assert!(project.cached_analysis().is_none());
}

#[test]
fn entry_rejects_shadowing_ambiguous_uses_and_unsupported_canonical_shapes() {
    for declaration in [
        "typedef int4 go_results_2;",
        "typedef struct { int4 changed; } go_results_2;",
        "struct go_results_2 { xunknown8 r0; xunknown8 r1; };",
        "struct named { int4 go_results_2; };",
        "typedef go_results_0 unsupported;",
        "typedef go_results_1 unsupported;",
        "typedef go_results_01 unsupported;",
        "typedef go_results_10 unsupported;",
        "typedef go_results_999999999999999999999 unsupported;",
    ] {
        let project = project(Arch::X86_64);
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Types, 1, Some(declaration.to_owned())).unwrap();
        let error = entry_types(&project, &annotations, &options()).unwrap_err().to_string();
        assert!(error.contains("entry Go type dependency"), "{declaration}: {error}");
        assert!(project.cached_analysis().is_none());
        assert!(project.go_prototypes.get().is_none());
    }
    let project = project(Arch::X86_64);
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, 1, Some("void analyst(go_results_2);".to_owned())).unwrap();
    assert!(entry_types(&project, &annotations, &options()).unwrap_err().to_string().contains("ambiguous"));
}

#[test]
fn entry_canonical_dependencies_are_bounded_by_the_selected_go_target() {
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, 1, Some("go_results_16 analyst(void);".to_owned())).unwrap();
    let arm = project(Arch::Aarch64);
    assert_eq!(entry_types(&arm, &annotations, &options()).unwrap(), [result_type(16)]);
    assert!(entry_types(&arm, &annotations, &DecompilerOptions::default()).is_err());
    assert!(entry_types(&project(Arch::X86_64), &annotations, &options()).is_err());
    assert!(entry_types(&project(Arch::X86), &annotations, &options()).is_err());
    let mut big_endian = project(Arch::Aarch64);
    big_endian.binary.big_endian = true;
    assert!(entry_types(&big_endian, &annotations, &options()).is_err());
}

#[test]
fn entry_go_replay_without_actual_dependencies_never_initializes_inference() {
    let project = project(Arch::X86_64);
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, 1, Some("int4 analyst(void);".to_owned())).unwrap();
    assert!(entry_types(&project, &annotations, &options()).unwrap().is_empty());
    assert!(entry_types(&project, &annotations, &DecompilerOptions::default()).unwrap().is_empty());
    assert!(project.cached_analysis().is_none());
    assert!(project.go_prototypes.get().is_none());
}

#[test]
fn entry_rejects_annotation_count_and_text_overflow_before_scanning_declarations() {
    let project = project(Arch::X86_64);
    let mut annotations = Annotations::in_memory();
    let changes: Vec<_> = (0..1024).map(|address| (Field::Global, address, Some("int4 value;".to_owned()))).collect();
    annotations.set_batch_validated(&changes, |_| Ok(())).unwrap();
    entry_types(&project, &annotations, &options()).unwrap();
    annotations.set(Field::Types, 2048, Some("#".to_owned())).unwrap();
    let error = entry_types(&project, &annotations, &options()).unwrap_err().to_string();
    assert!(error.contains("declaration count"), "{error}");

    let mut annotations = Annotations::in_memory();
    let text = format!("int4 value;{}", " ".repeat(65536 - "int4 value;".len()));
    let changes: Vec<_> = (0..16).map(|address| (Field::Global, address, Some(text.clone()))).collect();
    annotations.set_batch_validated(&changes, |_| Ok(())).unwrap();
    entry_types(&project, &annotations, &options()).unwrap();
    annotations.set(Field::Types, 2048, Some("#".to_owned())).unwrap();
    let error = entry_types(&project, &annotations, &options()).unwrap_err().to_string();
    assert!(error.contains("replay text"), "{error}");
    assert!(project.cached_analysis().is_none());
    assert!(project.go_prototypes.get().is_none());
}

#[test]
fn legacy_go_plan_keeps_generated_types_and_analyst_signature_precedence() {
    let project = project(Arch::X86_64);
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, 1, Some("int4 analyst(void);".to_owned())).unwrap();
    let types = vec![result_type(2)];
    project
        .go_prototypes
        .set(GoPrototypes {
            declarations: BTreeMap::from([
                (1, "void inferred_one(void);".to_owned()),
                (2, "void inferred_two(void);".to_owned()),
            ]),
            types: types.clone(),
        })
        .ok()
        .unwrap();
    let legacy = plan(&project, &annotations, &options());
    assert_eq!(legacy.types, types);
    assert!(legacy.prototypes.iter().all(|operation| matches!(
        operation,
        WorkerOperation::Symbol { address: 2, .. } | WorkerOperation::Prototype { address: 2, .. }
    )));
    assert_eq!(legacy.prototypes.len(), 2);
    assert!(plan(&project, &annotations, &DecompilerOptions::default()).types.is_empty());
}
