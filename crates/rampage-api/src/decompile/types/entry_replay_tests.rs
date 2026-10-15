use super::*;
use crate::annotations::{Annotations, Field};
use crate::debug_layout_import::{LayoutBundle, current_specification_digest, image_digest, seal_signature};
use rampage_decompiler::layout::{
    LayoutField, LayoutOrganization, LayoutScalar, LayoutType, PlainStructLayout, ScalarKind,
};

fn project() -> crate::Project {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    crate::Project::new(rampage_loaders::Binary::open(fixture).unwrap())
}

fn layout() -> PlainStructLayout {
    PlainStructLayout {
        name: "entry_record".to_owned(),
        size: 4,
        alignment: 4,
        organization: LayoutOrganization {
            pointer_size: 8,
            int_size: 4,
            long_size: 8,
            scalar_alignments: [1, 2, 4, 8],
        },
        fields: vec![LayoutField {
            name: "value".to_owned(),
            offset: 0,
            size: 4,
            ty: LayoutType::Scalar {
                scalar: LayoutScalar {
                    name: "int4".to_owned(),
                    kind: ScalarKind::SignedInteger,
                    size: 4,
                    alignment: 4,
                },
            },
        }],
    }
}

#[test]
fn entry_replays_all_faraway_analyst_dependencies_globals_and_signatures() {
    let project = project();
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 0x9000_0000, Some("typedef int4 distant_scalar;".to_owned())).unwrap();
    annotations
        .set(Field::Types, 0xa000_0000, Some("struct distant_record { distant_scalar value; };".to_owned()))
        .unwrap();
    annotations.set(Field::Global, 0xb000_0000, Some("distant_record shared_record;".to_owned())).unwrap();
    annotations
        .set(Field::Signature, 0xc000_0000, Some("distant_scalar analyst(distant_record *record);".to_owned()))
        .unwrap();
    let operations = plan_entry(&project, &annotations, &[], &BTreeMap::new()).unwrap();
    let parsed: Vec<_> = operations
        .iter()
        .filter_map(|operation| match operation {
            WorkerOperation::ParseTypes { declarations } => Some(declarations.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(parsed, ["typedef int4 distant_scalar;", "struct distant_record { distant_scalar value; };"]);
    assert!(operations.iter().any(|operation| matches!(
        operation,
        WorkerOperation::Global { address: 0xb000_0000, declaration } if declaration == "distant_record shared_record;"
    )));
    assert!(operations.iter().any(|operation| matches!(
        operation,
        WorkerOperation::Prototype { address: 0xc000_0000, indirect: false, declaration }
            if declaration == "distant_scalar analyst(distant_record *record);"
    )));
    assert!(project.cached_analysis().is_none());
    assert!(project.go_prototypes.get().is_none());
}

#[test]
fn entry_propagates_import_signatures_only_to_exact_supplied_stubs() {
    let mut project = project();
    let code = project.binary.entry.unwrap();
    let slot = 0x8000_0000;
    project.binary.import_slots =
        vec![rampage_loaders::ImportSlot { address: slot, name: "entry_import".to_owned(), library: None }];
    let mut annotations = Annotations::in_memory();
    let declaration = "int4 analyst_import(int4 value);";
    annotations.set(Field::Signature, slot, Some(declaration.to_owned())).unwrap();
    let targets = BTreeMap::from([(slot, vec![code + 1, code + 3]), (slot + 8, vec![code + 5])]);
    let operations = plan_entry(&project, &annotations, &[], &targets).unwrap();
    let prototypes: Vec<_> = operations
        .iter()
        .filter_map(|operation| match operation {
            WorkerOperation::Prototype { address, indirect, declaration: actual } => {
                assert_eq!(actual, declaration);
                Some((*address, *indirect))
            }
            _ => None,
        })
        .collect();
    assert_eq!(prototypes, [(slot, true), (code + 1, false), (code + 3, false)]);
    let unpropagated = plan_entry(&project, &annotations, &[], &BTreeMap::new()).unwrap();
    assert_eq!(unpropagated.len(), 1);
    assert!(project.cached_analysis().is_none());
}

#[test]
fn entry_assertions_follow_all_types_and_precede_every_global_and_signature() {
    let project = project();
    let text = LayoutBundle::encode(&image_digest(&project).unwrap(), &[layout()]).unwrap();
    let bundle = LayoutBundle::decode(&text).unwrap().unwrap();
    let sealed = seal_signature("int4 analyst(entry_record *record);", &[&bundle.layouts[0]]).unwrap();
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 0x9000_0000, Some(text)).unwrap();
    annotations.set(Field::Types, 0xa000_0000, Some("typedef int4 faraway_alias;".to_owned())).unwrap();
    annotations.set(Field::Global, 0xb000_0000, Some("entry_record stored;".to_owned())).unwrap();
    annotations.set(Field::Signature, 0xc000_0000, Some(sealed)).unwrap();
    let generated = ["typedef uint8 generated_dependency;".to_owned()];
    let operations = plan_entry(&project, &annotations, &generated, &BTreeMap::new()).unwrap();
    let assertion = operations
        .iter()
        .position(|operation| matches!(operation, WorkerOperation::AssertPlainStructLayout { .. }))
        .unwrap();
    assert!(operations[..assertion].iter().all(|operation| matches!(operation, WorkerOperation::ParseTypes { .. })));
    assert!(operations[assertion + 1..].iter().all(|operation| !matches!(
        operation,
        WorkerOperation::ParseTypes { .. } | WorkerOperation::AssertPlainStructLayout { .. }
    )));
    match &operations[assertion] {
        WorkerOperation::AssertPlainStructLayout { layout: actual, expected_context } => {
            assert_eq!(actual, &layout());
            assert_eq!(expected_context.as_deref(), Some(current_specification_digest().unwrap().as_str()));
        }
        _ => unreachable!(),
    }
    assert!(project.cached_analysis().is_none());
    assert!(project.go_prototypes.get().is_none());
}

#[test]
fn entry_plain_c_replay_matches_legacy_operations_byte_for_byte() {
    let project = project();
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 1, Some("typedef int4 analyst_integer;".to_owned())).unwrap();
    annotations.set(Field::Global, 2, Some("analyst_integer count;".to_owned())).unwrap();
    annotations.set(Field::Signature, 3, Some("analyst_integer analyst(void);".to_owned())).unwrap();
    let legacy = plan(&project, &annotations, &[]).unwrap();
    let entry = plan_entry(&project, &annotations, &[], &BTreeMap::new()).unwrap();
    assert_eq!(serde_json::to_vec(&legacy).unwrap(), serde_json::to_vec(&entry).unwrap());
}
