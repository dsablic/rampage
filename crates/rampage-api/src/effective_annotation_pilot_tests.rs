use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use rampage_loaders::Binary;

use crate::annotations::{
    Annotations, DataTypeAnnotation, Field, OperandTypeAnnotation, OperandTypeKind, encode_data_type,
    encode_operand_types,
};
use crate::{
    ApplyDataTypeRequest, ApplyOperandTypeRequest, DataStringEncoding, DecompileEntryRequest, EntryValidation,
    FunctionsQuery, Project, TypedDataQuery,
};

fn assert_entry(project: &Project, address: u64, name: &str, value: u8) {
    let result = project
        .decompile_entry(&DecompileEntryRequest { address, validation: EntryValidation::MetadataBacked })
        .unwrap();
    assert_eq!(result.decompilation.name, name);
    assert!(result.decompilation.code.contains(name), "{}", result.decompilation.code);
    assert!(result.decompilation.code.contains(&format!("return {value};")), "{}", result.decompilation.code);
}

#[test]
fn held_patch_exact_entry_keeps_names_and_code_until_a_new_effective_snapshot() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let original = Arc::new(Project::new(Binary::open(path).unwrap()));
    let main = original.resolve("main").unwrap();
    original.rename(main, Some("pilot_old_entry")).unwrap();
    original.functions(&FunctionsQuery::default()).unwrap();
    assert!(original.cached_analysis().is_some());
    assert_entry(&original, main, "pilot_old_entry", 5);
    {
        let _writer = original.annotations.write().unwrap();
        assert!(
            original
                .decompile_entry(&DecompileEntryRequest { address: main, validation: EntryValidation::MetadataBacked })
                .unwrap_err()
                .to_string()
                .contains("annotations are busy")
        );
    }

    let held = original.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project;
    assert!(held.cached_analysis().is_none());
    assert_entry(&held, main, "pilot_old_entry", 7);
    held.rename(main, Some("pilot_new_entry")).unwrap();
    {
        let writer = held.annotations.write().unwrap();
        assert_eq!(writer.name(main), Some("pilot_new_entry"));
        assert_entry(&held, main, "pilot_old_entry", 7);
        assert_entry(&original, main, "pilot_old_entry", 5);
    }
    {
        let _frozen_writer = held.frozen_annotations.get().unwrap().write().unwrap();
        assert!(
            held.decompile_entry(&DecompileEntryRequest { address: main, validation: EntryValidation::MetadataBacked })
                .unwrap_err()
                .to_string()
                .contains("annotations are busy")
        );
    }
    let current = held.effective_snapshot().unwrap();
    assert!(!Arc::ptr_eq(&held, &current));
    assert!(current.cached_analysis().is_none());
    assert_entry(&current, main, "pilot_new_entry", 7);
    assert!(current.cached_analysis().is_none());

    let latest = current.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 9, 0, 0, 0], false).unwrap().project;
    assert_entry(&latest, main, "pilot_new_entry", 9);
    assert_entry(&current, main, "pilot_new_entry", 7);
    assert_entry(&held, main, "pilot_old_entry", 7);
    assert!(held.cached_analysis().is_none());
    assert_entry(&original, main, "pilot_old_entry", 5);
}

fn frozen_metadata_project(annotations: Annotations) -> Project {
    let binary = Binary::from_snapshot_bytes(
        serde_json::to_vec(&serde_json::json!({
            "format": "rampage-snapshot-v1", "arch": "x86_64",
            "provenance": "Owned freeze-only annotation fixture; no byte patch admission is asserted",
            "regions": [
                {"name": "code", "address": "0x1000", "permissions": "r-x", "bytes": "48b80500000000000000c3"},
                {"name": "data", "address": "0x2000", "permissions": "rw-", "bytes": "6f6c6400"}
            ],
            "entry": "0x1000", "seeds": ["0x1000"]
        }))
        .unwrap(),
    )
    .unwrap();
    let snapshot = annotations.snapshot();
    let project = Project::with_annotations(binary, annotations);
    assert!(project.frozen_annotations.set(RwLock::new(snapshot)).is_ok());
    project
}

fn operand_display(project: &Project) -> String {
    let context = project.operand_listing_context().unwrap().expect("frozen operand binding");
    let displayed = context.display(project, 0x1000, &[0x48, 0xb8, 5, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(displayed.len(), 1);
    assert_eq!(displayed[0].width_bits, Some(64));
    displayed[0].display.clone()
}

#[test]
fn frozen_operand_listing_uses_held_bindings_and_types_but_edits_use_authority() {
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 0x9000, Some("enum Mode { MODE_OLD = 5 };".into())).unwrap();
    let binding = OperandTypeAnnotation {
        operand: 1,
        kind: OperandTypeKind::Enum,
        type_name: "Mode".into(),
        instruction_hex: "48b80500000000000000".into(),
    };
    annotations.set(Field::OperandType, 0x1000, Some(encode_operand_types(&[binding]).unwrap())).unwrap();
    let held = frozen_metadata_project(annotations);
    held.annotations.write().unwrap().set(Field::Types, 0x9000, Some("enum Mode { MODE_NEW = 5 };".into())).unwrap();
    assert_eq!(operand_display(&held), "Mode::MODE_OLD");
    let current = frozen_metadata_project(held.annotations.read().unwrap().snapshot());
    assert_eq!(operand_display(&current), "Mode::MODE_NEW");

    let clear = ApplyOperandTypeRequest { operand: 1, type_name: None, clear: true };
    assert!(held.apply_enum(0x1000, &clear).unwrap().changed);
    assert!(!held.apply_enum(0x1000, &clear).unwrap().changed);
    assert!(held.annotations.read().unwrap().operand_types().is_empty());
    assert_eq!(operand_display(&held), "Mode::MODE_OLD");
    let cleared = frozen_metadata_project(held.annotations.read().unwrap().snapshot());
    assert!(cleared.operand_listing_context().unwrap().is_none());
}

#[test]
fn frozen_typed_data_keeps_binding_and_label_while_edits_validate_authority() {
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Name, 0x2000, Some("pilot_old_data".into())).unwrap();
    let binding =
        DataTypeAnnotation { type_name: None, count: 1, byte_length: 3, encoding: Some(DataStringEncoding::Ascii) };
    annotations.set(Field::DataType, 0x2000, Some(encode_data_type(&binding).unwrap())).unwrap();
    let held = frozen_metadata_project(annotations);
    held.annotations.write().unwrap().set(Field::Name, 0x2000, Some("pilot_new_data".into())).unwrap();
    let request =
        ApplyDataTypeRequest { encoding: Some(DataStringEncoding::Ascii), byte_length: Some(4), ..Default::default() };
    assert!(held.apply_data_type(0x2000, &request).unwrap().changed);
    assert!(!held.apply_data_type(0x2000, &request).unwrap().changed);

    let query = TypedDataQuery { address: 0x2000, size: Some(4) };
    let old = held.read_data(&query).unwrap();
    assert_eq!(old.objects.len(), 1);
    assert_eq!(old.objects[0].name, "pilot_old_data");
    assert_eq!(old.objects[0].binding.byte_length, 3);
    assert_eq!(old.objects[0].fields[0].raw_hex.as_deref(), Some("6f6c64"));
    let current = frozen_metadata_project(held.annotations.read().unwrap().snapshot());
    let new = current.read_data(&query).unwrap();
    assert_eq!(new.objects.len(), 1);
    assert_eq!(new.objects[0].name, "pilot_new_data");
    assert_eq!(new.objects[0].binding.byte_length, 4);
    assert_eq!(new.objects[0].fields[0].raw_hex.as_deref(), Some("6f6c6400"));
}
