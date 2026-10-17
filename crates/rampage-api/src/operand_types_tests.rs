use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_arch::{MemoryOperand, Target};
use rampage_decompiler::{NamedEnumValue, NamedTypeField};
use rampage_loaders::Binary;

use super::*;

fn native(name: &str, kind: NamedTypeKind, size: u64) -> NamedType {
    NamedType {
        identity: None,
        name: name.into(),
        kind,
        size: Some(size),
        alignment: Some(4),
        incomplete: false,
        packing: None,
        fields: Vec::new(),
        enum_values: Vec::new(),
        target: None,
        array_length: None,
        callback: None,
        dependencies: Vec::new(),
        by_value_dependencies: Vec::new(),
    }
}

fn metadata() -> Vec<NamedType> {
    let mut mode = native("Mode", NamedTypeKind::Enum, 4);
    mode.enum_values = vec![
        NamedEnumValue { name: "MODE_READY".into(), value: "7".into() },
        NamedEnumValue { name: "MODE_BAD".into(), value: "-3".into() },
    ];
    let mut state = native("FieldState", NamedTypeKind::Struct, 8);
    state.fields = vec![
        NamedTypeField { identity: None, name: "prefix".into(), offset: 0, type_name: "int4".into(), size: Some(4) },
        NamedTypeField { identity: None, name: "bias".into(), offset: 4, type_name: "int4".into(), size: Some(4) },
    ];
    let mut alias = native("ModeAlias", NamedTypeKind::Typedef, 4);
    alias.target = Some("Mode".into());
    alias.identity = Some(serde_json::json!({"kind":14, "size":4, "typedef":{"reference":"Mode"}}));
    vec![mode, state, alias]
}

fn catalog() -> TypeCatalog {
    metadata().into_iter().map(|ty| (ty.name.clone(), ty)).collect()
}

fn annotation(kind: OperandTypeKind, name: &str, operand: u8, hex: &str) -> OperandTypeAnnotation {
    OperandTypeAnnotation { operand, kind, type_name: name.into(), instruction_hex: hex.into() }
}

fn operands(arch: rampage_arch::Arch, hex: &str) -> Vec<OperandEvidence> {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect::<Vec<_>>();
    rampage_arch::decoder(&Target::new(arch)).unwrap().operands(&bytes, 0x1000).unwrap()
}

#[test]
fn enum_uses_semantic_width_for_sign_extended_immediates_and_does_not_invent_flag_names() {
    let catalog = catalog();
    for (hex, expected, matched, value) in [
        ("83f807", "Mode::MODE_READY", true, 7),
        ("83f8fd", "Mode::MODE_BAD", true, 0xffff_fffd),
        ("83f809", "Mode(0x9)", false, 9),
    ] {
        let evidence = operands(rampage_arch::Arch::X86_64, hex);
        let entry = annotation(OperandTypeKind::Enum, "Mode", 1, hex);
        let display = display_entries(&[entry], hex, &evidence, &catalog).unwrap().remove(0);
        assert_eq!(display.display, expected);
        assert_eq!(display.matched, matched);
        assert_eq!(display.immediate, Some(value));
        assert_eq!(display.width_bits, Some(32));
    }
    let evidence = operands(rampage_arch::Arch::X86_64, "83f807");
    let alias = annotation(OperandTypeKind::Enum, "ModeAlias", 1, "83f807");
    assert_eq!(interpret(&alias, &evidence[1], &catalog).unwrap().display, "ModeAlias::MODE_READY");
}

#[test]
fn exact_integer_patterns_cover_signed_minimum_and_u64_maximum_without_float_conversion() {
    assert_eq!(enum_pattern("-9223372036854775808", 64, 64).unwrap(), 0x8000_0000_0000_0000);
    assert_eq!(enum_pattern("18446744073709551615", 64, 64).unwrap(), u64::MAX);
    assert_eq!(enum_pattern("-3", 8, 64).unwrap(), u64::MAX - 2);
    for value in ["-129", "256", "7.0", "1e2", "18446744073709551616"] {
        assert!(enum_pattern(value, 8, 32).is_err(), "{value}");
    }
    assert!(bit_mask(0).is_err());
    assert!(bit_mask(65).is_err());
}

#[test]
fn arm64_immediate_enum_uses_explicit_preferred_operand_order() {
    let evidence = operands(rampage_arch::Arch::Aarch64, "e0008052");
    let entry = annotation(OperandTypeKind::Enum, "Mode", 1, "e0008052");
    let display = display_entries(&[entry], "e0008052", &evidence, &catalog()).unwrap().remove(0);
    assert_eq!(display.display, "Mode::MODE_READY");
    assert_eq!(display.width_bits, Some(32));
}

#[test]
fn enums_do_not_synthesize_flag_combinations_and_large_values_serialize_as_exact_hex() {
    let mut catalog = catalog();
    catalog.get_mut("Mode").unwrap().enum_values = vec![
        NamedEnumValue { name: "ONE".into(), value: "1".into() },
        NamedEnumValue { name: "TWO".into(), value: "2".into() },
    ];
    let evidence = operands(rampage_arch::Arch::X86_64, "83f803");
    let entry = annotation(OperandTypeKind::Enum, "Mode", 1, "83f803");
    let display = interpret(&entry, &evidence[1], &catalog).unwrap();
    assert_eq!(display.display, "Mode(0x3)");
    assert!(!display.matched);
    catalog.get_mut("Mode").unwrap().enum_values.push(NamedEnumValue { name: "THREE".into(), value: "3".into() });
    assert_eq!(interpret(&entry, &evidence[1], &catalog).unwrap().display, "Mode::THREE");
    catalog.get_mut("Mode").unwrap().size = Some(8);
    catalog.get_mut("Mode").unwrap().enum_values.clear();
    let mut operand = evidence[1].clone();
    operand.width_bits = Some(64);
    operand.immediate = Some(u64::MAX);
    let display = interpret(&entry, &operand, &catalog).unwrap();
    assert_eq!(serde_json::to_value(display).unwrap()["immediate"], "0xffffffffffffffff");
}

#[test]
fn enum_refuses_registers_wrong_types_unknown_widths_and_oversized_enums() {
    let catalog = catalog();
    let evidence = operands(rampage_arch::Arch::X86_64, "83f807");
    let entry = annotation(OperandTypeKind::Enum, "Mode", 0, "83f807");
    assert!(interpret(&entry, &evidence[0], &catalog).is_err());
    let entry = annotation(OperandTypeKind::Enum, "FieldState", 1, "83f807");
    assert!(interpret(&entry, &evidence[1], &catalog).is_err());
    let entry = annotation(OperandTypeKind::Enum, "Mode", 1, "83f807");
    for width in [None, Some(0), Some(8), Some(65)] {
        let mut operand = evidence[1].clone();
        operand.width_bits = width;
        assert!(interpret(&entry, &operand, &catalog).is_err());
    }
    let missing = annotation(OperandTypeKind::Enum, "Missing", 1, "83f807");
    assert!(interpret(&missing, &evidence[1], &catalog).is_err());
}

#[test]
fn native_aliases_must_resolve_to_complete_supported_types_without_cycles() {
    let mut catalog = catalog();
    let evidence = operands(rampage_arch::Arch::X86_64, "83f807");
    let entry = annotation(OperandTypeKind::Enum, "ModeAlias", 1, "83f807");
    catalog.get_mut("ModeAlias").unwrap().target = Some("ModeAlias".into());
    catalog.get_mut("ModeAlias").unwrap().identity.as_mut().unwrap()["typedef"] =
        serde_json::json!({"reference":"ModeAlias"});
    assert!(interpret(&entry, &evidence[1], &catalog).is_err());
    catalog.get_mut("ModeAlias").unwrap().target = Some("Mode".into());
    catalog.get_mut("ModeAlias").unwrap().identity.as_mut().unwrap()["typedef"] =
        serde_json::json!({"reference":"Mode"});
    catalog.get_mut("Mode").unwrap().incomplete = true;
    assert!(interpret(&entry, &evidence[1], &catalog).is_err());
}

#[test]
fn typedef_resolution_uses_identity_references_not_display_targets() {
    let mut catalog = catalog();
    catalog.get_mut("ModeAlias").unwrap().target = Some("unqueryable display label".into());
    let entry = annotation(OperandTypeKind::Enum, "ModeAlias", 1, "83f807");
    let operand = operands(rampage_arch::Arch::X86_64, "83f807").remove(1);
    assert_eq!(interpret(&entry, &operand, &catalog).unwrap().display, "ModeAlias::MODE_READY");
    catalog.get_mut("ModeAlias").unwrap().identity = None;
    assert!(interpret(&entry, &operand, &catalog).is_err());
}

#[test]
fn anonymous_enum_identity_unsigned_bits_are_normalized_at_native_enum_width() {
    let entry = annotation(OperandTypeKind::Enum, "ModeAlias", 1, "83f8fd");
    let mut operand = operands(rampage_arch::Arch::X86_64, "83f8fd").remove(1);
    operand.width_bits = Some(64);
    operand.immediate = Some(u64::MAX - 2);
    for raw in ["4294967293", "18446744073709551613"] {
        let mut catalog = catalog();
        let alias = catalog.get_mut("ModeAlias").unwrap();
        alias.target = Some("anonymous".into());
        alias.identity = Some(serde_json::json!({"kind":14, "size":4, "typedef":{
            "kind":14, "size":4, "enum_values":[{"name":"NEGATIVE", "value":raw}]
        }}));
        assert_eq!(interpret(&entry, &operand, &catalog).unwrap().display, "ModeAlias::NEGATIVE");
        let identity = catalog.get_mut("ModeAlias").unwrap().identity.as_mut().unwrap();
        identity["kind"] = serde_json::json!(13);
        identity["typedef"]["kind"] = serde_json::json!(13);
        assert!(!interpret(&entry, &operand, &catalog).unwrap().matched);
        operand.immediate = Some(0xffff_fffd);
        assert_eq!(interpret(&entry, &operand, &catalog).unwrap().display, "ModeAlias::NEGATIVE");
        operand.immediate = Some(u64::MAX - 2);
    }
}

#[test]
fn offsets_use_native_field_boundaries_and_access_width_not_printed_assembly() {
    for (arch, hex) in [(rampage_arch::Arch::X86_64, "8b4704"), (rampage_arch::Arch::Aarch64, "200440b9")] {
        let evidence = operands(arch, hex);
        let entry = annotation(OperandTypeKind::Offset, "FieldState", 1, hex);
        let display = display_entries(&[entry], hex, &evidence, &catalog()).unwrap().remove(0);
        assert_eq!(display.display, "FieldState.bias");
        assert_eq!(display.field_path.as_deref(), Some("bias"));
        assert_eq!(display.displacement.as_deref(), Some("0x4"));
        assert_eq!(display.access_size, Some(4));
    }
}

#[test]
fn offsets_refuse_pc_relative_absolute_indexed_negative_unknown_width_and_partial_fields() {
    let catalog = catalog();
    let entry = annotation(OperandTypeKind::Offset, "FieldState", 1, "8b4704");
    let operand = operands(rampage_arch::Arch::X86_64, "8b4704").remove(1);
    let memory = operand.memory.as_ref().unwrap();
    for changed in [
        MemoryOperand { relative: true, ..memory.clone() },
        MemoryOperand { base: None, ..memory.clone() },
        MemoryOperand { index: Some("rcx".into()), ..memory.clone() },
        MemoryOperand { displacement: -4, ..memory.clone() },
        MemoryOperand { displacement: 5, ..memory.clone() },
        MemoryOperand { displacement: 8, ..memory.clone() },
        MemoryOperand { access_size: None, ..memory.clone() },
        MemoryOperand { access_size: Some(0), ..memory.clone() },
        MemoryOperand { access_size: Some(8), ..memory.clone() },
    ] {
        let mut operand = operand.clone();
        operand.memory = Some(changed);
        assert!(interpret(&entry, &operand, &catalog).is_err(), "{operand:?}");
    }
    for hex in ["8b0504000000", "8b448f04", "8b47fc", "8d4704"] {
        let evidence = operands(rampage_arch::Arch::X86_64, hex);
        assert!(interpret(&entry, &evidence[1], &catalog).is_err(), "{hex}");
    }
}

#[test]
fn stored_bindings_require_full_exact_current_instruction_and_existing_operand_index() {
    let evidence = operands(rampage_arch::Arch::X86_64, "83f807");
    for (hex, index) in [("83f8", 1), ("83f809", 1), ("83f80790", 1), ("83f807", 2)] {
        let entry = annotation(OperandTypeKind::Enum, "Mode", index, hex);
        assert!(display_entries(&[entry], "83f807", &evidence, &catalog()).is_err());
    }
}

fn project(hex: &str, annotations: Annotations) -> Project {
    let binary = Binary::from_snapshot_bytes(
        serde_json::to_vec(&serde_json::json!({
            "format":"rampage-snapshot-v1", "arch":"x86_64",
            "provenance":"Owned operand-annotation fixture; bytes are never executed",
            "regions":[{"name":"instructions","address":"0x1000","permissions":"r-x","bytes":hex}],
            "entry":"0x1000", "seeds":["0x1000"],
        }))
        .unwrap(),
    )
    .unwrap();
    let project = Project::with_annotations(binary, annotations);
    project
        .set_decompiler_options(Some(crate::DecompilerOptions { compiler: Some("gcc".into()), ..Default::default() }));
    project
}

fn declare(project: &Project) {
    project
        .declare_types(&crate::DeclareTypesRequest {
            declarations: Some(
                "enum Mode { MODE_READY = 7, MODE_BAD = -3 }; \
                            struct FieldState { int4 prefix; int4 bias; };"
                    .into(),
            ),
            ..Default::default()
        })
        .unwrap();
}

fn request(operand: u8, name: &str) -> ApplyOperandTypeRequest {
    ApplyOperandTypeRequest { operand, type_name: Some(name.into()), clear: false }
}

#[test]
fn anonymous_enum_and_struct_typedefs_apply_using_real_native_metadata_on_owned_code() {
    let project = project("83f80783f8fd8b4704c3", Annotations::in_memory());
    project
        .declare_types(&crate::DeclareTypesRequest {
            declarations: Some(
                "typedef enum { READY = 7, BAD = -3 } Mode; \
             typedef struct { int4 prefix; int4 bias; } State;"
                    .into(),
            ),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(project.get_type("Mode").unwrap().metadata.kind, NamedTypeKind::Typedef);
    assert_eq!(project.get_type("State").unwrap().metadata.kind, NamedTypeKind::Typedef);
    assert_eq!(project.apply_enum(0x1000, &request(1, "Mode")).unwrap().display.unwrap().display, "Mode::READY");
    assert_eq!(project.apply_enum(0x1003, &request(1, "Mode")).unwrap().display.unwrap().display, "Mode::BAD");
    assert_eq!(project.apply_offset(0x1006, &request(1, "State")).unwrap().display.unwrap().display, "State.bias");
    let lines = project.disassemble(Some("0x1000"), 3).unwrap();
    for (line, expected) in lines.iter().zip(["Mode::READY", "Mode::BAD", "State.bias"]) {
        assert_eq!(line.operand_annotations[0].display, expected);
        assert!(line.comment.as_deref().unwrap().contains(expected));
    }
}

#[test]
fn whole_annotation_validation_rejects_changed_source_bytes_and_missing_native_types() {
    let mut annotations = Annotations::in_memory();
    let entry = annotation(OperandTypeKind::Enum, "Mode", 1, "83f807");
    annotations.set(Field::OperandType, 0x1000, Some(encode_operand_types(&[entry]).unwrap())).unwrap();
    let original = project("83f807c3", Annotations::in_memory());
    assert!(validate_operand_annotations(&original, &annotations, &metadata()).is_ok());
    let changed = project("83f809c3", Annotations::in_memory());
    assert!(validate_operand_annotations(&changed, &annotations, &metadata()).is_err());
    assert!(validate_operand_annotations(&original, &annotations, &[]).is_err());
    let truncated = project("83f8", Annotations::in_memory());
    assert!(validate_operand_annotations(&truncated, &annotations, &metadata()).is_err());
}

#[test]
fn apply_preserves_other_operands_and_raw_listing_and_clear_needs_no_type_name() {
    let project = project("c7470407000000c3", Annotations::in_memory());
    declare(&project);
    project.comment(0x1000, Some("analyst note")).unwrap();
    let before = serde_json::to_value(project.disassemble(Some("0x1000"), 1).unwrap()).unwrap();
    let offset = project.apply_offset(0x1000, &request(0, "FieldState")).unwrap();
    assert_eq!(offset.display.unwrap().display, "FieldState.bias");
    let enumeration = project.apply_enum(0x1000, &request(1, "Mode")).unwrap();
    assert_eq!(enumeration.display.unwrap().display, "Mode::MODE_READY");
    let after = serde_json::to_value(project.disassemble(Some("0x1000"), 1).unwrap()).unwrap();
    for key in ["text", "bytes", "flow", "note", "data_ref", "immediate"] {
        assert_eq!(before[0][key], after[0][key], "{key}");
    }
    assert_eq!(after[0]["operand_annotations"].as_array().unwrap().len(), 2);
    assert!(after[0]["comment"].as_str().unwrap().contains("FieldState.bias"));
    assert!(after[0]["comment"].as_str().unwrap().contains("Mode::MODE_READY"));
    let clear = ApplyOperandTypeRequest { operand: 1, type_name: None, clear: true };
    let cleared = project.apply_enum(0x1000, &clear).unwrap();
    assert!(cleared.changed);
    assert!(cleared.annotation.is_none());
    let entries = entries_at(&project.annotations(), 0x1000).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].operand, 0);
    assert!(!project.apply_enum(0x1000, &clear).unwrap().changed);
    project.undo().unwrap();
    assert_eq!(entries_at(&project.annotations(), 0x1000).unwrap().len(), 2);
    project.redo().unwrap();
    assert_eq!(entries_at(&project.annotations(), 0x1000).unwrap().len(), 1);
}

#[test]
fn refused_request_and_full_response_preflight_do_not_publish_annotations_or_history() {
    let project = project("83f807c3", Annotations::in_memory());
    declare(&project);
    let before = project.annotations().revision();
    for request in [
        request(0, "Mode"),
        request(2, "Mode"),
        request(1, "FieldState"),
        request(1, "Missing"),
        ApplyOperandTypeRequest { operand: 1, type_name: Some("Mode".into()), clear: true },
    ] {
        assert!(project.apply_enum(0x1000, &request).is_err());
    }
    assert!(
        project
            .apply_enum_with_preflight(0x1000, &request(1, "Mode"), |receipt| {
                assert!(receipt.changed);
                assert_eq!(receipt.annotation.as_ref().unwrap().instruction_hex, "83f807");
                assert_eq!(receipt.display.as_ref().unwrap().display, "Mode::MODE_READY");
                Err(ApiError::Invalid("simulated response budget refusal".into()))
            })
            .is_err()
    );
    assert!(project.annotations().operand_types().is_empty());
    assert!(std::sync::Arc::ptr_eq(&before, &project.annotations().revision()));
    project.undo().unwrap();
    assert!(project.annotations().type_library().is_empty());
}

struct LogFixture(PathBuf);

impl LogFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("rampage-operand-types-{}-{index}.jsonl", std::process::id())))
    }

    fn open(&self) -> Annotations {
        Annotations::open_checked(self.0.clone()).unwrap()
    }
}

impl Drop for LogFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let mut lock = self.0.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }
}

#[test]
fn reopen_shared_client_conflicts_and_type_deletion_retain_binding_integrity() {
    let log = LogFixture::new();
    let first = project("83f807c3", log.open());
    declare(&first);
    first.apply_enum(0x1000, &request(1, "Mode")).unwrap();
    let reopened = project("83f807c3", log.open());
    assert_eq!(reopened.disassemble(Some("0x1000"), 1).unwrap()[0].operand_annotations[0].display, "Mode::MODE_READY");
    let bytes = std::fs::read(&log.0).unwrap();
    assert!(reopened.delete_type("Mode").is_err());
    assert_eq!(std::fs::read(&log.0).unwrap(), bytes);
    let clear = ApplyOperandTypeRequest { operand: 1, type_name: None, clear: true };
    reopened.apply_enum(0x1000, &clear).unwrap();
    assert!(first.undo().is_err());
    let replaced = project("83f809c3", log.open());
    reopened.undo().unwrap();
    replaced.refresh_annotations().unwrap();
    assert!(replaced.disassemble(Some("0x1000"), 1).is_err());
    assert!(replaced.apply_enum(0x1000, &clear).is_err());
}

#[test]
fn empty_operand_map_does_not_change_legacy_listing_json_or_create_lock_files() {
    let log = LogFixture::new();
    let project = project("83f807c3", log.open());
    let lines = project.disassemble(Some("0x1000"), 1).unwrap();
    assert!(lines[0].operand_annotations.is_empty());
    assert!(serde_json::to_value(&lines).unwrap()[0].get("operand_annotations").is_none());
    assert!(!log.0.exists());
    let mut lock = log.0.as_os_str().to_owned();
    lock.push(".lock");
    assert!(!PathBuf::from(lock).exists());
}
