use rampage_arch::Arch;
use rampage_decompiler::results::{StorageKind, VariableKind};
use rampage_decompiler::{Decompiler, LocalOverride, Segment, VariableStorage, validate_local_name};

const FIELDS: &[u8] = &[0x8b, 0x07, 0x0f, 0xaf, 0xc6, 0x03, 0x47, 0x04, 0xc3];

fn engine() -> Decompiler {
    Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: FIELDS, writable: false }]).unwrap()
}

fn variable_summary(result: &rampage_decompiler::StructuredResult) -> String {
    result
        .variables
        .iter()
        .take(8)
        .map(|variable| {
            let storage = variable
                .storage
                .iter()
                .take(2)
                .map(|mapping| {
                    format!(
                        "{:?}:{}@{:x?}/{} piece={:?} offset={:?} ranges={:?}",
                        mapping.kind,
                        mapping.space.as_deref().unwrap_or("?").chars().take(24).collect::<String>(),
                        mapping.address,
                        mapping.size,
                        mapping.is_piece,
                        mapping.symbol_offset,
                        mapping.use_ranges.as_ref().map(Vec::len),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{} {:?} {}: [{}] ({} mappings)",
                variable.name.chars().take(48).collect::<String>(),
                variable.kind,
                variable.data_type.name.chars().take(48).collect::<String>(),
                storage,
                variable.storage.len(),
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[test]
fn pointer_retyping_drives_native_field_rendering_and_parameter_names() {
    let mut engine = engine();
    engine.parse_c("struct PhaseState { int4 gain; int4 bias; };").unwrap();
    engine.decompile(0x1000, "param_1_helper", false).unwrap();
    let result = engine.structured_result().unwrap();
    let pointer = VariableStorage::try_from(&result.signature.parameters[0].storage).unwrap();
    let input = VariableStorage::try_from(&result.signature.parameters[1].storage).unwrap();
    assert!(pointer.use_ranges.iter().any(|range| range.start == 0xfff && range.end == 0xfff));
    let overrides = [
        LocalOverride {
            storage: pointer,
            name: Some("p".to_owned()),
            data_type: Some("struct PhaseState *".to_owned()),
        },
        LocalOverride { storage: input, name: Some("sample".to_owned()), data_type: None },
    ];
    engine.set_variable_overrides(0x1000, &overrides).unwrap();
    for _ in 0..2 {
        let text = engine.decompile(0x1000, "param_1_helper", false).unwrap();
        assert!(text.contains("p->gain"), "{text}");
        assert!(text.contains("p->bias"), "{text}");
        assert!(text.contains("sample"), "{text}");
        assert!(text.contains("param_1_helper("), "function name was text-substituted: {text}");
        let result = engine.structured_result().unwrap();
        assert_eq!(result.signature.parameters[0].name, "p");
        assert_eq!(result.signature.parameters[1].name, "sample");
        assert!(result.variables.iter().any(|variable| variable.name == "p"));
    }
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride {
                storage: overrides[0].storage.clone(),
                name: Some("state_bits".to_owned()),
                data_type: None,
            }],
        )
        .unwrap();
    let replaced = engine.decompile(0x1000, "param_1_helper", false).unwrap();
    assert!(replaced.contains("state_bits"), "{replaced}");
    assert!(!replaced.contains("->gain"), "{replaced}");
    assert!(!replaced.contains("sample"), "{replaced}");
    engine.set_variable_overrides(0x1000, &[]).unwrap();
    let cleared = engine.decompile(0x1000, "param_1_helper", false).unwrap();
    assert!(!cleared.contains("p->"), "{cleared}");
    assert!(!cleared.contains("sample"), "{cleared}");
    assert_eq!(engine.structured_result().unwrap().signature.parameters[0].name, result.signature.parameters[0].name);
}

#[test]
fn a_type_only_override_preserves_the_original_parameter_name() {
    let mut engine = engine();
    engine.parse_c("struct PhaseState { int4 gain; int4 bias; };").unwrap();
    engine.decompile(0x1000, "fields", false).unwrap();
    let original = engine.structured_result().unwrap();
    let storage = VariableStorage::try_from(&original.signature.parameters[0].storage).unwrap();
    for declaration in ["struct PhaseState *", "PhaseState *"] {
        engine
            .set_variable_overrides(
                0x1000,
                &[LocalOverride { storage: storage.clone(), name: None, data_type: Some(declaration.to_owned()) }],
            )
            .unwrap();
        let text = engine.decompile(0x1000, "fields", false).unwrap();
        assert!(text.contains("->gain"), "{text}");
        assert!(text.contains("->bias"), "{text}");
        assert_eq!(
            engine.structured_result().unwrap().signature.parameters[0].name,
            original.signature.parameters[0].name,
        );
    }
    for declaration in ["union PhaseState *", "enum PhaseState *", "struct MissingType *"] {
        assert!(
            engine
                .set_variable_overrides(
                    0x1000,
                    &[LocalOverride { storage: storage.clone(), name: None, data_type: Some(declaration.to_owned()) }]
                )
                .is_err(),
            "accepted mismatched or missing native tag {declaration}"
        );
    }
    engine.set_variable_overrides(0x1000, &[]).unwrap();
    engine.decompile(0x1000, "fields", false).unwrap();
    assert_eq!(engine.structured_result().unwrap().signature.parameters[0], original.signature.parameters[0]);
}

#[test]
fn aarch64_parameter_storage_supports_native_struct_pointer_edits() {
    // Clang 23 -Os phase_parameter from the owned local-variables.c fixture.
    let bytes = [0x08, 0x24, 0x40, 0x29, 0x08, 0x01, 0x01, 0x0b, 0x00, 0x01, 0x09, 0x0b, 0xc0, 0x03, 0x5f, 0xd6];
    let mut engine =
        Decompiler::open(Arch::Aarch64, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    engine.parse_c("struct PhaseState { int4 gain; int4 bias; };").unwrap();
    engine.decompile(0x1000, "phase_parameter", false).unwrap();
    let before = engine.structured_result().unwrap();
    assert_eq!(before.signature.parameters[0].storage.address_size_bytes, Some(4));
    assert_eq!(before.frame_context.as_ref().unwrap().address_size_bytes, 8);
    let storage = VariableStorage::try_from(&before.signature.parameters[0].storage).unwrap();
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride {
                storage: storage.clone(),
                name: Some("state".into()),
                data_type: Some("struct PhaseState *".into()),
            }],
        )
        .unwrap();
    let text = engine.decompile(0x1000, "phase_parameter", false).unwrap();
    assert!(text.contains("state->gain") && text.contains("state->bias"), "{text}");
    assert_eq!(
        VariableStorage::try_from(&engine.structured_result().unwrap().signature.parameters[0].storage).unwrap(),
        storage
    );
}

#[test]
fn selecting_only_a_later_parameter_keeps_the_native_input_set_intact() {
    let mut engine = engine();
    engine.decompile(0x1000, "fields", false).unwrap();
    let original = engine.structured_result().unwrap();
    let storage = VariableStorage::try_from(&original.signature.parameters[1].storage).unwrap();
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride { storage, name: Some("factor".to_owned()), data_type: Some("uint4".to_owned()) }],
        )
        .unwrap();
    let text = engine.decompile(0x1000, "fields", false).unwrap();
    assert!(text.contains("factor"), "{text}");
    let result = engine.structured_result().unwrap();
    assert_eq!(result.signature.parameters.len(), original.signature.parameters.len());
    assert_eq!(result.signature.parameters[0].storage, original.signature.parameters[0].storage);
    assert_eq!(result.signature.parameters[1].name, "factor");
}

#[test]
fn stack_local_mapping_is_renamed_and_retyped_in_scope() {
    let bytes = [
        0x48, 0x83, 0xec, 0x18, 0x89, 0x7c, 0x24, 0x14, 0x48, 0x8d, 0x7c, 0x24, 0x14, 0xe8, 0xee, 0x0f, 0, 0, 0x8b,
        0x44, 0x24, 0x14, 0x48, 0x83, 0xc4, 0x18, 0xc3,
    ];
    let mut engine =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    engine.set_symbol(0x2000, "consume").unwrap();
    engine.apply_prototype(0x2000, false, "void consume(int4 *value);").unwrap();
    engine.decompile(0x1000, "stack_value", false).unwrap();
    let result = engine.structured_result().unwrap();
    let local = result
        .variables
        .iter()
        .find(|variable| {
            variable.kind == VariableKind::Local
                && variable.storage.len() == 1
                && variable.storage[0].kind == StorageKind::Spacebase
                && variable.storage[0].size == 4
        })
        .unwrap_or_else(|| panic!("missing single whole four-byte stack local: {}", variable_summary(&result)));
    let mapping = &local.storage[0];
    assert_eq!(mapping.address_size_bytes, Some(8));
    assert_eq!(mapping.address.unwrap() as i64, -4);
    let selector = VariableStorage::try_from(mapping).unwrap();
    let mut without_width = mapping.clone();
    without_width.address_size_bytes = None;
    assert_eq!(VariableStorage::try_from(&without_width).unwrap(), selector);
    assert_eq!(
        serde_json::to_value(&selector).unwrap(),
        serde_json::json!({
            "kind": "spacebase", "space": "stack", "address": "0xfffffffffffffffc", "size": 4,
            "use_ranges": serde_json::to_value(&selector.use_ranges).unwrap()
        })
    );
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride {
                storage: VariableStorage::try_from(&local.storage[0]).unwrap(),
                name: Some("saved_count".to_owned()),
                data_type: Some("uint4".to_owned()),
            }],
        )
        .unwrap();
    let text = engine.decompile(0x1000, "stack_value", false).unwrap();
    assert!(text.contains("saved_count"), "{text}");
    let result = engine.structured_result().unwrap();
    let local = result.variables.iter().find(|variable| variable.name == "saved_count").unwrap();
    assert_eq!(local.data_type.name, "uint4");
    assert_eq!(local.storage[0].kind, StorageKind::Spacebase);
    engine.set_variable_overrides(0x1000, &[]).unwrap();
    assert!(!engine.decompile(0x1000, "stack_value", false).unwrap().contains("saved_count"));
}

#[test]
fn register_reuse_is_disambiguated_by_exact_call_definition_ranges() {
    let caller = [0x53, 0xe8, 0xfa, 0, 0, 0, 0x89, 0xc3, 0xe8, 0x03, 1, 0, 0, 0x01, 0xd8, 0x5b, 0xc3];
    let callee = [0xb8, 7, 0, 0, 0, 0xc3];
    let mut engine = Decompiler::open(
        Arch::X86_64,
        false,
        &[
            Segment { base: 0x1000, bytes: &caller, writable: false },
            Segment { base: 0x1100, bytes: &callee, writable: false },
            Segment { base: 0x1110, bytes: &callee, writable: false },
        ],
    )
    .unwrap();
    for (address, name) in [(0x1000, "add_returns"), (0x1100, "first"), (0x1110, "second")] {
        engine.set_symbol(address, name).unwrap();
        engine.apply_prototype(address, false, &format!("int4 {name}(void);")).unwrap();
    }
    engine.decompile(0x1000, "add_returns", false).unwrap();
    let result = engine.structured_result().unwrap();
    let local = result
        .variables
        .iter()
        .find(|variable| {
            variable.storage.len() == 1
                && variable.storage[0].space.as_deref() == Some("register")
                && variable.storage[0].address == Some(0)
                && variable.storage[0]
                    .use_ranges
                    .as_ref()
                    .is_some_and(|ranges| ranges.iter().any(|range| range.start == 0x1008 && range.end == 0x1008))
        })
        .expect("single whole EAX mapping at second call");
    let storage = VariableStorage::try_from(&local.storage[0]).unwrap();
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride {
                storage: storage.clone(),
                name: Some("second_result".to_owned()),
                data_type: Some("int4".to_owned()),
            }],
        )
        .unwrap();
    let text = engine.decompile(0x1000, "add_returns", false).unwrap();
    assert!(text.contains("second_result = second("), "{text}");
    assert!(text.contains("first("), "{text}");
    let mut missing_range = storage;
    missing_range.use_ranges.clear();
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride { storage: missing_range, name: Some("wrong_result".to_owned()), data_type: None }],
        )
        .unwrap();
    assert!(engine.decompile(0x1000, "add_returns", false).unwrap_err().to_string().contains("did not match"));
}

#[test]
fn absent_ambiguous_incomplete_and_wrong_sized_edits_are_refused_without_partial_renames() {
    let mut engine = engine();
    engine.decompile(0x1000, "fields", false).unwrap();
    let result = engine.structured_result().unwrap();
    let source = &result.signature.parameters[0].storage;
    let storage = VariableStorage::try_from(source).unwrap();
    let valid = LocalOverride { storage: storage.clone(), name: Some("must_not_apply".to_owned()), data_type: None };
    assert!(engine.set_variable_overrides(0x1000, &[valid.clone(), valid.clone()]).is_err());
    for data_type in ["int4", "void", "struct MissingType", "int4; int4 injected", "int4 (*)(int4)"] {
        let wrong = LocalOverride { storage: storage.clone(), name: None, data_type: Some(data_type.to_owned()) };
        assert!(engine.set_variable_overrides(0x1000, &[wrong]).is_err(), "accepted {data_type}");
    }
    let mut missing = valid.clone();
    missing.name = Some("absent".to_owned());
    missing.storage.address += 0x10000;
    engine.set_variable_overrides(0x1000, &[valid, missing]).unwrap();
    assert!(engine.decompile(0x1000, "fields", false).unwrap_err().to_string().contains("did not match"));
    assert!(engine.structured_result().is_err());
    engine.set_variable_overrides(0x1000, &[]).unwrap();
    assert!(!engine.decompile(0x1000, "fields", false).unwrap().contains("must_not_apply"));
    let mut incomplete = source.clone();
    incomplete.use_ranges = None;
    assert!(VariableStorage::try_from(&incomplete).is_err());
    incomplete = source.clone();
    incomplete.is_piece = None;
    assert!(VariableStorage::try_from(&incomplete).is_err());
    for kind in [StorageKind::Dynamic, StorageKind::Internal, StorageKind::Join, StorageKind::Unknown] {
        incomplete = source.clone();
        incomplete.kind = kind;
        assert!(VariableStorage::try_from(&incomplete).is_err());
    }
}

#[test]
fn selectors_accept_numeric_or_hex_addresses_but_always_serialize_losslessly() {
    let value = serde_json::json!({
        "kind": "spacebase", "space": "stack", "address": "0xfffffffffffffff0", "size": "0x8",
        "use_ranges": [{"space": "ram", "start": 4095, "end": "0x20000000000001"}]
    });
    let key: VariableStorage = serde_json::from_value(value).unwrap();
    let serialized = serde_json::to_value(&key).unwrap();
    assert_eq!(serialized["address"], "0xfffffffffffffff0");
    assert_eq!(serialized["use_ranges"][0]["start"], "0xfff");
    assert_eq!(serialized["use_ranges"][0]["end"], "0x20000000000001");
    let mut with_metadata = serialized.clone();
    with_metadata["address_size_bytes"] = serde_json::json!(8);
    assert!(serde_json::from_value::<VariableStorage>(with_metadata).is_err());
    for invalid in [serde_json::json!(-1), serde_json::json!(1.5), serde_json::json!("0x10000000000000000")] {
        let mut value = serialized.clone();
        value["address"] = invalid;
        assert!(serde_json::from_value::<VariableStorage>(value).is_err());
    }
    let mut incomplete = serialized;
    incomplete.as_object_mut().unwrap().remove("use_ranges");
    assert!(serde_json::from_value::<VariableStorage>(incomplete).is_err());
}

#[test]
fn x86_negative_stack_offsets_use_native_width_and_keep_exact_selector_wire_identity() {
    let bytes = [
        0x83, 0xec, 0x10, 0xc7, 0x44, 0x24, 0x0c, 7, 0, 0, 0, 0x8d, 0x44, 0x24, 0x0c, 0x50, 0xe8, 0xeb, 0x0f, 0, 0,
        0x83, 0xc4, 4, 0x8b, 0x44, 0x24, 0x0c, 0x83, 0xc4, 0x10, 0xc3,
    ];
    let mut engine =
        Decompiler::open(Arch::X86, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    engine.set_symbol(0x2000, "consume").unwrap();
    engine.apply_prototype(0x2000, false, "void consume(int4 *value);").unwrap();
    engine.decompile(0x1000, "stack_value", false).unwrap();
    let result = engine.structured_result().unwrap();
    let mapping = result
        .variables
        .iter()
        .flat_map(|variable| &variable.storage)
        .find(|storage| storage.space.as_deref() == Some("stack") && storage.address == Some(0xffff_fffc))
        .unwrap_or_else(|| panic!("missing negative stack mapping: {}", variable_summary(&result)));
    assert_eq!(mapping.address_size_bytes, Some(4));
    assert_eq!(mapping.address.unwrap() as u32 as i32, -4);
    let selector = VariableStorage::try_from(mapping).unwrap();
    let serialized = serde_json::to_value(&selector).unwrap();
    assert_eq!(
        serialized,
        serde_json::json!({
            "kind": "spacebase", "space": "stack", "address": "0xfffffffc", "size": 4,
            "use_ranges": serde_json::to_value(&selector.use_ranges).unwrap()
        })
    );
    let mut without_width = mapping.clone();
    without_width.address_size_bytes = None;
    assert_eq!(VariableStorage::try_from(&without_width).unwrap(), selector);
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride { storage: selector, name: Some("stack_count".to_owned()), data_type: None }],
        )
        .unwrap();
    assert!(engine.decompile(0x1000, "stack_value", false).unwrap().contains("stack_count"));
}

#[test]
fn reserved_names_refuse_the_entire_batch_and_preserve_previous_native_overrides() {
    let mut engine = engine();
    engine.decompile(0x1000, "fields", false).unwrap();
    let original = engine.structured_result().unwrap();
    let first = VariableStorage::try_from(&original.signature.parameters[0].storage).unwrap();
    let second = VariableStorage::try_from(&original.signature.parameters[1].storage).unwrap();
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride { storage: first.clone(), name: Some("retained_name".to_owned()), data_type: None }],
        )
        .unwrap();
    for name in [
        "return",
        "for",
        "int",
        "_Alignas",
        "_Alignof",
        "_Atomic",
        "_Bool",
        "_Complex",
        "_Generic",
        "_Imaginary",
        "_Noreturn",
        "_Static_assert",
        "_Thread_local",
    ] {
        let error = engine
            .set_variable_overrides(
                0x1000,
                &[
                    LocalOverride { storage: first.clone(), name: Some("must_not_apply".to_owned()), data_type: None },
                    LocalOverride { storage: second.clone(), name: Some(name.to_owned()), data_type: None },
                ],
            )
            .unwrap_err();
        assert!(error.to_string().contains("reserved C keyword"), "{name}: {error}");
        let text = engine.decompile(0x1000, "fields", false).unwrap();
        assert!(!text.contains("must_not_apply"), "{text}");
        let result = engine.structured_result().unwrap();
        assert_eq!(result.signature.parameters[0].name, "retained_name");
        assert_eq!(result.signature.parameters[1].name, original.signature.parameters[1].name);
    }
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride { storage: first, name: Some("renamed_after_refusal".to_owned()), data_type: None }],
        )
        .unwrap();
    let text = engine.decompile(0x1000, "fields", false).unwrap();
    assert!(text.contains("renamed_after_refusal"), "{text}");
    assert!(!text.contains("retained_name"), "{text}");
    engine.set_variable_overrides(0x1000, &[]).unwrap();
    engine.decompile(0x1000, "fields", false).unwrap();
    assert_eq!(engine.structured_result().unwrap().signature.parameters, original.signature.parameters);
}

#[test]
fn local_name_validation_keeps_identifier_bounds_without_rejecting_keyword_substrings() {
    for name in ["", "1value", "qualified::name", "two words", "non_ascii_λ", &"x".repeat(129)] {
        assert!(validate_local_name(name).is_err(), "accepted {name:?}");
    }
    for name in ["return_value", "For", "int4", "_Atomic_value", &"x".repeat(128)] {
        validate_local_name(name).unwrap();
    }
}

#[test]
fn batch_final_names_allow_vacated_parameter_names_and_swaps_across_replacement_and_clear() {
    let mut engine = engine();
    engine.decompile(0x1000, "fields", false).unwrap();
    let original = engine.structured_result().unwrap();
    assert_eq!(original.signature.parameters[0].name, "param_1");
    assert_eq!(original.signature.parameters[1].name, "param_2");
    let first = VariableStorage::try_from(&original.signature.parameters[0].storage).unwrap();
    let second = VariableStorage::try_from(&original.signature.parameters[1].storage).unwrap();
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride { storage: second.clone(), name: Some("sample".to_owned()), data_type: None }],
        )
        .unwrap();
    engine.decompile(0x1000, "fields", false).unwrap();
    assert_eq!(engine.structured_result().unwrap().signature.parameters[1].name, "sample");

    for (first_name, second_name) in [("param_2", "sample"), ("param_2", "param_1")] {
        let overrides = [
            LocalOverride { storage: first.clone(), name: Some(first_name.to_owned()), data_type: None },
            LocalOverride { storage: second.clone(), name: Some(second_name.to_owned()), data_type: None },
        ];
        engine.set_variable_overrides(0x1000, &overrides).unwrap();
        for _ in 0..2 {
            let text = engine.decompile(0x1000, "fields", false).unwrap();
            assert!(text.contains(first_name), "{text}");
            assert!(text.contains(second_name), "{text}");
            let result = engine.structured_result().unwrap();
            assert_eq!(result.signature.parameters[0].name, first_name);
            assert_eq!(result.signature.parameters[1].name, second_name);
            assert_eq!(result.signature.parameters[0].storage, original.signature.parameters[0].storage);
            assert_eq!(result.signature.parameters[1].storage, original.signature.parameters[1].storage);
        }
    }
    engine.set_variable_overrides(0x1000, &[]).unwrap();
    engine.decompile(0x1000, "fields", false).unwrap();
    assert_eq!(engine.structured_result().unwrap().signature.parameters, original.signature.parameters);
}

#[test]
fn final_name_collisions_with_unselected_or_type_only_symbols_are_refused_before_mutation() {
    let mut engine = engine();
    engine.decompile(0x1000, "fields", false).unwrap();
    let original = engine.structured_result().unwrap();
    let first = VariableStorage::try_from(&original.signature.parameters[0].storage).unwrap();
    let second = VariableStorage::try_from(&original.signature.parameters[1].storage).unwrap();
    let rename = LocalOverride {
        storage: first.clone(),
        name: Some(original.signature.parameters[1].name.clone()),
        data_type: None,
    };
    for overrides in [
        vec![rename.clone()],
        vec![rename, LocalOverride { storage: second.clone(), name: None, data_type: Some("int4".to_owned()) }],
    ] {
        engine.set_variable_overrides(0x1000, &overrides).unwrap();
        let error = engine.decompile(0x1000, "fields", false).unwrap_err();
        assert!(error.to_string().contains("final name is already used"), "{error}");
        assert!(engine.structured_result().is_err());
        engine.set_variable_overrides(0x1000, &[]).unwrap();
        engine.decompile(0x1000, "fields", false).unwrap();
        assert_eq!(engine.structured_result().unwrap().signature.parameters, original.signature.parameters);
    }
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride { storage: first, name: Some("valid_after_collision".to_owned()), data_type: None }],
        )
        .unwrap();
    let text = engine.decompile(0x1000, "fields", false).unwrap();
    assert!(text.contains("valid_after_collision"), "{text}");
    assert_eq!(engine.structured_result().unwrap().signature.parameters[0].name, "valid_after_collision");
}
