use rampage_arch::Arch;
use rampage_decompiler::results::{Call, CallValueStatus, VariableKind};
use rampage_decompiler::{
    Decompiler, DecompilerOptions, LocalOverride, MemoryRegion, Platform, Segment, TypeHint, VariableStorage,
};

// Source: fixtures/type_hints.c, fields. These bytes are analyzed, never executed.
const FIELDS: &[u8] = &[0x8b, 0x07, 0x0f, 0xaf, 0xc6, 0x03, 0x47, 0x04, 0xc3];
const TYPES: &str = "struct HintState { int4 gain; int4 bias; }; struct OtherState { int4 first; int4 second; };";

fn make_engine(bytes: &[u8]) -> Decompiler {
    let mut engine =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes, writable: false }]).unwrap();
    engine.parse_type_library(TYPES, None).unwrap();
    engine
}

fn assert_field_tokens(engine: &Decompiler, text: &str, expected: &[&str], absent: &[&str]) {
    let tokens = engine.tokens();
    for name in expected {
        let token = tokens
            .iter()
            .find(|token| token.kind == "field" && token.text == *name)
            .unwrap_or_else(|| panic!("missing native field token {name}: {tokens:?}"));
        let (start, end) = token.span.expect("native field span");
        assert_eq!(text.get(start..end), Some(*name), "{token:?}");
        assert!(token.address.is_some_and(|address| (0x1000..0x1009).contains(&address)), "{token:?}");
    }
    for name in absent {
        assert!(
            !tokens.iter().any(|token| token.kind == "field" && token.text == *name),
            "stale field {name}: {tokens:?}"
        );
    }
}

#[test]
fn native_parameter_seeds_render_fields_without_changing_names_or_storage_and_clear() {
    let mut engine = make_engine(FIELDS);
    let before_text = engine.decompile(0x1000, "fields", false).unwrap();
    let before = engine.structured_result().unwrap();
    let original = &before.signature.parameters[0];
    assert!(!before_text.contains("->gain"));
    for declaration in ["struct HintState *", "HintState *"] {
        engine.set_type_hints(0x1000, &[TypeHint::Parameter { index: 0, data_type: declaration.to_owned() }]).unwrap();
        for _ in 0..2 {
            let text = engine.decompile(0x1000, "fields", false).unwrap();
            assert!(text.contains("->gain") && text.contains("->bias"), "{text}");
            assert_field_tokens(&engine, &text, &["gain", "bias"], &["first", "second"]);
            let result = engine.structured_result().unwrap();
            assert_eq!(result.signature.parameters[0].storage, original.storage);
            assert_eq!(result.signature.parameters[0].name, original.name);
            assert_eq!(result.signature.parameters[1], before.signature.parameters[1]);
        }
    }
    engine
        .set_type_hints(0x1000, &[TypeHint::Parameter { index: 0, data_type: "struct OtherState *".to_owned() }])
        .unwrap();
    let replaced = engine.decompile(0x1000, "fields", false).unwrap();
    assert!(replaced.contains("->first") && !replaced.contains("->gain"), "{replaced}");
    assert_field_tokens(&engine, &replaced, &["first", "second"], &["gain", "bias"]);
    engine.set_type_hints(0x1000, &[]).unwrap();
    let cleared = engine.decompile(0x1000, "fields", false).unwrap();
    assert!(!cleared.contains("->first") && !cleared.contains("->gain"), "{cleared}");
    assert_field_tokens(&engine, &cleared, &[], &["gain", "bias", "first", "second"]);
    assert_eq!(engine.structured_result().unwrap().signature, before.signature);
}

#[test]
fn analyst_local_types_and_explicit_prototypes_win_over_native_seeds() {
    for explicit_prototype in [false, true] {
        let mut engine = make_engine(FIELDS);
        engine.decompile(0x1000, "fields", false).unwrap();
        let result = engine.structured_result().unwrap();
        if explicit_prototype {
            engine.apply_prototype(0x1000, false, "int4 fields(OtherState *owner, int4 sample);").unwrap();
        } else {
            engine
                .set_variable_overrides(
                    0x1000,
                    &[LocalOverride {
                        storage: VariableStorage::try_from(&result.signature.parameters[0].storage).unwrap(),
                        name: Some("owner".to_owned()),
                        data_type: Some("struct OtherState *".to_owned()),
                    }],
                )
                .unwrap();
        }
        engine
            .set_type_hints(0x1000, &[TypeHint::Parameter { index: 0, data_type: "struct HintState *".to_owned() }])
            .unwrap();
        let text = engine.decompile(0x1000, "fields", false).unwrap();
        assert!(text.contains("owner->first") && !text.contains("->gain"), "{text}");
    }
}

#[test]
fn whole_native_local_pointer_seed_is_retained_or_explicitly_unsupported() {
    // fixtures/type_hints.c, local_fields: call get_state; read both fields; add them.
    let bytes =
        [0x48, 0x83, 0xec, 8, 0xe8, 0xf7, 0, 0, 0, 0x8b, 0x10, 3, 0x50, 4, 0x89, 0xd0, 0x48, 0x83, 0xc4, 8, 0xc3];
    let mut engine = make_engine(&bytes);
    engine.set_symbol(0x1100, "get_state").unwrap();
    engine.decompile(0x1000, "local_fields", false).unwrap();
    let result = engine.structured_result().unwrap();
    let local = result
        .variables
        .iter()
        .find(|variable| {
            variable.kind == VariableKind::Local
                && variable.data_type.size == 8
                && variable.storage.len() == 1
                && VariableStorage::try_from(&variable.storage[0]).is_ok()
        })
        .expect("native pointer local");
    engine
        .set_type_hints(
            0x1000,
            &[TypeHint::Local {
                storage: VariableStorage::try_from(&local.storage[0]).unwrap(),
                data_type: "struct HintState *".to_owned(),
            }],
        )
        .unwrap();
    match engine.decompile(0x1000, "local_fields", false) {
        Ok(text) => assert!(text.contains("->gain") && text.contains("->bias"), "{text}"),
        Err(error) => assert!(error.to_string().contains("Unsupported native"), "{error}"),
    }
}

#[test]
fn native_return_hint_preserves_the_recovered_return_width_and_analyst_return_wins() {
    // fixtures/type_hints.c, identity: mov rax,rdi; ret.
    let mut engine = make_engine(&[0x48, 0x89, 0xf8, 0xc3]);
    engine.decompile(0x1000, "identity", false).unwrap();
    let before = engine.structured_result().unwrap();
    assert_eq!(before.signature.return_type.size, 8);
    engine.set_type_hints(0x1000, &[TypeHint::Return { data_type: "struct HintState *".to_owned() }]).unwrap();
    engine.decompile(0x1000, "identity", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert!(result.signature.return_type.name.contains("HintState"), "{result:?}");
    assert_eq!(result.signature.return_type.size, before.signature.return_type.size);
    engine.apply_prototype(0x1000, false, "OtherState *identity(OtherState *owner);").unwrap();
    engine.decompile(0x1000, "identity", false).unwrap();
    assert!(engine.structured_result().unwrap().signature.return_type.name.contains("OtherState"));
}

#[test]
fn call_evidence_has_exact_inputs_whole_mappings_and_only_proven_direct_returns() {
    for (bytes, direct) in
        [(&[0xe8, 0xfb, 0, 0, 0, 0xc3][..], true), (&[0xe8, 0xfb, 0, 0, 0, 0x83, 0xc0, 1, 0xc3][..], false)]
    {
        let mut engine = make_engine(bytes);
        engine.set_symbol(0x1100, "fields").unwrap();
        engine.apply_prototype(0x1100, false, "int4 fields(HintState *state, int4 sample);").unwrap();
        engine.set_symbol(0x1000, "caller").unwrap();
        engine.apply_prototype(0x1000, false, "int4 caller(HintState *state, int4 sample);").unwrap();
        engine.decompile(0x1000, "caller", false).unwrap();
        let result = engine.structured_result().unwrap();
        let call = &result.calls[0];
        assert_eq!(call.target, Some(0x1100));
        let arguments = call.arguments.as_ref().expect("simple native call evidence");
        assert_eq!(arguments.len(), 2);
        for (index, argument) in arguments.iter().enumerate() {
            assert_eq!(argument.input_index, index as u32 + 1);
            assert_eq!(argument.parameter_index, Some(index as u32));
            assert_eq!(argument.value.status, CallValueStatus::Variable);
            let storage = argument.value.storage.as_ref().expect("whole caller argument symbol");
            assert_eq!(*storage, VariableStorage::try_from(argument.value.raw_storage.as_ref().unwrap()).unwrap());
        }
        assert_eq!(call.result.as_ref().unwrap().direct_return, direct);
    }
}

#[test]
fn variadic_and_indirect_calls_refuse_evidence_and_hints_do_not_invent_parameters() {
    let mut engine = make_engine(&[0xe8, 0xfb, 0, 0, 0, 0xc3]);
    engine.set_symbol(0x1100, "variadic").unwrap();
    engine.apply_prototype(0x1100, false, "int4 variadic(int4 first, ...);").unwrap();
    engine.decompile(0x1000, "caller", false).unwrap();
    let call = &engine.structured_result().unwrap().calls[0];
    assert!(call.arguments.is_none() && call.result.is_none());
    assert!(call.evidence_unavailable.is_some());
    let mut engine = make_engine(&[0xff, 0xd7, 0xc3]);
    engine.decompile(0x1000, "indirect", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert!(result.calls[0].indirect && result.calls[0].arguments.is_none());
    engine.set_type_hints(0x1000, &[TypeHint::Parameter { index: 255, data_type: "int4".to_owned() }]).unwrap();
    assert!(engine.decompile(0x1000, "indirect", false).unwrap_err().to_string().contains("not recovered"));
}

#[test]
fn older_call_records_remain_readable_without_new_evidence() {
    let call: Call = serde_json::from_str(r#"{"source":4096,"target":4352,"name":"callee","indirect":false}"#).unwrap();
    assert!(call.arguments.is_none() && call.result.is_none() && call.evidence_unavailable.is_none());
}

#[test]
fn hinted_native_callee_shape_bootstraps_previously_absent_caller_inputs_without_a_prototype() {
    // fixtures/type_hints.c, fields at 0x1000 and caller at 0x1010.
    // caller: push rax; call fields; pop rcx; ret. No explicit caller/callee prototype is installed.
    let bytes = [
        0x8b, 7, 0x0f, 0xaf, 0xc6, 3, 0x47, 4, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x50, 0xe8, 0xea, 0xff,
        0xff, 0xff, 0x59, 0xc3,
    ];
    let mut engine = make_engine(&bytes);
    engine.set_symbol(0x1000, "fields").unwrap();
    engine.decompile(0x1010, "caller", false).unwrap();
    let before = engine.structured_result().unwrap();
    assert!(before.calls[0].arguments.as_deref().unwrap_or_default().is_empty());
    engine
        .set_type_hints(0x1000, &[TypeHint::Parameter { index: 0, data_type: "struct HintState *".to_owned() }])
        .unwrap();
    for _ in 0..2 {
        engine.decompile(0x1010, "caller", false).unwrap();
        let result = engine.structured_result().unwrap();
        let arguments = result.calls[0].arguments.as_ref().expect("native shape context");
        assert_eq!(arguments.len(), 2, "{result:?}");
        assert_eq!(arguments[0].input_index, 1);
        assert_eq!(arguments[0].parameter_index, Some(0));
        assert!(arguments[0].value.data_type.as_ref().unwrap().name.contains("HintState"), "{result:?}");
        assert!(arguments[0].value.storage.is_some(), "{result:?}");
        assert!(!arguments[0].value.type_locked, "derived context acquired an analyst lock: {result:?}");
        assert_eq!(result.signature.parameters.len(), 2, "{result:?}");
    }
    engine.set_type_hints(0x1000, &[]).unwrap();
    engine.decompile(0x1010, "caller", false).unwrap();
    let cleared = engine.structured_result().unwrap();
    assert!(cleared.calls[0].arguments.as_deref().unwrap_or_default().is_empty(), "{cleared:?}");
}

#[test]
fn user_global_types_are_native_argument_evidence_not_local_selectors() {
    // int caller(void) { return consume(shared_count); } with shared_count at 0x3000.
    let bytes = [0x8b, 0x3d, 0xfa, 0x1f, 0, 0, 0xe8, 0xf5, 0, 0, 0, 0xc3];
    let mut engine = Decompiler::open_regions(
        Arch::X86_64,
        false,
        &[
            MemoryRegion {
                base: 0x1000,
                bytes: &bytes,
                size: bytes.len() as u64,
                readable: true,
                writable: false,
                executable: true,
            },
            MemoryRegion {
                base: 0x3000,
                bytes: &[7, 0, 0, 0],
                size: 4,
                readable: true,
                writable: true,
                executable: false,
            },
        ],
    )
    .unwrap();
    engine.add_global(0x3000, "uint4 shared_count;").unwrap();
    engine.set_symbol(0x1100, "consume").unwrap();
    engine.apply_prototype(0x1100, false, "int4 consume(uint4 value);").unwrap();
    engine.decompile(0x1000, "caller", false).unwrap();
    let result = engine.structured_result().unwrap();
    let value = &result.calls[0].arguments.as_ref().unwrap()[0].value;
    assert_eq!(value.status, CallValueStatus::Global, "{value:?}");
    assert_eq!(value.global_address, Some(0x3000));
    assert!(value.type_locked && value.storage.is_none());
    assert_eq!(value.symbol_type.as_ref().unwrap().name, "uint4");
}

#[test]
fn native_callee_return_hint_context_makes_caller_result_fields_readable() {
    // factory at 0x1000: lea rax,[rip+0x1ff9]; ret (returns data at 0x3000).
    // reader at 0x1010: call factory; read [rax] and [rax+4]; add; ret.
    let bytes = [
        0x48, 0x8d, 5, 0xf9, 0x1f, 0, 0, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xe8, 0xeb, 0xff, 0xff,
        0xff, 0x8b, 0x10, 3, 0x50, 4, 0x89, 0xd0, 0xc3,
    ];
    let mut engine = Decompiler::open_regions(
        Arch::X86_64,
        false,
        &[
            MemoryRegion {
                base: 0x1000,
                bytes: &bytes,
                size: bytes.len() as u64,
                readable: true,
                writable: false,
                executable: true,
            },
            MemoryRegion {
                base: 0x3000,
                bytes: &[1, 0, 0, 0, 2, 0, 0, 0],
                size: 8,
                readable: true,
                writable: true,
                executable: false,
            },
        ],
    )
    .unwrap();
    engine.parse_type_library(TYPES, None).unwrap();
    engine.set_symbol(0x1000, "factory").unwrap();
    engine.set_type_hints(0x1000, &[TypeHint::Return { data_type: "struct HintState *".to_owned() }]).unwrap();
    let text = engine.decompile(0x1010, "reader", false).unwrap();
    assert!(text.contains("->gain") && text.contains("->bias"), "{text}");
    let result = engine.structured_result().unwrap();
    let output = result.calls[0].result.as_ref().unwrap();
    assert!(output.value.data_type.as_ref().unwrap().name.contains("HintState"), "{result:?}");
    assert!(!output.value.type_locked && !output.direct_return, "{result:?}");
}

#[test]
fn native_aggregate_lowering_is_not_reported_as_declared_parameters_or_propagation_evidence() {
    // struct Big caller(void) { return produce(); } with a SysV native hidden return pointer.
    let bytes = [0x53, 0x48, 0x89, 0xfb, 0xe8, 0xf7, 0, 0, 0, 0x48, 0x89, 0xd8, 0x5b, 0xc3];
    let mut engine = make_engine(&bytes);
    engine.parse_c("struct Big { uint8 first; uint8 second; uint8 third; };").unwrap();
    engine.set_symbol(0x1100, "produce").unwrap();
    engine.apply_prototype(0x1100, false, "Big produce(void);").unwrap();
    engine.set_symbol(0x1000, "caller").unwrap();
    engine.apply_prototype(0x1000, false, "Big caller(void);").unwrap();
    engine.decompile(0x1000, "caller", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert!(result.signature.parameters.is_empty(), "hidden return argument leaked: {result:?}");
    let call = &result.calls[0];
    assert!(call.arguments.is_none() && call.result.is_none() && call.evidence_unavailable.is_some(), "{call:?}");
}

#[test]
fn scalar_global_value_and_address_keep_distinct_argument_types_at_equal_widths() {
    for (load_opcode, address_of) in [(0x8b, false), (0x8d, true)] {
        let code = [0x48, load_opcode, 0x3d, 0xf9, 0x1f, 0, 0, 0xe8, 0xf4, 0, 0, 0, 0xc3];
        let data = [7, 0, 0, 0, 0, 0, 0, 0];
        let mut engine = Decompiler::open_regions(
            Arch::X86_64,
            false,
            &[
                MemoryRegion {
                    base: 0x1000,
                    bytes: &code,
                    size: code.len() as u64,
                    readable: true,
                    writable: false,
                    executable: true,
                },
                MemoryRegion { base: 0x3000, bytes: &data, size: 8, readable: true, writable: true, executable: false },
            ],
        )
        .unwrap();
        engine.add_global(0x3000, "uint8 scalar_global;").unwrap();
        engine.set_symbol(0x1100, "consume").unwrap();
        engine
            .apply_prototype(
                0x1100,
                false,
                if address_of { "uint8 consume(uint8 *value);" } else { "uint8 consume(uint8 value);" },
            )
            .unwrap();
        engine.decompile(0x1000, "caller", false).unwrap();
        let result = engine.structured_result().unwrap();
        let value = &result.calls[0].arguments.as_ref().unwrap()[0].value;
        assert_eq!(value.global_address, Some(0x3000));
        assert!(value.storage.is_none() && value.global_type_locked, "{value:?}");
        assert_eq!(value.global_object_type.as_ref().unwrap().name, "uint8");
        let argument_type = value.data_type.as_ref().unwrap();
        assert_eq!(argument_type.size, 8);
        if address_of {
            assert_eq!(value.status, CallValueStatus::GlobalAddress);
            assert!(value.symbol_type.is_none() && !value.type_locked, "{value:?}");
            assert!(argument_type.name.contains("uint8") && argument_type.name.contains('*'), "{value:?}");
        } else {
            assert_eq!(value.status, CallValueStatus::Global);
            assert_eq!(value.symbol_type.as_ref().unwrap().name, "uint8");
            assert!(value.type_locked && !argument_type.name.contains('*'), "{value:?}");
        }
    }
}

#[test]
fn renaming_a_different_parameter_does_not_turn_preservation_locks_into_analyst_types() {
    let bytes = [
        0x8b, 7, 0x0f, 0xaf, 0xc6, 3, 0x47, 4, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x50, 0xe8, 0xea, 0xff,
        0xff, 0xff, 0x59, 0xc3,
    ];
    let mut engine = make_engine(&bytes);
    engine.set_symbol(0x1000, "fields").unwrap();
    engine.decompile(0x1000, "fields", false).unwrap();
    let original = engine.structured_result().unwrap();
    engine
        .set_variable_overrides(
            0x1000,
            &[LocalOverride {
                storage: VariableStorage::try_from(&original.signature.parameters[1].storage).unwrap(),
                name: Some("sample".to_owned()),
                data_type: None,
            }],
        )
        .unwrap();
    engine
        .set_type_hints(0x1000, &[TypeHint::Parameter { index: 0, data_type: "struct HintState *".to_owned() }])
        .unwrap();
    for _ in 0..2 {
        let text = engine.decompile(0x1000, "fields", false).unwrap();
        assert!(text.contains("->gain") && text.contains("->bias") && text.contains("sample"), "{text}");
        engine.decompile(0x1010, "caller", false).unwrap();
        let result = engine.structured_result().unwrap();
        let arguments = result.calls[0].arguments.as_ref().unwrap();
        assert_eq!(arguments.len(), 2);
        assert!(arguments[0].value.data_type.as_ref().unwrap().name.contains("HintState"), "{result:?}");
        assert!(arguments.iter().all(|argument| !argument.value.type_locked), "synthetic locks leaked: {result:?}");
    }
    engine.set_type_hints(0x1000, &[]).unwrap();
    let cleared = engine.decompile(0x1000, "fields", false).unwrap();
    assert!(cleared.contains("sample") && !cleared.contains("->gain"), "{cleared}");
    engine
        .set_type_hints(0x1000, &[TypeHint::Parameter { index: 0, data_type: "struct OtherState *".to_owned() }])
        .unwrap();
    let replaced = engine.decompile(0x1000, "fields", false).unwrap();
    assert!(replaced.contains("sample") && replaced.contains("->first") && !replaced.contains("->gain"), "{replaced}");
}

#[test]
fn unrelated_stack_parameter_hint_is_isolated_until_a_native_call_edge_needs_its_shape() {
    // fixtures/type_hints.c, windows_stack_fields: RCX holds state; the fifth argument is [RSP+0x28].
    let owner = [0x8b, 1, 3, 0x41, 4, 3, 0x44, 0x24, 0x28, 0xc3];
    let unrelated = [0xb8, 7, 0, 0, 0, 0xc3];
    // Preserve incoming register arguments and forward the fifth argument in a real Windows x64 frame.
    let caller = [
        0x48, 0x83, 0xec, 0x28, 0x8b, 0x44, 0x24, 0x50, 0x89, 0x44, 0x24, 0x20, 0xe8, 0xef, 0xfd, 0xff, 0xff, 0x48,
        0x83, 0xc4, 0x28, 0xc3,
    ];
    let regions = [(0x1000, &owner[..]), (0x1100, &unrelated[..]), (0x1200, &caller[..])].map(|(base, bytes)| {
        MemoryRegion { base, bytes, size: bytes.len() as u64, readable: true, writable: false, executable: true }
    });
    let mut engine = Decompiler::open_with_options(
        Arch::X86_64,
        false,
        &regions,
        &DecompilerOptions { platform: Platform::Windows, ..Default::default() },
    )
    .unwrap();
    engine.parse_type_library(TYPES, None).unwrap();
    engine.set_symbol(0x1000, "stack_fields").unwrap();
    // Fix only the native shape: the first parameter remains size-only, not an analyst pointer assertion.
    engine
        .apply_prototype(
            0x1000,
            false,
            "int4 stack_fields(xunknown8 state, int4 unused1, int4 unused2, int4 unused3, int4 extra);",
        )
        .unwrap();
    engine.decompile(0x1000, "stack_fields", false).unwrap();
    let baseline = engine.structured_result().unwrap();
    assert_eq!(baseline.signature.calling_convention.as_deref(), Some("__fastcall"));
    assert_eq!(baseline.signature.parameters.len(), 5);
    assert!(
        baseline.signature.parameters.iter().any(|parameter| {
            parameter.storage.kind == rampage_decompiler::results::StorageKind::Spacebase
                && parameter.storage.address == Some(0x28)
                && parameter.storage.size == 4
        }),
        "native stack-passed scalar parameter: {baseline:?}"
    );
    let index = baseline
        .signature
        .parameters
        .iter()
        .position(|parameter| {
            parameter.storage.kind == rampage_decompiler::results::StorageKind::Processor
                && parameter.data_type.name.contains('*')
        })
        .expect("native register-passed state pointer");
    engine
        .set_type_hints(
            0x1000,
            &[TypeHint::Parameter { index: index as u32, data_type: "struct HintState *".to_owned() }],
        )
        .unwrap();
    let owner_text = engine.decompile(0x1000, "stack_fields", false).unwrap();
    assert!(owner_text.contains("->gain") && owner_text.contains("->bias"), "{owner_text}");
    engine.decompile(0x1100, "unrelated", false).unwrap();
    assert!(engine.structured_result().unwrap().calls.is_empty());
    let error = engine.decompile(0x1200, "caller", false).unwrap_err();
    assert!(error.to_string().contains("complete register mapping"), "{error}");
}

#[test]
fn unknown_prototype_cannot_hide_a_recovered_two_register_call_output() {
    // uint64_t caller(void) { unsigned __int128 value = produce(); return value + (value >> 64); }
    let code = [0x50, 0xe8, 0xfa, 0, 0, 0, 0x48, 1, 0xd0, 0x59, 0xc3];
    let mut engine = make_engine(&code);
    engine.set_symbol(0x1100, "produce").unwrap();
    engine.decompile(0x1000, "caller", false).unwrap();
    let result = engine.structured_result().unwrap();
    let call = &result.calls[0];
    assert!(call.evidence_unavailable.is_some() && call.arguments.is_none() && call.result.is_none(), "{call:?}");
    let reason = call.evidence_unavailable.as_deref().unwrap();
    assert!(
        reason.contains("actual_width=")
            && reason.contains("actual_space=")
            && reason.contains("prototype_return_width="),
        "{reason}"
    );
}

fn exact_return_wrapper_engine() -> Decompiler {
    exact_return_wrapper_engine_with_pop(0x59)
}

fn exact_return_wrapper_engine_with_pop(pop: u8) -> Decompiler {
    // tests/fixtures/src/type-propagation.c: prop_factory at 0x20118c, prop_return_caller at 0x201190.
    let code = [0x48, 0x89, 0xf8, 0xc3, 0x50, 0xe8, 0xf6, 0xff, 0xff, 0xff, pop, 0xc3];
    let mut engine =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x20118c, bytes: &code, writable: false }]).unwrap();
    engine.parse_type_library("struct PropState { int4 gain; int4 bias; };", None).unwrap();
    engine.set_symbol(0x20118c, "factory").unwrap();
    engine.set_symbol(0x201190, "return_caller").unwrap();
    engine
}

#[test]
fn exact_wrapper_explicit_caller_return_proves_an_untyped_factory_edge_without_hard_callee_types() {
    let mut leaf = exact_return_wrapper_engine();
    leaf.decompile(0x20118c, "factory", false).unwrap();
    assert_eq!(leaf.structured_result().unwrap().signature.return_type.size, 8);
    let mut engine = exact_return_wrapper_engine();
    engine.apply_prototype(0x201190, false, "PropState *return_caller(PropState *opaque);").unwrap();
    let text = engine.decompile(0x201190, "return_caller", false).unwrap();
    let result = engine.structured_result().unwrap();
    let call = &result.calls[0];
    assert_eq!(call.source, Some(0x201191));
    assert_eq!(call.target, Some(0x20118c));
    assert!(call.evidence_unavailable.is_none(), "{call:?}\n{text}");
    let output = call.result.as_ref().expect("same-width native return flow from the actual factory output");
    assert!(output.direct_return, "{result:?}\n{text}");
    assert_eq!(output.value.data_type.as_ref().unwrap().size, 8);
    assert!(output.value.data_type.as_ref().unwrap().name.contains("PropState"), "{result:?}");
    let arguments = call.arguments.as_ref().unwrap();
    assert_eq!(arguments.len(), 1);
    assert_eq!(arguments[0].input_index, 1);
    assert_eq!(arguments[0].parameter_index, Some(0));
    engine.decompile(0x20118c, "factory", false).unwrap();
    let untyped = engine.structured_result().unwrap();
    assert_eq!(untyped.signature.return_type.size, 8);
    assert!(
        !untyped.signature.return_type.name.contains("PropState"),
        "caller inference hard-typed callee: {untyped:?}"
    );
}

#[test]
fn exact_wrapper_explicit_factory_return_survives_pop_rcx_and_recovers_the_unlocked_caller_return() {
    let mut engine = exact_return_wrapper_engine();
    engine.apply_prototype(0x20118c, false, "PropState *factory(void *opaque);").unwrap();
    for _ in 0..2 {
        let text = engine.decompile(0x201190, "return_caller", false).unwrap();
        let result = engine.structured_result().unwrap();
        assert_eq!(result.signature.return_type.size, 8, "{result:?}\n{text}");
        assert!(result.signature.return_type.name.contains("PropState"), "{result:?}\n{text}");
        let call = &result.calls[0];
        assert_eq!(call.source, Some(0x201191));
        assert_eq!(call.target, Some(0x20118c));
        assert!(call.evidence_unavailable.is_none(), "{call:?}");
        let output = call.result.as_ref().expect("native CALL result used by normal RETURN");
        assert!(output.direct_return && !output.value.type_locked, "{result:?}");
        assert!(output.value.data_type.as_ref().unwrap().name.contains("PropState"), "{result:?}");
    }
}

#[test]
fn exact_wrapper_weak_factory_return_context_recovers_only_a_proven_unlocked_return() {
    let mut engine = exact_return_wrapper_engine();
    engine.set_type_hints(0x20118c, &[TypeHint::Return { data_type: "struct PropState *".to_owned() }]).unwrap();
    let text = engine.decompile(0x201190, "return_caller", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert!(result.signature.return_type.name.contains("PropState"), "{result:?}\n{text}");
    let call = &result.calls[0];
    assert!(call.evidence_unavailable.is_none(), "{call:?}");
    let output = call.result.as_ref().expect("SSA-proven weak callee return context");
    assert!(output.direct_return && !output.value.type_locked, "{result:?}");
}

#[test]
fn restoring_rax_after_the_exact_factory_call_does_not_manufacture_a_return_edge() {
    let mut engine = exact_return_wrapper_engine_with_pop(0x58);
    engine.apply_prototype(0x20118c, false, "PropState *factory(void *opaque);").unwrap();
    let text = engine.decompile(0x201190, "return_caller", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert!(!result.signature.return_type.name.contains("PropState"), "{result:?}\n{text}");
    assert!(result.calls[0].result.as_ref().is_none_or(|value| !value.direct_return), "{result:?}\n{text}");
}

#[test]
fn identity_factory_context_keeps_unlocked_result_types_through_native_output_token_inference() {
    let code = [
        0x48, 0x89, 0xf8, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x50, 0xe8,
        0xea, 0xff, 0xff, 0xff, 0x59, 0x8b, 0x10, 3, 0x50, 4, 0x89, 0xd0, 0xc3,
    ];
    let mut engine = make_engine(&code);
    engine.set_symbol(0x1000, "identity_factory").unwrap();
    engine.set_type_hints(0x1000, &[TypeHint::Return { data_type: "struct HintState *".to_owned() }]).unwrap();
    for _ in 0..2 {
        let text = engine.decompile(0x1010, "reader", false).unwrap();
        assert!(text.contains("->gain") && text.contains("->bias"), "{text}");
        let result = engine.structured_result().unwrap();
        let output = result.calls[0].result.as_ref().unwrap();
        assert!(output.value.data_type.as_ref().unwrap().name.contains("HintState"), "{result:?}");
        assert!(!output.value.type_locked && !output.direct_return, "{result:?}");
    }
}

#[test]
fn ordinary_decompilation_keeps_c_when_call_argument_evidence_exhausts_its_budget() {
    for (calls, arguments, complete_calls) in [(86usize, 3usize, 85usize), (257, 1, 256)] {
        // fixtures/type_hints.c, many_calls: repeated calls with scalar constants, returning the last result.
        let base = 0x1000u64;
        let target = 0x8000u64;
        let mut code = vec![0x48, 0x83, 0xec, 8];
        for _ in 0..calls {
            for opcode in [0xbf, 0xbe, 0xba].into_iter().take(arguments) {
                code.push(opcode);
                code.extend_from_slice(&1u32.to_le_bytes());
            }
            code.push(0xe8);
            let next = base + code.len() as u64 + 4;
            let displacement = i32::try_from(target - next).unwrap();
            code.extend_from_slice(&displacement.to_le_bytes());
        }
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 8, 0xc3]);
        let mut engine =
            Decompiler::open(Arch::X86_64, false, &[Segment { base, bytes: &code, writable: false }]).unwrap();
        engine.set_symbol(target, "consume").unwrap();
        engine
            .apply_prototype(
                target,
                false,
                if arguments == 3 {
                    "int4 consume(int4 first, int4 second, int4 third);"
                } else {
                    "int4 consume(int4 first);"
                },
            )
            .unwrap();
        // No propagation or TypeHints operation is requested.
        let text = engine.decompile(base, "many_calls", false).unwrap();
        assert_eq!(text.matches("consume(").count(), calls, "{text}");
        let result = engine.structured_result().unwrap();
        assert_eq!(result.calls.len(), calls);
        let exported = result.calls.iter().filter_map(|call| call.arguments.as_ref()).map(Vec::len).sum::<usize>();
        assert_eq!(exported, complete_calls * arguments);
        assert!(exported <= 256);
        for (index, call) in result.calls.iter().enumerate() {
            assert_eq!(call.target, Some(target));
            assert!(call.source.is_some());
            if index < complete_calls {
                assert_eq!(call.arguments.as_ref().unwrap().len(), arguments);
                assert!(call.evidence_unavailable.is_none(), "{call:?}");
            } else {
                assert!(call.arguments.is_none() && call.result.is_none(), "partial call proof: {call:?}");
                assert!(call.evidence_unavailable.as_deref().unwrap().contains("budget exceeded"), "{call:?}");
            }
        }
    }
}
