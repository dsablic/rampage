#![cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]

use rampage_decompiler::worker::{
    PROTOCOL_VERSION, TypeQuery, WorkerConfig, WorkerFunction, WorkerOperation, WorkerOptions, WorkerRequest,
    run_supervised,
};

fn request(query: TypeQuery, validate_only: bool) -> WorkerRequest {
    WorkerRequest {
        version: PROTOCOL_VERSION,
        arch: "x86_64".to_owned(),
        big_endian: false,
        options: WorkerOptions::default(),
        mappings: Vec::new(),
        code_modes: Vec::new(),
        operations: vec![WorkerOperation::TypeLibrary {
            declarations: "typedef struct Record { char tag; long value; } Record;
                           typedef int (*Visitor)(struct Record *record);"
                .to_owned(),
            packing: Some(1),
        }],
        decompile: WorkerFunction { address: 0, name: String::new(), thumb: false },
        tokens: false,
        validate_only,
        type_query: Some(query),
    }
}

fn config() -> WorkerConfig {
    WorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

#[test]
fn worker_replays_multiple_anonymous_typedef_batches_without_empty_name_collisions() {
    let mut request = request(TypeQuery::Inventory, true);
    request.operations = vec![
        WorkerOperation::TypeLibrary {
            declarations: "typedef enum { READY = 7, BAD = -3 } Mode;
                typedef struct { int4 prefix; int4 bias; } State;"
                .to_owned(),
            packing: None,
        },
        WorkerOperation::TypeLibrary {
            declarations: "typedef union { int4 number; uint1 bytes[4]; } Payload;
                typedef enum { STOP = 9 } OtherMode;"
                .to_owned(),
            packing: None,
        },
        WorkerOperation::TypeLibrary {
            declarations: "typedef struct { int8 value; } OtherState;
                typedef union { int8 value; uint1 bytes[8]; } OtherPayload;"
                .to_owned(),
            packing: None,
        },
    ];
    let output = run_supervised(&request, &config(), None).unwrap();
    let batches = output.type_declarations.unwrap();
    assert_eq!(batches.len(), 3);
    assert_eq!(batches[0].iter().map(|ty| ty.name.as_str()).collect::<Vec<_>>(), ["Mode", "State"]);
    assert_eq!(batches[1].iter().map(|ty| ty.name.as_str()).collect::<Vec<_>>(), ["Payload", "OtherMode"]);
    assert_eq!(batches[2].iter().map(|ty| ty.name.as_str()).collect::<Vec<_>>(), ["OtherState", "OtherPayload"]);
    let types = output.type_inventory.unwrap();
    assert!(types.iter().all(|ty| !ty.name.is_empty()));
    let mode = types.iter().find(|ty| ty.name == "Mode").unwrap();
    assert_eq!(mode.kind, rampage_decompiler::NamedTypeKind::Typedef);
    assert_eq!(mode.enum_values.iter().find(|value| value.name == "READY").unwrap().value, "7");
    assert_eq!(mode.enum_values.iter().find(|value| value.name == "BAD").unwrap().value, "-3");
    let state = types.iter().find(|ty| ty.name == "State").unwrap();
    assert_eq!(state.kind, rampage_decompiler::NamedTypeKind::Typedef);
    assert_eq!(state.fields[1].name, "bias");
    assert_eq!(state.fields[1].offset, 4);
    assert_eq!(state.size, Some(8));
    let payload = types.iter().find(|ty| ty.name == "Payload").unwrap();
    assert_eq!(payload.size, Some(4));
    assert!(payload.fields.iter().all(|field| field.offset == 0));
}

#[test]
fn worker_refuses_named_overwrites_after_anonymous_typedef_registration() {
    for replacement in [
        WorkerOperation::TypeLibrary {
            declarations: "typedef struct { int8 replacement; } State;".to_owned(),
            packing: None,
        },
        WorkerOperation::ParseTypes { declarations: "typedef struct { int8 replacement; } State;".to_owned() },
    ] {
        let mut request = request(TypeQuery::Inventory, true);
        request.operations = vec![
            WorkerOperation::TypeLibrary {
                declarations: "typedef struct { int4 prefix; int4 bias; } State;".to_owned(),
                packing: None,
            },
            replacement,
        ];
        let error = run_supervised(&request, &config(), None).unwrap_err().to_string();
        assert!(error.contains("operation 1"), "{error}");
    }
}

#[test]
fn query_runs_after_type_library_replay_without_entry_bytes_even_in_validation_mode() {
    for validate_only in [false, true] {
        let output =
            run_supervised(&request(TypeQuery::Get { name: "Record".to_owned() }, validate_only), &config(), None)
                .unwrap();
        assert!(output.text.is_empty());
        assert!(output.structure.is_none());
        let types = output.type_inventory.unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].fields[1].offset, 1);
        assert_eq!(types[0].size, Some(9));
        assert_eq!(types[0].packing, Some(1));
    }
    let output = run_supervised(&request(TypeQuery::Inventory, true), &config(), None).unwrap();
    let types = output.type_inventory.unwrap();
    assert!(types.iter().any(|ty| ty.name == "Record"));
    assert!(types.iter().any(|ty| ty.name == "Visitor" && ty.callback.is_some()));
    assert!(!types.iter().any(|ty| ty.name == "int4"));
}

#[test]
fn query_uses_worker_target_model_and_get_does_not_dump_builtins() {
    let mut request = request(TypeQuery::Get { name: "Record".to_owned() }, true);
    request.options.platform = "windows".to_owned();
    let output = run_supervised(&request, &config(), None).unwrap();
    assert_eq!(output.type_inventory.unwrap()[0].size, Some(5));
    request.type_query = Some(TypeQuery::Get { name: "void".to_owned() });
    let types = run_supervised(&request, &config(), None).unwrap().type_inventory.unwrap();
    assert_eq!(types.len(), 1);
    assert_eq!(types[0].name, "void");
    assert_eq!(types[0].size, None);
}

#[test]
fn setup_failures_are_indexed_and_invalid_query_or_packing_never_succeeds() {
    let mut request = request(TypeQuery::Inventory, true);
    request.operations.push(WorkerOperation::TypeLibrary {
        declarations: "extern int NotAType(int value);".to_owned(),
        packing: None,
    });
    let error = run_supervised(&request, &config(), None).unwrap_err().to_string();
    assert!(error.contains("operation 1"), "{error}");
    request.operations.truncate(1);
    request.type_query = Some(TypeQuery::Get { name: "missing".to_owned() });
    assert!(run_supervised(&request, &config(), None).is_err());
    request.type_query = Some(TypeQuery::Get { name: "x".repeat(257) });
    assert!(run_supervised(&request, &config(), None).is_err());
    request.type_query = Some(TypeQuery::Inventory);
    request.operations[0] =
        WorkerOperation::TypeLibrary { declarations: "typedef int Value;".to_owned(), packing: Some(3) };
    assert!(run_supervised(&request, &config(), None).is_err());
}

#[test]
fn declarations_keep_batch_order_final_roots_and_exclude_incidental_native_names() {
    for validate_only in [false, true] {
        let mut request = request(TypeQuery::Inventory, validate_only);
        request.operations = vec![
            WorkerOperation::TypeLibrary {
                declarations: "struct Record; typedef int4 (*Cb)(struct Record *p);
                    typedef struct Record { uint1 tag; Cb cb; struct Record *next; } Record;"
                    .to_owned(),
                packing: None,
            },
            WorkerOperation::TypeLibrary {
                declarations: "typedef struct ReturnOnly *(*OtherCallback)(struct ParameterOnly *p);
                    struct Container { struct Nested { int4 value; } nested; };"
                    .to_owned(),
                packing: None,
            },
        ];
        let output = run_supervised(&request, &config(), None).unwrap();
        let batches = output.type_declarations.unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].iter().map(|ty| ty.name.as_str()).collect::<Vec<_>>(), ["Record", "Cb"]);
        assert!(!batches[0][0].incomplete);
        assert_eq!(batches[0][0].size, Some(24));
        assert_eq!(batches[1].iter().map(|ty| ty.name.as_str()).collect::<Vec<_>>(), ["OtherCallback", "Container"]);
        let inventory = output.type_inventory.unwrap();
        assert!(inventory.iter().any(|ty| ty.name == "ReturnOnly"));
        assert!(inventory.iter().any(|ty| ty.name == "ParameterOnly"));
        assert!(inventory.iter().any(|ty| ty.name == "Nested"));
    }
    let mut request = request(TypeQuery::Inventory, true);
    request.type_query = None;
    let output = run_supervised(&request, &config(), None).unwrap();
    assert!(output.type_inventory.is_none());
    assert_eq!(output.type_declarations.unwrap().len(), 1);
}

#[test]
fn later_legacy_type_parsing_cannot_redefine_library_types_with_or_without_queries() {
    for query in [None, Some(TypeQuery::Inventory)] {
        for declarations in
            ["typedef struct { uint1 replacement; } Record;", "typedef struct { char tag; int8 value; } Record;"]
        {
            let mut request = request(TypeQuery::Inventory, true);
            request.type_query = query.clone();
            request.operations[0] = WorkerOperation::TypeLibrary {
                declarations: "struct Record { char tag; int8 value; };".to_owned(),
                packing: None,
            };
            request.operations.push(WorkerOperation::ParseTypes { declarations: declarations.to_owned() });
            let error = run_supervised(&request, &config(), None).unwrap_err().to_string();
            assert!(error.contains("operation 1"), "{error}");
        }
    }
}

#[test]
fn nested_library_names_are_protected_and_later_batches_cannot_complete_earlier_forwards() {
    for later in [
        WorkerOperation::ParseTypes { declarations: "typedef struct { uint1 replacement; } Nested;".to_owned() },
        WorkerOperation::TypeLibrary { declarations: "struct Incidental { int4 value; };".to_owned(), packing: None },
    ] {
        let mut request = request(TypeQuery::Inventory, true);
        request.operations = vec![
            WorkerOperation::TypeLibrary {
                declarations: "struct Container { struct Nested { int4 value; } nested; };
                    typedef int4 (*Visit)(struct Incidental *p);"
                    .to_owned(),
                packing: None,
            },
            later,
        ];
        let error = run_supervised(&request, &config(), None).unwrap_err().to_string();
        assert!(error.contains("operation 1"), "{error}");
    }
}

#[test]
fn worker_exposes_c_int_enum_layout_and_native_variadic_callback_flags() {
    let mut request = request(TypeQuery::Inventory, true);
    request.operations = vec![WorkerOperation::TypeLibrary {
        declarations: "enum Signed { Negative = -3, Positive = 7 };
            typedef int4 (*Callback)(char *format, ...);
            struct EnumRecord { uint4 prefix; enum Signed mode; uint4 payload; Callback callback; void *next; };"
            .to_owned(),
        packing: None,
    }];
    let types = run_supervised(&request, &config(), None).unwrap().type_inventory.unwrap();
    let enumeration = types.iter().find(|ty| ty.name == "Signed").unwrap();
    assert_eq!(enumeration.size, Some(4));
    assert_eq!(enumeration.enum_values.iter().find(|value| value.name == "Negative").unwrap().value, "-3");
    let callback = types.iter().find(|ty| ty.name == "Callback").unwrap();
    assert!(callback.callback.as_ref().unwrap().variadic);
    let record = types.iter().find(|ty| ty.name == "EnumRecord").unwrap();
    assert_eq!(record.fields.iter().map(|field| field.offset).collect::<Vec<_>>(), [0, 4, 8, 16, 24]);
    assert_eq!(record.size, Some(32));
}

#[test]
fn windows_worker_callbacks_export_declared_aggregates_not_hidden_or_indirect_abi_parameters() {
    let mut request = request(TypeQuery::Inventory, true);
    request.options.platform = "windows".to_owned();
    request.operations = vec![WorkerOperation::TypeLibrary {
        declarations: "struct Large { int8 first; int8 second; int8 third; };
            typedef struct Large (*ReturnLarge)(struct Large value, int4 marker);
            struct Anonymous { struct Large (*cb)(struct Large value); };"
            .to_owned(),
        packing: None,
    }];
    let types = run_supervised(&request, &config(), None).unwrap().type_inventory.unwrap();
    let callback = types.iter().find(|ty| ty.name == "ReturnLarge").unwrap();
    let signature = callback.callback.as_ref().unwrap();
    assert_eq!(signature.return_type, "Large");
    assert_eq!(signature.parameters.len(), 2);
    assert_eq!(signature.parameters[0].name, "value");
    assert_eq!(signature.parameters[0].type_name, "Large");
    assert_eq!(signature.parameters[1].name, "marker");
    assert!(signature.calling_convention.is_some());
    assert_eq!(callback.dependencies, ["Large"]);
    let anonymous = types.iter().find(|ty| ty.name == "Anonymous").unwrap();
    assert!(anonymous.fields[0].identity.is_some());
}

#[test]
fn worker_native_parser_accepts_known_tags_and_typedef_named_members_and_parameters() {
    let mut request = request(TypeQuery::Inventory, true);
    request.mappings = vec![
        rampage_decompiler::worker::WorkerMapping {
            base: 0x1000,
            hex_bytes: "c3".to_owned(),
            size: 1,
            readable: true,
            writable: false,
            executable: true,
        },
        rampage_decompiler::worker::WorkerMapping {
            base: 0x2000,
            hex_bytes: "00000000000000000000000000000000".to_owned(),
            size: 16,
            readable: true,
            writable: true,
            executable: false,
        },
    ];
    request.operations = vec![
        WorkerOperation::TypeLibrary {
            declarations: "struct State { int4 value; }; typedef int4 String;
                struct Holder { int4 String; }; typedef int4 (*Named)(int4 String, struct State *State);"
                .to_owned(),
            packing: None,
        },
        WorkerOperation::Symbol { address: 0x1000, name: "subject".to_owned() },
        WorkerOperation::Prototype {
            address: 0x1000,
            indirect: false,
            declaration: "int4 subject(struct State *String);".to_owned(),
        },
        WorkerOperation::Global { address: 0x2000, declaration: "struct State data;".to_owned() },
    ];
    let types = run_supervised(&request, &config(), None).unwrap().type_inventory.unwrap();
    let holder = types.iter().find(|ty| ty.name == "Holder").unwrap();
    assert_eq!(holder.fields[0].name, "String");
    assert!(holder.dependencies.is_empty());
    let signature = types.iter().find(|ty| ty.name == "Named").unwrap().callback.as_ref().unwrap();
    assert_eq!(signature.parameters[0].name, "String");
    assert_eq!(signature.parameters[1].name, "State");
}
