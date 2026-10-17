#![cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]

use rampage_decompiler::worker::{
    PROTOCOL_VERSION, WorkerConfig, WorkerFunction, WorkerMapping, WorkerOperation, WorkerOptions, WorkerRequest,
    run_supervised,
};
use rampage_decompiler::{LocalOverride, VariableStorage};

fn request() -> WorkerRequest {
    WorkerRequest {
        version: PROTOCOL_VERSION,
        arch: "x86_64".to_owned(),
        big_endian: false,
        options: WorkerOptions::default(),
        mappings: vec![WorkerMapping {
            base: 0x1000,
            hex_bytes: "8b070fafc6034704c3".to_owned(),
            size: 9,
            readable: true,
            writable: false,
            executable: true,
        }],
        code_modes: Vec::new(),
        operations: Vec::new(),
        decompile: WorkerFunction { address: 0x1000, name: "fields".to_owned(), thumb: false },
        tokens: true,
        validate_only: false,
        type_query: None,
    }
}

fn config() -> WorkerConfig {
    WorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

#[test]
fn worker_replays_storage_keyed_local_types_before_decompilation() {
    let mut request = request();
    let initial = run_supervised(&request, &config(), None).unwrap();
    let structure = initial.structure.unwrap();
    let mapping = &structure.signature.parameters[0].storage;
    assert_eq!(mapping.address_size_bytes, Some(4));
    let frame = structure.frame_context.as_ref().unwrap();
    assert_eq!(frame.stack_space, "stack");
    assert_eq!(frame.address_size_bytes, 8);
    let storage = VariableStorage::try_from(&structure.signature.parameters[0].storage).unwrap();
    let mut without_width = mapping.clone();
    without_width.address_size_bytes = None;
    assert_eq!(VariableStorage::try_from(&without_width).unwrap(), storage);
    assert!(serde_json::to_value(&storage).unwrap().get("address_size_bytes").is_none());
    request.operations = vec![
        WorkerOperation::ParseTypes { declarations: "struct PhaseState { int4 gain; int4 bias; };".to_owned() },
        WorkerOperation::LocalVariables {
            address: 0x1000,
            overrides: vec![LocalOverride {
                storage: storage.clone(),
                name: Some("p".to_owned()),
                data_type: Some("struct PhaseState *".to_owned()),
            }],
        },
    ];
    let output = run_supervised(&request, &config(), None).unwrap();
    assert!(output.text.contains("p->gain"), "{}", output.text);
    assert!(output.text.contains("p->bias"), "{}", output.text);
    assert_eq!(output.structure.unwrap().signature.parameters[0].name, "p");
    assert!(output.tokens.unwrap().iter().any(|token| token.text == "p"));

    let WorkerOperation::LocalVariables { overrides, .. } = &mut request.operations[1] else { unreachable!() };
    overrides[0].storage.use_ranges[0].start += 1;
    overrides[0].storage.use_ranges[0].end += 1;
    let error = run_supervised(&request, &config(), None).unwrap_err();
    assert!(error.to_string().contains("did not match"), "{error}");

    request.operations.push(WorkerOperation::LocalVariables { address: 0x1000, overrides: Vec::new() });
    let cleared = run_supervised(&request, &config(), None).unwrap();
    assert!(!cleared.text.contains("p->"), "{}", cleared.text);
}

#[test]
fn worker_refuses_keyword_names_without_partial_output_and_accepts_a_later_valid_batch() {
    let mut request = request();
    let original = run_supervised(&request, &config(), None).unwrap().structure.unwrap();
    let first = VariableStorage::try_from(&original.signature.parameters[0].storage).unwrap();
    let second = VariableStorage::try_from(&original.signature.parameters[1].storage).unwrap();
    for name in ["return", "for", "int", "_Generic", "_Static_assert", "_Thread_local"] {
        request.operations = vec![WorkerOperation::LocalVariables {
            address: 0x1000,
            overrides: vec![
                LocalOverride { storage: first.clone(), name: Some("must_not_apply".to_owned()), data_type: None },
                LocalOverride { storage: second.clone(), name: Some(name.to_owned()), data_type: None },
            ],
        }];
        let error = run_supervised(&request, &config(), None).unwrap_err();
        assert!(error.to_string().contains("reserved C keyword"), "{name}: {error}");
    }
    request.operations.clear();
    let unchanged = run_supervised(&request, &config(), None).unwrap();
    assert!(!unchanged.text.contains("must_not_apply"), "{}", unchanged.text);
    assert_eq!(unchanged.structure.unwrap().signature.parameters, original.signature.parameters);
    request.operations = vec![WorkerOperation::LocalVariables {
        address: 0x1000,
        overrides: vec![
            LocalOverride { storage: first, name: Some("state_pointer".to_owned()), data_type: None },
            LocalOverride { storage: second, name: Some("input_factor".to_owned()), data_type: None },
        ],
    }];
    let output = run_supervised(&request, &config(), None).unwrap();
    let result = output.structure.unwrap();
    assert_eq!(result.signature.parameters[0].name, "state_pointer");
    assert_eq!(result.signature.parameters[1].name, "input_factor");
    assert!(output.text.contains("state_pointer"), "{}", output.text);
    assert!(output.text.contains("input_factor"), "{}", output.text);
}

#[test]
fn worker_replays_vacated_names_and_parameter_swaps_as_one_final_name_batch() {
    let mut request = request();
    let original = run_supervised(&request, &config(), None).unwrap().structure.unwrap();
    let first = VariableStorage::try_from(&original.signature.parameters[0].storage).unwrap();
    let second = VariableStorage::try_from(&original.signature.parameters[1].storage).unwrap();
    for (first_name, second_name) in [("param_2", "sample"), ("param_2", "param_1")] {
        request.operations = vec![WorkerOperation::LocalVariables {
            address: 0x1000,
            overrides: vec![
                LocalOverride { storage: first.clone(), name: Some(first_name.to_owned()), data_type: None },
                LocalOverride { storage: second.clone(), name: Some(second_name.to_owned()), data_type: None },
            ],
        }];
        let output = run_supervised(&request, &config(), None).unwrap();
        assert!(output.text.contains(first_name), "{}", output.text);
        assert!(output.text.contains(second_name), "{}", output.text);
        let result = output.structure.unwrap();
        assert_eq!(result.signature.parameters[0].name, first_name);
        assert_eq!(result.signature.parameters[1].name, second_name);
        assert_eq!(result.signature.parameters[0].storage, original.signature.parameters[0].storage);
        assert_eq!(result.signature.parameters[1].storage, original.signature.parameters[1].storage);
    }
    request.operations.push(WorkerOperation::LocalVariables { address: 0x1000, overrides: Vec::new() });
    let cleared = run_supervised(&request, &config(), None).unwrap();
    assert_eq!(cleared.structure.unwrap().signature.parameters, original.signature.parameters);
}
