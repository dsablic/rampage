#![cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]

use rampage_decompiler::results::CallValueStatus;
use rampage_decompiler::worker::{
    PROTOCOL_VERSION, WorkerConfig, WorkerFunction, WorkerMapping, WorkerOperation, WorkerOptions, WorkerOutput,
    WorkerRequest, run_supervised,
};
use rampage_decompiler::{LocalOverride, TypeHint, VariableStorage};

fn request() -> WorkerRequest {
    WorkerRequest {
        version: PROTOCOL_VERSION,
        arch: "x86_64".to_owned(),
        big_endian: false,
        options: WorkerOptions::default(),
        // rampage-decompiler/tests/fixtures/type_hints.c, fields. Never executed.
        mappings: vec![WorkerMapping {
            base: 0x1000,
            hex_bytes: "8b070fafc6034704c3".to_owned(),
            size: 9,
            readable: true,
            writable: false,
            executable: true,
        }],
        code_modes: Vec::new(),
        operations: vec![WorkerOperation::TypeLibrary {
            declarations: "struct HintState { int4 gain; int4 bias; }; struct OtherState { int4 first; int4 second; };"
                .to_owned(),
            packing: None,
        }],
        decompile: WorkerFunction { address: 0x1000, name: "fields".to_owned(), thumb: false },
        tokens: true,
        validate_only: false,
        type_query: None,
    }
}

fn config() -> WorkerConfig {
    WorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

fn assert_field_tokens(output: &WorkerOutput, expected: &[&str], absent: &[&str]) {
    let tokens = output.tokens.as_ref().expect("requested native tokens");
    for name in expected {
        let token = tokens
            .iter()
            .find(|token| token.kind == "field" && token.text == *name)
            .unwrap_or_else(|| panic!("missing native field token {name}: {tokens:?}"));
        let (start, end) = token.span.expect("native field span");
        assert_eq!(output.text.get(start..end), Some(*name), "{token:?}");
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
fn worker_replays_replaces_and_clears_native_parameter_hints() {
    let mut request = request();
    let before = run_supervised(&request, &config(), None).unwrap().structure.unwrap();
    request.operations.push(WorkerOperation::TypeHints {
        address: 0x1000,
        hints: vec![TypeHint::Parameter { index: 0, data_type: "struct HintState *".to_owned() }],
    });
    for _ in 0..2 {
        let output = run_supervised(&request, &config(), None).unwrap();
        assert!(output.text.contains("->gain") && output.text.contains("->bias"), "{}", output.text);
        assert_field_tokens(&output, &["gain", "bias"], &["first", "second"]);
        let signature = output.structure.unwrap().signature;
        assert_eq!(signature.parameters[0].storage, before.signature.parameters[0].storage);
        assert_eq!(signature.parameters[1], before.signature.parameters[1]);
    }
    request.operations.push(WorkerOperation::TypeHints {
        address: 0x1000,
        hints: vec![TypeHint::Parameter { index: 0, data_type: "struct OtherState *".to_owned() }],
    });
    let replaced = run_supervised(&request, &config(), None).unwrap();
    assert!(replaced.text.contains("->first") && !replaced.text.contains("->gain"), "{}", replaced.text);
    assert_field_tokens(&replaced, &["first", "second"], &["gain", "bias"]);
    request.operations.push(WorkerOperation::TypeHints { address: 0x1000, hints: Vec::new() });
    let cleared = run_supervised(&request, &config(), None).unwrap();
    assert_field_tokens(&cleared, &[], &["gain", "bias", "first", "second"]);
    assert_eq!(cleared.structure.unwrap().signature, before.signature);
    assert!(!cleared.text.contains("->first") && !cleared.text.contains("->gain"), "{}", cleared.text);
}

#[test]
fn analyst_overrides_win_independent_of_worker_operation_order() {
    let initial = run_supervised(&request(), &config(), None).unwrap().structure.unwrap();
    for hint_first in [false, true] {
        let mut request = request();
        let analyst = WorkerOperation::LocalVariables {
            address: 0x1000,
            overrides: vec![LocalOverride {
                storage: VariableStorage::try_from(&initial.signature.parameters[0].storage).unwrap(),
                name: Some("owner".to_owned()),
                data_type: Some("struct OtherState *".to_owned()),
            }],
        };
        let hint = WorkerOperation::TypeHints {
            address: 0x1000,
            hints: vec![TypeHint::Parameter { index: 0, data_type: "struct HintState *".to_owned() }],
        };
        request.operations.extend(if hint_first { vec![hint, analyst] } else { vec![analyst, hint] });
        let output = run_supervised(&request, &config(), None).unwrap();
        assert!(output.text.contains("owner->first") && !output.text.contains("->gain"), "{}", output.text);
    }
}

#[test]
fn native_hint_parser_refuses_injection_wrong_width_and_variadic_shapes() {
    for declaration in ["int4; int4 injected", "int4 (*)(int4)", "union HintState *", "void", "int4"] {
        let mut request = request();
        request.operations.push(WorkerOperation::TypeHints {
            address: 0x1000,
            hints: vec![TypeHint::Parameter { index: 0, data_type: declaration.to_owned() }],
        });
        assert!(run_supervised(&request, &config(), None).is_err(), "accepted {declaration}");
    }
    let mut request = request();
    request.operations.push(WorkerOperation::Symbol { address: 0x1000, name: "fields".to_owned() });
    request.operations.push(WorkerOperation::Prototype {
        address: 0x1000,
        indirect: false,
        declaration: "int4 fields(HintState *state, ...);".to_owned(),
    });
    request.operations.push(WorkerOperation::TypeHints {
        address: 0x1000,
        hints: vec![TypeHint::Parameter { index: 0, data_type: "struct HintState *".to_owned() }],
    });
    let error = run_supervised(&request, &config(), None).unwrap_err();
    assert!(error.to_string().contains("Unsupported variadic"), "{error}");
}

#[test]
fn worker_callee_hint_context_recovers_two_call_arguments_without_an_explicit_prototype() {
    let mut request = request();
    request.mappings[0].hex_bytes = ["8b070fafc6034704c3", "cccccccccccccc", "50e8eaffffff59c3"].concat();
    request.mappings[0].size = 24;
    request.decompile.address = 0x1010;
    request.decompile.name = "caller".to_owned();
    request.operations.push(WorkerOperation::Symbol { address: 0x1000, name: "fields".to_owned() });
    let baseline = run_supervised(&request, &config(), None).unwrap().structure.unwrap();
    assert!(baseline.calls[0].arguments.as_deref().unwrap_or_default().is_empty());
    request.operations.push(WorkerOperation::TypeHints {
        address: 0x1000,
        hints: vec![TypeHint::Parameter { index: 0, data_type: "struct HintState *".to_owned() }],
    });
    let output = run_supervised(&request, &config(), None).unwrap();
    let result = output.structure.unwrap();
    let arguments = result.calls[0].arguments.as_ref().expect("native callee shape context");
    assert_eq!(arguments.len(), 2, "{result:?}");
    assert_eq!(arguments[0].parameter_index, Some(0));
    assert!(arguments[0].value.data_type.as_ref().unwrap().name.contains("HintState"), "{result:?}");
    assert!(arguments[0].value.storage.is_some() && !arguments[0].value.type_locked, "{result:?}");
    assert_eq!(result.signature.parameters.len(), 2, "{result:?}");
}

#[test]
fn worker_return_hint_context_reaches_caller_result_fields_without_locks() {
    let mut request = request();
    request.mappings[0].hex_bytes = ["4889f8c3", &"cc".repeat(12), "50e8eaffffff598b1003500489d0c3"].concat();
    request.mappings[0].size = 31;
    request.decompile.address = 0x1010;
    request.decompile.name = "reader".to_owned();
    request.operations.push(WorkerOperation::Symbol { address: 0x1000, name: "identity_factory".to_owned() });
    request.operations.push(WorkerOperation::TypeHints {
        address: 0x1000,
        hints: vec![TypeHint::Return { data_type: "struct HintState *".to_owned() }],
    });
    let output = run_supervised(&request, &config(), None).unwrap();
    assert!(output.text.contains("->gain") && output.text.contains("->bias"), "{}", output.text);
    let result = output.structure.unwrap();
    let value = &result.calls[0].result.as_ref().unwrap().value;
    assert!(value.data_type.as_ref().unwrap().name.contains("HintState") && !value.type_locked, "{value:?}");
}

#[test]
fn worker_keeps_scalar_global_values_and_object_addresses_distinct() {
    for address_of in [false, true] {
        let mut request = request();
        request.mappings[0].hex_bytes =
            if address_of { "488d3df91f0000e8f4000000c3" } else { "488b3df91f0000e8f4000000c3" }.to_owned();
        request.mappings[0].size = 13;
        request.mappings.push(WorkerMapping {
            base: 0x3000,
            hex_bytes: "0700000000000000".to_owned(),
            size: 8,
            readable: true,
            writable: true,
            executable: false,
        });
        request.operations.extend([
            WorkerOperation::Global { address: 0x3000, declaration: "uint8 scalar_global;".to_owned() },
            WorkerOperation::Symbol { address: 0x1100, name: "consume".to_owned() },
            WorkerOperation::Prototype {
                address: 0x1100,
                indirect: false,
                declaration: if address_of { "uint8 consume(uint8 *value);" } else { "uint8 consume(uint8 value);" }
                    .to_owned(),
            },
        ]);
        let result = run_supervised(&request, &config(), None).unwrap().structure.unwrap();
        let value = &result.calls[0].arguments.as_ref().unwrap()[0].value;
        assert_eq!(value.global_address, Some(0x3000));
        assert!(value.global_type_locked && value.storage.is_none(), "{value:?}");
        assert_eq!(value.global_object_type.as_ref().unwrap().name, "uint8");
        if address_of {
            assert_eq!(value.status, CallValueStatus::GlobalAddress);
            assert!(value.symbol_type.is_none() && !value.type_locked, "{value:?}");
            assert!(value.data_type.as_ref().unwrap().name.contains('*'), "{value:?}");
        } else {
            assert_eq!(value.status, CallValueStatus::Global);
            assert_eq!(value.symbol_type.as_ref().unwrap().name, "uint8");
            assert!(value.type_locked && !value.data_type.as_ref().unwrap().name.contains('*'), "{value:?}");
        }
    }
}

#[test]
fn worker_keeps_ordinary_c_when_propagation_argument_evidence_budget_is_exhausted() {
    let mut request = request();
    let target = 0x8000u64;
    let mut code = vec![0x48, 0x83, 0xec, 8];
    for _ in 0..86 {
        for opcode in [0xbf, 0xbe, 0xba] {
            code.push(opcode);
            code.extend_from_slice(&1u32.to_le_bytes());
        }
        code.push(0xe8);
        let next = 0x1000 + code.len() as u64 + 4;
        code.extend_from_slice(&i32::try_from(target - next).unwrap().to_le_bytes());
    }
    code.extend_from_slice(&[0x48, 0x83, 0xc4, 8, 0xc3]);
    request.mappings[0].size = code.len() as u64;
    request.mappings[0].hex_bytes = code.iter().map(|byte| format!("{byte:02x}")).collect();
    request.decompile.name = "many_calls".to_owned();
    request.operations.extend([
        WorkerOperation::Symbol { address: target, name: "consume".to_owned() },
        WorkerOperation::Prototype {
            address: target,
            indirect: false,
            declaration: "int4 consume(int4 first, int4 second, int4 third);".to_owned(),
        },
    ]);
    let output = run_supervised(&request, &config(), None).unwrap();
    assert_eq!(output.text.matches("consume(").count(), 86, "{}", output.text);
    let result = output.structure.unwrap();
    assert_eq!(result.calls.len(), 86);
    assert!(result.calls[..85].iter().all(|call| call.arguments.as_ref().is_some_and(|args| args.len() == 3)));
    let last = result.calls.last().unwrap();
    assert!(last.arguments.is_none() && last.result.is_none(), "{last:?}");
    assert!(last.evidence_unavailable.as_deref().unwrap().contains("budget exceeded"), "{last:?}");
    assert_eq!(last.target, Some(target));
}

#[test]
fn worker_exact_wrapper_exposes_both_genuine_return_directions_without_a_return_hint() {
    for caller_is_explicit in [false, true] {
        let mut request = request();
        request.mappings[0].base = 0x20118c;
        request.mappings[0].hex_bytes = "4889f8c350e8f6ffffff59c3".to_owned();
        request.mappings[0].size = 12;
        request.decompile.address = 0x201190;
        request.decompile.name = "return_caller".to_owned();
        request.operations = vec![
            WorkerOperation::TypeLibrary {
                declarations: "struct PropState { int4 gain; int4 bias; };".to_owned(),
                packing: None,
            },
            WorkerOperation::Symbol { address: 0x20118c, name: "factory".to_owned() },
            WorkerOperation::Symbol { address: 0x201190, name: "return_caller".to_owned() },
            WorkerOperation::Prototype {
                address: if caller_is_explicit { 0x201190 } else { 0x20118c },
                indirect: false,
                declaration: if caller_is_explicit {
                    "PropState *return_caller(PropState *opaque);"
                } else {
                    "PropState *factory(void *opaque);"
                }
                .to_owned(),
            },
        ];
        let output = run_supervised(&request, &config(), None).unwrap();
        let result = output.structure.unwrap();
        assert_eq!(result.signature.return_type.size, 8, "{result:?}\n{}", output.text);
        assert!(result.signature.return_type.name.contains("PropState"), "{result:?}\n{}", output.text);
        let call = &result.calls[0];
        assert_eq!(call.source, Some(0x201191));
        assert_eq!(call.target, Some(0x20118c));
        assert!(call.evidence_unavailable.is_none(), "{call:?}");
        let value = call.result.as_ref().expect("actual native wrapper return flow");
        assert!(value.direct_return, "{result:?}");
        assert!(value.value.data_type.as_ref().unwrap().name.contains("PropState"), "{result:?}");
    }
}
