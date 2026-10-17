#![cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]

use rampage_decompiler::worker::{
    PROTOCOL_VERSION, WorkerCodeMode, WorkerConfig, WorkerError, WorkerFunction, WorkerMapping, WorkerOperation,
    WorkerOptions, WorkerRequest, run_supervised,
};

fn config() -> WorkerConfig {
    WorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

fn request() -> WorkerRequest {
    WorkerRequest {
        version: PROTOCOL_VERSION,
        arch: "x86_64".to_owned(),
        big_endian: false,
        options: WorkerOptions::default(),
        mappings: vec![WorkerMapping {
            base: 0x1000,
            hex_bytes: "89f8c3".to_owned(),
            size: 3,
            readable: true,
            writable: false,
            executable: true,
        }],
        code_modes: Vec::new(),
        operations: Vec::new(),
        decompile: WorkerFunction { address: 0x1000, name: "fixture".to_owned(), thumb: false },
        tokens: true,
        validate_only: false,
        type_query: None,
    }
}

#[test]
fn bundled_worker_decompiles_default_fixture_and_returns_address_linked_tokens() {
    let output = run_supervised(&request(), &config(), None).expect("bundled worker decompiles");
    assert!(output.text.contains("fixture"), "{}", output.text);
    assert!(output.text.contains("return"), "{}", output.text);
    let tokens = output.tokens.expect("requested tokens");
    assert!(!tokens.is_empty());
    assert!(tokens.iter().any(|token| token.address == Some(0x1000)), "{tokens:?}");
}

#[test]
fn worker_applies_ordered_symbols_types_and_address_bound_prototypes() {
    let mut request = request();
    request.operations = vec![
        WorkerOperation::ParseTypes { declarations: "typedef int4 fixture_word;".to_owned() },
        WorkerOperation::Symbol { address: 0x1000, name: "original".to_owned() },
        WorkerOperation::Prototype {
            address: 0x1000,
            indirect: false,
            declaration: "fixture_word canonical(fixture_word input);".to_owned(),
        },
        WorkerOperation::Symbol { address: 0x1000, name: "renamed".to_owned() },
    ];
    request.decompile.name = "renamed".to_owned();
    let output = run_supervised(&request, &config(), None).unwrap();
    assert!(output.text.contains("renamed(fixture_word input)"), "{}", output.text);
    assert!(!output.text.contains("original"), "{}", output.text);
}

#[test]
fn subprocess_checks_complete_layouts_before_decompilation_or_validation_success() {
    use rampage_decompiler::layout::{
        LayoutField, LayoutOrganization, LayoutScalar, LayoutType, PlainStructLayout, ScalarKind,
    };

    let layout = PlainStructLayout {
        name: "worker_record".to_owned(),
        size: 8,
        alignment: 4,
        organization: LayoutOrganization {
            pointer_size: 8,
            int_size: 4,
            long_size: 8,
            scalar_alignments: [1, 2, 4, 8],
        },
        fields: vec![
            LayoutField {
                name: "count".to_owned(),
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
            },
            LayoutField {
                name: "tail".to_owned(),
                offset: 4,
                size: 1,
                ty: LayoutType::Scalar {
                    scalar: LayoutScalar {
                        name: "uint1".to_owned(),
                        kind: ScalarKind::UnsignedInteger,
                        size: 1,
                        alignment: 1,
                    },
                },
            },
        ],
    };
    let mut request = request();
    request.mappings[0].hex_bytes = "8b070fb6570401d0c3".to_owned();
    request.mappings[0].size = 9;
    request.operations = vec![
        WorkerOperation::ParseTypes { declarations: "struct worker_record { int4 count; uint1 tail; };".to_owned() },
        WorkerOperation::AssertPlainStructLayout { layout, expected_context: None },
        WorkerOperation::Symbol { address: 0x1000, name: "fixture".to_owned() },
        WorkerOperation::Prototype {
            address: 0x1000,
            indirect: false,
            declaration: "int4 fixture(worker_record *item);".to_owned(),
        },
    ];
    let checked = run_supervised(&request, &config(), None).unwrap();
    assert!(checked.text.contains("->count"), "{}", checked.text);
    assert!(checked.text.contains("->tail"), "{}", checked.text);
    let mut control = request.clone();
    control.operations.remove(1);
    let unchecked = run_supervised(&control, &config(), None).unwrap();
    assert_eq!(checked.text, unchecked.text);
    assert_eq!(checked.structure, unchecked.structure);
    assert_eq!(serde_json::to_value(checked.tokens).unwrap(), serde_json::to_value(unchecked.tokens).unwrap());

    for validate_only in [false, true] {
        request.validate_only = validate_only;
        run_supervised(&request, &config(), None).unwrap();
        let mut wrong = request.clone();
        let WorkerOperation::AssertPlainStructLayout { layout, .. } = &mut wrong.operations[1] else { unreachable!() };
        layout.fields[1].offset = 5;
        layout.validate().unwrap();
        assert!(matches!(
            run_supervised(&wrong, &config(), None),
            Err(WorkerError::Decompile(message)) if message.contains("operation 1") && message.contains("layout")
        ));
    }
    let mut reversed = request;
    reversed.operations.swap(0, 1);
    assert!(matches!(
        run_supervised(&reversed, &config(), None),
        Err(WorkerError::Decompile(message)) if message.contains("operation 0")
    ));
}

#[test]
fn malformed_layout_wire_errors_do_not_echo_oversized_values_or_keys() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let oversized = "private_input_marker_".repeat(2048);
    let payloads = [
        format!(r#"{{"fields":[{{"ty":{{"kind":"{oversized}"}}}}]}}"#),
        format!(r#"{{"{oversized}":[]}}"#),
        format!(r#"{{"name":"{}"}}"#, r"\u0078".repeat(4096)),
    ];
    for payload in payloads {
        let input = format!(r#"{{"version":{PROTOCOL_VERSION},"arch":"x86_64","mappings":[],"operations":["#)
            + &format!(r#"{{"layout":{payload},"op":"assert_plain_struct_layout"}}"#)
            + r#"],"decompile":{"address":4096}}"#;
        let mut child = Command::new(env!("CARGO_BIN_EXE_rampage-worker"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let written = child.stdin.take().unwrap().write_all(input.as_bytes());
        let output = child.wait_with_output().unwrap();
        written.unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(output.stdout.len() <= 2048, "malformed layout error expanded to {} bytes", output.stdout.len());
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["version"], PROTOCOL_VERSION);
        assert_eq!(response["status"], "error");
        assert!(response["message"].as_str().unwrap().len() <= 1024);
        assert!(!response["message"].as_str().unwrap().contains("private_input_marker"));
    }
}

#[test]
fn worker_resolves_import_runtime_prototypes_in_selected_target_abi() {
    let mut request = request();
    request.mappings[0].hex_bytes = "bf00200000ff15f51f000031c0c3".to_owned();
    request.mappings[0].size = 14;
    request.mappings.extend([
        WorkerMapping {
            base: 0x2000,
            hex_bytes: "6772656574696e6700".to_owned(),
            size: 9,
            readable: true,
            writable: false,
            executable: false,
        },
        WorkerMapping {
            base: 0x3000,
            hex_bytes: "0000000000000000".to_owned(),
            size: 8,
            readable: true,
            writable: true,
            executable: false,
        },
    ]);
    request.operations = vec![
        WorkerOperation::Import { slot: 0x3000, target: None, name: "puts@got".to_owned() },
        WorkerOperation::RuntimePrototype { address: 0x3000, indirect: true, name: "puts".to_owned(), optional: false },
    ];
    let output = run_supervised(&request, &config(), None).unwrap();
    assert!(output.text.contains("puts@got(\"greeting\")"), "{}", output.text);
}

#[test]
fn failed_setup_and_unknown_runtime_prototypes_report_operation_index() {
    for operation in [
        WorkerOperation::Prototype { address: 0x5000, indirect: false, declaration: "int4 missing(void);".to_owned() },
        WorkerOperation::RuntimePrototype {
            address: 0x1000,
            indirect: false,
            name: "unknown_runtime".to_owned(),
            optional: false,
        },
    ] {
        let mut request = request();
        request.operations.push(operation);
        let result = run_supervised(&request, &config(), None);
        assert!(matches!(result, Err(WorkerError::Decompile(message)) if message.contains("operation 0")));
    }
}

#[test]
fn arm_thumb_mode_operations_are_replayed_before_decompilation() {
    let mut request = request();
    request.arch = "arm".to_owned();
    request.mappings[0].hex_bytes = "00207047".to_owned();
    request.mappings[0].size = 4;
    request.operations.push(WorkerOperation::Mode { modes: vec![WorkerCodeMode { address: 0x1000, thumb: true }] });
    request.decompile.thumb = true;
    let output = run_supervised(&request, &config(), None).unwrap();
    assert!(output.text.contains("return 0"), "{}", output.text);
}

#[test]
fn unsupported_request_version_and_bad_memory_bytes_fail_as_structured_errors() {
    let mut wrong_version = request();
    wrong_version.version += 1;
    assert!(matches!(
        run_supervised(&wrong_version, &config(), None),
        Err(WorkerError::Protocol(message)) if message.contains("unsupported worker protocol version")
    ));
    let mut bad_hex = request();
    bad_hex.mappings[0].hex_bytes = "invalid".to_owned();
    assert!(matches!(run_supervised(&bad_hex, &config(), None), Err(WorkerError::Decompile(_))));
}

#[test]
fn worker_resolves_runtime_prototype_widths_using_windows_compiler_selection() {
    let mut request = request();
    request.options.platform = "windows".to_owned();
    request.operations = vec![
        WorkerOperation::Symbol { address: 0x1000, name: "converted".to_owned() },
        WorkerOperation::RuntimePrototype {
            address: 0x1000,
            indirect: false,
            name: "strtol".to_owned(),
            optional: false,
        },
    ];
    request.decompile.name = "converted".to_owned();
    request.tokens = false;
    let output = run_supervised(&request, &config(), None).unwrap();
    assert!(output.language_id.ends_with(":windows"), "{}", output.language_id);
    assert!(output.text.contains("int4 converted(char *s,char **end,int4 base)"), "{}", output.text);
    assert!(output.tokens.is_none());
}
