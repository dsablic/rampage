//! Source-only gates: the parent supplies a componentized runtime-probe and trusted PluginWorker executable.
//! No guest build, componentization, target installation, or download occurs here.
//! No application-ready hook exposes entry into guest CPU execution. Pre-cancellation is covered;
//! cancellation during compilation or guest CPU execution remains unproven by these gates.
//! Sequential recovery calls check admission release after return, not permit ownership during cleanup.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rampage_plugin::{
    COMPONENT_INTERFACE, MAX_COMPONENT_BYTES, MAX_EXECUTION_TIMEOUT, MAX_FUEL, PluginConfig, PluginError, run_component,
};
use rampage_plugin_contract::{BinaryFact, FunctionFacts, SCHEMA_VERSION, TriageFact, TriageFacts, validate_facts};

const CONTROL: &[u8] = br#"{"schemaVersion":1,"outcome":{"status":"failure","code":"invalid_input"}}"#;

fn fixtures() -> (Vec<u8>, PluginConfig) {
    let worker = std::env::var_os("RAMPAGE_PLUGIN_WORKER").expect("required trusted PluginWorker executable");
    let path = std::env::var_os("RAMPAGE_RUNTIME_PROBE_COMPONENT").expect("required runtime-probe component");
    let worker = PathBuf::from(worker);
    assert!(worker.is_absolute(), "trusted worker path must be absolute");
    let mut component = Vec::new();
    File::open(path)
        .expect("open externally built runtime-probe component")
        .take(MAX_COMPONENT_BYTES as u64 + 1)
        .read_to_end(&mut component)
        .expect("read bounded runtime-probe component");
    assert!(component.len() <= MAX_COMPONENT_BYTES, "component exceeds admission ceiling");
    (component, PluginConfig::new(worker))
}

fn input(selector: Option<u8>) -> Vec<u8> {
    let facts = TriageFacts {
        schema_version: SCHEMA_VERSION,
        exhaustive: true,
        record_total: 2,
        per_section: 1,
        binary: BinaryFact {
            id: 1,
            format: "Elf".to_owned(),
            arch: "x86_64".to_owned(),
            entry: None,
            section_count: 0,
            segment_count: 0,
        },
        triage: TriageFact {
            id: 2,
            image_size: 0,
            entropy: 0.0,
            sha256: "0".repeat(64),
            md5: "0".repeat(32),
            hints: Vec::new(),
        },
        detections: Vec::new(),
        managed: None,
        capabilities: Vec::new(),
        imports: Vec::new(),
        strings: Vec::new(),
        functions: FunctionFacts::Available { rows: Vec::new() },
        signature_matches: Vec::new(),
    };
    validate_facts(&facts).expect("valid synthetic contract facts, not analyzed workflow facts");
    let mut bytes = selector.into_iter().collect::<Vec<_>>();
    serde_json::to_writer(&mut bytes, &facts).expect("serialize valid facts");
    bytes
}

fn assert_control(component: &[u8], config: &PluginConfig) {
    let bytes = run_component(component, &input(None), config, None).expect("fixed control response");
    // More than two chunks and a partial final word expose offset, endian, and padding mistakes.
    assert!(CONTROL.len() > 64 && !CONTROL.len().is_multiple_of(8));
    assert_eq!(bytes, CONTROL);
}

#[test]
#[ignore = "requires RAMPAGE_PLUGIN_WORKER and RAMPAGE_RUNTIME_PROBE_COMPONENT; run explicitly"]
fn adversarial_resource_controls_through_trusted_worker() {
    // One test keeps process-wide admission deterministic without test threads racing for the permit.
    let (component, config) = fixtures();
    assert_control(&component, &config);

    let mut wrong_version = component.clone();
    let original = COMPONENT_INTERFACE.as_bytes();
    let replacement = COMPONENT_INTERFACE.replace("@0.0.1", "@9.9.9");
    assert_eq!(replacement.len(), original.len());
    let mut changed = 0;
    for offset in 0..=wrong_version.len().saturating_sub(original.len()) {
        if wrong_version.get(offset..offset + original.len()) == Some(original) {
            wrong_version[offset..offset + original.len()].copy_from_slice(replacement.as_bytes());
            changed += 1;
        }
    }
    assert!(changed > 0, "the compiled fixture must contain its actual versioned export name");
    assert_eq!(run_component(&wrong_version, &input(None), &config, None), Err(PluginError::Abi));
    assert_control(&component, &config);

    let imported = b"\0asm\x0d\0\x01\0\x07\x05\x01\x40\0\x01\0\x0a\x06\x01\0\x01f\x01\0";
    assert_eq!(run_component(imported, &input(None), &config, None), Err(PluginError::Abi));
    assert_control(&component, &config);

    let mut malformed_output = b" \n".to_vec();
    malformed_output.extend_from_slice(&input(None));
    assert_eq!(run_component(&component, &malformed_output, &config, None), Err(PluginError::InvalidOutput));
    assert_control(&component, &config);

    let cancellation = AtomicBool::new(true);
    assert_eq!(
        run_component(&component, &input(Some(b'\t')), &config, Some(&cancellation)),
        Err(PluginError::Cancelled),
    );
    assert_control(&component, &config);

    let mut fuel_limited = config.clone();
    fuel_limited.fuel = 100_000.min(MAX_FUEL);
    // The control must succeed under this exact budget; initialization alone must not explain Fuel.
    assert_control(&component, &fuel_limited);
    for selector in *b"\t\n" {
        assert_eq!(
            run_component(&component, &input(Some(selector)), &fuel_limited, None),
            Err(PluginError::Fuel),
            "fuel must interrupt selector {selector}",
        );
        assert_control(&component, &config);
    }

    let mut epoch_limited = config.clone();
    epoch_limited.fuel = MAX_FUEL;
    epoch_limited.execution_timeout = Duration::from_millis(1);
    assert!(epoch_limited.execution_timeout < MAX_EXECUTION_TIMEOUT);
    assert!(epoch_limited.execution_timeout < epoch_limited.timeout);
    for selector in *b"\t\n" {
        assert_eq!(
            run_component(&component, &input(Some(selector)), &epoch_limited, None),
            Err(PluginError::ExecutionDeadline),
            "execution epoch must interrupt selector {selector}, not outer timeout or fuel",
        );
        assert_control(&component, &config);
    }

    assert_eq!(run_component(&component, &input(Some(b'\r')), &config, None), Err(PluginError::Resource),);
    assert_control(&component, &config);

    assert_eq!(run_component(&component, &input(Some(b' ')), &config, None), Err(PluginError::OutputTooLarge),);
    assert_control(&component, &config);
}
