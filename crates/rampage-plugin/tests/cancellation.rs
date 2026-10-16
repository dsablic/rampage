//! Source-only acceptance: the parent supplies the existing runtime-probe component and trusted worker.
//! A checkpoint witnesses an active Wasm call boundary, not the probe's Rust loop body or compiler entry.
//! Cleanup success is asserted for these runs; admission quarantine after failed cleanup is not established.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use rampage_decompiler::worker::{SupervisedMetrics, SupervisedOwnership};
use rampage_plugin::{
    GuestCall, MAX_COMPONENT_BYTES, PluginConfig, PluginError, PluginObservation, run_component,
    run_component_checkpointed,
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
    serde_json::to_writer(&mut bytes, &facts).expect("serialize prepared facts");
    bytes
}

fn assert_control(component: &[u8], config: &PluginConfig, control: &[u8]) {
    assert_eq!(run_component(component, control, config, None).expect("ordinary control response"), CONTROL);
}

fn assert_busy(component: &[u8], config: &PluginConfig, control: &[u8]) {
    assert_eq!(run_component(component, control, config, None), Err(PluginError::Busy));
}

fn assert_cleaned(metrics: &SupervisedMetrics) {
    assert_eq!(metrics.ownership, SupervisedOwnership::Reaped);
    assert_eq!(metrics.cleanup_succeeded, Some(true));
    assert!(metrics.cleanup_error.is_none());
    assert!(metrics.root_exit_status.is_some(), "actual reaped root status is required");
    assert!(metrics.root_reaped_us.is_some());
    assert!(metrics.cleanup_finished_us.is_some());
    // Aborted pipe readers may be Stopped rather than Eof; neither is a substitute for owned cleanup.
}

#[test]
#[ignore = "requires RAMPAGE_PLUGIN_WORKER and RAMPAGE_RUNTIME_PROBE_COMPONENT; run explicitly"]
fn guest_active_cancellation_retains_real_admission_through_owned_cleanup() {
    // One test owns every admission check so test-runner threads cannot race the process-wide permit.
    let (component, config) = fixtures();
    let control = input(None);
    assert_control(&component, &config, &control);

    for (call, selector) in [(GuestCall::Run, b'\t'), (GuestCall::Output, b'\n')] {
        let cancellation = AtomicBool::new(false);
        let mut active = 0;
        let mut finished = 0;
        let run = run_component_checkpointed(
            &component,
            &input(Some(selector)),
            &config,
            &cancellation,
            call,
            &mut |observation| match observation {
                PluginObservation::GuestActive(actual) => {
                    assert_eq!(actual, call);
                    assert_eq!((active, finished), (0, 0));
                    active += 1;
                    assert_busy(&component, &config, &control);
                    cancellation.store(true, Ordering::Release);
                }
                PluginObservation::SupervisionFinished(metrics) => {
                    assert_eq!((active, finished), (1, 0));
                    assert!(cancellation.load(Ordering::Acquire));
                    assert_cleaned(metrics);
                    assert_busy(&component, &config, &control);
                    finished += 1;
                }
            },
        );
        assert_eq!((active, finished), (1, 1));
        assert_eq!(run.result, Err(PluginError::Cancelled));
        assert_cleaned(run.metrics.as_ref().expect("failure retains supervision metrics"));
        assert_control(&component, &config, &control);
    }

    // Returning without cancelling must fail and clean up, never resume the parked guest or hang until timeout.
    let cancellation = AtomicBool::new(false);
    let mut active = 0;
    let mut finished = 0;
    let run = run_component_checkpointed(
        &component,
        &input(Some(b'\t')),
        &config,
        &cancellation,
        GuestCall::Run,
        &mut |observation| match observation {
            PluginObservation::GuestActive(call) => {
                assert_eq!(call, GuestCall::Run);
                assert_eq!((active, finished), (0, 0));
                active += 1;
                assert_busy(&component, &config, &control);
            }
            PluginObservation::SupervisionFinished(metrics) => {
                assert_eq!((active, finished), (1, 0));
                assert_cleaned(metrics);
                assert_busy(&component, &config, &control);
                finished += 1;
            }
        },
    );
    assert_eq!((active, finished), (1, 1));
    assert!(!cancellation.load(Ordering::Acquire));
    assert_eq!(run.result, Err(PluginError::Protocol));
    assert_cleaned(run.metrics.as_ref().expect("observer failure retains cleanup metrics"));
    assert_control(&component, &config, &control);

    for panic_after_cleanup in [false, true] {
        let cancellation = AtomicBool::new(false);
        let mut active = 0;
        let mut finished = 0;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run_component_checkpointed(
                &component,
                &input(Some(b'\t')),
                &config,
                &cancellation,
                GuestCall::Run,
                &mut |observation| match observation {
                    PluginObservation::GuestActive(_) => {
                        active += 1;
                        assert_busy(&component, &config, &control);
                        if !panic_after_cleanup {
                            panic!("intentional checkpoint observer panic");
                        }
                        cancellation.store(true, Ordering::Release);
                    }
                    PluginObservation::SupervisionFinished(metrics) => {
                        finished += 1;
                        assert_cleaned(metrics);
                        assert_busy(&component, &config, &control);
                        panic!("intentional checkpoint observer panic");
                    }
                },
            );
        }));
        let payload = panic.expect_err("the selected trusted observer must actually panic");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"intentional checkpoint observer panic"));
        assert_eq!(active, 1);
        assert_eq!(finished, usize::from(panic_after_cleanup));
        assert_control(&component, &config, &control);
    }

    let cancellation = AtomicBool::new(false);
    let mut finished = 0;
    let run = run_component_checkpointed(
        &component,
        &input(Some(b'\t')),
        &config,
        &cancellation,
        GuestCall::Run,
        &mut |observation| match observation {
            PluginObservation::GuestActive(_) => assert_busy(&component, &config, &control),
            PluginObservation::SupervisionFinished(metrics) => {
                assert_cleaned(metrics);
                assert_busy(&component, &config, &control);
                cancellation.store(true, Ordering::Release);
                finished += 1;
            }
        },
    );
    assert_eq!(finished, 1);
    assert_eq!(run.result, Err(PluginError::Cancelled));
    assert_cleaned(run.metrics.as_ref().unwrap());
    assert_control(&component, &config, &control);

    // Errors after real admission but before supervision release their scope without inventing observations.
    let cancellation = AtomicBool::new(false);
    let run =
        run_component_checkpointed(b"not a component", &control, &config, &cancellation, GuestCall::Run, &mut |_| {
            panic!("preflight rejection must not report worker observations")
        });
    assert_eq!(run.result, Err(PluginError::Preflight));
    assert!(run.metrics.is_none());
    assert_control(&component, &config, &control);

    let mut missing_worker = config.clone();
    missing_worker.executable = PathBuf::from("/dev/null/rampage-plugin-worker");
    let mut finished = 0;
    let run = run_component_checkpointed(
        &component,
        &control,
        &missing_worker,
        &cancellation,
        GuestCall::Run,
        &mut |observation| match observation {
            PluginObservation::GuestActive(_) => panic!("failed spawn cannot witness active Wasm"),
            PluginObservation::SupervisionFinished(metrics) => {
                assert_eq!(finished, 0);
                assert_eq!(metrics.ownership, SupervisedOwnership::NotSpawned);
                assert!(metrics.root_exit_status.is_none());
                assert!(metrics.cleanup_succeeded.is_none());
                assert_busy(&component, &config, &control);
                finished += 1;
            }
        },
    );
    assert_eq!(finished, 1);
    assert_eq!(run.result, Err(PluginError::Worker));
    assert!(run.metrics.is_some());
    assert_control(&component, &config, &control);
}
