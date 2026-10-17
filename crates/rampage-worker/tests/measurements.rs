#![cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rampage_decompiler::worker::{
    PROTOCOL_VERSION, SupervisedInputOutcome, SupervisedOwnership, SupervisedStreamOutcome, WorkerConfig,
    WorkerDataOrganization, WorkerError, WorkerFunction, WorkerMapping, WorkerOptions, WorkerOutput, WorkerRequest,
    WorkerToken, run_supervised, run_supervised_measured,
};
use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion};
use serde_json::{Value, json};

// Complete owned instruction image for the independent oracle: int owned_return_five(void) { return 5; }
const IMAGE: &[u8] = &[0xb8, 5, 0, 0, 0, 0xc3];
const BASE: u64 = 0x1000;

fn config() -> WorkerConfig {
    WorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

fn request() -> WorkerRequest {
    WorkerRequest {
        version: PROTOCOL_VERSION,
        arch: "x86_64".to_owned(),
        big_endian: false,
        options: WorkerOptions { compiler: Some("gcc".to_owned()), ..Default::default() },
        mappings: vec![WorkerMapping {
            base: BASE,
            hex_bytes: IMAGE.iter().map(|byte| format!("{byte:02x}")).collect(),
            size: IMAGE.len() as u64,
            readable: true,
            writable: false,
            executable: true,
        }],
        code_modes: Vec::new(),
        operations: Vec::new(),
        decompile: WorkerFunction { address: BASE, name: "owned_return_five".to_owned(), thumb: false },
        tokens: true,
        validate_only: false,
        type_query: None,
    }
}

fn native() -> Result<WorkerOutput, rampage_decompiler::Error> {
    let regions = [MemoryRegion {
        base: BASE,
        bytes: IMAGE,
        size: IMAGE.len() as u64,
        readable: true,
        writable: false,
        executable: true,
    }];
    let options = DecompilerOptions { compiler: Some("gcc".to_owned()), ..Default::default() };
    let mut engine = Decompiler::open_with_options("x86_64".parse().unwrap(), false, &regions, &options)?;
    let text = engine.decompile(BASE, "owned_return_five", false)?;
    let tokens = engine
        .tokens()
        .into_iter()
        .map(|token| WorkerToken { text: token.text, kind: token.kind, address: token.address, span: token.span })
        .collect();
    let organization = engine.data_organization();
    Ok(WorkerOutput {
        type_declarations: None,
        type_inventory: None,
        text,
        language_id: engine.language_id().to_owned(),
        data_organization: WorkerDataOrganization {
            pointer: organization.pointer,
            int: organization.int,
            long: organization.long,
        },
        tokens: Some(tokens),
        structure: Some(engine.structured_result()?),
    })
}

fn oracle(output: &WorkerOutput) -> bool {
    output.language_id == "x86:LE:64:default:gcc"
        && output.text.contains("return 5;")
        && output.tokens.as_ref().is_some_and(|tokens| !tokens.is_empty())
        && output.structure.is_some()
}

#[test]
fn measured_actual_worker_preserves_native_and_unmeasured_outputs_for_the_complete_owned_image() {
    let inline = native().unwrap();
    let plain = run_supervised(&request(), &config(), None).unwrap();
    let run = run_supervised_measured(&request(), &config(), None);
    let measured = run.result.unwrap();
    assert!(oracle(&inline) && oracle(&plain) && oracle(&measured));
    assert_eq!(serde_json::to_value(&measured).unwrap(), serde_json::to_value(&plain).unwrap());
    assert_eq!(serde_json::to_value(&measured).unwrap(), serde_json::to_value(&inline).unwrap());
    assert_eq!(run.metrics.ownership, SupervisedOwnership::Reaped);
    assert_eq!(run.metrics.cleanup_succeeded, Some(true));
    assert_eq!(run.metrics.input.outcome, Some(SupervisedInputOutcome::FullyDelivered));
    assert_eq!(run.metrics.input.requested_bytes, Some(run.metrics.input.written_bytes));
    assert!(run.metrics.spawn_complete_us.is_some());
    assert!(run.metrics.root_reaped_us.is_some());
    assert!(run.metrics.response_decoded_us.is_some());
    assert!(run.metrics.control_completion_us.is_some());
    assert!(run.metrics.intentional_stop);
    let root_status = run.metrics.root_exit_status.unwrap();
    assert!(!root_status.success);
    assert_eq!(root_status.code, None);
    assert_eq!(root_status.signal, Some(9));
    assert_eq!(run.metrics.stdout.outcome, Some(SupervisedStreamOutcome::Eof));
    assert_eq!(run.metrics.stderr.outcome, Some(SupervisedStreamOutcome::Eof));
    assert!(run.metrics.stdout.eof_us.unwrap() <= run.metrics.response_decode_started_us.unwrap());
    assert!(run.metrics.stderr.eof_us.unwrap() <= run.metrics.response_decode_started_us.unwrap());
    assert!(run.metrics.root_reaped_us.unwrap() <= run.metrics.response_decode_started_us.unwrap());
    assert!(run.metrics.root_reaped_us.unwrap() <= run.metrics.total_elapsed_us);
    assert_eq!(run.metrics.rss.samples > 0, run.metrics.rss.max_observed_child_rss_bytes.is_some());
}

#[test]
fn measured_actual_worker_error_keeps_decompile_category_and_actual_intentional_root_status() {
    let mut request = request();
    request.arch = "not_an_architecture".to_owned();
    let run = run_supervised_measured(&request, &config(), None);
    assert!(matches!(run.result, Err(WorkerError::Decompile(_))));
    assert!(run.metrics.control_completion_us.is_some());
    assert!(run.metrics.intentional_stop);
    assert_eq!(run.metrics.root_exit_status.unwrap().signal, Some(9));
    assert_eq!(run.metrics.cleanup_succeeded, Some(true));
}

#[test]
fn measured_output_limit_never_becomes_operation_success_after_an_intentional_root_signal() {
    let config = WorkerConfig { max_stdout_bytes: 1, ..config() };
    let run = run_supervised_measured(&request(), &config, None);
    assert!(matches!(run.result, Err(WorkerError::OutputTooLarge { stream: "stdout", .. })));
    assert_eq!(run.metrics.stdout.outcome, Some(SupervisedStreamOutcome::OutputLimit));
    assert!(run.metrics.stdout.eof_us.is_none());
    if run.metrics.intentional_stop {
        assert!(run.metrics.control_completion_us.is_some());
    }
    assert!(run.metrics.root_reaped_us.is_some());
}

#[test]
fn a_non_control_worker_preserves_its_primary_protocol_failure() {
    let config = WorkerConfig { executable: Some("/bin/cat".into()), ..config() };
    let run = run_supervised_measured(&request(), &config, None);
    assert!(matches!(run.result, Err(WorkerError::Protocol(_))));
    assert!(run.metrics.control_completion_us.is_none());
    assert!(!run.metrics.intentional_stop);
    if run.metrics.cleanup_succeeded == Some(false) {
        assert!(run.metrics.cleanup_error.is_some());
    }
}

fn failure_code(error: &WorkerError) -> &'static str {
    match error {
        WorkerError::Io { .. } => "supervision_io",
        WorkerError::RequestTooLarge { .. } => "request_limit",
        WorkerError::OutputTooLarge { .. } => "output_limit",
        WorkerError::MemoryLimit { .. } => "memory_limit",
        WorkerError::Timeout => "timeout",
        WorkerError::Cancelled => "cancelled",
        WorkerError::Exit { .. } => "worker_exit",
        WorkerError::Cleanup { .. } => "cleanup_failure",
        WorkerError::Protocol(_) => "protocol_failure",
        WorkerError::Decompile(_) => "decompile_failure",
        WorkerError::UnsupportedPlatform => "unsupported_supervision",
    }
}

fn output_path() -> PathBuf {
    let requested = PathBuf::from(
        std::env::var_os("RAMPAGE_WORKER_MEASUREMENTS")
            .expect("set RAMPAGE_WORKER_MEASUREMENTS to a new file in caller-owned private external scratch"),
    );
    assert!(requested.is_absolute());
    let parent = requested.parent().unwrap().canonicalize().unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    assert!(!parent.starts_with(root), "measurement output must be outside the source workspace");
    assert!(parent.is_dir());
    assert_eq!(parent.metadata().unwrap().permissions().mode() & 0o077, 0, "scratch must be private");
    let output = parent.join(requested.file_name().unwrap());
    assert!(!output.try_exists().unwrap(), "measurement output must be new");
    output
}

#[test]
#[ignore = "source-only worker pilot; requires explicit private RAMPAGE_WORKER_MEASUREMENTS output"]
fn owned_instruction_image_three_repetitions_native_and_isolated() {
    let output = output_path();
    let started = Instant::now();
    let mut records = Vec::<Value>::with_capacity(6);
    let mut supervision_unavailable = false;
    for repeat in 0..3 {
        let order = if repeat % 2 == 0 { ["native", "isolated"] } else { ["isolated", "native"] };
        for backend in order {
            let remaining = Duration::from_secs(120).saturating_sub(started.elapsed());
            if remaining.is_zero() || supervision_unavailable {
                records.push(json!({
                    "repeat": repeat + 1,
                    "backend": backend,
                    "status": if supervision_unavailable { "not_run_supervision" } else { "not_run_budget" },
                }));
                continue;
            }
            let stage = Instant::now();
            if backend == "native" {
                let result = native();
                let elapsed = stage.elapsed().as_micros() as u64;
                let passed = result.as_ref().is_ok_and(oracle);
                records.push(json!({
                    "repeat": repeat + 1,
                    "backend": backend,
                    "status": if passed { "passed" } else { "failed" },
                    "driver_elapsed_us": elapsed,
                    "source_oracle_passed": passed,
                    "failure_code": if result.is_err() { Some("native_error") }
                        else if !passed { Some("source_oracle_failed") } else { None },
                    "supervisor": null,
                    "native_rss": null,
                }));
            } else {
                let config = WorkerConfig { timeout: remaining.min(Duration::from_secs(30)), ..config() };
                let run = run_supervised_measured(&request(), &config, None);
                let elapsed = stage.elapsed().as_micros() as u64;
                let passed = run.result.as_ref().is_ok_and(oracle);
                supervision_unavailable = run.metrics.ownership == SupervisedOwnership::Unverified
                    || run.metrics.cleanup_succeeded == Some(false)
                    || (run.metrics.spawn_complete_us.is_some() && run.metrics.root_reaped_us.is_none());
                records.push(json!({
                    "repeat": repeat + 1,
                    "backend": backend,
                    "status": if passed { "passed" } else { "failed" },
                    "driver_elapsed_us": elapsed,
                    "source_oracle_passed": passed,
                    "failure_code": run.result.as_ref().err().map(failure_code)
                        .or_else(|| (!passed).then_some("source_oracle_failed")),
                    "supervisor": run.metrics,
                }));
            }
        }
    }
    let passed = records.iter().all(|row| row["status"] == "passed");
    let report = json!({
        "schema_version": 1,
        "scope": "direct engine/worker API pilot, not CLI or Project exact-entry API or whole-file evidence",
        "case": "owned_return_five_x86_64_complete_instruction_image",
        "input_bytes": IMAGE.len(),
        "mapping": "same complete six-byte image and permissions in both backends",
        "options": { "compiler": "gcc", "platform": "default", "tokens": true, "annotations": "none" },
        "temperature": "fresh native handle; process globals may be warm; fresh process per isolated request",
        "spec_cache": "filesystem and OS caches may remain warm; no cold-start claim",
        "rss_scope": "direct worker root only, sampled/shared-inclusive, not guaranteed peak; native RSS unavailable",
        "limits": { "worker_timeout_seconds": 30, "run_budget_seconds": 120, "repeats_per_backend": 3 },
        "native_deadline": "cooperative only; synchronous native initialization/execution is not forcibly bounded",
        "phase_policy": "host milestones overlap and do not identify child parsing or native initialization",
        "driver_scope": "backend helper including request/native setup; supervisor total is supervisor-only",
        "records": records,
    });
    let bytes = serde_json::to_vec_pretty(&report).unwrap();
    assert!(bytes.len() <= 1024 * 1024);
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(output).unwrap();
    file.write_all(&bytes).unwrap();
    file.write_all(b"\n").unwrap();
    assert!(passed, "pilot failures were retained in the sanitized measurement report; no retries performed");
}
