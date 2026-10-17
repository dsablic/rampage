#![cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::ops::Range;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rampage_api::{ApiError, DecompileEntryRequest, EntryDecompilation, EntryValidation, Project};
use rampage_decompiler::worker::{SupervisedOwnership, WorkerConfig};
use rampage_decompiler::{DecompilerOptions, Platform};
use rampage_loaders::Binary;
use serde_json::{Value, json};

const JOURNAL_BYTES: usize = 1024 * 1024;
const RECORD_BYTES: usize = 16 * 1024;
const INPUT_BYTES: usize = 1024 * 1024;

type Failure = &'static str;

fn digest(bytes: &[u8]) -> Result<String, Failure> {
    let mut child = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "digest_spawn")?;
    let written = child.stdin.take().ok_or("digest_pipe")?.write_all(bytes);
    let output = child.wait_with_output().map_err(|_| "digest_wait")?;
    written.map_err(|_| "digest_input")?;
    if !output.status.success() || output.stdout.len() > 256 {
        return Err("digest_output");
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| "digest_output")?;
    let digest = text.split_whitespace().next().ok_or("digest_output")?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("digest_output");
    }
    Ok(digest.to_ascii_lowercase())
}

fn output_file() -> Result<File, Failure> {
    let path = PathBuf::from(std::env::var_os("RAMPAGE_ENTRY_MEASUREMENTS").ok_or("output_not_configured")?);
    if !path.is_absolute() {
        return Err("output_not_absolute");
    }
    let parent = path.parent().ok_or("output_parent")?.canonicalize().map_err(|_| "output_parent")?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().map_err(|_| "workspace_root")?;
    if parent.starts_with(root) || parent.metadata().map_err(|_| "output_parent")?.permissions().mode() & 0o077 != 0 {
        return Err("output_not_private_external");
    }
    let output = parent.join(path.file_name().ok_or("output_filename")?);
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(output).map_err(|_| "output_create")
}

struct RecordBuffer(Vec<u8>);

impl Write for RecordBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > RECORD_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn append_record(writer: &mut impl Write, total: &mut usize, record: &Value) -> Result<(), Failure> {
    let mut buffer = RecordBuffer(Vec::new());
    serde_json::to_writer(&mut buffer, record).map_err(|_| "journal_record_limit")?;
    let length = buffer.0.len().checked_add(1).ok_or("journal_limit")?;
    if length > JOURNAL_BYTES.saturating_sub(*total) {
        return Err("journal_limit");
    }
    buffer.0.push(b'\n');
    writer.write_all(&buffer.0).map_err(|_| "journal_write")?;
    writer.flush().map_err(|_| "journal_flush")?;
    *total += length;
    Ok(())
}

struct Journal {
    file: File,
    bytes: usize,
    started: Instant,
}

impl Journal {
    fn record(&mut self, mut record: Value) -> Result<(), Failure> {
        record
            .as_object_mut()
            .ok_or("journal_record_type")?
            .insert("journal_elapsed_us".into(), micros(self.started.elapsed()).into());
        append_record(&mut self.file, &mut self.bytes, &record)?;
        self.file.sync_data().map_err(|_| "journal_sync")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileIdentity {
    fn of(metadata: &std::fs::Metadata) -> Result<Self, Failure> {
        if !metadata.is_file() {
            return Err("input_not_regular");
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

struct FrozenFile {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    sha256: String,
}

impl FrozenFile {
    fn capture(path: PathBuf, limit: usize) -> Result<Self, Failure> {
        let identity = FileIdentity::of(&std::fs::symlink_metadata(&path).map_err(|_| "input_metadata")?)?;
        if identity.length > limit as u64 {
            return Err("input_limit");
        }
        let file = File::open(&path).map_err(|_| "input_open")?;
        let mut bytes = Vec::new();
        (&file).take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| "input_read")?;
        if bytes.len() > limit {
            return Err("input_limit");
        }
        let frozen = Self { path, file, identity, sha256: digest(&bytes)? };
        frozen.validate()?;
        Ok(frozen)
    }

    fn validate(&self) -> Result<(), Failure> {
        let descriptor = FileIdentity::of(&self.file.metadata().map_err(|_| "input_metadata")?)?;
        let path = FileIdentity::of(&std::fs::symlink_metadata(&self.path).map_err(|_| "input_metadata")?)?;
        if descriptor != self.identity || path != self.identity {
            return Err("input_identity_changed");
        }
        Ok(())
    }
}

struct Case {
    fixture: &'static str,
    entry: &'static str,
    compiler: &'static str,
    platform: Platform,
    addition: bool,
}

const CASES: [Case; 3] = [
    Case { fixture: "hello-x64-dyn.elf", entry: "main", compiler: "gcc", platform: Platform::Default, addition: false },
    Case { fixture: "hello-x64.exe", entry: "add", compiler: "windows", platform: Platform::Windows, addition: true },
    Case { fixture: "hello-x64.macho", entry: "_main", compiler: "gcc", platform: Platform::Darwin, addition: false },
];

struct FrozenImage {
    path: PathBuf,
    binary: Binary,
    file: Vec<u8>,
    image: Vec<u8>,
    selection: Range<usize>,
    sha256: String,
    image_sha256: String,
}

fn backing(binary: &Binary) -> Result<(), Failure> {
    if !binary.validate_available_backing_source().map_err(|_| "fixture_backing_changed")? {
        return Err("fixture_not_original_mapped");
    }
    Ok(())
}

impl FrozenImage {
    fn capture(path: &Path) -> Result<Self, Failure> {
        let binary = Binary::open(path).map_err(|_| "fixture_open")?;
        backing(&binary)?;
        if binary.file_bytes().len() > INPUT_BYTES || binary.image_bytes().len() > INPUT_BYTES {
            return Err("fixture_limit");
        }
        let file = binary.file_bytes().to_vec();
        let image = binary.image_bytes().to_vec();
        let selection = binary.inventory_source_context().0;
        backing(&binary)?;
        let sha256 = digest(&file)?;
        let image_sha256 = digest(&image)?;
        backing(&binary)?;
        Ok(Self { path: path.to_owned(), binary, file, image, selection, sha256, image_sha256 })
    }

    fn admit(&self, project: &Project) -> Result<(), Failure> {
        backing(&self.binary)?;
        backing(&project.binary)?;
        let matches = project.binary.inventory_source_context().0 == self.selection
            && project.binary.file_bytes() == self.file.as_slice()
            && project.binary.image_bytes() == self.image.as_slice();
        backing(&project.binary)?;
        backing(&self.binary)?;
        if !matches {
            return Err("fixture_bytes_or_selection_changed");
        }
        Ok(())
    }
}

fn failure_category(error: &ApiError) -> Failure {
    match error {
        ApiError::Load { .. } => "api_load",
        ApiError::Unsupported(_) => "api_unsupported",
        ApiError::NotFound(_) => "api_not_found",
        ApiError::Invalid(_) => "api_invalid",
        ApiError::Unavailable(_) => "api_unavailable",
        ApiError::NativeTypeHintUnsupported(_) => "api_native_type_hint_unsupported",
        ApiError::DebuggerCaptureStagingRetained(_) => "api_staging_retained",
    }
}

fn oracle(result: &EntryDecompilation, compiler: &str, addition: bool) -> bool {
    let output = &result.decompilation;
    if output.language_id != format!("x86:LE:64:default:{compiler}")
        || !result.context.full_image_mapping
        || !result.context.mapped_backing_checked
        || result.context.mapped_regions == 0
        || result.context.mapped_backed_bytes == 0
        || output.tokens.is_empty()
    {
        return false;
    }
    if !addition {
        return output.code.contains("return 5;")
            && (output.code.contains("puts@plt(\"rampage fixture greeting\")")
                || output.code.contains("puts(\"rampage fixture greeting\")")
                || output.code.contains("_puts(\"rampage fixture greeting\")"));
    }
    let Ok(structure) = serde_json::to_value(&output.structure) else { return false };
    let Some(parameters) = structure["signature"]["parameters"].as_array() else { return false };
    if parameters.len() != 2 {
        return false;
    }
    let Some(left) = parameters[0]["name"].as_str() else { return false };
    let Some(right) = parameters[1]["name"].as_str() else { return false };
    let compact: String = output.code.chars().filter(|ch| !ch.is_whitespace() && !matches!(ch, '(' | ')')).collect();
    compact.contains(&format!("return{left}+{right};")) || compact.contains(&format!("return{right}+{left};"))
}

fn attempt_plan() -> Vec<Value> {
    let mut plan = Vec::new();
    for (case_index, case) in CASES.iter().enumerate() {
        for repeat in 1..=3 {
            let order = if repeat % 2 == 1 { ["native", "isolated"] } else { ["isolated", "native"] };
            for backend in order {
                plan.push(json!({
                    "id": plan.len() + 1, "case_index": case_index,
                    "fixture": case.fixture, "repeat": repeat, "backend": backend,
                }));
            }
        }
    }
    plan
}

fn capture_inputs(journal: &mut Journal) -> Result<(FrozenFile, FrozenFile, Vec<FrozenImage>), Failure> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    journal.record(json!({ "event": "setup_started", "input": "owned_source" }))?;
    let source = FrozenFile::capture(root.join("tests/fixtures/src/hello.c"), INPUT_BYTES)?;
    journal.record(json!({ "event": "setup_started", "input": "worker" }))?;
    let worker = FrozenFile::capture(PathBuf::from(env!("CARGO_BIN_EXE_rampage-worker")), 128 * INPUT_BYTES)?;
    let mut images = Vec::new();
    for case in &CASES {
        journal.record(json!({ "event": "setup_started", "input": case.fixture }))?;
        images.push(FrozenImage::capture(&root.join("tests/fixtures/bin").join(case.fixture))?);
    }
    source.validate()?;
    worker.validate()?;
    for image in &images {
        backing(&image.binary)?;
    }
    journal.record(json!({
        "event": "inputs_frozen", "source_sha256": source.sha256, "worker_sha256": worker.sha256,
        "images": images.iter().zip(&CASES).map(|(image, case)| json!({
            "fixture": case.fixture, "source_sha256": image.sha256, "image_sha256": image.image_sha256,
            "file_bytes": image.file.len(), "selected_image_bytes": image.image.len(),
        })).collect::<Vec<_>>(),
    }))?;
    Ok((source, worker, images))
}

fn measured_attempt(
    journal: &mut Journal,
    attempt: &Value,
    source: &FrozenFile,
    worker: &FrozenFile,
    image: &FrozenImage,
    reference: &mut Option<String>,
    blocked: &mut Option<Failure>,
) -> Result<Value, Failure> {
    let id = &attempt["id"];
    let case = &CASES[attempt["case_index"].as_u64().ok_or("plan_invalid")? as usize];
    let isolated = attempt["backend"] == "isolated";
    source.validate()?;
    worker.validate()?;
    backing(&image.binary)?;
    let setup = Instant::now();
    let project = Project::new(Binary::open(&image.path).map_err(|_| "fixture_open")?);
    project.set_decompiler_options(Some(DecompilerOptions {
        compiler: Some(case.compiler.to_owned()),
        platform: case.platform,
        ..Default::default()
    }));
    if isolated {
        project.set_decompiler_worker(Some(WorkerConfig {
            executable: Some(worker.path.clone()),
            timeout: Duration::from_secs(15),
            ..Default::default()
        }));
    }
    let request = DecompileEntryRequest {
        address: project.resolve(case.entry).map_err(|_| "entry_missing")?,
        validation: EntryValidation::MetadataBacked,
    };
    let setup_elapsed = setup.elapsed();
    image.admit(&project)?;
    source.validate()?;
    worker.validate()?;
    journal.record(json!({ "event": "attempt_admitted", "id": id, "open_settings_us": micros(setup_elapsed) }))?;

    let cancellation = AtomicBool::new(false);
    let mut metrics = None;
    let mut phase_count = 0;
    let mut checkpoint_failed = false;
    let execution = Instant::now();
    let result = project.decompile_entry_measured(
        &request,
        &cancellation,
        |event| {
            phase_count += 1;
            if !checkpoint_failed
                && (phase_count > 32
                    || journal
                        .record(json!({
                            "event": "host_phase", "id": id, "progress": event,
                        }))
                        .is_err())
            {
                checkpoint_failed = true;
                cancellation.store(true, Ordering::Release);
            }
        },
        |value| metrics = Some(value),
    );
    let execution_elapsed = execution.elapsed();
    if let Some(metrics) = &metrics {
        let unavailable = metrics.ownership == SupervisedOwnership::Unverified
            || metrics.cleanup_succeeded == Some(false)
            || (metrics.spawn_complete_us.is_some() && metrics.root_reaped_us.is_none());
        if unavailable {
            *blocked = Some("supervision_unavailable");
        }
    }
    if checkpoint_failed {
        return Err("journal_phase_checkpoint");
    }
    let failure = result.as_ref().err().map(failure_category);
    journal.record(json!({
        "event": "operation_returned", "id": id, "failure_category": failure,
        "open_settings_us": micros(setup_elapsed), "operation_us": micros(execution_elapsed),
        "driver_elapsed_us": micros(setup_elapsed.saturating_add(execution_elapsed)),
        "supervisor": metrics,
        "preparation_timings": result.as_ref().ok().map(|result| &result.context.timings),
    }))?;
    image.admit(&project)?;
    source.validate()?;
    worker.validate()?;
    let output_digest = match &result {
        Ok(result) => Some(digest(&serde_json::to_vec(&result.decompilation).map_err(|_| "result_encoding")?)?),
        Err(_) => None,
    };
    let parity = match (&*reference, &output_digest) {
        (Some(reference), Some(observed)) => reference == observed,
        (None, Some(observed)) => {
            *reference = Some(observed.clone());
            true
        }
        _ => false,
    };
    let oracle_passed = result.as_ref().is_ok_and(|result| oracle(result, case.compiler, case.addition));
    let supervision_passed = isolated == metrics.is_some()
        && metrics.as_ref().is_none_or(|metrics| metrics.cleanup_succeeded == Some(true) && metrics.intentional_stop);
    let passed = oracle_passed && parity && supervision_passed && !project.analysis_cache_status().program;
    Ok(json!({
        "event": "attempt_completed", "id": id, "status": if passed { "passed" } else { "failed" },
        "failure_category": failure.or((!passed).then_some("acceptance_check_failed")),
        "source_oracle_passed": oracle_passed, "parity_passed": parity, "supervision_passed": supervision_passed,
        "result_sha256": output_digest,
    }))
}

fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn run_experiment() -> Result<bool, Failure> {
    let file = output_file()?;
    let started = Instant::now();
    let mut journal = Journal { file, bytes: 0, started };
    let plan = attempt_plan();
    journal.record(json!({
        "event": "header", "schema": "rampage-owned-entry-journal-v2", "plan": plan,
        "scope": "Project exact-entry API over complete owned ELF, PE and Mach-O images; targets never executed",
        "settings": "matched explicit compiler/platform, metadata-backed entry, tokens and structured result",
        "temperature": "fresh Project and native handle per attempt; fresh worker process for isolated attempts",
        "cache_policy": "OS/spec/process-global caches uncontrolled; no cold-start claim",
        "limits": { "attempts_per_backend_per_image": 3, "worker_seconds": 15, "run_budget_seconds": 150 },
        "native_deadline": "cooperative only; caller must use a finite external test-process timeout",
        "timing_scope": "driver sums open/settings and API work; excludes identity checks and other checkpoints",
        "observer_cost": "durable host-phase checkpoints occur inside API work and count toward its budget",
        "rss_scope": "owned worker root only, shared-inclusive sampled maximum; native RSS unavailable",
        "interruption_policy": "a start without completion is interrupted/unknown, never an inferred timeout failure",
    }))?;
    let (source, worker, images) = match capture_inputs(&mut journal) {
        Ok(inputs) => inputs,
        Err(category) if category.starts_with("journal_") => return Err(category),
        Err(category) => {
            journal.record(json!({ "event": "setup_failed", "failure_category": category }))?;
            for attempt in &plan {
                journal.record(json!({ "event": "attempt_not_run", "id": attempt["id"], "reason": "setup_failed" }))?;
            }
            journal.record(json!({
                "event": "summary", "planned": plan.len(), "completed": 0, "passed": 0,
                "failed": 0, "not_run": plan.len(), "all_passed": false,
            }))?;
            return Ok(false);
        }
    };
    let mut references = [None, None, None];
    let (mut passed, mut failed, mut not_run) = (0, 0, 0);
    let mut blocked = None;
    for attempt in &plan {
        if blocked.is_some() || started.elapsed() >= Duration::from_secs(150) {
            not_run += 1;
            journal.record(json!({
                "event": "attempt_not_run", "id": attempt["id"],
                "reason": blocked.unwrap_or("run_budget"),
            }))?;
            continue;
        }
        journal.record(json!({ "event": "attempt_started", "id": attempt["id"] }))?;
        let index = attempt["case_index"].as_u64().ok_or("plan_invalid")? as usize;
        let completion = match measured_attempt(
            &mut journal,
            attempt,
            &source,
            &worker,
            &images[index],
            &mut references[index],
            &mut blocked,
        ) {
            Ok(completion) => completion,
            Err(category) if category.starts_with("journal_") => return Err(category),
            Err(category) => {
                blocked = Some("attempt_prerequisite_failed");
                json!({
                    "event": "attempt_completed", "id": attempt["id"],
                    "status": "failed", "failure_category": category,
                })
            }
        };
        if completion["status"] == "passed" {
            passed += 1
        } else {
            failed += 1
        }
        journal.record(completion)?;
    }
    let all_passed = passed == plan.len();
    journal.record(json!({
        "event": "summary", "planned": plan.len(), "completed": passed + failed,
        "passed": passed, "failed": failed, "not_run": not_run, "all_passed": all_passed,
    }))?;
    Ok(all_passed)
}

#[test]
#[ignore = "owned full-image pilot; requires explicit private RAMPAGE_ENTRY_MEASUREMENTS JSONL output"]
fn owned_full_images_three_repetitions_native_and_isolated_exact_entry() {
    match run_experiment() {
        Ok(true) => {}
        Ok(false) => panic!("measurement failures/unrun attempts retained; no retry or backend fallback"),
        Err(category) => panic!("measurement journal stopped: {category}"),
    }
}

#[test]
fn failure_records_never_publish_api_message_or_private_path_text() {
    let private = "/private/sentinel/worker stderr with secret payload";
    let errors = [
        ApiError::Load { path: private.into(), source: rampage_loaders::LoadError::Malformed(private.into()) },
        ApiError::NotFound(private.into()),
        ApiError::Invalid(private.into()),
        ApiError::Unavailable(private.into()),
        ApiError::NativeTypeHintUnsupported(private.into()),
    ];
    let mut bytes = Vec::new();
    let mut total = 0;
    for error in &errors {
        append_record(
            &mut bytes,
            &mut total,
            &json!({
                "event": "operation_returned", "id": 1, "failure_category": failure_category(error),
            }),
        )
        .unwrap();
    }
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("private") && !text.contains("stderr") && !text.contains("secret"));
    let categories: Vec<_> = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["failure_category"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        categories,
        ["api_load", "api_not_found", "api_invalid", "api_unavailable", "api_native_type_hint_unsupported"]
    );
}

#[derive(Default)]
struct CheckpointWriter {
    bytes: Vec<u8>,
    checkpoint: Vec<u8>,
}

impl Write for CheckpointWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.checkpoint.clone_from(&self.bytes);
        Ok(())
    }
}

#[test]
fn an_interrupted_attempt_leaves_its_start_and_prior_completion_checkpointed_without_a_fake_failure() {
    let mut writer = CheckpointWriter::default();
    let mut total = 0;
    append_record(&mut writer, &mut total, &json!({ "event": "header", "plan": attempt_plan() })).unwrap();
    append_record(&mut writer, &mut total, &json!({ "event": "attempt_started", "id": 1 })).unwrap();
    append_record(
        &mut writer,
        &mut total,
        &json!({
            "event": "attempt_completed", "id": 1, "status": "passed",
        }),
    )
    .unwrap();
    append_record(&mut writer, &mut total, &json!({ "event": "attempt_started", "id": 2 })).unwrap();
    let records: Vec<Value> = std::str::from_utf8(&writer.checkpoint)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records[0]["plan"].as_array().unwrap().len(), 18);
    assert_eq!(records[2]["event"], "attempt_completed");
    assert_eq!(records.last().unwrap()["event"], "attempt_started");
    assert_eq!(records.last().unwrap()["id"], 2);
    assert!(!records.iter().any(|record| record["id"] == 2 && record["event"] == "attempt_completed"));
    assert!(!records.iter().any(|record| record["event"] == "summary"));
}

#[test]
fn oversized_records_and_exhausted_journals_leave_the_prior_checkpoint_unchanged() {
    let mut writer = CheckpointWriter::default();
    let mut total = 0;
    append_record(&mut writer, &mut total, &json!({ "event": "attempt_started", "id": 1 })).unwrap();
    let before = writer.checkpoint.clone();
    let before_total = total;
    assert_eq!(append_record(&mut writer, &mut total, &json!("x".repeat(RECORD_BYTES))), Err("journal_record_limit"));
    assert_eq!(writer.bytes, before);
    assert_eq!(writer.checkpoint, before);
    assert_eq!(total, before_total);
    total = JOURNAL_BYTES;
    assert_eq!(append_record(&mut writer, &mut total, &json!({ "event": "summary" })), Err("journal_limit"));
    assert_eq!(writer.bytes, before);
    assert_eq!(writer.checkpoint, before);
}
