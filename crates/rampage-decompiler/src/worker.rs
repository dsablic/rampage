//! One-request worker protocol and bounded, cancellable subprocess supervision.
//!
//! The native architecture retains Ghidra's 100,000-instruction-per-function limit. The supervisor additionally
//! bounds request/response sizes, memory use, and wall-clock time. Linux enforces address-space limits; Darwin
//! uses sampled resident-memory checks because AS/RSS is advisory and current kernels reject DATA limits.
//! It is a crash/resource
//! isolation boundary, not a sandbox for running untrusted executables.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rampage_arch::Arch;
use serde::{Deserialize, Serialize};

use crate::{Decompiler, DecompilerOptions, MemoryRegion, Platform};

mod metrics;

use metrics::Measurement;
pub use metrics::{
    SupervisedCleanupError, SupervisedExitStatus, SupervisedInputMetrics, SupervisedInputOutcome, SupervisedMetrics,
    SupervisedOwnership, SupervisedRssBackend, SupervisedRssError, SupervisedRssMetrics, SupervisedRun,
    SupervisedStreamMetrics, SupervisedStreamOutcome,
};

pub const MAX_REQUEST_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STDERR_BYTES: usize = 64 * 1024;
pub const PROTOCOL_VERSION: u32 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub version: u32,
    pub arch: String,
    #[serde(default)]
    pub big_endian: bool,
    #[serde(default)]
    pub options: WorkerOptions,
    pub mappings: Vec<WorkerMapping>,
    #[serde(default)]
    pub code_modes: Vec<WorkerCodeMode>,
    /// Applied in order, so a later type/prototype can depend on an earlier declaration or symbol.
    #[serde(default)]
    pub operations: Vec<WorkerOperation>,
    pub decompile: WorkerFunction,
    #[serde(default)]
    pub tokens: bool,
    #[serde(default)]
    pub validate_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerOptions {
    pub platform: String,
    #[serde(default)]
    pub compiler: Option<String>,
    #[serde(default)]
    pub arm_be8: bool,
}

impl Default for WorkerOptions {
    fn default() -> Self {
        Self { platform: "default".to_owned(), compiler: None, arm_be8: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerMapping {
    pub base: u64,
    /// File-backed bytes encoded as consecutive hexadecimal pairs, without a prefix.
    pub hex_bytes: String,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCodeMode {
    pub address: u64,
    pub thumb: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerOperation {
    Symbol {
        address: u64,
        name: String,
    },
    Import {
        slot: u64,
        target: Option<u64>,
        name: String,
    },
    Prototype {
        address: u64,
        indirect: bool,
        declaration: String,
    },
    ParseTypes {
        declarations: String,
    },
    /// Read-only, ephemeral check of an already parsed flat struct, before dependent prototypes.
    /// Reassert in every worker/session/compiler rebuild; this operation supplies no persistence.
    AssertPlainStructLayout {
        layout: crate::layout::PlainStructLayout,
        /// Checked import pins the child's exact embedded manifest before native initialization.
        /// None preserves general/manual/external assertions. Older strict workers refuse this added field.
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "expected_context")]
        expected_context: Option<String>,
    },
    Global {
        address: u64,
        declaration: String,
    },
    Mode {
        modes: Vec<WorkerCodeMode>,
    },
    /// Resolve a built-in C prototype using the worker's selected compiler, rather than the host's ABI.
    RuntimePrototype {
        address: u64,
        indirect: bool,
        name: String,
        #[serde(default)]
        optional: bool,
    },
    /// Mark a registered function, or an import slot's function, as never returning.
    NoReturn {
        address: u64,
        indirect: bool,
    },
}

fn expected_context<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    struct ContextVisitor;
    impl<'de> serde::de::Visitor<'de> for ContextVisitor {
        type Value = Option<String>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an optional canonical 64-byte SHA-256 context identity")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
            struct DigestVisitor;
            impl serde::de::Visitor<'_> for DigestVisitor {
                type Value = String;
                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a canonical 64-byte SHA-256 context identity")
                }
                fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
                    if !context_digest_valid(value) {
                        return Err(E::custom("invalid checked context identity"));
                    }
                    Ok(value.to_owned())
                }
            }
            deserializer.deserialize_str(DigestVisitor).map(Some)
        }
    }
    deserializer.deserialize_option(ContextVisitor)
}

fn context_digest_valid(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerFunction {
    pub address: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub thumb: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerResponse {
    Ok { version: u32, output: Box<WorkerOutput> },
    Error { version: u32, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerOutput {
    pub text: String,
    pub language_id: String,
    pub data_organization: WorkerDataOrganization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<WorkerToken>>,
    #[serde(default)]
    pub structure: Option<crate::StructuredResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerDataOrganization {
    pub pointer: u8,
    pub int: u8,
    pub long: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerToken {
    pub text: String,
    pub kind: String,
    pub address: Option<u64>,
    #[serde(default)]
    pub span: Option<(usize, usize)>,
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Overrides RAMPAGE_WORKER and the executable next to the calling application.
    pub executable: Option<PathBuf>,
    pub timeout: Duration,
    /// Linux: hard AS/DATA limit. Darwin: sampled RSS limit, which can overshoot between checks.
    pub memory_limit_bytes: u64,
    /// These may lower, but never raise, the protocol's hard limits.
    pub max_request_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            executable: None,
            timeout: Duration::from_secs(30),
            memory_limit_bytes: 1024 * 1024 * 1024,
            max_request_bytes: MAX_REQUEST_BYTES,
            max_stdout_bytes: MAX_STDOUT_BYTES,
            max_stderr_bytes: MAX_STDERR_BYTES,
        }
    }
}

#[derive(Debug)]
pub enum WorkerError {
    Io {
        action: &'static str,
        source: io::Error,
    },
    RequestTooLarge {
        limit: usize,
    },
    OutputTooLarge {
        stream: &'static str,
        limit: usize,
    },
    MemoryLimit {
        limit: u64,
    },
    Timeout,
    Cancelled,
    Exit {
        status: String,
        stderr: String,
    },
    /// Group signaling failed; `root: None` means direct-child cleanup succeeded, not group cleanup.
    Cleanup {
        group: io::Error,
        root: Option<Box<WorkerError>>,
    },
    Protocol(String),
    Decompile(String),
    UnsupportedPlatform,
}

impl fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { action, source } => write!(formatter, "worker {action}: {source}"),
            Self::RequestTooLarge { limit } => write!(formatter, "worker request exceeds {limit} bytes"),
            Self::OutputTooLarge { stream, limit } => write!(formatter, "worker {stream} exceeds {limit} bytes"),
            Self::MemoryLimit { limit } => write!(formatter, "decompiler worker memory exceeds {limit} bytes"),
            Self::Timeout => formatter.write_str("decompiler worker timed out"),
            Self::Cancelled => formatter.write_str("decompiler worker cancelled"),
            Self::Exit { status, stderr } => write!(formatter, "decompiler worker exited with {status}: {stderr}"),
            Self::Cleanup { group, root } => {
                write!(formatter, "worker group cleanup failed: {group}")?;
                if let Some(root) = root {
                    write!(formatter, "; direct-child cleanup failed: {root}")?;
                }
                Ok(())
            }
            Self::Protocol(message) => write!(formatter, "invalid worker protocol: {message}"),
            Self::Decompile(message) => write!(formatter, "decompiler worker: {message}"),
            Self::UnsupportedPlatform => {
                formatter.write_str("worker resource supervision is unsupported on this platform")
            }
        }
    }
}

impl std::error::Error for WorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Cleanup { group, .. } => Some(group),
            _ => None,
        }
    }
}

fn io_error(action: &'static str, source: io::Error) -> WorkerError {
    WorkerError::Io { action, source }
}

fn cancelled(cancellation: Option<&AtomicBool>) -> bool {
    cancellation.is_some_and(|flag| flag.load(Ordering::Acquire))
}

#[derive(Clone, Copy)]
struct SupervisorBudget<'a> {
    started: std::time::Instant,
    timeout: Duration,
    cancellation: Option<&'a AtomicBool>,
}

impl SupervisorBudget<'_> {
    fn check(&self) -> Result<(), WorkerError> {
        if cancelled(self.cancellation) {
            return Err(WorkerError::Cancelled);
        }
        if self.started.elapsed() >= self.timeout {
            return Err(WorkerError::Timeout);
        }
        Ok(())
    }
}

/// Launch one worker, drain all three pipes concurrently, and attempt owned-group cleanup before reaping its root.
/// Missing workers are errors; supervision never falls back to an in-process native call.
/// Supported supervisor hosts are 64-bit Linux and macOS; other hosts return UnsupportedPlatform.
/// Requires default SIGCHLD handling and exclusive ownership of the child's wait status. Concurrent signal
/// disposition changes or external child reaping are unsupported; lost ownership prevents further signals.
/// Descendants that leave the worker's process group are outside this supervisor's cleanup boundary.
/// Prior supervision errors retain precedence over failures in best-effort Drop cleanup.
/// Failed child/response outcomes also retain their primary category; the measured API records secondary
/// cleanup failure. A successful response never waives a cleanup failure.
/// Legacy workers without private completion must exit, permit anchored group cleanup, and produce actual
/// pipe EOF. On Darwin even a valid exit-zero p4 response may fail with zombie-group EPERM; this is a restricted
/// compatibility contract, not proof that the group is empty. All custom SIGCHLD handlers are rejected,
/// including handlers that do not reap; callers must retain SIG_DFL and exclusive child-wait ownership.
pub fn run_supervised(
    request: &WorkerRequest,
    config: &WorkerConfig,
    cancellation: Option<&AtomicBool>,
) -> Result<WorkerOutput, WorkerError> {
    let started = std::time::Instant::now();
    let measurement = Measurement::new(started, false);
    run_supervised_inner(request, config, cancellation, started, &measurement)
}

/// Opt-in host-only observations, retained even when supervision fails. This does not change protocol v4.
/// Offsets share this call's start, overlap, and do not expose worker-internal initialization phases.
/// The ownership and cleanup requirements of [`run_supervised`] apply. Sampling is synchronous; neither
/// OS queries nor spawn are forcibly interruptible, and observation overhead counts toward the budget.
pub fn run_supervised_measured(
    request: &WorkerRequest,
    config: &WorkerConfig,
    cancellation: Option<&AtomicBool>,
) -> SupervisedRun {
    let started = std::time::Instant::now();
    let measurement = Measurement::new(started, true);
    let result = run_supervised_inner(request, config, cancellation, started, &measurement);
    SupervisedRun { result, metrics: measurement.finish().expect("enabled supervisor measurement") }
}

/// Runs one explicitly configured binary with opaque application bytes, without decompiler protocol decoding.
/// Requires config.executable; no ambient worker lookup or in-process fallback is performed. Request/stdout/
/// stderr limits may only lower the existing hard caps. The original timeout covers the complete operation.
/// Successful bytes require full input delivery, actual output EOF, accepted process outcome and successful
/// owned cleanup. The SIGCHLD, exclusive wait ownership, legacy-worker and platform restrictions of
/// run_supervised apply. This is resource/crash supervision, not a component sandbox or protocol decoder.
#[doc(hidden)]
pub fn run_supervised_bytes(
    bytes: Vec<u8>,
    config: &WorkerConfig,
    cancellation: Option<&AtomicBool>,
) -> Result<Vec<u8>, WorkerError> {
    let started = std::time::Instant::now();
    let budget = SupervisorBudget { started, timeout: config.timeout, cancellation };
    budget.check()?;
    let executable = config.executable.as_deref().ok_or_else(|| {
        io_error(
            "locate executable",
            io::Error::new(io::ErrorKind::InvalidInput, "byte supervision requires an explicit executable"),
        )
    })?;
    let limit = config.max_request_bytes.min(MAX_REQUEST_BYTES);
    if bytes.len() > limit {
        return Err(WorkerError::RequestTooLarge { limit });
    }
    let measurement = Measurement::new(started, false);
    budget.check()?;
    let process = supervised_process(executable, bytes, config, cancellation, started, &measurement)?;
    finish_bytes_process(process, budget, &measurement)
}

fn finish_bytes_process(
    mut process: ProcessOutput,
    budget: SupervisorBudget<'_>,
    measurement: &Measurement,
) -> Result<Vec<u8>, WorkerError> {
    check_process_exit(&mut process, budget, measurement)?;
    if !process.outputs_eof {
        return Err(WorkerError::Protocol("worker output pipes did not reach EOF".to_owned()));
    }
    if !process.input_fully_delivered {
        return Err(WorkerError::Protocol("worker did not receive the complete request".to_owned()));
    }
    if let Some(error) = process.cleanup_error {
        return Err(error);
    }
    budget.check()?;
    Ok(process.stdout)
}

fn run_supervised_inner(
    request: &WorkerRequest,
    config: &WorkerConfig,
    cancellation: Option<&AtomicBool>,
    started: std::time::Instant,
    measurement: &Measurement,
) -> Result<WorkerOutput, WorkerError> {
    let budget = SupervisorBudget { started, timeout: config.timeout, cancellation };
    budget.check()?;
    validate_layout_operations(request, Some(budget))?;
    measurement.record(|data, elapsed| data.request_preflight_complete_us = Some(elapsed));
    measurement.record(|data, elapsed| data.request_serialization_started_us = Some(elapsed));
    let bytes = serialize_supervised(request, config.max_request_bytes.min(MAX_REQUEST_BYTES), budget)?;
    measurement.record(|data, elapsed| {
        data.request_serialization_complete_us = Some(elapsed);
        data.input.requested_bytes = Some(bytes.len() as u64);
    });
    let executable = match &config.executable {
        Some(path) => path.clone(),
        None => match std::env::var_os("RAMPAGE_WORKER") {
            Some(path) => PathBuf::from(path),
            None => std::env::current_exe()
                .map_err(|error| io_error("locate executable", error))?
                .with_file_name(if cfg!(windows) { "rampage-worker.exe" } else { "rampage-worker" }),
        },
    };
    budget.check()?;
    let process = supervised_process(&executable, bytes, config, cancellation, started, measurement)?;
    finish_process(process, config.max_stdout_bytes, budget, measurement)
}

fn finish_process(
    mut process: ProcessOutput,
    stdout_limit: usize,
    budget: SupervisorBudget<'_>,
    measurement: &Measurement,
) -> Result<WorkerOutput, WorkerError> {
    check_process_exit(&mut process, budget, measurement)?;
    measurement.record(|data, elapsed| data.response_decode_started_us = Some(elapsed));
    let response = decode_supervised_response(process.stdout.as_slice(), stdout_limit, budget)?;
    measurement.record(|data, elapsed| data.response_decoded_us = Some(elapsed));
    budget.check()?;
    match response {
        WorkerResponse::Ok { version, output } if version == PROTOCOL_VERSION => {
            if !process.outputs_eof {
                return Err(WorkerError::Protocol("worker output pipes did not reach EOF".to_owned()));
            }
            if process.controlled_stop && !process.input_fully_delivered {
                return Err(WorkerError::Protocol("controlled worker did not receive the complete request".to_owned()));
            }
            match process.cleanup_error {
                Some(error) => Err(error),
                None => Ok(*output),
            }
        }
        WorkerResponse::Error { version, message } if version == PROTOCOL_VERSION => {
            Err(WorkerError::Decompile(message))
        }
        _ => Err(WorkerError::Protocol("unsupported response version".to_owned())),
    }
}

fn check_process_exit(
    process: &mut ProcessOutput,
    budget: SupervisorBudget<'_>,
    measurement: &Measurement,
) -> Result<(), WorkerError> {
    if let Some(error) = &process.cleanup_error {
        measurement.record(|data, _| {
            data.cleanup_succeeded = Some(false);
            data.cleanup_error = Some(SupervisedCleanupError::from(error));
        });
    }
    budget.check()?;
    if !process.allows_response_validation() && !(process.control_error.is_some() && process.ended_with_host_stop()) {
        return Err(WorkerError::Exit {
            status: process.status.to_string(),
            stderr: String::from_utf8_lossy(&process.stderr).into_owned(),
        });
    }
    if let Some(error) = process.control_error.take() {
        return Err(error);
    }
    Ok(())
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    overflow: bool,
}

struct SupervisedWriter<'a> {
    buffer: BoundedBuffer,
    budget: SupervisorBudget<'a>,
    interruption: Option<WorkerError>,
}

impl Write for SupervisedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Err(error) = self.budget.check() {
            self.interruption = Some(error);
            return Err(io::Error::other("worker serialization interrupted"));
        }
        // Keep an individual write bounded too, including serde's large unescaped strings.
        self.buffer.write(&bytes[..bytes.len().min(8192)])
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialize_supervised(
    value: &impl Serialize,
    limit: usize,
    budget: SupervisorBudget<'_>,
) -> Result<Vec<u8>, WorkerError> {
    budget.check()?;
    let mut writer = SupervisedWriter { buffer: BoundedBuffer::new(limit), budget, interruption: None };
    let result = serde_json::to_writer(&mut writer, value);
    if let Some(error) = writer.interruption {
        return Err(error);
    }
    budget.check()?;
    match result {
        Ok(()) => Ok(writer.buffer.bytes),
        Err(_) if writer.buffer.overflow => Err(WorkerError::RequestTooLarge { limit }),
        Err(error) => Err(WorkerError::Protocol(error.to_string())),
    }
}

struct SupervisedReader<'a, R> {
    input: R,
    remaining: usize,
    limit: usize,
    budget: SupervisorBudget<'a>,
    interruption: Option<WorkerError>,
}

impl<R: Read> Read for SupervisedReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Err(error) = self.budget.check() {
            self.interruption = Some(error);
            return Err(io::Error::other("worker response decoding interrupted"));
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let capacity = buffer.len().min(self.remaining.saturating_add(1)).min(8192);
        let count = self.input.read(&mut buffer[..capacity])?;
        if let Err(error) = self.budget.check() {
            self.interruption = Some(error);
            return Err(io::Error::other("worker response decoding interrupted"));
        }
        if count > self.remaining {
            self.interruption = Some(WorkerError::OutputTooLarge { stream: "stdout", limit: self.limit });
            return Err(io::Error::other("worker response exceeds size limit"));
        }
        self.remaining -= count;
        Ok(count)
    }
}

fn decode_supervised_response(
    input: impl Read,
    limit: usize,
    budget: SupervisorBudget<'_>,
) -> Result<WorkerResponse, WorkerError> {
    budget.check()?;
    let limit = limit.min(MAX_STDOUT_BYTES);
    let mut reader = SupervisedReader { input, remaining: limit, limit, budget, interruption: None };
    let result = serde_json::from_reader(&mut reader);
    if let Some(error) = reader.interruption {
        return Err(error);
    }
    budget.check()?;
    result.map_err(|error| WorkerError::Protocol(error.to_string()))
}

impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self { bytes: Vec::new(), limit, overflow: false }
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.overflow = true;
            return Err(io::Error::other("JSON size limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialize_bounded(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, WorkerError> {
    let mut buffer = BoundedBuffer::new(limit);
    match serde_json::to_writer(&mut buffer, value) {
        Ok(()) => Ok(buffer.bytes),
        Err(_) if buffer.overflow => Err(WorkerError::RequestTooLarge { limit }),
        Err(error) => Err(WorkerError::Protocol(error.to_string())),
    }
}

/// Handles exactly one raw stdio JSON request. Errors are JSON responses, not stderr text. The supervised
/// binary entry point may hold the process after this returns, without accepting another request.
pub fn serve_stdio() -> Result<(), WorkerError> {
    let response = match read_request(io::stdin().lock()).and_then(execute_request) {
        Ok(output) => WorkerResponse::Ok { version: PROTOCOL_VERSION, output: Box::new(output) },
        Err(message) => WorkerResponse::Error { version: PROTOCOL_VERSION, message },
    };
    let bytes = match serialize_bounded(&response, MAX_STDOUT_BYTES) {
        Ok(bytes) => bytes,
        Err(WorkerError::RequestTooLarge { .. }) => serialize_bounded(
            &WorkerResponse::Error {
                version: PROTOCOL_VERSION,
                message: "serialized decompiler output exceeds worker limit".to_owned(),
            },
            MAX_STDOUT_BYTES,
        )?,
        Err(error) => return Err(error),
    };
    io::stdout().lock().write_all(&bytes).map_err(|error| io_error("write response", error))
}

/// Binary-only lifecycle entry point. Standalone calls without the private control environment retain
/// serve_stdio behavior. Library callers should use serve_stdio, which never consumes ambient descriptors.
/// The control descriptor is duplicated before validation; only the fresh duplicate is owned or closed.
pub fn serve_worker_stdio() -> Result<(), WorkerError> {
    serve_binary_stdio(serve_stdio)
}

/// Binary-only lifecycle wrapper for one trusted handler implementing its own application protocol.
/// With private control, setup precedes the single handler call; successful handler return is followed by
/// stdio flush/release, private completion and a live-root hold. Without control, the handler result is returned
/// directly. The control capability uses only a fresh owned duplicate; the selected original is unchanged.
/// No decompiler request/response is constructed or decoded. The launching supervisor enforces resource caps;
/// the handler is responsible for its own bounded application decoding and component/runtime capabilities.
pub fn serve_binary_stdio(handler: impl FnOnce() -> Result<(), WorkerError>) -> Result<(), WorkerError> {
    #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
    {
        unix::serve_binary_stdio(handler)
    }
    #[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
    {
        handler()
    }
}

fn read_request(input: impl Read) -> Result<WorkerRequest, String> {
    let mut bytes = Vec::new();
    input
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read request: {error}"))?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("worker request exceeds protocol limit".to_owned());
    }
    crate::layout_wire::decode_worker(&bytes, |bytes| {
        serde_json::from_slice(bytes).map_err(|_| "decode request: invalid worker schema".to_owned())
    })
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("mapping hex bytes must contain complete pairs".to_owned());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            match (digit(pair[0]), digit(pair[1])) {
                (Some(high), Some(low)) => Ok((high << 4) | low),
                _ => Err("mapping contains invalid hex bytes".to_owned()),
            }
        })
        .collect()
}

fn validate_layout_operations(
    request: &WorkerRequest,
    budget: Option<SupervisorBudget<'_>>,
) -> Result<(), WorkerError> {
    if request.version != PROTOCOL_VERSION {
        return Err(WorkerError::Protocol(format!("unsupported worker protocol version {}", request.version)));
    }
    for (index, operation) in request.operations.iter().enumerate() {
        if let Some(budget) = budget {
            budget.check()?;
        }
        if let WorkerOperation::AssertPlainStructLayout { layout, expected_context } = operation {
            layout.validate().map_err(|error| WorkerError::Protocol(format!("operation {index}: {error}")))?;
            if expected_context.as_deref().is_some_and(|text| !context_digest_valid(text)) {
                return Err(WorkerError::Protocol("invalid checked context identity".to_owned()));
            }
        }
    }
    Ok(())
}

fn execute_request(request: WorkerRequest) -> Result<WorkerOutput, String> {
    validate_layout_operations(&request, None).map_err(|error| match error {
        WorkerError::Protocol(message) => message,
        other => other.to_string(),
    })?;
    let checked_context = request.operations.iter().find_map(|operation| match operation {
        WorkerOperation::AssertPlainStructLayout { expected_context: Some(expected), .. } => Some(expected.as_str()),
        _ => None,
    });
    if let Some(expected) = checked_context {
        let actual = rampage_arch::hex::bytes(&crate::context::embedded_manifest_sha256());
        if expected != actual
            || request.operations.iter().any(|operation| {
                matches!(operation,
            WorkerOperation::AssertPlainStructLayout { expected_context: Some(other), .. } if other != expected)
            })
        {
            return Err(
                "checked worker embedded specification identity does not match the requested context".to_owned()
            );
        }
        crate::require_verified_bundled_native_context().map_err(|error| error.to_string())?;
    }
    let arch: Arch = request.arch.parse()?;
    let platform = match request.options.platform.as_str() {
        "default" => Platform::Default,
        "windows" => Platform::Windows,
        "darwin" => Platform::Darwin,
        other => return Err(format!("unknown decompiler platform {other:?}")),
    };
    let options = DecompilerOptions { platform, compiler: request.options.compiler, arm_be8: request.options.arm_be8 };
    if request.mappings.len() > 4096 {
        return Err("worker memory region limit exceeded (4096)".to_owned());
    }
    let byte_count = request.mappings.iter().try_fold(0usize, |count, mapping| {
        count.checked_add(mapping.hex_bytes.len()).filter(|&count| count <= MAX_REQUEST_BYTES)
    });
    if byte_count.is_none() {
        return Err("worker mapping byte limit exceeded".to_owned());
    }
    let bytes: Vec<_> =
        request.mappings.iter().map(|mapping| decode_hex(&mapping.hex_bytes)).collect::<Result<_, _>>()?;
    let regions: Vec<_> = request
        .mappings
        .iter()
        .zip(&bytes)
        .map(|(mapping, bytes)| MemoryRegion {
            base: mapping.base,
            bytes,
            size: mapping.size,
            readable: mapping.readable,
            writable: mapping.writable,
            executable: mapping.executable,
        })
        .collect();
    let mut engine = Decompiler::open_with_options(arch, request.big_endian, &regions, &options)
        .map_err(|error| error.to_string())?;
    let modes: Vec<_> = request.code_modes.iter().map(|mode| (mode.address, mode.thumb)).collect();
    engine.set_code_modes(&modes).map_err(|error| error.to_string())?;
    for (index, operation) in request.operations.into_iter().enumerate() {
        let result = match operation {
            WorkerOperation::Symbol { address, name } => engine.set_symbol(address, &name),
            WorkerOperation::Import { slot, target, name } => engine.add_import(slot, target, &name),
            WorkerOperation::Prototype { address, indirect, declaration } => {
                engine.apply_prototype(address, indirect, &declaration)
            }
            WorkerOperation::ParseTypes { declarations } => engine.parse_c(&declarations),
            WorkerOperation::AssertPlainStructLayout { layout, expected_context } => {
                if expected_context.is_some() {
                    engine.verify_bundled_plain_struct_counterpart(&layout)
                } else {
                    engine.assert_plain_struct_layout(&layout)
                }
            }
            WorkerOperation::Global { address, declaration } => engine.add_global(address, &declaration),
            WorkerOperation::Mode { modes } => {
                let modes: Vec<_> = modes.into_iter().map(|mode| (mode.address, mode.thumb)).collect();
                engine.set_code_modes(&modes)
            }
            WorkerOperation::RuntimePrototype { address, indirect, name, optional } => {
                match engine.c_prototype(&name) {
                    Some(declaration) => engine.apply_prototype(address, indirect, &declaration),
                    None if optional => Ok(()),
                    None => Err(crate::Error::Ghidra(format!("no runtime prototype for {name:?}"))),
                }
            }
            WorkerOperation::NoReturn { address, indirect } => engine.set_noreturn(address, indirect),
        };
        result.map_err(|error| format!("operation {index}: {error}"))?;
    }
    if request.decompile.name.contains('\0') {
        return Err("function name contains NUL".to_owned());
    }
    if arch.pointer_size() == 4 && request.decompile.address > u64::from(u32::MAX) {
        return Err("function address exceeds target width".to_owned());
    }
    let text = if request.validate_only {
        String::new()
    } else {
        engine
            .decompile(request.decompile.address, &request.decompile.name, request.decompile.thumb)
            .map_err(|error| error.to_string())?
    };
    let tokens = request.tokens.then(|| {
        engine
            .tokens()
            .into_iter()
            .map(|token| WorkerToken { text: token.text, kind: token.kind, address: token.address, span: token.span })
            .collect()
    });
    let organization = engine.data_organization();
    let structure =
        if request.validate_only { None } else { Some(engine.structured_result().map_err(|error| error.to_string())?) };
    Ok(WorkerOutput {
        text,
        language_id: engine.language_id().to_owned(),
        data_organization: WorkerDataOrganization {
            pointer: organization.pointer,
            int: organization.int,
            long: organization.long,
        },
        tokens,
        structure,
    })
}

#[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
use unix::supervised_process;

#[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
fn supervised_process(
    _executable: &std::path::Path,
    _bytes: Vec<u8>,
    _config: &WorkerConfig,
    _cancellation: Option<&AtomicBool>,
    _started: std::time::Instant,
    _measurement: &Measurement,
) -> Result<ProcessOutput, WorkerError> {
    Err(WorkerError::UnsupportedPlatform)
}

#[derive(Debug)]
struct ProcessOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: std::process::ExitStatus,
    controlled_stop: bool,
    host_stopped_root: bool,
    input_fully_delivered: bool,
    outputs_eof: bool,
    control_error: Option<WorkerError>,
    cleanup_error: Option<WorkerError>,
}

impl ProcessOutput {
    fn ended_with_host_stop(&self) -> bool {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
        {
            use std::os::unix::process::ExitStatusExt;
            self.host_stopped_root && self.status.signal() == Some(libc::SIGKILL)
        }
        #[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
        {
            false
        }
    }

    fn allows_response_validation(&self) -> bool {
        if self.status.success() {
            return true;
        }
        #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
        {
            use std::os::unix::process::ExitStatusExt;
            self.controlled_stop && self.status.signal() == Some(libc::SIGKILL)
        }
        #[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
        {
            false
        }
    }
}

#[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
mod unix {
    use std::ffi::c_int;
    #[cfg(target_os = "linux")]
    use std::ffi::c_ulong;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::Path;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Instant;

    use super::*;

    const POLL_INTERVAL: Duration = Duration::from_millis(5);
    const CONTROL_ENV: &str = "RAMPAGE_SUPERVISOR_CONTROL";
    const CONTROL_HELLO: &[u8] = b"RAMPAGE-CONTROL/1/HOST\0";
    const CONTROL_DONE: &[u8] = b"RAMPAGE-CONTROL/1/RESPONSE-FLUSHED/0\0";

    struct HostControl {
        socket: UnixStream,
        bytes: [u8; CONTROL_DONE.len()],
        received: usize,
        complete: bool,
        closed: bool,
    }

    impl HostControl {
        fn authorized(&self) -> bool {
            self.complete && !self.closed
        }

        fn pair() -> Result<(Self, UnixStream), WorkerError> {
            let (host, child) = UnixStream::pair().map_err(|error| io_error("create control socket", error))?;
            let mut host = control_above_stdio(host)?;
            let child = control_above_stdio(child)?;
            // UnixStream::pair creates close-on-exec endpoints. Queue the bounded handshake before spawning,
            // so the child can validate it with a non-consuming, nonblocking peek before claiming the fd.
            host.write_all(CONTROL_HELLO).map_err(|error| io_error("write control handshake", error))?;
            host.set_nonblocking(true).map_err(|error| io_error("configure control socket", error))?;
            Ok((
                Self { socket: host, bytes: [0; CONTROL_DONE.len()], received: 0, complete: false, closed: false },
                child,
            ))
        }

        fn poll(&mut self, measurement: &Measurement) -> Result<(), WorkerError> {
            if self.closed {
                return Ok(());
            }
            if self.complete {
                let mut extra = [0];
                for _ in 0..8 {
                    match self.socket.read(&mut extra) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                        result => {
                            self.complete = false;
                            self.closed = true;
                            return match result {
                                Ok(0) => {
                                    Err(WorkerError::Protocol("private completion peer closed before stop".to_owned()))
                                }
                                Ok(_) => Err(WorkerError::Protocol("unexpected private completion bytes".to_owned())),
                                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                                    Err(WorkerError::Protocol("private completion peer reset before stop".to_owned()))
                                }
                                Err(error) => Err(io_error("inspect control completion tail", error)),
                            };
                        }
                    }
                }
                self.complete = false;
                self.closed = true;
                return Err(io_error("inspect control completion tail", io::ErrorKind::Interrupted.into()));
            }
            match self.socket.read(&mut self.bytes[self.received..]) {
                Ok(0) => {
                    self.closed = true;
                    if self.received != 0 {
                        return Err(WorkerError::Protocol("truncated private control completion".to_owned()));
                    }
                }
                Ok(count) => {
                    self.received += count;
                    if self.received == self.bytes.len() {
                        if self.bytes.as_slice() != CONTROL_DONE {
                            return Err(WorkerError::Protocol("invalid private control completion".to_owned()));
                        }
                        self.complete = true;
                        measurement.record(|data, elapsed| data.control_completion_us = Some(elapsed));
                        return self.poll(measurement);
                    }
                }
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                // Legacy executables may close the inherited socket without consuming its queued handshake.
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset && self.received == 0 => {
                    self.closed = true;
                }
                Err(error) => return Err(io_error("read control completion", error)),
            }
            Ok(())
        }
    }

    fn control_above_stdio(socket: UnixStream) -> Result<UnixStream, WorkerError> {
        if socket.as_raw_fd() >= 3 {
            return Ok(socket);
        }
        // SAFETY: duplicate this owned socket above standard descriptors before Command configures child stdio.
        let fd = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(io_error("reserve control descriptor", io::Error::last_os_error()));
        }
        // SAFETY: fcntl returned a fresh owned descriptor; dropping the original only closes our own socket.
        Ok(unsafe { UnixStream::from_raw_fd(fd) })
    }

    fn inherit_control(fd: RawFd) -> io::Result<()> {
        // SAFETY: only the child endpoint is made inheritable in this pre-exec callback; fcntl is signal-safe.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn validate_worker_control(value: &str) -> Result<OwnedFd, WorkerError> {
        let invalid = || WorkerError::Protocol("invalid private worker control capability".to_owned());
        let text = value.strip_prefix("1:").filter(|_| value.len() <= 32).ok_or_else(invalid)?;
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let candidate: c_int = text.parse().map_err(|_| invalid())?;
        if candidate < 3 {
            return Err(invalid());
        }
        // SAFETY: fcntl atomically returns a fresh descriptor or fails; the selected ambient fd is neither
        // owned nor closed here. Validation and all subsequent I/O operate only on the fresh duplicate.
        let duplicate = unsafe { libc::fcntl(candidate, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(io_error("duplicate worker control descriptor", io::Error::last_os_error()));
        }
        // SAFETY: this descriptor was freshly allocated by fcntl, independently of any existing Rust/C owner.
        let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
        let fd = owned.as_raw_fd();
        let mut kind: c_int = 0;
        // The v1 worker endpoint must block while holding the completed root, unlike the host endpoint.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_NONBLOCK != 0 {
            return Err(invalid());
        }
        let mut kind_size = std::mem::size_of::<c_int>() as libc::socklen_t;
        // SAFETY: read-only descriptor checks use writable, correctly sized host socket structures.
        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut peer_size = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let socket_result = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE, (&mut kind as *mut c_int).cast(), &mut kind_size)
        };
        if socket_result != 0
            || kind_size != std::mem::size_of::<c_int>() as libc::socklen_t
            || kind != libc::SOCK_STREAM
            || unsafe { libc::getpeername(fd, (&mut peer as *mut libc::sockaddr_storage).cast(), &mut peer_size) } != 0
            || peer_size < 2
            || c_int::from(peer.ss_family) != libc::AF_UNIX
        {
            return Err(invalid());
        }
        let mut hello = [0; CONTROL_HELLO.len()];
        let mut verified = false;
        for _ in 0..8 {
            // SAFETY: MSG_PEEK does not consume data or claim ownership of an ambient descriptor.
            let count =
                unsafe { libc::recv(fd, hello.as_mut_ptr().cast(), hello.len(), libc::MSG_PEEK | libc::MSG_DONTWAIT) };
            if count == hello.len() as isize && hello.as_slice() == CONTROL_HELLO {
                verified = true;
                break;
            }
            if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(invalid());
        }
        if !verified {
            return Err(invalid());
        }
        Ok(owned)
    }

    fn claim_worker_control(value: &str) -> Result<UnixStream, WorkerError> {
        let descriptor = validate_worker_control(value)?;
        let mut socket = UnixStream::from(descriptor);
        let mut hello = [0; CONTROL_HELLO.len()];
        socket.read_exact(&mut hello).map_err(|error| io_error("consume control handshake", error))?;
        if hello.as_slice() != CONTROL_HELLO {
            return Err(WorkerError::Protocol("private control handshake changed".to_owned()));
        }
        Ok(socket)
    }

    pub(super) fn serve_binary_stdio(handler: impl FnOnce() -> Result<(), WorkerError>) -> Result<(), WorkerError> {
        let Some(value) = std::env::var_os(CONTROL_ENV) else {
            return handler();
        };
        let value =
            value.to_str().ok_or_else(|| WorkerError::Protocol("invalid private control version".to_owned()))?;
        let mut control = claim_worker_control(value)?;
        handler()?;
        io::stdout().lock().flush().map_err(|error| io_error("flush response", error))?;
        io::stderr().lock().flush().map_err(|error| io_error("flush diagnostics", error))?;
        // SAFETY: flush native C stdio before releasing its original pipe endpoints.
        if unsafe { libc::fflush(std::ptr::null_mut()) } != 0 {
            return Err(io_error("flush native stdio", io::Error::last_os_error()));
        }
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|error| io_error("open null output", error))?;
        if null.as_raw_fd() < 3 {
            return Err(WorkerError::Protocol("worker standard descriptors were not retained".to_owned()));
        }
        for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            // SAFETY: dup2 atomically replaces an owned standard endpoint; 1/2 are never left closed and reused.
            if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
                return Err(io_error("release worker output pipe", io::Error::last_os_error()));
            }
        }
        control.write_all(CONTROL_DONE).map_err(|error| io_error("write control completion", error))?;
        let mut byte = [0];
        loop {
            match control.read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(WorkerError::Protocol("unexpected private control command".to_owned())),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error("wait for supervisor release", error)),
            }
        }
    }

    #[cfg(test)]
    pub(super) fn closed_control_fixture(response: &WorkerResponse) -> String {
        control_fixture(response, true, "", "eval \"exec $control_fd>&-\"\nexec >/dev/null 2>&1\nexec /bin/sleep 10")
    }

    #[cfg(test)]
    pub(super) fn pipe_holder_control_fixture(response: &WorkerResponse) -> String {
        control_fixture(response, true, "/bin/sleep 10 </dev/null &", "exec >/dev/null 2>&1\nexec /bin/sleep 10")
    }

    #[cfg(test)]
    pub(super) fn failed_control_fixture(response: &WorkerResponse, crash: bool) -> String {
        control_fixture(response, false, "", if crash { "kill -SEGV $$" } else { "exit 42" })
    }

    #[cfg(test)]
    fn control_fixture(response: &WorkerResponse, read_request: bool, setup: &str, finish: &str) -> String {
        control_bytes_fixture(&serde_json::to_vec(response).unwrap(), read_request, setup, finish)
    }

    #[cfg(test)]
    pub(super) fn binary_control_fixture(response: &[u8]) -> String {
        control_bytes_fixture(response, true, "", "exec >/dev/null 2>&1\nexec /bin/sleep 10")
    }

    #[cfg(test)]
    fn control_bytes_fixture(response: &[u8], read_request: bool, setup: &str, finish: &str) -> String {
        let payload: String = response.iter().map(|byte| format!("\\{byte:03o}")).collect();
        let frame = std::str::from_utf8(&CONTROL_DONE[..CONTROL_DONE.len() - 1]).unwrap();
        let input = if read_request { "/bin/cat >/dev/null" } else { "" };
        // Test-only Bash handles arbitrary inherited descriptor numbers. Live fixtures have a finite fallback;
        // exit/crash fixtures deliberately do not consume a large request, preventing early authorized stop.
        let script = format!(
            "set +m\n\
             control_fd=\"${{{CONTROL_ENV}#1:}}\"\n\
             eval \"/bin/dd bs=1 count={} <&$control_fd >/dev/null 2>&1\"\n\
             {input}\n\
             {setup}\n\
             printf '{payload}'\n\
             eval \"printf '{frame}\\\\000' >&$control_fd\"\n\
             {finish}\n",
            CONTROL_HELLO.len(),
        );
        format!("exec /bin/bash -c '{}'", script.replace('\'', "'\\''"))
    }

    #[cfg(target_os = "macos")]
    type Rlim = u64;
    #[cfg(target_os = "linux")]
    type Rlim = c_ulong;

    #[repr(C)]
    struct Rlimit {
        current: Rlim,
        maximum: Rlim,
    }

    unsafe extern "C" {
        fn setrlimit(resource: c_int, limit: *const Rlimit) -> c_int;
        fn kill(pid: c_int, signal: c_int) -> c_int;
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    }

    #[cfg(all(target_os = "linux", not(any(target_arch = "mips", target_arch = "mips64"))))]
    const RLIMIT_AS: c_int = 9;
    #[cfg(all(target_os = "linux", any(target_arch = "mips", target_arch = "mips64")))]
    const RLIMIT_AS: c_int = 6;
    #[cfg(target_os = "linux")]
    const RLIMIT_DATA: c_int = 2;
    const RLIMIT_CORE: c_int = 4;
    #[cfg(target_os = "macos")]
    const O_NONBLOCK: c_int = 4;
    #[cfg(all(target_os = "linux", any(target_arch = "sparc", target_arch = "sparc64")))]
    const O_NONBLOCK: c_int = 0x4000;
    #[cfg(all(target_os = "linux", any(target_arch = "mips", target_arch = "mips64")))]
    const O_NONBLOCK: c_int = 128;
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "sparc", target_arch = "sparc64", target_arch = "mips", target_arch = "mips64"))
    ))]
    const O_NONBLOCK: c_int = 2048;

    fn limit_memory(_bytes: Rlim) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        for resource in [RLIMIT_AS, RLIMIT_DATA] {
            let limit = Rlimit { current: _bytes, maximum: _bytes };
            // SAFETY: POD rlimit matches the host ABI; setrlimit is async-signal-safe in this pre-exec callback.
            if unsafe { setrlimit(resource, &limit) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let no_core = Rlimit { current: 0, maximum: 0 };
        // SAFETY: valid POD limit; core dumps must not escape the worker's output/memory bounds.
        if unsafe { setrlimit(RLIMIT_CORE, &no_core) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[repr(C)]
    #[derive(Default)]
    struct ProcTaskInfo {
        virtual_size: u64,
        resident_size: u64,
        total_user: u64,
        total_system: u64,
        threads_user: u64,
        threads_system: u64,
        counters: [i32; 12],
    }

    #[cfg(target_os = "macos")]
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buffer: *mut std::ffi::c_void, size: c_int) -> c_int;
    }

    #[cfg(target_os = "macos")]
    fn resident_memory(pid: u32) -> io::Result<Option<u64>> {
        let mut info = ProcTaskInfo::default();
        let size = std::mem::size_of::<ProcTaskInfo>() as c_int;
        // SAFETY: proc_taskinfo's layout and PROC_PIDTASKINFO (4) match the Darwin SDK; buffer is writable.
        let count = unsafe { proc_pidinfo(pid as c_int, 4, 0, (&mut info as *mut ProcTaskInfo).cast(), size) };
        if count != size {
            let error = io::Error::last_os_error();
            // An exiting process can disappear from proc_pidinfo before waitpid reports its exit.
            if error.raw_os_error() == Some(3) {
                return Ok(None);
            }
            return Err(error);
        }
        Ok(Some(info.resident_size))
    }

    #[cfg(target_os = "macos")]
    fn check_memory(pid: u32, limit: u64, measurement: &Measurement) -> Result<(), WorkerError> {
        let sample = resident_memory(pid);
        measurement.rss(&sample);
        if sample.map_err(|error| io_error("inspect memory", error))?.is_some_and(|bytes| bytes > limit) {
            return Err(WorkerError::MemoryLimit { limit });
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn resident_memory(pid: u32) -> io::Result<Option<u64>> {
        let file = match std::fs::File::open(format!("/proc/{pid}/status")) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 16 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "proc status exceeds observation bound"));
        }
        parse_linux_rss(&bytes)
    }

    #[cfg(any(target_os = "linux", test))]
    fn parse_linux_rss(bytes: &[u8]) -> io::Result<Option<u64>> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid proc resident-memory field");
        let mut rss = None;
        for line in bytes.split(|byte| *byte == b'\n') {
            let Some(value) = line.strip_prefix(b"VmRSS:") else { continue };
            if rss.is_some() {
                return Err(invalid());
            }
            let value = std::str::from_utf8(value).map_err(|_| invalid())?;
            let mut fields = value.split_ascii_whitespace();
            let bytes = fields
                .next()
                .ok_or_else(invalid)?
                .parse::<u64>()
                .map_err(|_| invalid())?
                .checked_mul(1024)
                .ok_or_else(invalid)?;
            if fields.next() != Some("kB") || fields.next().is_some() {
                return Err(invalid());
            }
            rss = Some(bytes);
        }
        Ok(rss)
    }

    fn nonblocking(fd: RawFd) -> Result<(), WorkerError> {
        // SAFETY: the caller keeps the pipe open; these fcntl commands query/update its status flags.
        let flags = unsafe { fcntl(fd, 3) };
        if flags < 0 || unsafe { fcntl(fd, 4, flags | O_NONBLOCK) } < 0 {
            return Err(io_error("configure pipe", io::Error::last_os_error()));
        }
        Ok(())
    }

    struct ProcessGuard<'a> {
        child: Child,
        stop: Arc<AtomicBool>,
        terminated: bool,
        cleanup_complete: bool,
        status: Option<ExitStatus>,
        stopped_live_root: bool,
        measurement: Option<&'a Measurement>,
    }

    fn require_default_child_reaping() -> io::Result<()> {
        // SAFETY: a null new action only reads the process disposition into a correctly sized host structure.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err(io::Error::other("worker supervision requires default SIGCHLD handling without SA_NOCLDWAIT"));
        }
        Ok(())
    }

    fn observe_child(pid: u32, budget: Option<SupervisorBudget<'_>>) -> Result<bool, WorkerError> {
        observe_child_with(pid, budget, probe_child)
    }

    fn probe_child(pid: u32) -> io::Result<bool> {
        // SAFETY: the host siginfo_t is writable; WNOWAIT leaves an exited direct child unreaped.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
        };
        if result == 0 {
            // SAFETY: successful waitid initialized siginfo; zero si_pid denotes a still-running child.
            Ok(unsafe { info.si_pid() } != 0)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn observe_child_with(
        pid: u32,
        budget: Option<SupervisorBudget<'_>>,
        mut probe: impl FnMut(u32) -> io::Result<bool>,
    ) -> Result<bool, WorkerError> {
        for _ in 0..8 {
            if let Some(budget) = budget {
                budget.check()?;
            }
            require_default_child_reaping().map_err(|error| io_error("inspect SIGCHLD", error))?;
            match probe(pid) {
                Ok(exited) => return Ok(exited),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error("observe owned child", error)),
            }
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        Err(io_error("observe owned child", io::ErrorKind::Interrupted.into()))
    }

    fn signal_process(pid: c_int, signal: c_int) -> io::Result<()> {
        // SAFETY: the caller has just revalidated its unreaped direct child before signaling its PID/group.
        if unsafe { kill(pid, signal) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    impl ProcessGuard<'_> {
        fn note_observation(&self, result: &Result<bool, WorkerError>) {
            if let Some(measurement) = self.measurement {
                measurement.record(|data, elapsed| match result {
                    Ok(true) => {
                        data.exit_observed_us.get_or_insert(elapsed);
                    }
                    Err(error) if !matches!(error, WorkerError::Timeout | WorkerError::Cancelled) => {
                        data.ownership = SupervisedOwnership::Unverified;
                    }
                    _ => {}
                });
            }
        }

        fn observe(&mut self, budget: SupervisorBudget<'_>) -> Result<bool, WorkerError> {
            let result = observe_child(self.child.id(), Some(budget));
            self.note_observation(&result);
            if let Err(error) = &result
                && !matches!(error, WorkerError::Timeout | WorkerError::Cancelled)
            {
                self.terminated = true;
                self.stop.store(true, Ordering::Release);
            }
            result
        }

        fn terminate(&mut self) -> Result<Option<ExitStatus>, WorkerError> {
            self.terminate_with(signal_process)
        }

        fn terminate_with(
            &mut self,
            signal: impl FnMut(c_int, c_int) -> io::Result<()>,
        ) -> Result<Option<ExitStatus>, WorkerError> {
            self.terminate_using(|pid| observe_child(pid, None), signal)
        }

        fn terminate_using(
            &mut self,
            observe: impl FnMut(u32) -> Result<bool, WorkerError>,
            signal: impl FnMut(c_int, c_int) -> io::Result<()>,
        ) -> Result<Option<ExitStatus>, WorkerError> {
            self.terminate_with_budget(observe, signal, None)
        }

        fn terminate_completed(&mut self, budget: SupervisorBudget<'_>) -> Result<Option<ExitStatus>, WorkerError> {
            self.terminate_with_budget(|pid| observe_child(pid, None), signal_process, Some(budget))
        }

        fn terminate_with_budget(
            &mut self,
            mut observe: impl FnMut(u32) -> Result<bool, WorkerError>,
            mut signal: impl FnMut(c_int, c_int) -> io::Result<()>,
            completion_budget: Option<SupervisorBudget<'_>>,
        ) -> Result<Option<ExitStatus>, WorkerError> {
            if self.terminated {
                return if self.cleanup_complete {
                    Ok(self.status)
                } else {
                    Err(io_error(
                        "cleanup",
                        io::Error::other("previous cleanup did not complete; signaling is disabled"),
                    ))
                };
            }
            // Disarm even on an unknown ownership/probe failure: Drop must never retry numeric signaling.
            self.terminated = true;
            if completion_budget.is_none() {
                self.stop.store(true, Ordering::Release);
            }
            if let Some(measurement) = self.measurement {
                measurement.record(|data, elapsed| data.cleanup_started_us = Some(elapsed));
            }
            let result = self.cleanup_using(&mut observe, &mut signal, completion_budget);
            if let Some(measurement) = self.measurement {
                measurement.record(|data, elapsed| {
                    data.cleanup_finished_us = Some(elapsed);
                    data.cleanup_succeeded = Some(result.is_ok());
                    data.cleanup_error = result.as_ref().err().map(SupervisedCleanupError::from);
                });
            }
            result
        }

        fn cleanup_using(
            &mut self,
            observe: &mut impl FnMut(u32) -> Result<bool, WorkerError>,
            signal: &mut impl FnMut(c_int, c_int) -> io::Result<()>,
            completion_budget: Option<SupervisorBudget<'_>>,
        ) -> Result<Option<ExitStatus>, WorkerError> {
            let pid = self.child.id();
            // A std Child alone is not proof: ECHILD or an unsafe disposition forbids either signal.
            let observed = observe(pid);
            self.note_observation(&observed);
            let was_exited = observed?;
            let group_result = signal(-(pid as c_int), libc::SIGKILL);
            if !was_exited && group_result.is_ok() {
                self.stopped_live_root = true;
                if let Some(budget) = completion_budget {
                    // A completed worker is waiting on control, not further request work. Observe the accepted
                    // group stop before considering a redundant direct signal that can race zombie permission
                    // checks on Darwin. This uses the existing deadline, not a new performance/grace threshold.
                    loop {
                        let observed = observe(pid);
                        self.note_observation(&observed);
                        if observed? || budget.check().is_err() {
                            break;
                        }
                        let remaining = budget.timeout.saturating_sub(budget.started.elapsed()).min(POLL_INTERVAL);
                        thread::park_timeout(remaining);
                    }
                }
            }
            let group_error = group_result.err().filter(|error| error.raw_os_error() != Some(libc::ESRCH));
            let root_result = (|| {
                // Group failure does not revoke direct-child authority; independently check it again.
                let mut direct_error = None;
                let observed = observe(pid);
                self.note_observation(&observed);
                if !observed? {
                    match signal(pid as c_int, libc::SIGKILL) {
                        Ok(()) => self.stopped_live_root = true,
                        Err(error) => {
                            let observed = observe(pid);
                            self.note_observation(&observed);
                            if !observed? {
                                return Err(io_error("terminate owned child", error));
                            }
                            if error.raw_os_error() != Some(libc::ESRCH) {
                                direct_error = Some(error);
                            }
                        }
                    }
                }
                // An already-exited root needs no direct signal, including on hosts denying zombie signals.
                // Reap only after the group attempt, keeping its identity anchored throughout signaling.
                let status = self.child.wait().map_err(|error| {
                    if let Some(measurement) = self.measurement {
                        measurement.record(|data, _| data.ownership = SupervisedOwnership::Unverified);
                    }
                    io_error("reap owned child", error)
                })?;
                self.status = Some(status);
                if let Some(measurement) = self.measurement {
                    measurement.record(|data, elapsed| {
                        data.root_reaped_us = Some(elapsed);
                        data.exit_observed_us.get_or_insert(elapsed);
                        data.root_exit_status = Some(SupervisedExitStatus {
                            success: status.success(),
                            code: status.code(),
                            signal: status.signal(),
                        });
                        data.ownership = SupervisedOwnership::Reaped;
                    });
                }
                match direct_error {
                    Some(error) => Err(io_error("terminate owned child", error)),
                    None => Ok(self.status),
                }
            })();
            match group_error {
                Some(group) => Err(WorkerError::Cleanup { group, root: root_result.err().map(Box::new) }),
                None => {
                    self.cleanup_complete = root_result.is_ok();
                    root_result
                }
            }
        }
    }

    impl Drop for ProcessGuard<'_> {
        fn drop(&mut self) {
            // Controlled cleanup leaves readers draining to real EOF. Abort/timeout must still release the
            // scoped nonblocking threads, including when the root has already been reaped.
            self.stop.store(true, Ordering::Release);
            let _ = self.terminate();
        }
    }

    enum PipeResult {
        Input(Result<bool, WorkerError>),
        Stdout(Result<PipeRead, WorkerError>),
        Stderr(Result<PipeRead, WorkerError>),
    }

    struct PipeRead {
        bytes: Vec<u8>,
        eof: bool,
    }

    fn read_pipe(
        mut pipe: impl Read,
        limit: usize,
        stream: &'static str,
        stop: &AtomicBool,
        measurement: &Measurement,
    ) -> Result<PipeRead, WorkerError> {
        let mut observation = measurement
            .enabled()
            .then(|| SupervisedStreamMetrics { started_us: Some(measurement.elapsed_us()), ..Default::default() });
        let result = (|| {
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) => {
                        if let Some(observation) = &mut observation {
                            observation.eof_us = Some(measurement.elapsed_us());
                            observation.outcome = Some(SupervisedStreamOutcome::Eof);
                        }
                        return Ok(PipeRead { bytes, eof: true });
                    }
                    Ok(count) => {
                        if let Some(observation) = &mut observation {
                            observation.first_byte_us.get_or_insert_with(|| measurement.elapsed_us());
                            observation.read_bytes = observation.read_bytes.saturating_add(count as u64);
                        }
                        if count > limit.saturating_sub(bytes.len()) {
                            if let Some(observation) = &mut observation {
                                observation.outcome = Some(SupervisedStreamOutcome::OutputLimit);
                            }
                            return Err(WorkerError::OutputTooLarge { stream, limit });
                        }
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::Acquire) {
                            if let Some(observation) = &mut observation {
                                observation.outcome = Some(SupervisedStreamOutcome::Stopped);
                            }
                            return Ok(PipeRead { bytes, eof: false });
                        }
                        thread::park_timeout(POLL_INTERVAL);
                    }
                    Err(error) => return Err(io_error("read pipe", error)),
                }
            }
        })();
        if let Some(mut observation) = observation {
            observation.finished_us = Some(measurement.elapsed_us());
            observation.outcome.get_or_insert(SupervisedStreamOutcome::ReadError);
            measurement.record(|data, _| match stream {
                "stdout" => data.stdout = observation,
                _ => data.stderr = observation,
            });
        }
        result
    }

    fn write_pipe(
        mut pipe: impl Write,
        bytes: &[u8],
        stop: &AtomicBool,
        measurement: &Measurement,
    ) -> Result<bool, WorkerError> {
        let mut observation = measurement.enabled().then(|| SupervisedInputMetrics {
            requested_bytes: Some(bytes.len() as u64),
            started_us: Some(measurement.elapsed_us()),
            ..Default::default()
        });
        let result = (|| {
            let mut remaining = bytes;
            while !remaining.is_empty() {
                if stop.load(Ordering::Acquire) {
                    if let Some(observation) = &mut observation {
                        observation.outcome = Some(SupervisedInputOutcome::Stopped);
                    }
                    return Ok(false);
                }
                match pipe.write(remaining) {
                    Ok(0) => return Err(io_error("write request", io::ErrorKind::WriteZero.into())),
                    Ok(count) => {
                        if let Some(observation) = &mut observation {
                            observation.first_write_us.get_or_insert_with(|| measurement.elapsed_us());
                            observation.written_bytes = observation.written_bytes.saturating_add(count as u64);
                        }
                        remaining = &remaining[count..];
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::park_timeout(POLL_INTERVAL),
                    // Preserve existing success/error precedence, but never label this full delivery.
                    Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                        if let Some(observation) = &mut observation {
                            observation.outcome = Some(SupervisedInputOutcome::BrokenPipe);
                        }
                        return Ok(false);
                    }
                    Err(error) => return Err(io_error("write request", error)),
                }
            }
            if let Some(observation) = &mut observation {
                observation.outcome = Some(SupervisedInputOutcome::FullyDelivered);
            }
            Ok(true)
        })();
        if let Some(mut observation) = observation {
            observation.finished_us = Some(measurement.elapsed_us());
            observation.outcome.get_or_insert(SupervisedInputOutcome::WriteError);
            measurement.record(|data, _| data.input = observation);
        }
        result
    }

    pub(super) fn supervised_process(
        executable: &Path,
        bytes: Vec<u8>,
        config: &WorkerConfig,
        cancellation: Option<&AtomicBool>,
        started: Instant,
        measurement: &Measurement,
    ) -> Result<ProcessOutput, WorkerError> {
        let memory_limit = config.memory_limit_bytes;
        if memory_limit == 0 {
            return Err(io_error("spawn", io::Error::other("worker memory limit must be nonzero")));
        }
        let (mut control, child_control) = HostControl::pair()?;
        let control_fd = child_control.as_raw_fd();
        let mut command = Command::new(executable);
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
        command.env(CONTROL_ENV, format!("1:{control_fd}"));
        // SAFETY: only signal-safe setrlimit/fcntl operations run here; the parent's fd flags stay unchanged.
        unsafe {
            command.pre_exec(move || {
                limit_memory(memory_limit)?;
                inherit_control(control_fd)
            })
        };
        require_default_child_reaping().map_err(|error| io_error("inspect SIGCHLD", error))?;
        measurement.record(|data, elapsed| data.spawn_started_us = Some(elapsed));
        let child = command.spawn().map_err(|error| io_error("spawn", error))?;
        drop(child_control);
        measurement.record(|data, elapsed| {
            data.spawn_complete_us = Some(elapsed);
            data.ownership = SupervisedOwnership::Unreaped;
            data.rss.nominal_poll_interval_us = Some(POLL_INTERVAL.as_micros() as u64);
        });
        let stop = Arc::new(AtomicBool::new(false));
        thread::scope(|scope| {
            // The guard must drop inside the scope, before scope waits for the nonblocking I/O threads.
            let mut process = ProcessGuard {
                child,
                stop: stop.clone(),
                terminated: false,
                cleanup_complete: false,
                status: None,
                stopped_live_root: false,
                measurement: measurement.enabled().then_some(measurement),
            };
            let stdin = process.child.stdin.take().ok_or_else(|| WorkerError::Protocol("missing stdin".to_owned()))?;
            let stdout =
                process.child.stdout.take().ok_or_else(|| WorkerError::Protocol("missing stdout".to_owned()))?;
            let stderr =
                process.child.stderr.take().ok_or_else(|| WorkerError::Protocol("missing stderr".to_owned()))?;
            nonblocking(stdin.as_raw_fd())?;
            nonblocking(stdout.as_raw_fd())?;
            nonblocking(stderr.as_raw_fd())?;
            measurement.record(|data, elapsed| data.pipe_setup_complete_us = Some(elapsed));
            let (sender, receiver) = mpsc::channel();
            let input_sender = sender.clone();
            let input_stop = stop.clone();
            thread::Builder::new()
                .name("decompiler-worker-stdin".to_owned())
                .spawn_scoped(scope, move || {
                    let result = write_pipe(stdin, &bytes, &input_stop, measurement);
                    let _ = input_sender.send(PipeResult::Input(result));
                })
                .map_err(|error| io_error("spawn stdin thread", error))?;
            let output_sender = sender.clone();
            let output_stop = stop.clone();
            let stdout_limit = config.max_stdout_bytes.min(MAX_STDOUT_BYTES);
            thread::Builder::new()
                .name("decompiler-worker-stdout".to_owned())
                .spawn_scoped(scope, move || {
                    let result = read_pipe(stdout, stdout_limit, "stdout", &output_stop, measurement);
                    let _ = output_sender.send(PipeResult::Stdout(result));
                })
                .map_err(|error| io_error("spawn stdout thread", error))?;
            let error_stop = stop.clone();
            let stderr_limit = config.max_stderr_bytes.min(MAX_STDERR_BYTES);
            thread::Builder::new()
                .name("decompiler-worker-stderr".to_owned())
                .spawn_scoped(scope, move || {
                    let result = read_pipe(stderr, stderr_limit, "stderr", &error_stop, measurement);
                    let _ = sender.send(PipeResult::Stderr(result));
                })
                .map_err(|error| io_error("spawn stderr thread", error))?;
            let mut stdout: Option<PipeRead> = None;
            let mut stderr: Option<PipeRead> = None;
            let mut status = None;
            let mut input_finished = false;
            let mut input_fully_delivered = false;
            let mut controlled_stop = false;
            let mut cleanup_error = None;
            let mut control_error = None;
            loop {
                if cancelled(cancellation) {
                    return Err(WorkerError::Cancelled);
                }
                if started.elapsed() >= config.timeout {
                    return Err(WorkerError::Timeout);
                }
                if status.is_none() {
                    if control_error.is_none() {
                        control_error = control.poll(measurement).err();
                    }
                    let budget = SupervisorBudget { started, timeout: config.timeout, cancellation };
                    let exited = process.observe(budget)?;
                    #[cfg(target_os = "macos")]
                    let exited = {
                        let mut exited = exited;
                        if !exited && let Err(error) = check_memory(process.child.id(), memory_limit, measurement) {
                            // An exit between observation and proc_pidinfo is not a monitoring failure.
                            exited = process.observe(budget)?;
                            if !exited {
                                return Err(error);
                            }
                        }
                        exited
                    };
                    #[cfg(target_os = "linux")]
                    if !exited && measurement.enabled() {
                        // Only the just-observed, directly owned unreaped root is read; sampled IDs grant no authority.
                        measurement.rss(&resident_memory(process.child.id()));
                    }
                    if !exited && input_finished && input_fully_delivered && control_error.is_none() {
                        // Pipe holders may be descendants awaiting our group stop. Revalidate control, then
                        // stop the authenticated live group before waiting for their real output EOF.
                        control_error = control.poll(measurement).err();
                    }
                    let completed_live = !exited
                        && control_error.is_none()
                        && control.authorized()
                        && input_finished
                        && input_fully_delivered;
                    if exited || completed_live || control_error.is_some() {
                        // Retain control failure until the real status is known: an actual failed exit/crash
                        // outranks that transport error, but killing a still-live invalid peer does not.
                        let cleanup =
                            if completed_live { process.terminate_completed(budget) } else { process.terminate() };
                        match cleanup {
                            Ok(value) => status = value,
                            Err(error) => {
                                status = process.status;
                                if status.is_none() {
                                    return Err(error);
                                }
                                cleanup_error = Some(error);
                            }
                        }
                        controlled_stop = completed_live
                            && process.stopped_live_root
                            && status.is_some_and(|value| value.signal() == Some(libc::SIGKILL));
                        measurement.record(|data, _| data.intentional_stop = controlled_stop);
                    }
                }
                if input_finished && let (Some(stdout), Some(stderr), Some(status)) = (&mut stdout, &mut stderr, status)
                {
                    return Ok(ProcessOutput {
                        stdout: std::mem::take(&mut stdout.bytes),
                        stderr: std::mem::take(&mut stderr.bytes),
                        status,
                        controlled_stop,
                        host_stopped_root: process.stopped_live_root,
                        input_fully_delivered,
                        outputs_eof: stdout.eof && stderr.eof,
                        control_error,
                        cleanup_error,
                    });
                }
                let remaining = config.timeout.saturating_sub(started.elapsed()).min(POLL_INTERVAL);
                match receiver.recv_timeout(remaining) {
                    Ok(PipeResult::Input(result)) => {
                        input_fully_delivered = result?;
                        input_finished = true;
                    }
                    Ok(PipeResult::Stdout(result)) => stdout = Some(result?),
                    Ok(PipeResult::Stderr(result)) => stderr = Some(result?),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        if !input_finished || stdout.is_none() || stderr.is_none() {
                            return Err(WorkerError::Protocol("worker pipe thread terminated".to_owned()));
                        }
                        thread::park_timeout(remaining);
                    }
                }
            }
        })
    }

    #[cfg(test)]
    mod measurement_tests {
        use super::*;

        struct PartialBrokenWriter(bool);

        impl Write for PartialBrokenWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0 {
                    Err(io::ErrorKind::BrokenPipe.into())
                } else {
                    self.0 = true;
                    Ok(bytes.len().min(2))
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct BlockedReader;

        impl Read for BlockedReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }

        #[test]
        fn partial_broken_and_stopped_writers_never_claim_full_delivery() {
            let measurement = Measurement::new(Instant::now(), true);
            assert!(!write_pipe(PartialBrokenWriter(false), b"abcd", &AtomicBool::new(false), &measurement).unwrap());
            let metrics = measurement.finish().unwrap();
            assert_eq!(metrics.input.written_bytes, 2);
            assert_eq!(metrics.input.requested_bytes, Some(4));
            assert_eq!(metrics.input.outcome, Some(SupervisedInputOutcome::BrokenPipe));
            assert!(metrics.input.first_write_us.is_some());

            let measurement = Measurement::new(Instant::now(), true);
            assert!(!write_pipe(Vec::new(), b"abcd", &AtomicBool::new(true), &measurement).unwrap());
            let metrics = measurement.finish().unwrap();
            assert_eq!(metrics.input.written_bytes, 0);
            assert_eq!(metrics.input.outcome, Some(SupervisedInputOutcome::Stopped));
            assert!(metrics.input.first_write_us.is_none());
        }

        #[test]
        fn full_writes_eof_and_output_limits_record_actual_pipe_observations() {
            let measurement = Measurement::new(Instant::now(), true);
            let stop = AtomicBool::new(false);
            assert!(write_pipe(Vec::new(), b"abcd", &stop, &measurement).unwrap());
            let output = read_pipe(&b"abc"[..], 8, "stdout", &stop, &measurement).unwrap();
            assert_eq!(output.bytes, b"abc");
            assert!(output.eof);
            assert!(matches!(
                read_pipe(&b"toolong"[..], 2, "stderr", &stop, &measurement),
                Err(WorkerError::OutputTooLarge { stream: "stderr", .. })
            ));
            let metrics = measurement.finish().unwrap();
            assert_eq!(metrics.input.outcome, Some(SupervisedInputOutcome::FullyDelivered));
            assert_eq!(metrics.input.written_bytes, metrics.input.requested_bytes.unwrap());
            assert_eq!(metrics.stdout.read_bytes, 3);
            assert!(metrics.stdout.first_byte_us.is_some());
            assert!(metrics.stdout.first_byte_us <= metrics.stdout.eof_us);
            assert!(metrics.stdout.eof_us.is_some());
            assert_eq!(metrics.stdout.outcome, Some(SupervisedStreamOutcome::Eof));
            assert_eq!(metrics.stderr.read_bytes, 7);
            assert_eq!(metrics.stderr.outcome, Some(SupervisedStreamOutcome::OutputLimit));
            assert!(metrics.stderr.eof_us.is_none());
        }

        #[test]
        fn stopped_readers_do_not_invent_eof_or_first_byte_timestamps() {
            let measurement = Measurement::new(Instant::now(), true);
            let output = read_pipe(BlockedReader, 8, "stdout", &AtomicBool::new(true), &measurement).unwrap();
            assert!(output.bytes.is_empty());
            assert!(!output.eof);
            let metrics = measurement.finish().unwrap();
            assert_eq!(metrics.stdout.outcome, Some(SupervisedStreamOutcome::Stopped));
            assert_eq!(metrics.stdout.read_bytes, 0);
            assert!(metrics.stdout.first_byte_us.is_none());
            assert!(metrics.stdout.eof_us.is_none());
        }

        #[test]
        fn proc_rss_units_missing_fields_duplicates_and_overflow_are_checked() {
            assert_eq!(parse_linux_rss(b"Name:\towned\nVmRSS:\t12 kB\n").unwrap(), Some(12 * 1024));
            assert_eq!(parse_linux_rss(b"Name:\tzombie\n").unwrap(), None);
            assert_eq!(parse_linux_rss(b"VmRSS: 0 kB\n").unwrap(), Some(0));
            for value in [
                &b"VmRSS: 12 MB\n"[..],
                &b"VmRSS: -1 kB\n"[..],
                &b"VmRSS: 18446744073709551615 kB\n"[..],
                &b"VmRSS: 2 kB\nVmRSS: 3 kB\n"[..],
                &b"VmRSS: 1 kB unexpected\n"[..],
            ] {
                assert_eq!(parse_linux_rss(value).unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
        }

        #[test]
        fn reaped_root_and_failed_group_cleanup_remain_separate_in_metrics() {
            let measurement = Measurement::new(Instant::now(), true);
            require_default_child_reaping().unwrap();
            let child = Command::new("/bin/sh")
                .args(["-c", "exit 23"])
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut process = ProcessGuard {
                child,
                stop: Arc::new(AtomicBool::new(false)),
                terminated: false,
                cleanup_complete: false,
                status: None,
                stopped_live_root: false,
                measurement: Some(&measurement),
            };
            let budget =
                SupervisorBudget { started: Instant::now(), timeout: Duration::from_secs(5), cancellation: None };
            while !process.observe(budget).unwrap() {
                thread::park_timeout(POLL_INTERVAL);
            }
            let pid = process.child.id();
            let error = process
                .terminate_with(|target, _| {
                    assert_eq!(target, -(pid as c_int));
                    Err(io::Error::from_raw_os_error(libc::EPERM))
                })
                .unwrap_err();
            assert!(matches!(error, WorkerError::Cleanup { root: None, .. }));
            drop(process);
            let metrics = measurement.finish().unwrap();
            assert_eq!(metrics.root_exit_status.unwrap().code, Some(23));
            assert_eq!(metrics.ownership, SupervisedOwnership::Reaped);
            assert_eq!(metrics.cleanup_succeeded, Some(false));
            assert!(metrics.cleanup_finished_us.is_some());
            assert!(metrics.root_reaped_us.is_some());
        }

        #[test]
        fn completed_cleanup_keeps_readers_draining_and_drop_still_aborts_them() {
            require_default_child_reaping().unwrap();
            let child = Command::new("/bin/sh").args(["-c", "exit 0"]).process_group(0).spawn().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let mut process = ProcessGuard {
                child,
                stop: stop.clone(),
                terminated: false,
                cleanup_complete: false,
                status: None,
                stopped_live_root: false,
                measurement: None,
            };
            let budget =
                SupervisorBudget { started: Instant::now(), timeout: Duration::from_secs(5), cancellation: None };
            while !process.observe(budget).unwrap() {
                thread::park_timeout(POLL_INTERVAL);
            }
            assert!(
                process
                    .terminate_with_budget(|pid| observe_child(pid, None), |_, _| Ok(()), Some(budget))
                    .unwrap()
                    .unwrap()
                    .success()
            );
            assert!(!stop.load(Ordering::Acquire), "group cleanup must not fabricate stopped-reader EOF");
            drop(process);
            assert!(stop.load(Ordering::Acquire), "abort must release readers even after root reap");
        }
    }

    #[cfg(test)]
    mod control_tests {
        use super::*;

        #[test]
        fn invalid_capabilities_leave_ambient_files_and_socket_data_untouched() {
            let file = std::fs::File::open("/dev/null").unwrap();
            assert!(claim_worker_control(&format!("1:{}", file.as_raw_fd())).is_err());
            file.metadata().unwrap();
            for value in ["1:0", "1:1", "1:2", "2:3", "1:-1", "1:+3"] {
                assert!(claim_worker_control(value).is_err());
            }
            let (mut host, mut child) = UnixStream::pair().unwrap();
            let data = b"not-a-worker-control-handshake";
            host.write_all(data).unwrap();
            assert!(claim_worker_control(&format!("1:{}", child.as_raw_fd())).is_err());
            let mut retained = vec![0; data.len()];
            child.read_exact(&mut retained).unwrap();
            assert_eq!(retained, data);
        }

        #[test]
        fn handshake_validation_is_non_consuming_and_completion_is_not_a_root_exit() {
            let measurement = Measurement::new(Instant::now(), true);
            let (mut host, mut child) = HostControl::pair().unwrap();
            let value = format!("1:{}", child.as_raw_fd());
            let duplicate = validate_worker_control(&value).unwrap();
            assert_ne!(duplicate.as_raw_fd(), child.as_raw_fd());
            drop(duplicate);
            let mut hello = [0; CONTROL_HELLO.len()];
            child.read_exact(&mut hello).unwrap();
            assert_eq!(hello.as_slice(), CONTROL_HELLO);
            child.write_all(CONTROL_DONE).unwrap();
            host.poll(&measurement).unwrap();
            assert!(host.complete);
            assert!(host.authorized());
            let metrics = measurement.finish().unwrap();
            assert!(metrics.control_completion_us.is_some());
            assert!(!metrics.intentional_stop);
            assert!(metrics.root_exit_status.is_none());
        }

        #[test]
        fn claiming_and_dropping_control_owns_only_a_fresh_duplicate() {
            let (mut host, mut original) = HostControl::pair().unwrap();
            let fd = original.as_raw_fd();
            // SAFETY: these only inspect descriptors owned by this test.
            let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(descriptor_flags >= 0 && status_flags >= 0);
            let duplicate = claim_worker_control(&format!("1:{fd}")).unwrap();
            assert!(duplicate.as_raw_fd() >= 3);
            assert_ne!(duplicate.as_raw_fd(), fd);
            assert_ne!(unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
            drop(duplicate);
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, descriptor_flags);
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, status_flags);
            original.peer_addr().unwrap();
            host.socket.write_all(b"retained").unwrap();
            let mut bytes = [0; 8];
            original.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"retained");
        }

        #[test]
        fn completion_followed_by_peer_eof_revokes_authorization() {
            for poll_before_close in [false, true] {
                let measurement = Measurement::new(Instant::now(), true);
                let (mut host, mut child) = HostControl::pair().unwrap();
                let mut hello = [0; CONTROL_HELLO.len()];
                child.read_exact(&mut hello).unwrap();
                child.write_all(CONTROL_DONE).unwrap();
                if poll_before_close {
                    host.poll(&measurement).unwrap();
                    assert!(host.authorized());
                }
                drop(child);
                assert!(matches!(host.poll(&measurement), Err(WorkerError::Protocol(_))));
                assert!(host.closed);
                assert!(!host.complete);
                assert!(!host.authorized());
                host.poll(&measurement).unwrap();
                assert!(!host.authorized());
                assert!(measurement.finish().unwrap().control_completion_us.is_some());
            }
        }

        #[test]
        fn legacy_close_and_incomplete_or_unknown_private_completions_are_distinct() {
            let measurement = Measurement::new(Instant::now(), false);
            let (mut host, child) = HostControl::pair().unwrap();
            drop(child);
            host.poll(&measurement).unwrap();
            assert!(host.closed && !host.complete);
            for frame in [&b"partial"[..], &[0; CONTROL_DONE.len()][..]] {
                let (mut host, mut child) = HostControl::pair().unwrap();
                let mut hello = [0; CONTROL_HELLO.len()];
                child.read_exact(&mut hello).unwrap();
                child.write_all(frame).unwrap();
                drop(child);
                let result = host.poll(&measurement);
                if frame.len() == CONTROL_DONE.len() {
                    assert!(matches!(result, Err(WorkerError::Protocol(_))));
                } else {
                    result.unwrap();
                    assert!(matches!(host.poll(&measurement), Err(WorkerError::Protocol(_))));
                }
            }
            let (mut host, mut child) = HostControl::pair().unwrap();
            child.write_all(CONTROL_DONE).unwrap();
            child.write_all(b"extra").unwrap();
            assert!(matches!(host.poll(&measurement), Err(WorkerError::Protocol(_))));
        }
    }

    #[cfg(test)]
    mod ownership_tests {
        use std::cell::Cell;

        use super::*;

        const DISPOSITION_HELPER_SUCCESS: i32 = 73;

        fn guard(script: &str) -> ProcessGuard<'static> {
            require_default_child_reaping().unwrap();
            let child = Command::new("/bin/sh")
                .args(["-c", script])
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            ProcessGuard {
                child,
                stop: Arc::new(AtomicBool::new(false)),
                terminated: false,
                cleanup_complete: false,
                status: None,
                stopped_live_root: false,
                measurement: None,
            }
        }

        fn await_exit(process: &mut ProcessGuard<'_>) {
            let budget =
                SupervisorBudget { started: Instant::now(), timeout: Duration::from_secs(5), cancellation: None };
            while !process.observe(budget).unwrap() {
                thread::park_timeout(POLL_INTERVAL);
            }
        }

        fn assert_lost_ownership(error: WorkerError) {
            assert!(matches!(error,
                WorkerError::Io { action: "observe owned child", source }
                    if source.raw_os_error() == Some(libc::ECHILD)
            ));
        }

        #[test]
        fn exited_root_remains_waitable_through_group_cleanup_then_reaps_once() {
            let mut process = guard("exit 23");
            let pid = process.child.id();
            await_exit(&mut process);
            assert!(observe_child(pid, None).unwrap());
            assert!(observe_child(pid, None).unwrap());
            let mut targets = Vec::new();
            let status = process
                .terminate_with(|target, _| {
                    assert!(observe_child(pid, None).unwrap());
                    targets.push(target);
                    // Mock the signal boundary here; the descendant witness test exercises real group cleanup.
                    assert!(observe_child(pid, None).unwrap());
                    Ok(())
                })
                .unwrap()
                .unwrap();
            assert_eq!(targets, [-(pid as c_int)]);
            assert_eq!(status.code(), Some(23));
            assert_lost_ownership(observe_child(pid, None).unwrap_err());
            let repeated = process.terminate_with(|_, _| panic!("signaled after reaping")).unwrap().unwrap();
            assert_eq!(repeated.code(), Some(23));
        }

        #[test]
        fn group_permission_failure_still_revalidates_kills_and_reaps_a_running_root() {
            // Closing the owned stdin also lets this root exit if an injected assertion panics.
            let mut process = guard("read release");
            let pid = process.child.id();
            let probes = Cell::new(0);
            let mut targets = Vec::new();
            let error = process
                .terminate_using(
                    |pid| {
                        probes.set(probes.get() + 1);
                        observe_child(pid, None)
                    },
                    |target, signal| {
                        targets.push(target);
                        if target < 0 {
                            assert_eq!(probes.get(), 1);
                            Err(io::Error::from_raw_os_error(libc::EPERM))
                        } else {
                            assert_eq!(probes.get(), 2);
                            signal_process(target, signal)
                        }
                    },
                )
                .unwrap_err();
            assert_eq!(targets, [-(pid as c_int), pid as c_int]);
            assert!(matches!(error, WorkerError::Cleanup { group, root: None }
                if group.raw_os_error() == Some(libc::EPERM)));
            assert!(!process.status.unwrap().success());
            assert_lost_ownership(observe_child(pid, None).unwrap_err());
            process.terminate_with(|_, _| panic!("retried incomplete group cleanup after reaping")).unwrap_err();
        }

        #[test]
        fn group_permission_failure_reaps_an_exited_root_without_direct_signaling() {
            let mut process = guard("exit 23");
            let pid = process.child.id();
            await_exit(&mut process);
            let mut targets = Vec::new();
            let error = process
                .terminate_with(|target, _| {
                    targets.push(target);
                    assert_eq!(target, -(pid as c_int));
                    Err(io::Error::from_raw_os_error(libc::EPERM))
                })
                .unwrap_err();
            assert!(matches!(error, WorkerError::Cleanup { group, root: None }
                if group.raw_os_error() == Some(libc::EPERM)));
            assert_eq!(targets, [-(pid as c_int)]);
            assert_eq!(process.status.unwrap().code(), Some(23));
            assert_lost_ownership(observe_child(pid, None).unwrap_err());
            process.terminate_with(|_, _| panic!("retried group cleanup after reaping")).unwrap_err();
        }

        #[test]
        fn unknown_probe_errors_and_interruption_exhaustion_disarm_without_signaling() {
            for code in [libc::EIO, libc::EINTR] {
                let mut process = guard("exit 0");
                await_exit(&mut process);
                let mut attempts = 0;
                let error = process
                    .terminate_using(
                        |pid| {
                            observe_child_with(pid, None, |_| {
                                attempts += 1;
                                assert!(attempts <= 16, "interrupted observation did not stop retrying");
                                Err(io::Error::from_raw_os_error(code))
                            })
                        },
                        |_, _| panic!("signaled without successful observation"),
                    )
                    .unwrap_err();
                match error {
                    WorkerError::Io { action: "observe owned child", source } if code == libc::EINTR => {
                        assert_eq!(source.kind(), io::ErrorKind::Interrupted);
                        assert!(attempts > 1);
                    }
                    WorkerError::Io { action: "observe owned child", source } => {
                        assert_eq!(source.raw_os_error(), Some(code));
                        assert_eq!(attempts, 1);
                    }
                    other => panic!("unexpected observation error: {other}"),
                }
                process.terminate_with(|_, _| panic!("retried after unknown ownership")).unwrap_err();
                assert!(process.child.wait().unwrap().success());
            }
        }

        #[test]
        fn interrupted_observation_retries_and_rechecks_cancellation_before_the_next_probe() {
            let mut process = guard("exit 0");
            let pid = process.child.id();
            await_exit(&mut process);
            let mut attempts = 0;
            assert!(
                observe_child_with(pid, None, |_| {
                    attempts += 1;
                    if attempts == 1 { Err(io::ErrorKind::Interrupted.into()) } else { probe_child(pid) }
                })
                .unwrap()
            );
            assert_eq!(attempts, 2);
            let cancellation = AtomicBool::new(false);
            let budget = SupervisorBudget {
                started: Instant::now(),
                timeout: Duration::from_secs(5),
                cancellation: Some(&cancellation),
            };
            attempts = 0;
            let result = observe_child_with(pid, Some(budget), |_| {
                attempts += 1;
                cancellation.store(true, Ordering::Release);
                Err(io::ErrorKind::Interrupted.into())
            });
            assert!(matches!(result, Err(WorkerError::Cancelled)));
            assert_eq!(attempts, 1);
            assert!(matches!(
                observe_child_with(
                    pid,
                    Some(SupervisorBudget { timeout: Duration::ZERO, cancellation: None, ..budget }),
                    |_| panic!("probed after deadline"),
                ),
                Err(WorkerError::Timeout)
            ));
            assert!(process.child.wait().unwrap().success());
        }

        #[test]
        fn group_failure_and_unknown_revalidation_are_both_preserved_without_direct_signaling() {
            let mut process = guard("exit 0");
            let pid = process.child.id();
            await_exit(&mut process);
            let mut observations = 0;
            let mut signals = 0;
            let error = process
                .terminate_using(
                    |pid| {
                        observations += 1;
                        if observations == 1 {
                            observe_child(pid, None)
                        } else {
                            observe_child_with(pid, None, |_| Err(io::Error::from_raw_os_error(libc::EIO)))
                        }
                    },
                    |target, _| {
                        signals += 1;
                        assert_eq!(target, -(pid as c_int));
                        Err(io::Error::from_raw_os_error(libc::EPERM))
                    },
                )
                .unwrap_err();
            match error {
                WorkerError::Cleanup { group, root: Some(root) } => {
                    assert_eq!(group.raw_os_error(), Some(libc::EPERM));
                    assert!(matches!(*root, WorkerError::Io { action: "observe owned child", source }
                        if source.raw_os_error() == Some(libc::EIO)));
                }
                other => panic!("lost combined cleanup failure: {other}"),
            }
            assert_eq!(signals, 1);
            process.terminate_with(|_, _| panic!("retried after failed revalidation")).unwrap_err();
            assert!(process.child.wait().unwrap().success());
        }

        #[test]
        fn group_cleanup_terminates_a_handshaken_descendant_not_just_supervisor_readers() {
            require_default_child_reaping().unwrap();
            let child = Command::new("/bin/sh")
                .args(["-c", "exec 3<&0; (read release <&3) & printf '%s\\n' \"$!\"; exit 23"])
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut process = ProcessGuard {
                child,
                stop: Arc::new(AtomicBool::new(false)),
                terminated: false,
                cleanup_complete: false,
                status: None,
                stopped_live_root: false,
                measurement: None,
            };
            // Holding stdin keeps the descendant's builtin read alive; dropping it also cleans up on panic.
            let input = process.child.stdin.take().unwrap();
            let mut witness = process.child.stdout.take().unwrap();
            nonblocking(witness.as_raw_fd()).unwrap();
            let started = Instant::now();
            let mut handshake = Vec::with_capacity(16);
            loop {
                assert!(started.elapsed() < Duration::from_secs(5), "descendant handshake stalled");
                let mut byte = [0];
                match witness.read(&mut byte) {
                    Ok(1) if byte[0] == b'\n' => break,
                    Ok(1) => {
                        assert!(handshake.len() < 16);
                        handshake.push(byte[0]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::park_timeout(POLL_INTERVAL),
                    other => panic!("incomplete descendant handshake: {other:?}"),
                }
            }
            let descendant: u32 = std::str::from_utf8(&handshake).unwrap().parse().unwrap();
            assert!(descendant > 0 && descendant != process.child.id());
            await_exit(&mut process);
            let mut byte = [0];
            assert_eq!(witness.read(&mut byte).unwrap_err().kind(), io::ErrorKind::WouldBlock);
            let cleanup = process.terminate();
            let started = Instant::now();
            loop {
                assert!(started.elapsed() < Duration::from_secs(5), "descendant still holds its lifetime witness");
                match witness.read(&mut byte) {
                    Ok(0) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::park_timeout(POLL_INTERVAL),
                    other => panic!("unexpected descendant witness: {other:?}"),
                }
            }
            // This raw pipe never consults ProcessGuard.stop; EOF requires the blocked descendant to exit.
            drop(input);
            assert_eq!(cleanup.unwrap().unwrap().code(), Some(23));
        }

        #[test]
        fn externally_reaped_root_forbids_both_signals_and_drop_retry() {
            for observe_first in [false, true] {
                let mut process = guard("exit 0");
                await_exit(&mut process);
                assert!(process.child.wait().unwrap().success());
                if observe_first {
                    let budget = SupervisorBudget {
                        started: Instant::now(),
                        timeout: Duration::from_secs(5),
                        cancellation: None,
                    };
                    assert_lost_ownership(process.observe(budget).unwrap_err());
                    process.terminate_with(|_, _| panic!("signaled a reaped root")).unwrap_err();
                } else {
                    let error = process.terminate_with(|_, _| panic!("signaled a reaped root")).unwrap_err();
                    assert_lost_ownership(error);
                }
                assert!(process.terminated);
                process.terminate_with(|_, _| panic!("retried lost ownership")).unwrap_err();
            }
        }

        #[test]
        fn ownership_is_revalidated_between_group_and_direct_signal() {
            let mut process = guard("exit 0");
            let pid = process.child.id();
            await_exit(&mut process);
            let mut signals = 0;
            let error = process
                .terminate_with(|target, _| {
                    signals += 1;
                    assert_eq!(target, -(pid as c_int));
                    let mut status = 0;
                    // SAFETY: this simulates an unsupported foreign reaper for this test's exited direct child.
                    assert_eq!(unsafe { libc::waitpid(pid as c_int, &mut status, libc::WNOHANG) }, pid as c_int);
                    Ok(())
                })
                .unwrap_err();
            assert_lost_ownership(error);
            assert_eq!(signals, 1);
            process.terminate_with(|_, _| panic!("retried after foreign reaping")).unwrap_err();
        }

        #[test]
        fn unsafe_sigchld_dispositions_are_refused_in_isolated_subprocesses() {
            for case in ["ignore", "no_cldwait", "non_reaping_handler"] {
                let child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "worker::unix::ownership_tests::sigchld_disposition_subprocess",
                        "--ignored",
                        "--test-threads=1",
                    ])
                    .env("RAMPAGE_SUPERVISOR_SIGCHLD_CASE", case)
                    .process_group(0)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let mut process = ProcessGuard {
                    child,
                    stop: Arc::new(AtomicBool::new(false)),
                    terminated: false,
                    cleanup_complete: false,
                    status: None,
                    stopped_live_root: false,
                    measurement: None,
                };
                await_exit(&mut process);
                let cleanup = process.terminate();
                // This driver verifies the isolated helper, not successful cleanup of an unknown group.
                // Keep zombie-only group EPERM visible, while checking that its root was nevertheless reaped.
                match cleanup {
                    Ok(Some(_)) => {}
                    Err(WorkerError::Cleanup { group, root: None }) if group.raw_os_error() == Some(libc::EPERM) => {
                        assert!(!process.cleanup_complete);
                        eprintln!(
                            "SIGCHLD helper {case}: group cleanup EPERM retained; root status checked separately"
                        );
                    }
                    other => panic!("SIGCHLD helper cleanup failed: {other:?}"),
                }
                assert_eq!(process.status.unwrap().code(), Some(DISPOSITION_HELPER_SUCCESS), "SIGCHLD case {case}",);
            }
        }

        #[test]
        #[ignore = "isolated helper selected by unsafe_sigchld_dispositions_are_refused_in_isolated_subprocesses"]
        fn sigchld_disposition_subprocess() {
            let Ok(case) = std::env::var("RAMPAGE_SUPERVISOR_SIGCHLD_CASE") else {
                return;
            };
            struct RestoreDisposition(libc::sigaction);
            impl Drop for RestoreDisposition {
                fn drop(&mut self) {
                    // SAFETY: restore the disposition saved in this isolated test subprocess.
                    assert_eq!(unsafe { libc::sigaction(libc::SIGCHLD, &self.0, std::ptr::null_mut()) }, 0);
                }
            }
            extern "C" fn non_reaping_child_handler(_: c_int) {}

            require_default_child_reaping().unwrap();
            let mut process = guard("exit 0");
            await_exit(&mut process);
            // SAFETY: these are correctly sized host structures; only this helper process mutates SIGCHLD.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
            match case.as_str() {
                "ignore" => action.sa_sigaction = libc::SIG_IGN,
                "no_cldwait" => {
                    action.sa_sigaction = libc::SIG_DFL;
                    action.sa_flags = libc::SA_NOCLDWAIT;
                }
                "non_reaping_handler" => action.sa_sigaction = non_reaping_child_handler as *const () as usize,
                _ => panic!("unknown SIGCHLD test case"),
            }
            assert_eq!(unsafe { libc::sigaction(libc::SIGCHLD, &action, &mut previous) }, 0);
            let restore = RestoreDisposition(previous);
            let result = supervised_process(
                Path::new("/definitely-missing-rampage-worker"),
                Vec::new(),
                &WorkerConfig::default(),
                None,
                Instant::now(),
                &Measurement::new(Instant::now(), false),
            );
            assert!(matches!(result, Err(WorkerError::Io { action: "inspect SIGCHLD", .. })));
            let error = process.terminate_with(|_, _| panic!("signaled under unsafe SIGCHLD handling")).unwrap_err();
            assert!(matches!(error, WorkerError::Io { action: "inspect SIGCHLD", .. }));
            process.terminate_with(|_, _| panic!("retried after unsafe disposition")).unwrap_err();
            drop(restore);
            require_default_child_reaping().unwrap();
            // The root exited before changing disposition; reap it if the kernel has not already done so.
            let _ = process.child.wait();
            // A distinct status proves the exact helper ran, rather than a mistyped filter selecting no tests.
            std::process::exit(DISPOSITION_HELPER_SUCCESS);
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        directory: PathBuf,
        executable: PathBuf,
        pid: PathBuf,
    }

    impl Fixture {
        fn new(body: &str) -> Self {
            let index = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!("rampage-worker-{}-{index}", std::process::id()));
            fs::create_dir(&directory).expect("create isolated fixture directory");
            let executable = directory.join("worker");
            let pid = directory.join("pid");
            let fixture = Self { directory, executable, pid };
            let quoted_pid = fixture.pid.display().to_string().replace('\'', "'\\''");
            let script = format!("#!/bin/sh\nprintf '%s' \"$$\" > '{quoted_pid}'\n{body}\n");
            fs::write(&fixture.executable, script).expect("write fixture");
            fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o700))
                .expect("make fixture executable");
            fixture
        }

        fn config(&self) -> WorkerConfig {
            WorkerConfig {
                executable: Some(self.executable.clone()),
                timeout: Duration::from_secs(5),
                ..Default::default()
            }
        }

        fn assert_reaped(&self) {
            let pid: i32 = fs::read_to_string(&self.pid).expect("worker started").parse().expect("pid");
            unsafe extern "C" {
                fn kill(pid: i32, signal: i32) -> i32;
            }
            // A killed child can briefly linger in the process table after run_supervised returns, so poll rather
            // than sampling once; signal zero queries existence without sending a signal.
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                // SAFETY: querying existence of a pid we spawned via the fixture.
                if unsafe { kill(pid, 0) } == -1 {
                    return;
                }
                assert!(Instant::now() < deadline, "worker {pid} still exists");
                thread::sleep(Duration::from_millis(5));
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn request() -> WorkerRequest {
        WorkerRequest {
            version: PROTOCOL_VERSION,
            arch: "x86_64".to_owned(),
            big_endian: false,
            options: WorkerOptions::default(),
            mappings: vec![WorkerMapping {
                base: 0x1000,
                hex_bytes: "31c0c3".to_owned(),
                size: 3,
                readable: true,
                writable: false,
                executable: true,
            }],
            code_modes: Vec::new(),
            operations: Vec::new(),
            decompile: WorkerFunction { address: 0x1000, name: "fixture".to_owned(), thumb: false },
            tokens: false,
            validate_only: false,
        }
    }

    fn budget(cancellation: Option<&AtomicBool>) -> SupervisorBudget<'_> {
        SupervisorBudget { started: Instant::now(), timeout: Duration::from_secs(5), cancellation }
    }

    #[test]
    fn byte_supervision_requires_explicit_executable_and_bounds_requests_before_spawn() {
        let result = run_supervised_bytes(b"application request".to_vec(), &WorkerConfig::default(), None);
        assert!(matches!(result, Err(WorkerError::Io { action: "locate executable", source })
            if source.kind() == io::ErrorKind::InvalidInput));
        let fixture = Fixture::new("exit 0");
        let config = WorkerConfig { max_request_bytes: 2, ..fixture.config() };
        assert!(matches!(
            run_supervised_bytes(vec![0, 1, 2], &config, None),
            Err(WorkerError::RequestTooLarge { limit: 2 })
        ));
        assert!(!fixture.pid.exists());
        let config = WorkerConfig { timeout: Duration::ZERO, ..fixture.config() };
        assert!(matches!(run_supervised_bytes(Vec::new(), &config, None), Err(WorkerError::Timeout)));
        assert!(matches!(
            run_supervised_bytes(Vec::new(), &fixture.config(), Some(&AtomicBool::new(true))),
            Err(WorkerError::Cancelled)
        ));
        assert!(!fixture.pid.exists());
    }

    #[test]
    fn byte_supervision_returns_opaque_binary_empty_and_application_error_responses_without_p4_decoding() {
        for payload in
            [vec![0, 0xff, 0x80, b'\n', b'%'], Vec::new(), br#"{"application":"component","status":"error"}"#.to_vec()]
        {
            let fixture = Fixture::new(&unix::binary_control_fixture(&payload));
            let config = WorkerConfig { max_request_bytes: 3, ..fixture.config() };
            let output = run_supervised_bytes(vec![0, 0xff, 0x80], &config, None).unwrap();
            assert_eq!(output, payload);
            fixture.assert_reaped();
        }
    }

    #[test]
    fn byte_supervision_preserves_output_limits() {
        let fixture = Fixture::new(&unix::binary_control_fixture(b"application response"));
        let config = WorkerConfig { max_stdout_bytes: 1, ..fixture.config() };
        assert!(matches!(
            run_supervised_bytes(b"request".to_vec(), &config, None),
            Err(WorkerError::OutputTooLarge { stream: "stdout", limit: 1 })
        ));
        fixture.assert_reaped();
    }

    #[test]
    fn opaque_success_still_requires_full_input_real_eof_and_successful_cleanup() {
        use std::os::unix::process::ExitStatusExt;

        for failure in ["input", "eof", "cleanup"] {
            let process = ProcessOutput {
                stdout: b"application bytes, not worker JSON".to_vec(),
                stderr: Vec::new(),
                status: std::process::ExitStatus::from_raw(0),
                controlled_stop: false,
                host_stopped_root: false,
                input_fully_delivered: failure != "input",
                outputs_eof: failure != "eof",
                control_error: None,
                cleanup_error: (failure == "cleanup")
                    .then(|| WorkerError::Cleanup { group: io::Error::from_raw_os_error(libc::EPERM), root: None }),
            };
            let result = finish_bytes_process(process, budget(None), &Measurement::new(Instant::now(), false));
            if failure == "cleanup" {
                assert!(matches!(result, Err(WorkerError::Cleanup { .. })));
            } else {
                assert!(matches!(result, Err(WorkerError::Protocol(_))));
            }
        }
    }

    #[test]
    fn secondary_group_failure_preserves_primary_categories_and_rejects_valid_legacy_success() {
        use std::os::unix::process::ExitStatusExt;

        let output = WorkerOutput {
            text: "return 0;".to_owned(),
            language_id: "x86:LE:64:default:gcc".to_owned(),
            data_organization: WorkerDataOrganization { pointer: 8, int: 4, long: 8 },
            tokens: None,
            structure: None,
        };
        let success =
            serde_json::to_vec(&WorkerResponse::Ok { version: PROTOCOL_VERSION, output: Box::new(output) }).unwrap();
        let worker_error = serde_json::to_vec(&WorkerResponse::Error {
            version: PROTOCOL_VERSION,
            message: "fixture error".to_owned(),
        })
        .unwrap();
        let partial_request_error = worker_error.clone();
        let wrong_version = serde_json::to_vec(&WorkerResponse::Error {
            version: PROTOCOL_VERSION + 1,
            message: "wrong version".to_owned(),
        })
        .unwrap();
        for (raw_status, stdout, expected) in [
            (42 << 8, Vec::new(), "exit"),
            (libc::SIGSEGV, Vec::new(), "exit"),
            (0, b"not json".to_vec(), "protocol"),
            (0, wrong_version, "protocol"),
            (0, worker_error, "decompile"),
            (0, success.clone(), "cleanup"),
        ] {
            let measurement = Measurement::new(Instant::now(), true);
            let result = finish_process(
                ProcessOutput {
                    stdout,
                    stderr: b"native failure".to_vec(),
                    status: std::process::ExitStatus::from_raw(raw_status),
                    controlled_stop: false,
                    host_stopped_root: false,
                    input_fully_delivered: true,
                    outputs_eof: true,
                    control_error: None,
                    cleanup_error: Some(WorkerError::Cleanup {
                        group: io::Error::from_raw_os_error(libc::EPERM),
                        root: None,
                    }),
                },
                MAX_STDOUT_BYTES,
                budget(None),
                &measurement,
            );
            match expected {
                "exit" => {
                    assert!(matches!(result, Err(WorkerError::Exit { stderr, .. }) if stderr == "native failure"));
                }
                "protocol" => assert!(matches!(result, Err(WorkerError::Protocol(_)))),
                "decompile" => assert!(matches!(result, Err(WorkerError::Decompile(_)))),
                "cleanup" => assert!(matches!(result, Err(WorkerError::Cleanup { .. }))),
                _ => unreachable!(),
            }
            let metrics = measurement.finish().unwrap();
            assert_eq!(metrics.cleanup_succeeded, Some(false));
            assert!(matches!(
                metrics.cleanup_error,
                Some(SupervisedCleanupError::GroupSignal { os_code: Some(libc::EPERM), root_failed: false, .. })
            ));
        }
        for (signal, controlled_stop, input_fully_delivered, expected_success) in [
            (libc::SIGKILL, false, true, false),
            (libc::SIGKILL, true, true, true),
            (libc::SIGSEGV, true, true, false),
            (libc::SIGKILL, true, false, false),
        ] {
            let measurement = Measurement::new(Instant::now(), false);
            let result = finish_process(
                ProcessOutput {
                    stdout: success.clone(),
                    stderr: Vec::new(),
                    status: std::process::ExitStatus::from_raw(signal),
                    controlled_stop,
                    host_stopped_root: controlled_stop,
                    input_fully_delivered,
                    outputs_eof: true,
                    control_error: None,
                    cleanup_error: None,
                },
                MAX_STDOUT_BYTES,
                budget(None),
                &measurement,
            );
            assert_eq!(result.is_ok(), expected_success);
            if !input_fully_delivered {
                assert!(matches!(result, Err(WorkerError::Protocol(_))));
            } else if !expected_success {
                assert!(matches!(result, Err(WorkerError::Exit { .. })));
            }
        }
        let measurement = Measurement::new(Instant::now(), false);
        let result = finish_process(
            ProcessOutput {
                stdout: partial_request_error,
                stderr: Vec::new(),
                status: std::process::ExitStatus::from_raw(libc::SIGKILL),
                controlled_stop: true,
                host_stopped_root: true,
                input_fully_delivered: false,
                outputs_eof: true,
                control_error: None,
                cleanup_error: None,
            },
            MAX_STDOUT_BYTES,
            budget(None),
            &measurement,
        );
        assert!(matches!(result, Err(WorkerError::Decompile(_))));
        for raw_status in [42 << 8, libc::SIGSEGV] {
            let result = finish_process(
                ProcessOutput {
                    stdout: success.clone(),
                    stderr: b"actual failed child".to_vec(),
                    status: std::process::ExitStatus::from_raw(raw_status),
                    controlled_stop: false,
                    host_stopped_root: true,
                    input_fully_delivered: true,
                    outputs_eof: true,
                    control_error: Some(WorkerError::Protocol("completion peer closed".to_owned())),
                    cleanup_error: None,
                },
                MAX_STDOUT_BYTES,
                budget(None),
                &measurement,
            );
            assert!(matches!(result, Err(WorkerError::Exit { stderr, .. }) if stderr == "actual failed child"));
        }
        let result = finish_process(
            ProcessOutput {
                stdout: success,
                stderr: Vec::new(),
                status: std::process::ExitStatus::from_raw(0),
                controlled_stop: false,
                host_stopped_root: false,
                input_fully_delivered: true,
                outputs_eof: false,
                control_error: None,
                cleanup_error: None,
            },
            MAX_STDOUT_BYTES,
            budget(None),
            &measurement,
        );
        assert!(matches!(result, Err(WorkerError::Protocol(message)) if message.contains("EOF")));
    }

    #[test]
    fn measured_preflight_serialization_and_spawn_failures_keep_partial_observations() {
        let mut invalid = request();
        invalid.version = PROTOCOL_VERSION + 1;
        let run = run_supervised_measured(&invalid, &WorkerConfig::default(), None);
        assert!(matches!(run.result, Err(WorkerError::Protocol(_))));
        assert!(run.metrics.request_preflight_complete_us.is_none());
        assert!(run.metrics.spawn_started_us.is_none());
        assert_eq!(run.metrics.ownership, SupervisedOwnership::NotSpawned);
        assert!(run.metrics.rss.max_observed_child_rss_bytes.is_none());

        let config = WorkerConfig { timeout: Duration::ZERO, ..Default::default() };
        let run = run_supervised_measured(&request(), &config, None);
        assert!(matches!(run.result, Err(WorkerError::Timeout)));
        assert!(run.metrics.spawn_started_us.is_none());
        assert!(run.metrics.cleanup_started_us.is_none());

        let config = WorkerConfig { max_request_bytes: 1, ..Default::default() };
        let run = run_supervised_measured(&request(), &config, None);
        assert!(matches!(run.result, Err(WorkerError::RequestTooLarge { .. })));
        assert!(run.metrics.request_preflight_complete_us.is_some());
        assert!(run.metrics.request_serialization_complete_us.is_none());
        assert!(run.metrics.input.requested_bytes.is_none());
        assert!(run.metrics.spawn_started_us.is_none());

        let fixture = Fixture::new("exit 0");
        let config = WorkerConfig { executable: Some(fixture.directory.join("missing")), ..fixture.config() };
        let run = run_supervised_measured(&request(), &config, None);
        assert!(matches!(run.result, Err(WorkerError::Io { action: "spawn", .. })));
        assert!(run.metrics.request_serialization_complete_us.is_some());
        assert!(run.metrics.spawn_started_us.is_some());
        assert!(run.metrics.spawn_complete_us.is_none());
        assert!(run.metrics.cleanup_succeeded.is_none());
        assert!(!fixture.pid.exists());
    }

    fn successful_fixture_response() -> WorkerResponse {
        WorkerResponse::Ok {
            version: PROTOCOL_VERSION,
            output: Box::new(WorkerOutput {
                text: "return 0;".to_owned(),
                language_id: "x86:LE:64:default:gcc".to_owned(),
                data_organization: WorkerDataOrganization { pointer: 8, int: 4, long: 8 },
                tokens: None,
                structure: None,
            }),
        }
    }

    #[test]
    fn closed_completion_peer_cannot_authorize_success_from_a_still_running_worker() {
        let response = successful_fixture_response();
        let fixture = Fixture::new(&unix::closed_control_fixture(&response));
        let run = run_supervised_measured(&request(), &fixture.config(), None);
        assert!(matches!(run.result, Err(WorkerError::Protocol(message)) if message.contains("peer")));
        assert!(run.metrics.control_completion_us.is_some());
        assert!(!run.metrics.intentional_stop);
        assert_eq!(run.metrics.stdout.read_bytes, serde_json::to_vec(&response).unwrap().len() as u64);
        assert!(run.metrics.root_reaped_us.is_some());
        let status = run.metrics.root_exit_status.unwrap();
        assert!(!status.success);
        assert_eq!(status.signal, Some(libc::SIGKILL));
        fixture.assert_reaped();
    }

    #[test]
    fn authenticated_completion_stops_live_group_before_waiting_for_descendant_pipe_eof() {
        let response = successful_fixture_response();
        let fixture = Fixture::new(&unix::pipe_holder_control_fixture(&response));
        let run = run_supervised_measured(&request(), &fixture.config(), None);
        let output = run.result.expect("authenticated live group must stop before ten-second holders exit naturally");
        assert_eq!(output.text, "return 0;");
        assert!(run.metrics.intentional_stop);
        assert_eq!(run.metrics.cleanup_succeeded, Some(true));
        assert_eq!(run.metrics.root_exit_status.unwrap().signal, Some(libc::SIGKILL));
        assert_eq!(run.metrics.stdout.outcome, Some(SupervisedStreamOutcome::Eof));
        assert_eq!(run.metrics.stderr.outcome, Some(SupervisedStreamOutcome::Eof));
        let cleanup = run.metrics.cleanup_started_us.unwrap();
        let decode = run.metrics.response_decode_started_us.unwrap();
        assert!(cleanup <= run.metrics.stdout.eof_us.unwrap());
        assert!(cleanup <= run.metrics.stderr.eof_us.unwrap());
        assert!(run.metrics.stdout.eof_us.unwrap() <= decode);
        assert!(run.metrics.stderr.eof_us.unwrap() <= decode);
        assert!(run.metrics.root_reaped_us.unwrap() <= decode);
        fixture.assert_reaped();
    }

    #[test]
    fn completed_control_then_failed_child_exit_keeps_exit_and_crash_precedence() {
        for crash in [false, true] {
            let response = successful_fixture_response();
            let fixture = Fixture::new(&unix::failed_control_fixture(&response, crash));
            let mut request = request();
            request.mappings[0].hex_bytes = "ab".repeat(512 * 1024);
            request.mappings[0].size = 512 * 1024;
            let run = run_supervised_measured(&request, &fixture.config(), None);
            assert!(matches!(run.result, Err(WorkerError::Exit { .. })));
            assert!(run.metrics.control_completion_us.is_some());
            assert!(!run.metrics.intentional_stop);
            let status = run.metrics.root_exit_status.unwrap();
            if crash {
                assert_eq!(status.signal, Some(libc::SIGSEGV));
            } else {
                assert_eq!(status.code, Some(42));
            }
            assert!(run.metrics.root_reaped_us.is_some());
            fixture.assert_reaped();
        }
    }

    #[test]
    fn measured_decode_failures_keep_delivered_input_output_and_reap_observations() {
        let fixture = Fixture::new("printf '%s' 'not json'; /bin/cat >/dev/null");
        let run = run_supervised_measured(&request(), &fixture.config(), None);
        assert!(matches!(run.result, Err(WorkerError::Protocol(_))));
        assert_eq!(run.metrics.input.outcome, Some(SupervisedInputOutcome::FullyDelivered));
        assert_eq!(run.metrics.input.requested_bytes, Some(run.metrics.input.written_bytes));
        assert_eq!(run.metrics.stdout.read_bytes, 8);
        assert!(run.metrics.stdout.first_byte_us.is_some());
        assert!(run.metrics.response_decoded_us.is_none());
        assert!(run.metrics.root_reaped_us.is_some());
        if run.metrics.cleanup_succeeded == Some(false) {
            assert!(run.metrics.cleanup_error.is_some());
        }
        assert_eq!(run.metrics.ownership, SupervisedOwnership::Reaped);
        fixture.assert_reaped();
    }

    #[test]
    fn measured_cancellation_keeps_drop_cleanup_and_joined_pipe_reports() {
        let fixture = Fixture::new("exec /bin/sleep 60");
        let cancellation = AtomicBool::new(false);
        let run = thread::scope(|scope| {
            scope.spawn(|| {
                await_file(&fixture.pid);
                cancellation.store(true, Ordering::Release);
            });
            run_supervised_measured(&request(), &fixture.config(), Some(&cancellation))
        });
        assert!(matches!(run.result, Err(WorkerError::Cancelled)));
        assert!(run.metrics.spawn_complete_us.is_some());
        assert!(run.metrics.root_reaped_us.is_some());
        assert!(run.metrics.root_exit_status.is_some());
        assert!(run.metrics.cleanup_finished_us.is_some());
        assert_eq!(run.metrics.cleanup_succeeded, Some(true));
        assert!(run.metrics.stdout.finished_us.is_some());
        assert!(run.metrics.stderr.finished_us.is_some());
        fixture.assert_reaped();

        let run = run_supervised_measured(&request(), &fixture.config(), Some(&AtomicBool::new(true)));
        assert!(matches!(run.result, Err(WorkerError::Cancelled)));
        assert!(run.metrics.spawn_started_us.is_none());
        assert!(run.metrics.cleanup_started_us.is_none());
    }

    #[test]
    fn measured_output_limit_keeps_the_failing_reader_report_after_guard_cleanup() {
        let fixture = Fixture::new("/bin/dd if=/dev/zero bs=1024 count=1 2>/dev/null; exec /bin/sleep 60");
        let config = WorkerConfig { max_stdout_bytes: 16, ..fixture.config() };
        let run = run_supervised_measured(&request(), &config, None);
        assert!(matches!(run.result, Err(WorkerError::OutputTooLarge { stream: "stdout", .. })));
        assert_eq!(run.metrics.stdout.outcome, Some(SupervisedStreamOutcome::OutputLimit));
        assert!(run.metrics.stdout.read_bytes > 16);
        assert!(run.metrics.stdout.eof_us.is_none());
        assert!(run.metrics.root_reaped_us.is_some());
        assert_eq!(run.metrics.cleanup_succeeded, Some(true));
        fixture.assert_reaped();
    }

    struct GatedSerialization {
        reached: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
        finished: AtomicBool,
    }

    impl Serialize for GatedSerialization {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;

            let mut sequence = serializer.serialize_seq(Some(3))?;
            sequence.serialize_element("first")?;
            self.reached.send(()).expect("signal serialization gate");
            self.resume.recv_timeout(Duration::from_secs(5)).expect("resume serialization");
            sequence.serialize_element("second")?;
            self.finished.store(true, Ordering::Release);
            sequence.serialize_element("third")?;
            sequence.end()
        }
    }

    #[test]
    fn serialization_cancellation_interrupts_the_next_write_not_just_the_final_result() {
        let cancellation = AtomicBool::new(false);
        let (reached, await_reached) = mpsc::channel();
        let (resume, await_resume) = mpsc::channel();
        let value = GatedSerialization { reached, resume: await_resume, finished: AtomicBool::new(false) };
        thread::scope(|scope| {
            let cancellation = &cancellation;
            scope.spawn(move || {
                await_reached.recv_timeout(Duration::from_secs(5)).expect("serialization started");
                cancellation.store(true, Ordering::Release);
                resume.send(()).expect("release serialization gate");
            });
            let result = serialize_supervised(&value, MAX_REQUEST_BYTES, budget(Some(cancellation)));
            assert!(matches!(result, Err(WorkerError::Cancelled)), "{result:?}");
        });
        assert!(!value.finished.load(Ordering::Acquire), "serialization continued after cancellation");
    }

    #[test]
    fn expired_serialization_budget_stops_before_visiting_the_value() {
        struct MustNotSerialize;
        impl Serialize for MustNotSerialize {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                panic!("expired serialization must not visit the value")
            }
        }
        let budget = SupervisorBudget { timeout: Duration::ZERO, ..budget(None) };
        let result = serialize_supervised(&MustNotSerialize, MAX_REQUEST_BYTES, budget);
        assert!(matches!(result, Err(WorkerError::Timeout)), "{result:?}");
    }

    struct GatedResponse<'a> {
        bytes: &'a [u8],
        reached: Option<mpsc::Sender<()>>,
        resume: mpsc::Receiver<()>,
        reads: usize,
    }

    impl Read for GatedResponse<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.reads == 8
                && let Some(reached) = self.reached.take()
            {
                reached.send(()).expect("signal response decoding gate");
                self.resume.recv_timeout(Duration::from_secs(5)).expect("resume response decoding");
            }
            self.reads += 1;
            self.bytes.read(buffer)
        }
    }

    #[test]
    fn response_cancellation_interrupts_active_decoding() {
        let bytes = br#"{"version":1,"status":"error","message":"not a cancellation"}"#;
        let cancellation = AtomicBool::new(false);
        let (reached, await_reached) = mpsc::channel();
        let (resume, await_resume) = mpsc::channel();
        let mut input = GatedResponse { bytes, reached: Some(reached), resume: await_resume, reads: 0 };
        thread::scope(|scope| {
            let cancellation = &cancellation;
            scope.spawn(move || {
                await_reached.recv_timeout(Duration::from_secs(5)).expect("response decoding started");
                cancellation.store(true, Ordering::Release);
                resume.send(()).expect("release response decoding gate");
            });
            let result = decode_supervised_response(&mut input, MAX_STDOUT_BYTES, budget(Some(cancellation)));
            assert!(matches!(result, Err(WorkerError::Cancelled)), "{result:?}");
        });
        assert!(!input.bytes.is_empty(), "response was fully decoded despite cancellation");
    }

    #[test]
    fn expired_response_budget_never_returns_a_successful_output() {
        let response = WorkerResponse::Ok {
            version: PROTOCOL_VERSION,
            output: Box::new(WorkerOutput {
                text: "return 0;".to_owned(),
                language_id: "fixture".to_owned(),
                structure: None,
                data_organization: WorkerDataOrganization { pointer: 8, int: 4, long: 8 },
                tokens: Some(vec![WorkerToken {
                    text: "return".to_owned(),
                    kind: "keyword".to_owned(),
                    address: None,
                    span: None,
                }]),
            }),
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let budget = SupervisorBudget { timeout: Duration::ZERO, ..budget(None) };
        let result = decode_supervised_response(bytes.as_slice(), MAX_STDOUT_BYTES, budget);
        assert!(matches!(result, Err(WorkerError::Timeout)), "{result:?}");
    }

    #[test]
    fn response_cancellation_at_eof_cannot_return_success() {
        struct CancelAtEof<'a> {
            bytes: &'a [u8],
            cancellation: &'a AtomicBool,
        }
        impl Read for CancelAtEof<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let count = self.bytes.read(buffer)?;
                if count == 0 {
                    self.cancellation.store(true, Ordering::Release);
                }
                Ok(count)
            }
        }
        let cancellation = AtomicBool::new(false);
        let bytes = br#"{"version":1,"status":"ok","output":{"text":"fixture","language_id":"fixture",
            "data_organization":{"pointer":8,"int":4,"long":8}}}"#;
        let input = CancelAtEof { bytes, cancellation: &cancellation };
        let result = decode_supervised_response(input, MAX_STDOUT_BYTES, budget(Some(&cancellation)));
        assert!(matches!(result, Err(WorkerError::Cancelled)), "{result:?}");
    }

    #[test]
    fn supervised_serialization_preserves_long_strings_across_partial_writes() {
        let text = "unescaped".repeat(4096);
        let bytes = serialize_supervised(&text, MAX_REQUEST_BYTES, budget(None)).unwrap();
        assert_eq!(serde_json::from_slice::<String>(&bytes).unwrap(), text);
        let result = serialize_supervised(&text, 8193, budget(None));
        assert!(matches!(result, Err(WorkerError::RequestTooLarge { limit: 8193 })), "{result:?}");
    }

    #[test]
    fn response_decoding_honors_size_limits_and_rejects_trailing_input() {
        let bytes = br#"{"version":1,"status":"error","message":"fixture"}"#;
        let result = decode_supervised_response(bytes.as_slice(), 8, budget(None));
        assert!(matches!(result, Err(WorkerError::OutputTooLarge { stream: "stdout", limit: 8 })), "{result:?}");
        let mut trailing = bytes.to_vec();
        trailing.extend_from_slice(b" {}");
        assert!(matches!(
            decode_supervised_response(trailing.as_slice(), MAX_STDOUT_BYTES, budget(None)),
            Err(WorkerError::Protocol(_))
        ));
        assert!(matches!(
            decode_supervised_response(bytes.as_slice(), bytes.len(), budget(None)),
            Ok(WorkerResponse::Error { .. })
        ));
    }

    fn await_file(path: &Path) {
        let started = Instant::now();
        while fs::read_to_string(path).ok().and_then(|text| text.parse::<u32>().ok()).is_none() {
            assert!(started.elapsed() < Duration::from_secs(5), "worker did not start");
            thread::park_timeout(Duration::from_millis(1));
        }
    }

    #[test]
    fn timeout_interrupts_a_blocked_stdin_writer_and_reaps_child() {
        let fixture = Fixture::new("exec /bin/sleep 60");
        let mut config = fixture.config();
        config.timeout = Duration::from_secs(1);
        let mut request = request();
        request.mappings[0].hex_bytes = "ab".repeat(256 * 1024);
        let started = Instant::now();
        assert!(matches!(run_supervised(&request, &config, None), Err(WorkerError::Timeout)));
        // Only guards against a true hang: under heavy parallel load the 1s timeout can take several seconds of
        // wall clock to surface, so the bound is generous rather than tight.
        assert!(started.elapsed() < Duration::from_secs(60));
        fixture.assert_reaped();
    }

    #[test]
    fn cancellation_after_spawn_interrupts_pipe_reads_and_reaps_child() {
        let fixture = Fixture::new("exec /bin/sleep 60");
        let cancellation = AtomicBool::new(false);
        thread::scope(|scope| {
            scope.spawn(|| {
                await_file(&fixture.pid);
                cancellation.store(true, Ordering::Release);
            });
            let result = run_supervised(&request(), &fixture.config(), Some(&cancellation));
            assert!(matches!(result, Err(WorkerError::Cancelled)), "{result:?}");
        });
        fixture.assert_reaped();
    }

    #[test]
    fn already_cancelled_never_spawns_a_child() {
        let fixture = Fixture::new("exit 0");
        let result = run_supervised(&request(), &fixture.config(), Some(&AtomicBool::new(true)));
        assert!(matches!(result, Err(WorkerError::Cancelled)));
        assert!(!fixture.pid.exists());
    }

    #[test]
    fn oversized_requests_are_rejected_before_spawn() {
        let fixture = Fixture::new("exit 0");
        let config = WorkerConfig { max_request_bytes: 8, ..fixture.config() };
        assert!(matches!(run_supervised(&request(), &config, None), Err(WorkerError::RequestTooLarge { .. })));
        assert!(!fixture.pid.exists());
    }

    #[test]
    fn overflow_in_either_output_stream_kills_and_reaps_child() {
        for stream in ["stdout", "stderr"] {
            let redirect = if stream == "stderr" { " >&2" } else { "" };
            let fixture = Fixture::new(&format!("/bin/dd if=/dev/zero bs=8192 count=4{redirect}\nexec /bin/sleep 60"));
            let config = WorkerConfig { max_stdout_bytes: 1024, max_stderr_bytes: 1024, ..fixture.config() };
            let result = run_supervised(&request(), &config, None);
            assert!(
                matches!(result, Err(WorkerError::OutputTooLarge { stream: found, .. }) if found == stream),
                "{result:?}"
            );
            fixture.assert_reaped();
        }
    }

    #[test]
    fn successful_exit_does_not_wait_for_descendants_holding_pipes() {
        let response = WorkerResponse::Error { version: PROTOCOL_VERSION, message: "fixture response".to_owned() };
        let json = serde_json::to_string(&response).unwrap();
        let fixture = Fixture::new(&format!("/bin/sleep 60 &\nprintf '%s' '{json}'\nexit 0"));
        let started = Instant::now();
        let result = run_supervised(&request(), &fixture.config(), None);
        assert!(matches!(result, Err(WorkerError::Decompile(_))), "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
        fixture.assert_reaped();
    }

    #[test]
    fn nonzero_exit_preserves_bounded_stderr_and_reaps_child() {
        let fixture = Fixture::new("printf '%s' 'native failure' >&2\nexit 42");
        let result = run_supervised(&request(), &fixture.config(), None);
        assert!(matches!(result, Err(WorkerError::Exit { stderr, .. }) if stderr.contains("native failure")));
        fixture.assert_reaped();
    }

    #[test]
    fn stderr_is_drained_while_a_large_request_is_still_being_written() {
        let response = WorkerResponse::Error { version: PROTOCOL_VERSION, message: "fixture response".to_owned() };
        let json = serde_json::to_string(&response).unwrap();
        let fixture = Fixture::new(&format!(
            "printf '%s' '{json}'\n/usr/bin/awk 'BEGIN {{for (i=0;i<8192;i++) printf \"abcdefgh\"}}' >&2\n\
             /bin/cat >/dev/null"
        ));
        let mut request = request();
        request.mappings[0].hex_bytes = "ab".repeat(256 * 1024);
        let result = run_supervised(&request, &fixture.config(), None);
        assert!(matches!(result, Err(WorkerError::Decompile(_))), "{result:?}");
        fixture.assert_reaped();
    }

    #[test]
    fn native_crash_is_an_exit_error_without_leaving_a_child_or_core_dump() {
        let fixture = Fixture::new("kill -SEGV $$");
        let result = run_supervised(&request(), &fixture.config(), None);
        assert!(matches!(result, Err(WorkerError::Exit { .. })), "{result:?}");
        fixture.assert_reaped();
    }

    #[test]
    fn malformed_or_wrong_version_response_is_not_success() {
        for response in ["not json", r#"{"status":"error","version":999,"message":"bad version"}"#] {
            let fixture = Fixture::new(&format!("printf '%s' '{response}'"));
            let result = run_supervised(&request(), &fixture.config(), None);
            assert!(matches!(result, Err(WorkerError::Protocol(_))), "{result:?}");
            fixture.assert_reaped();
        }
    }

    #[test]
    fn failed_spawn_and_invalid_memory_configuration_are_explicit_errors() {
        let fixture = Fixture::new("exit 0");
        let missing = WorkerConfig { executable: Some(fixture.directory.join("missing")), ..fixture.config() };
        assert!(matches!(run_supervised(&request(), &missing, None), Err(WorkerError::Io { action: "spawn", .. })));
        let invalid_memory = WorkerConfig { memory_limit_bytes: 0, ..fixture.config() };
        assert!(matches!(
            run_supervised(&request(), &invalid_memory, None),
            Err(WorkerError::Io { action: "spawn", .. })
        ));
        assert!(!fixture.pid.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resident_memory_limit_kills_and_reaps_child_on_darwin() {
        let fixture = Fixture::new("exec /bin/sleep 60");
        let config = WorkerConfig { memory_limit_bytes: 1, ..fixture.config() };
        let result = run_supervised(&request(), &config, None);
        assert!(matches!(result, Err(WorkerError::MemoryLimit { .. })), "{result:?}");
        if fixture.pid.exists() {
            fixture.assert_reaped();
        }
    }

    #[test]
    fn mapping_decode_rejects_partial_nonhex_and_nonascii_pairs() {
        for text in ["a", "0g", "é", "😀"] {
            assert!(decode_hex(text).is_err(), "accepted {text:?}");
        }
        assert_eq!(decode_hex("00aAff").unwrap(), [0, 0xaa, 0xff]);
    }

    fn layout_probe() -> crate::layout::PlainStructLayout {
        use crate::layout::{LayoutField, LayoutOrganization, LayoutScalar, LayoutType, ScalarKind};

        let int = LayoutScalar { name: "int4".to_owned(), kind: ScalarKind::SignedInteger, size: 4, alignment: 4 };
        crate::layout::PlainStructLayout {
            name: "layout_probe".to_owned(),
            size: 24,
            alignment: 8,
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
                    ty: LayoutType::Scalar { scalar: int.clone() },
                },
                LayoutField {
                    name: "value".to_owned(),
                    offset: 8,
                    size: 8,
                    ty: LayoutType::Pointer { name: String::new(), size: 8, alignment: 8, pointee: int },
                },
                LayoutField {
                    name: "tail".to_owned(),
                    offset: 16,
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
        }
    }

    fn layout_request(validate_only: bool) -> WorkerRequest {
        let mut request = request();
        request.validate_only = validate_only;
        request.mappings[0].hex_bytes = "8b07c3".to_owned();
        request.operations = vec![
            WorkerOperation::ParseTypes {
                declarations: "struct layout_probe { int4 count; int4 *value; uint1 tail; };".to_owned(),
            },
            WorkerOperation::AssertPlainStructLayout { layout: layout_probe(), expected_context: None },
            WorkerOperation::Symbol { address: 0x1000, name: "fixture".to_owned() },
            WorkerOperation::Prototype {
                address: 0x1000,
                indirect: false,
                declaration: "int4 fixture(layout_probe *item);".to_owned(),
            },
        ];
        request
    }

    #[test]
    fn a_different_embedded_context_is_refused_before_architecture_or_native_initialization() {
        let mut request = layout_request(true);
        let mut expected = rampage_arch::hex::bytes(&crate::context::embedded_manifest_sha256());
        let replacement = if expected.starts_with('0') { "1" } else { "0" };
        expected.replace_range(..1, replacement);
        let WorkerOperation::AssertPlainStructLayout { expected_context, .. } = &mut request.operations[1] else {
            unreachable!()
        };
        *expected_context = Some(expected);
        request.arch = "must-not-reach-architecture-selection".to_owned();
        let error = execute_request(request).unwrap_err();
        assert!(error.contains("embedded specification identity does not match"), "{error}");
    }

    #[test]
    fn checked_context_wire_bounds_are_applied_before_native_work_and_manual_wire_stays_unchanged() {
        let manual = layout_request(true);
        let manual_wire = serde_json::to_vec(&manual).unwrap();
        assert!(!String::from_utf8(manual_wire.clone()).unwrap().contains("expected_context"));
        read_request(manual_wire.as_slice()).unwrap();
        let mut invalid = manual;
        let WorkerOperation::AssertPlainStructLayout { expected_context, .. } = &mut invalid.operations[1] else {
            unreachable!()
        };
        *expected_context = Some("a".repeat(65));
        assert!(validate_layout_operations(&invalid, None).is_err());
        let wire = serde_json::to_vec(&invalid).unwrap();
        assert!(read_request(wire.as_slice()).is_err());
    }

    #[test]
    fn ordered_worker_layout_assertion_matches_native_including_validation_only() {
        let bytes = [0x8b, 0x07, 0xc3];
        let mut native = Decompiler::open_regions(
            Arch::X86_64,
            false,
            &[MemoryRegion { base: 0x1000, bytes: &bytes, size: 3, readable: true, writable: false, executable: true }],
        )
        .unwrap();
        native.parse_c("struct layout_probe { int4 count; int4 *value; uint1 tail; };").unwrap();
        native.assert_plain_struct_layout(&layout_probe()).unwrap();
        native.set_symbol(0x1000, "fixture").unwrap();
        native.apply_prototype(0x1000, false, "int4 fixture(layout_probe *item);").unwrap();
        let text = native.decompile(0x1000, "fixture", false).unwrap();
        assert!(text.contains("->count"), "{text}");
        for validate_only in [false, true] {
            let request = layout_request(validate_only);
            let encoded = serialize_bounded(&request, MAX_REQUEST_BYTES).unwrap();
            let decoded = read_request(encoded.as_slice()).unwrap();
            let result = execute_request(decoded).unwrap();
            if validate_only {
                assert!(result.text.is_empty());
                assert!(result.structure.is_none());
            } else {
                assert_eq!(result.text, text);
            }
            let mut request = layout_request(validate_only);
            if let WorkerOperation::AssertPlainStructLayout { layout, .. } = &mut request.operations[1]
                && let crate::layout::LayoutType::Scalar { scalar } = &mut layout.fields[0].ty
            {
                scalar.kind = crate::layout::ScalarKind::UnsignedInteger;
            }
            let error = execute_request(request).unwrap_err();
            assert!(error.starts_with("operation 1:"), "{error}");
            assert!(error.contains("does not match"), "{error}");
            let mut request = layout_request(validate_only);
            request.operations.swap(0, 1);
            let error = execute_request(request).unwrap_err();
            assert!(error.starts_with("operation 0:"), "{error}");
        }
    }

    #[test]
    fn invalid_layout_inputs_are_checked_before_serialization_spawn_or_native_setup() {
        let mut request = layout_request(true);
        request.arch = "not_an_arch".to_owned();
        if let WorkerOperation::AssertPlainStructLayout { layout, .. } = &mut request.operations[1] {
            layout.fields[0].offset = u32::MAX;
        }
        let error = execute_request(request.clone()).unwrap_err();
        assert!(error.starts_with("operation 1:"), "{error}");
        let fixture = Fixture::new("exit 0");
        let config = WorkerConfig { max_request_bytes: 1, ..fixture.config() };
        let result = run_supervised(&request, &config, None);
        assert!(matches!(result, Err(WorkerError::Protocol(message)) if message.starts_with("operation 1:")));
        assert!(!fixture.pid.exists());
        for version in [0, 3, PROTOCOL_VERSION + 1] {
            let mut request = layout_request(true);
            request.version = version;
            let error = execute_request(request).unwrap_err();
            assert!(error.contains("unsupported worker protocol version"), "{error}");
        }
    }

    #[test]
    fn raw_stdio_reader_preflights_hostile_assertions_before_serde_materialization() {
        let zeros = format!("[{}0]", "0,".repeat(1_000_000));
        let escaped = "\\u0061".repeat(200_000);
        let giant = "hostile_marker".repeat(100_000);
        for operation in [
            format!(r#"{{"op":"assert_plain_struct_layout","layout":{{"fields":{zeros}}}}}"#),
            format!(r#"{{"layout":{{"f\u0069elds":{zeros}}},"op":"assert_plain_struct_layout"}}"#),
            format!(r#"{{"layout":{{"name":"{escaped}"}},"op":"assert_plain_struct_layout"}}"#),
            format!(r#"{{"layout":{{}},"{giant}":null,"op":"assert_plain_struct_layout"}}"#),
        ] {
            let wire = format!(
                r#"{{"version":{PROTOCOL_VERSION},"arch":"x86_64","mappings":[],"decompile":{{"address":4096}},
                "operations":[{operation}]}}"#
            );
            let error = read_request(wire.as_bytes()).unwrap_err();
            assert!(error.starts_with("operation 0:"), "{error}");
            assert!(error.len() <= 160);
            assert!(!error.contains("hostile_marker"));
        }
    }

    #[test]
    fn malformed_schema_diagnostics_do_not_format_serde_offending_values() {
        for operation in [
            r#"{"op":"unexpected_variant"}"#,
            r#"{"op":"symbol","address":"unexpected_type","name":"fixture"}"#,
            r#"{"op":"symbol","address":4096,"name":"fixture","unexpected_property":1}"#,
        ] {
            let wire = format!(
                r#"{{"version":{PROTOCOL_VERSION},"arch":"x86_64","mappings":[],"decompile":{{"address":4096}},
                "operations":[{operation}]}}"#
            );
            assert_eq!(read_request(wire.as_bytes()).unwrap_err(), "decode request: invalid worker schema");
        }
        let wire = serde_json::to_string(&layout_request(true)).unwrap();
        let wire = wire.replacen("\"kind\":\"scalar\"", "\"kind\":\"unexpected_kind\"", 1);
        assert_eq!(read_request(wire.as_bytes()).unwrap_err(), "decode request: invalid worker schema");
    }
}
