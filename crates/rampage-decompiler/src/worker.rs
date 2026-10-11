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

pub const MAX_REQUEST_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STDERR_BYTES: usize = 64 * 1024;
pub const PROTOCOL_VERSION: u32 = 1;

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
}

impl Default for WorkerOptions {
    fn default() -> Self {
        Self { platform: "default".to_owned(), compiler: None }
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
    Ok { version: u32, output: WorkerOutput },
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
    Io { action: &'static str, source: io::Error },
    RequestTooLarge { limit: usize },
    OutputTooLarge { stream: &'static str, limit: usize },
    MemoryLimit { limit: u64 },
    Timeout,
    Cancelled,
    Exit { status: String, stderr: String },
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

/// Launch one worker, drain all three pipes concurrently, and always kill/reap it before returning.
/// Missing workers are errors; supervision never falls back to an in-process native call.
/// Supported supervisor hosts are 64-bit Linux and macOS; other hosts return UnsupportedPlatform.
pub fn run_supervised(
    request: &WorkerRequest,
    config: &WorkerConfig,
    cancellation: Option<&AtomicBool>,
) -> Result<WorkerOutput, WorkerError> {
    let started = std::time::Instant::now();
    let budget = SupervisorBudget { started, timeout: config.timeout, cancellation };
    let bytes = serialize_supervised(request, config.max_request_bytes.min(MAX_REQUEST_BYTES), budget)?;
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
    let (stdout, stderr, status) = supervised_process(&executable, bytes, config, cancellation, started)?;
    budget.check()?;
    if !status.success() {
        return Err(WorkerError::Exit {
            status: status.to_string(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        });
    }
    let response = decode_supervised_response(stdout.as_slice(), config.max_stdout_bytes, budget)?;
    budget.check()?;
    match response {
        WorkerResponse::Ok { version, output } if version == PROTOCOL_VERSION => Ok(output),
        WorkerResponse::Error { version, message } if version == PROTOCOL_VERSION => {
            Err(WorkerError::Decompile(message))
        }
        _ => Err(WorkerError::Protocol("unsupported response version".to_owned())),
    }
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

/// The worker binary handles exactly one JSON request, then exits. Errors are JSON responses, not stderr text.
pub fn serve_stdio() -> Result<(), WorkerError> {
    let response = match read_request(io::stdin().lock()).and_then(execute_request) {
        Ok(output) => WorkerResponse::Ok { version: PROTOCOL_VERSION, output },
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

fn read_request(input: impl Read) -> Result<WorkerRequest, String> {
    let mut bytes = Vec::new();
    input
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read request: {error}"))?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("worker request exceeds protocol limit".to_owned());
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("decode request: {error}"))
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

fn execute_request(request: WorkerRequest) -> Result<WorkerOutput, String> {
    if request.version != PROTOCOL_VERSION {
        return Err(format!("unsupported worker protocol version {}", request.version));
    }
    let arch: Arch = request.arch.parse()?;
    let platform = match request.options.platform.as_str() {
        "default" => Platform::Default,
        "windows" => Platform::Windows,
        "darwin" => Platform::Darwin,
        other => return Err(format!("unknown decompiler platform {other:?}")),
    };
    let options = DecompilerOptions { platform, compiler: request.options.compiler };
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
            .map(|token| WorkerToken { text: token.text, kind: token.kind, address: token.address })
            .collect()
    });
    let organization = engine.data_organization();
    Ok(WorkerOutput {
        text,
        language_id: engine.language_id().to_owned(),
        data_organization: WorkerDataOrganization {
            pointer: organization.pointer,
            int: organization.int,
            long: organization.long,
        },
        tokens,
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
) -> Result<(Vec<u8>, Vec<u8>, std::process::ExitStatus), WorkerError> {
    Err(WorkerError::UnsupportedPlatform)
}

#[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
mod unix {
    use std::ffi::c_int;
    #[cfg(target_os = "linux")]
    use std::ffi::c_ulong;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Instant;

    use super::*;

    const POLL_INTERVAL: Duration = Duration::from_millis(5);
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
    fn check_memory(pid: u32, limit: u64) -> Result<(), WorkerError> {
        let mut info = ProcTaskInfo::default();
        let size = std::mem::size_of::<ProcTaskInfo>() as c_int;
        // SAFETY: proc_taskinfo's layout and PROC_PIDTASKINFO (4) match the Darwin SDK; buffer is writable.
        let count = unsafe { proc_pidinfo(pid as c_int, 4, 0, (&mut info as *mut ProcTaskInfo).cast(), size) };
        if count != size {
            let error = io::Error::last_os_error();
            // An exiting process can disappear from proc_pidinfo before waitpid reports its exit.
            if error.raw_os_error() == Some(3) {
                return Ok(());
            }
            return Err(io_error("inspect memory", error));
        }
        if info.resident_size > limit {
            return Err(WorkerError::MemoryLimit { limit });
        }
        Ok(())
    }

    fn nonblocking(fd: RawFd) -> Result<(), WorkerError> {
        // SAFETY: the caller keeps the pipe open; these fcntl commands query/update its status flags.
        let flags = unsafe { fcntl(fd, 3) };
        if flags < 0 || unsafe { fcntl(fd, 4, flags | O_NONBLOCK) } < 0 {
            return Err(io_error("configure pipe", io::Error::last_os_error()));
        }
        Ok(())
    }

    struct ProcessGuard {
        child: Child,
        stop: Arc<AtomicBool>,
        terminated: bool,
    }

    impl ProcessGuard {
        fn terminate(&mut self) {
            if self.terminated {
                return;
            }
            self.terminated = true;
            self.stop.store(true, Ordering::Release);
            // SAFETY: process_group(0) gives this worker its own group; a negative PID targets only that group.
            unsafe { kill(-(self.child.id() as c_int), 9) };
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            self.terminate();
        }
    }

    enum PipeResult {
        Input(Result<(), WorkerError>),
        Stdout(Result<Vec<u8>, WorkerError>),
        Stderr(Result<Vec<u8>, WorkerError>),
    }

    fn read_pipe(
        mut pipe: impl Read,
        limit: usize,
        stream: &'static str,
        stop: &AtomicBool,
    ) -> Result<Vec<u8>, WorkerError> {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => return Ok(bytes),
                Ok(count) => {
                    if count > limit.saturating_sub(bytes.len()) {
                        return Err(WorkerError::OutputTooLarge { stream, limit });
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if stop.load(Ordering::Acquire) {
                        return Ok(bytes);
                    }
                    thread::park_timeout(POLL_INTERVAL);
                }
                Err(error) => return Err(io_error("read pipe", error)),
            }
        }
    }

    fn write_pipe(mut pipe: impl Write, bytes: &[u8], stop: &AtomicBool) -> Result<(), WorkerError> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            match pipe.write(remaining) {
                Ok(0) => return Err(io_error("write request", io::ErrorKind::WriteZero.into())),
                Ok(count) => remaining = &remaining[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::park_timeout(POLL_INTERVAL),
                // The exit status/protocol distinguish early closure from a successful response.
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
                Err(error) => return Err(io_error("write request", error)),
            }
        }
        Ok(())
    }

    pub(super) fn supervised_process(
        executable: &Path,
        bytes: Vec<u8>,
        config: &WorkerConfig,
        cancellation: Option<&AtomicBool>,
        started: Instant,
    ) -> Result<(Vec<u8>, Vec<u8>, ExitStatus), WorkerError> {
        let memory_limit = config.memory_limit_bytes;
        if memory_limit == 0 {
            return Err(io_error("spawn", io::Error::other("worker memory limit must be nonzero")));
        }
        let mut command = Command::new(executable);
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
        // SAFETY: the callback only calls setrlimit/last_os_error; it allocates nothing and touches no locks.
        unsafe { command.pre_exec(move || limit_memory(memory_limit)) };
        let child = command.spawn().map_err(|error| io_error("spawn", error))?;
        let stop = Arc::new(AtomicBool::new(false));
        thread::scope(|scope| {
            // The guard must drop inside the scope, before scope waits for the nonblocking I/O threads.
            let mut process = ProcessGuard { child, stop: stop.clone(), terminated: false };
            let stdin = process.child.stdin.take().ok_or_else(|| WorkerError::Protocol("missing stdin".to_owned()))?;
            let stdout =
                process.child.stdout.take().ok_or_else(|| WorkerError::Protocol("missing stdout".to_owned()))?;
            let stderr =
                process.child.stderr.take().ok_or_else(|| WorkerError::Protocol("missing stderr".to_owned()))?;
            nonblocking(stdin.as_raw_fd())?;
            nonblocking(stdout.as_raw_fd())?;
            nonblocking(stderr.as_raw_fd())?;
            let (sender, receiver) = mpsc::channel();
            let input_sender = sender.clone();
            let input_stop = stop.clone();
            thread::Builder::new()
                .name("decompiler-worker-stdin".to_owned())
                .spawn_scoped(scope, move || {
                    let _ = input_sender.send(PipeResult::Input(write_pipe(stdin, &bytes, &input_stop)));
                })
                .map_err(|error| io_error("spawn stdin thread", error))?;
            let output_sender = sender.clone();
            let output_stop = stop.clone();
            let stdout_limit = config.max_stdout_bytes.min(MAX_STDOUT_BYTES);
            thread::Builder::new()
                .name("decompiler-worker-stdout".to_owned())
                .spawn_scoped(scope, move || {
                    let result = read_pipe(stdout, stdout_limit, "stdout", &output_stop);
                    let _ = output_sender.send(PipeResult::Stdout(result));
                })
                .map_err(|error| io_error("spawn stdout thread", error))?;
            let error_stop = stop.clone();
            let stderr_limit = config.max_stderr_bytes.min(MAX_STDERR_BYTES);
            thread::Builder::new()
                .name("decompiler-worker-stderr".to_owned())
                .spawn_scoped(scope, move || {
                    let result = read_pipe(stderr, stderr_limit, "stderr", &error_stop);
                    let _ = sender.send(PipeResult::Stderr(result));
                })
                .map_err(|error| io_error("spawn stderr thread", error))?;
            let (mut stdout, mut stderr, mut status) = (None, None, None);
            let mut input_finished = false;
            loop {
                if cancelled(cancellation) {
                    return Err(WorkerError::Cancelled);
                }
                if started.elapsed() >= config.timeout {
                    return Err(WorkerError::Timeout);
                }
                if status.is_none() {
                    status = process.child.try_wait().map_err(|error| io_error("wait", error))?;
                    #[cfg(target_os = "macos")]
                    if status.is_none()
                        && let Err(error) = check_memory(process.child.id(), memory_limit)
                    {
                        // An exit between try_wait and proc_pidinfo is not a monitoring failure.
                        status = process.child.try_wait().map_err(|error| io_error("wait", error))?;
                        if status.is_none() {
                            return Err(error);
                        }
                    }
                    if status.is_some() {
                        // Kill inherited-pipe holders too; drain buffered bytes, then stop on WouldBlock.
                        process.terminate();
                    }
                }
                if input_finished && let (Some(stdout), Some(stderr), Some(status)) = (&mut stdout, &mut stderr, status)
                {
                    return Ok((std::mem::take(stdout), std::mem::take(stderr), status));
                }
                let remaining = config.timeout.saturating_sub(started.elapsed()).min(POLL_INTERVAL);
                match receiver.recv_timeout(remaining) {
                    Ok(PipeResult::Input(result)) => {
                        result?;
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
            // SAFETY: signal zero queries existence without sending a signal.
            assert_eq!(unsafe { kill(pid, 0) }, -1, "worker {pid} still exists");
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
            output: WorkerOutput {
                text: "return 0;".to_owned(),
                language_id: "fixture".to_owned(),
                data_organization: WorkerDataOrganization { pointer: 8, int: 4, long: 8 },
                tokens: Some(vec![WorkerToken {
                    text: "return".to_owned(),
                    kind: "keyword".to_owned(),
                    address: None,
                }]),
            },
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
        assert!(started.elapsed() < Duration::from_secs(5));
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
}
