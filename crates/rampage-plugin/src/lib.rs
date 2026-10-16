//! Experimental, import-free component execution in a trusted one-request worker.
//!
//! Compilation, structural parsing, and execution live in the supervised process. Fuel and epochs do not
//! meter compilation. The process boundary provides crash/resource isolation, not an OS sandbox. Supported
//! hosts are 64-bit Linux/macOS with default SIGCHLD handling and exclusive ownership of child wait status.
//! Linux uses hard AS/DATA limits; Darwin's sampled RSS can overshoot. Spawn and OS queries are not forcibly
//! interruptible, and descendants escaping the owned process group are outside its cleanup boundary.
//!
//! The caller supplies already-read component bytes and prepared, exhaustive typed facts. This crate grants
//! no file authority, performs no program analysis, and has no inline execution fallback or ambient imports.
//! The exact ABI is `run(list<u8>) -> u32` plus `output(u32) -> tuple<u64, u64, u64, u64>` in the versioned
//! triage interface. Scalar returns avoid retaining pointers across automatic post-return cleanup.
//! The length is checked before host allocation; output is copied in at most 8192 fixed 32-byte calls.
//! Time/fuel ceilings are experimental policy, not measured performance guarantees.
//!
//! Raw admission is an explicit subset: plain core function types; synchronous primitive/list/tuple
//! component values and depth-bounded inline instance types. GC/rec groups/subtyping, inline component,
//! resource/record/variant/async types, and extended constant expressions are unsupported (`Preflight`).
//! Type counts/depth and instance/canonical vector lengths are checked before owning dependency readers.

#![forbid(unsafe_code)]

mod error;
mod preflight;
mod protocol;
mod runtime;

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rampage_decompiler::worker::{WorkerConfig, WorkerError, run_supervised_bytes};
use rampage_plugin_contract::TriageFacts;

pub use error::PluginError;
pub use rampage_plugin_contract::{COMPONENT_INTERFACE, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES};

pub const MAX_COMPONENT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_FUEL: u64 = 50_000_000;
pub const MAX_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_EXECUTION_TIMEOUT: Duration = Duration::from_millis(500);
pub const MAX_WORKER_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_MEMORIES: usize = 2;
pub const MAX_TABLE_ELEMENTS: usize = 10_000;
pub const MAX_TABLES: usize = 2;
pub const MAX_INSTANCES: usize = 8;
pub const MAX_WASM_STACK: usize = 512 * 1024;

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Limits may be lowered, never raised above this crate's ceilings. The executable must be explicit and
/// absolute, selected by the trusted caller, and must implement the plugin worker protocol, not p4.
#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub executable: PathBuf,
    pub timeout: Duration,
    pub memory_limit_bytes: u64,
    pub fuel: u64,
    pub execution_timeout: Duration,
}

impl PluginConfig {
    pub fn new(executable: PathBuf) -> Self {
        Self {
            executable,
            timeout: MAX_TIMEOUT,
            memory_limit_bytes: MAX_WORKER_MEMORY_BYTES,
            fuel: MAX_FUEL,
            execution_timeout: MAX_EXECUTION_TIMEOUT,
        }
    }
}

struct Permit;

impl Permit {
    fn acquire() -> Result<Self, PluginError> {
        ACTIVE.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).map_err(|_| PluginError::Busy)?;
        Ok(Self)
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
struct Budget<'a> {
    started: Instant,
    timeout: Duration,
    cancellation: Option<&'a AtomicBool>,
}

impl Budget<'_> {
    fn check(self) -> Result<(), PluginError> {
        if self.cancellation.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            return Err(PluginError::Cancelled);
        }
        if self.started.elapsed() >= self.timeout {
            return Err(PluginError::Timeout);
        }
        Ok(())
    }
}

/// Returns admitted contract JSON bytes, not a native report or host-endorsed findings. There is one
/// process-wide admission permit and no queue. It is held through supervisor cleanup and result validation,
/// including cancellation/error returns. Parent fact preparation has its own budget outside this call.
pub fn run_component(
    component: &[u8],
    input: &[u8],
    config: &PluginConfig,
    cancellation: Option<&AtomicBool>,
) -> Result<Vec<u8>, PluginError> {
    let budget = Budget { started: Instant::now(), timeout: config.timeout.min(MAX_TIMEOUT), cancellation };
    budget.check()?;
    let _permit = Permit::acquire()?;
    if !cfg!(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")) {
        return Err(PluginError::UnsupportedPlatform);
    }
    if !config.executable.is_absolute()
        || config.memory_limit_bytes == 0
        || config.fuel == 0
        || config.execution_timeout.as_millis() == 0
    {
        return Err(PluginError::Configuration);
    }
    if component.len() > MAX_COMPONENT_BYTES {
        return Err(PluginError::ComponentTooLarge);
    }
    if component.get(..8) != Some(b"\0asm\x0d\0\x01\0".as_slice()) {
        return Err(PluginError::Preflight);
    }
    let facts = admit_input(input)?;
    budget.check()?;
    let component_hex = protocol::encode_hex(component, || budget.check())?;
    let input_hex = protocol::encode_hex(input, || budget.check())?;
    let execution_timeout = config.execution_timeout.min(MAX_EXECUTION_TIMEOUT);
    let request = protocol::Request {
        version: protocol::VERSION,
        component_hex: &component_hex,
        input_hex: &input_hex,
        fuel: config.fuel.min(MAX_FUEL),
        execution_timeout_ms: execution_timeout.as_millis() as u64,
    };
    let bytes = protocol::serialize(&request, protocol::MAX_REQUEST_BYTES, || budget.check())?;
    budget.check()?;
    let worker = WorkerConfig {
        executable: Some(config.executable.clone()),
        timeout: budget.timeout.saturating_sub(budget.started.elapsed()),
        memory_limit_bytes: config.memory_limit_bytes.min(MAX_WORKER_MEMORY_BYTES),
        max_request_bytes: protocol::MAX_REQUEST_BYTES,
        max_stdout_bytes: protocol::MAX_RESPONSE_BYTES,
        max_stderr_bytes: protocol::MAX_STDERR_BYTES,
    };
    let result = run_supervised_bytes(bytes, &worker, cancellation).map_err(PluginError::from);
    budget.check()?;
    let response = result?;
    let output = match protocol::decode_response(&response)? {
        protocol::Response::Ok { output_hex, .. } => protocol::decode_hex(output_hex, MAX_OUTPUT_BYTES)?,
        protocol::Response::Error { code, .. } => return Err(code),
    };
    admit_output(&output, &facts)?;
    budget.check()?;
    Ok(output)
}

fn admit_input(bytes: &[u8]) -> Result<TriageFacts, PluginError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(PluginError::InputTooLarge);
    }
    rampage_plugin_contract::decode_facts(bytes).map_err(|_| PluginError::InvalidInput)
}

fn admit_output(bytes: &[u8], facts: &TriageFacts) -> Result<(), PluginError> {
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(PluginError::OutputTooLarge);
    }
    rampage_plugin_contract::decode_response(bytes, facts).map(|_| ()).map_err(|_| PluginError::InvalidOutput)
}

/// One-request binary handler. Use only inside the trusted executable's `serve_binary_stdio` lifecycle.
/// No paths, commands, or host tools are accepted over this protocol. Worker errors contain static codes.
#[doc(hidden)]
pub fn serve_stdio() -> Result<(), WorkerError> {
    let result = protocol::read_request(io::stdin().lock()).and_then(|bytes| execute_request(&bytes));
    let output_hex;
    let response = match result {
        Ok(output) => {
            output_hex = protocol::encode_hex(&output, || Ok(())).map_err(worker_protocol_error)?;
            protocol::Response::Ok { version: protocol::VERSION, output_hex: &output_hex }
        }
        Err(code) => protocol::Response::Error { version: protocol::VERSION, code },
    };
    let bytes =
        protocol::serialize(&response, protocol::MAX_RESPONSE_BYTES, || Ok(())).map_err(worker_protocol_error)?;
    io::stdout().lock().write_all(&bytes).map_err(|source| WorkerError::Io { action: "write plugin response", source })
}

fn worker_protocol_error(_: PluginError) -> WorkerError {
    WorkerError::Protocol("plugin response failure".to_owned())
}

fn execute_request(bytes: &[u8]) -> Result<Vec<u8>, PluginError> {
    if !cfg!(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")) {
        return Err(PluginError::UnsupportedPlatform);
    }
    let request = protocol::decode_request(bytes)?;
    if request.fuel == 0
        || request.fuel > MAX_FUEL
        || request.execution_timeout_ms == 0
        || request.execution_timeout_ms > MAX_EXECUTION_TIMEOUT.as_millis() as u64
    {
        return Err(PluginError::Configuration);
    }
    let component = protocol::decode_hex(request.component_hex, MAX_COMPONENT_BYTES)?;
    let input = protocol::decode_hex(request.input_hex, MAX_INPUT_BYTES)?;
    let facts = admit_input(&input)?;
    preflight::admit(&component)?;
    let output =
        runtime::execute(&component, &input, request.fuel, Duration::from_millis(request.execution_timeout_ms))?;
    admit_output(&output, &facts)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FACTS: &str = r#"{
        "schemaVersion":1,"exhaustive":true,"recordTotal":2,"perSection":25,
        "binary":{"id":1,"format":"Elf","arch":"x86_64","entry":null,"sectionCount":0,"segmentCount":0},
        "triage":{"id":2,"imageSize":0,"entropy":0.0,
            "sha256":"0000000000000000000000000000000000000000000000000000000000000000",
            "md5":"00000000000000000000000000000000","hints":[]},
        "detections":[],"managed":null,"capabilities":[],"imports":[],"strings":[],
        "functions":{"status":"available","rows":[]},"signatureMatches":[]
    }"#;

    #[test]
    fn shared_input_admission_handles_decoded_keys_and_text_limits() {
        let escaped = FACTS.replace("schemaVersion", r"schema\u0056ersion");
        assert!(admit_input(escaped.as_bytes()).is_ok());
        let duplicate = FACTS.replace(r#""schemaVersion":1"#, r#""schemaVersion":1,"schema\u0056ersion":1"#);
        assert_eq!(admit_input(duplicate.as_bytes()), Err(PluginError::InvalidInput));
        let text = r"\u00e9".repeat(rampage_plugin_contract::MAX_TEXT_BYTES / 2 + 1);
        let oversized_text = FACTS.replace("Elf", &text);
        assert_eq!(admit_input(oversized_text.as_bytes()), Err(PluginError::InvalidInput));
    }

    #[test]
    fn shared_output_admission_rejects_duplicate_decoded_enum_keys_and_deep_values() {
        let facts = admit_input(FACTS.as_bytes()).expect("valid prepared facts");
        let failure = br#"{"schemaVersion":1,"outcome":{"status":"failure","code":"invalid_input"}}"#;
        assert_eq!(admit_output(failure, &facts), Ok(()));
        let duplicate = br#"{
            "schemaVersion":1,"outcome":{"status":"failure","sta\u0074us":"report","code":"invalid_input"}
        }"#;
        assert_eq!(admit_output(duplicate, &facts), Err(PluginError::InvalidOutput));
        let nested = format!(
            "{}0{}",
            "[".repeat(rampage_plugin_contract::MAX_JSON_DEPTH + 1),
            "]".repeat(rampage_plugin_contract::MAX_JSON_DEPTH + 1)
        );
        assert_eq!(admit_output(nested.as_bytes(), &facts), Err(PluginError::InvalidOutput));
    }

    #[test]
    fn byte_quotas_keep_distinct_static_errors_before_shared_decoding() {
        assert_eq!(admit_input(&vec![b' '; MAX_INPUT_BYTES + 1]), Err(PluginError::InputTooLarge));
        let facts = admit_input(FACTS.as_bytes()).expect("valid prepared facts");
        assert_eq!(admit_output(&vec![b' '; MAX_OUTPUT_BYTES + 1], &facts), Err(PluginError::OutputTooLarge));
    }

    #[test]
    fn admission_is_nonblocking_and_released_by_scope_exit() {
        let permit = Permit::acquire().expect("first permit");
        assert!(matches!(Permit::acquire(), Err(PluginError::Busy)));
        drop(permit);
        assert!(Permit::acquire().is_ok());
    }

    #[test]
    fn diagnostic_worker_text_cannot_escape_static_classification() {
        let error = WorkerError::Exit { status: "secret".to_owned(), stderr: "guest diagnostic".to_owned() };
        assert_eq!(PluginError::from(error).to_string(), "plugin_worker");
    }
}
