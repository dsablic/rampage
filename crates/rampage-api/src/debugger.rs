//! Explicit, bounded queries of an operator-started local LLDB bridge. No image or debugger is opened here.

use std::path::Path;
use std::time::Instant;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ApiError;

pub const MAX_DEBUGGER_REQUEST_BYTES: usize = 16_384;
pub const MAX_DEBUGGER_RESPONSE_BYTES: usize = 262_144;
const DEFAULT_RESPONSE_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebuggerToken {
    pub backend: DebuggerBackend,
    pub session_id: String,
    pub process_unique_id: u64,
    pub stop_id: u64,
    pub target_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DebuggerBackend {
    #[serde(rename = "lldb-sb")]
    LldbSb,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum DebuggerAddress {
    Integer(u64),
    Hex(String),
}

impl DebuggerAddress {
    fn value(&self) -> Result<u64, ApiError> {
        let value = match self {
            Self::Integer(value) => *value,
            Self::Hex(text) => {
                let digits = text.strip_prefix("0x").filter(|digits| {
                    !digits.is_empty() && digits.len() <= 16 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
                u64::from_str_radix(digits.ok_or_else(|| invalid("expected an integer or 0x hexadecimal address"))?, 16)
                    .map_err(|_| invalid("invalid hexadecimal address"))?
            }
        };
        if value == u64::MAX {
            return Err(invalid("address or thread ID exceeds protocol limit"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum DebuggerPermissions {
    #[serde(rename = "r--")]
    Read,
    #[serde(rename = "rw-")]
    ReadWrite,
    #[serde(rename = "r-x")]
    ReadExecute,
    #[serde(rename = "rwx")]
    ReadWriteExecute,
}

/// Only these read-only operations can be serialized onto the socket. Unknown and duplicate fields are refused.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum DebuggerRequest {
    DescribeSession {
        #[schemars(range(min = 1, max = 1))]
        version: u8,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        expected_token: Option<DebuggerToken>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        response_budget: Option<usize>,
    },
    ListModules {
        #[schemars(range(min = 1, max = 1))]
        version: u8,
        expected_token: DebuggerToken,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        response_budget: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        offset: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        limit: Option<usize>,
    },
    ListThreads {
        #[schemars(range(min = 1, max = 1))]
        version: u8,
        expected_token: DebuggerToken,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        response_budget: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        offset: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        limit: Option<usize>,
    },
    ReadRegisters {
        #[schemars(range(min = 1, max = 1))]
        version: u8,
        expected_token: DebuggerToken,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        response_budget: Option<usize>,
        thread_id: DebuggerAddress,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        registers: Option<Vec<String>>,
    },
    ReadMemory {
        #[schemars(range(min = 1, max = 1))]
        version: u8,
        expected_token: DebuggerToken,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        response_budget: Option<usize>,
        address: DebuggerAddress,
        size: usize,
        permissions: DebuggerPermissions,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        thread_id: Option<DebuggerAddress>,
    },
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl DebuggerRequest {
    pub fn from_json(text: &str) -> Result<Self, ApiError> {
        if text.len() > MAX_DEBUGGER_REQUEST_BYTES {
            return Err(invalid("debugger request exceeds 16384 bytes"));
        }
        let value: UniqueValue =
            serde_json::from_str(text).map_err(|error| invalid(&format!("invalid request: {error}")))?;
        let request: Self =
            serde_json::from_value(value.0).map_err(|error| invalid(&format!("invalid request: {error}")))?;
        request.validate()?;
        Ok(request)
    }

    pub fn operation(&self) -> &'static str {
        match self {
            Self::DescribeSession { .. } => "describe_session",
            Self::ListModules { .. } => "list_modules",
            Self::ListThreads { .. } => "list_threads",
            Self::ReadRegisters { .. } => "read_registers",
            Self::ReadMemory { .. } => "read_memory",
        }
    }

    fn common(&self) -> (u8, Option<&DebuggerToken>, Option<usize>) {
        match self {
            Self::DescribeSession { version, expected_token, response_budget } => {
                (*version, expected_token.as_ref(), *response_budget)
            }
            Self::ListModules { version, expected_token, response_budget, .. }
            | Self::ListThreads { version, expected_token, response_budget, .. }
            | Self::ReadRegisters { version, expected_token, response_budget, .. }
            | Self::ReadMemory { version, expected_token, response_budget, .. } => {
                (*version, Some(expected_token), *response_budget)
            }
        }
    }

    /// Tool callers can narrow a response, but never enlarge the caller's requested budget.
    pub(crate) fn cap_response_budget(&mut self, maximum: usize) {
        let budget = match self {
            Self::DescribeSession { response_budget, .. }
            | Self::ListModules { response_budget, .. }
            | Self::ListThreads { response_budget, .. }
            | Self::ReadRegisters { response_budget, .. }
            | Self::ReadMemory { response_budget, .. } => response_budget,
        };
        *budget = Some(budget.unwrap_or(DEFAULT_RESPONSE_BYTES).min(maximum));
    }

    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        let (version, token, budget) = self.common();
        if version != 1 || !(1024..=MAX_DEBUGGER_RESPONSE_BYTES).contains(&budget.unwrap_or(DEFAULT_RESPONSE_BYTES)) {
            return Err(invalid("version must be 1 and response_budget must be in 1024..=262144"));
        }
        if let Some(token) = token {
            validate_token(token)?;
        }
        match self {
            Self::ListModules { offset, limit, .. } | Self::ListThreads { offset, limit, .. } => {
                if offset.unwrap_or(0) > 4096 || !(1..=128).contains(&limit.unwrap_or(32)) {
                    return Err(invalid("offset must be in 0..=4096 and limit in 1..=128"));
                }
            }
            Self::ReadRegisters { thread_id, registers, .. } => {
                validate_thread(thread_id)?;
                if let Some(names) = registers {
                    let unique: std::collections::BTreeSet<_> = names.iter().collect();
                    if names.is_empty()
                        || names.len() > 34
                        || unique.len() != names.len()
                        || names.iter().any(|name| !allowed_register(name))
                    {
                        return Err(invalid("registers must be unique read-only register names (1..=34)"));
                    }
                }
            }
            Self::ReadMemory { address, size, thread_id, .. } => {
                if !(1..=65536).contains(size) || address.value()?.checked_add(*size as u64).is_none() {
                    return Err(invalid("memory size must be in 1..=65536 and the range must not overflow"));
                }
                if let Some(thread) = thread_id {
                    validate_thread(thread)?;
                }
            }
            Self::DescribeSession { .. } => {}
        }
        Ok(())
    }
}

fn allowed_register(name: &str) -> bool {
    if matches!(
        name,
        "sp" | "lr" | "pc" | "cpsr" | "rax" | "rbx" | "rcx" | "rdx" | "rdi" | "rsi" | "rbp" | "rsp" | "rip" | "rflags"
    ) {
        return true;
    }
    for (prefix, maximum) in [('x', 30), ('r', 15)] {
        if let Some(digits) = name.strip_prefix(prefix)
            && let Ok(index) = digits.parse::<u8>()
            && index <= maximum
            && digits == index.to_string()
        {
            return true;
        }
    }
    false
}

fn validate_thread(thread: &DebuggerAddress) -> Result<(), ApiError> {
    if thread.value()? == 0 {
        return Err(invalid("thread_id must be positive"));
    }
    Ok(())
}

fn validate_token(token: &DebuggerToken) -> Result<(), ApiError> {
    if !(1..=128).contains(&token.session_id.chars().count())
        || token.process_unique_id == 0
        || token.target_index == u32::MAX
    {
        return Err(invalid("invalid debugger stop token"));
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebuggerObservation {
    pub content_sha256: String,
    pub consistency: String,
    pub atomic_snapshot: bool,
    pub identity_scope: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebuggerError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebuggerResponse {
    pub protocol: String,
    pub ok: bool,
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<DebuggerToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<DebuggerObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DebuggerError>,
}

/// Sends one JSON line and write-half-closes before receiving one response line and EOF.
/// `deadline` bounds connecting, writing, receiving the frame and waiting for the server to close it.
pub fn query_debugger(
    socket: &Path,
    request: &DebuggerRequest,
    deadline: Instant,
) -> Result<DebuggerResponse, ApiError> {
    request.validate()?;
    remaining(deadline)?;
    let mut encoded = serde_json::to_vec(request).map_err(|error| invalid(&error.to_string()))?;
    if encoded.len() > MAX_DEBUGGER_REQUEST_BYTES {
        return Err(invalid("debugger request exceeds 16384 bytes"));
    }
    encoded.push(b'\n');
    let budget = request.common().2.unwrap_or(DEFAULT_RESPONSE_BYTES);
    let bytes = transport::exchange(socket, &encoded, budget, deadline)?;
    let value: UniqueValue =
        serde_json::from_slice(&bytes).map_err(|error| invalid(&format!("malformed debugger response: {error}")))?;
    let value = value.0;
    let object = value.as_object().ok_or_else(|| invalid("debugger response must be an object"))?;
    let keys: &[&str] = if object.get("ok") == Some(&Value::Bool(true)) {
        &["protocol", "ok", "operation", "token", "data", "observation"]
    } else {
        &["protocol", "ok", "operation", "error"]
    };
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid("malformed debugger response envelope"));
    }
    let response: DebuggerResponse =
        serde_json::from_value(value).map_err(|error| invalid(&format!("malformed debugger response: {error}")))?;
    if response.protocol != "rampage-lldb-query-v1"
        || response.operation.as_deref().is_some_and(|operation| operation != request.operation())
        || response.ok && response.operation.as_deref() != Some(request.operation())
    {
        return Err(invalid("debugger response protocol or operation mismatch"));
    }
    if response.ok {
        if response.error.is_some() || !response.data.as_ref().is_some_and(Value::is_object) {
            return Err(invalid("malformed successful debugger response"));
        }
        let token = response.token.as_ref().ok_or_else(|| invalid("missing debugger stop token"))?;
        validate_token(token)?;
        if request.common().1.is_some_and(|expected| expected != token) {
            return Err(invalid("debugger response stop token mismatch"));
        }
        let observation = response.observation.as_ref().ok_or_else(|| invalid("missing observation evidence"))?;
        if observation.atomic_snapshot
            || observation.consistency != "revalidated-non-atomic"
            || observation.identity_scope.is_empty()
            || observation.content_sha256.len() != 64
            || !observation.content_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("invalid debugger observation evidence"));
        }
    } else if response.token.is_some()
        || response.data.is_some()
        || response.observation.is_some()
        || !response.error.as_ref().is_some_and(|error| !error.code.is_empty() && !error.message.is_empty())
    {
        return Err(invalid("malformed debugger error response"));
    }
    remaining(deadline)?;
    Ok(response)
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

fn remaining(deadline: Instant) -> Result<std::time::Duration, ApiError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| ApiError::Unavailable("debugger query deadline exceeded".to_owned()))
}

// Deserializing arbitrary evidence must not silently collapse duplicate JSON fields.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate fields")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<UniqueValue, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<UniqueValue, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<UniqueValue, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<UniqueValue, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<UniqueValue, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<UniqueValue, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<UniqueValue, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<UniqueValue, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON field"));
                    }
                    values.insert(key, map.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
mod transport {
    use super::*;
    pub fn exchange(_: &Path, _: &[u8], _: usize, _: Instant) -> Result<Vec<u8>, ApiError> {
        Err(ApiError::Unavailable("local debugger Unix socket transport is unavailable on this platform".to_owned()))
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
mod transport {
    use super::*;
    use std::ffi::{c_int, c_void};
    use std::fs::{File, Metadata};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::path::Component;

    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    fn io_error(error: impl std::fmt::Display) -> ApiError {
        ApiError::Unavailable(format!("local debugger socket: {error}"))
    }

    struct CheckedPath {
        directories: Vec<File>,
        socket: Metadata,
    }

    fn check_path(path: &Path) -> Result<CheckedPath, ApiError> {
        use rustix::fs::{Mode, OFlags, open, openat};
        if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
            return Err(invalid("debugger socket must be an explicit absolute path"));
        }
        if path
            .as_os_str()
            .as_bytes()
            .split(|byte| *byte == b'/')
            .skip(1)
            .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            return Err(invalid("debugger socket path must not contain empty, dot or parent components"));
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = File::from(open("/", flags, Mode::empty()).map_err(io_error)?);
        let mut directories = Vec::new();
        let mut components = path.components().skip(1).peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(invalid("debugger socket path must not contain dot or parent components"));
            };
            if components.peek().is_some() {
                directory = File::from(openat(&directory, name, flags, Mode::empty()).map_err(io_error)?);
                directories.push(directory.try_clone().map_err(io_error)?);
            }
        }
        let parent = directory.metadata().map_err(io_error)?;
        // SAFETY: geteuid takes no arguments and has no memory safety preconditions.
        let uid = unsafe { geteuid() };
        if parent.uid() != uid || parent.mode() & 0o7777 != 0o700 {
            return Err(invalid("debugger socket parent must be a same-user private 0700 directory"));
        }
        let socket = std::fs::symlink_metadata(path).map_err(io_error)?;
        if !socket.file_type().is_socket() || socket.uid() != uid || socket.mode() & 0o7777 != 0o600 {
            return Err(invalid("debugger socket must be a same-user 0600 socket, not a symlink"));
        }
        Ok(CheckedPath { directories, socket })
    }

    fn same_file(first: &Metadata, second: &Metadata) -> bool {
        first.dev() == second.dev()
            && first.ino() == second.ino()
            && first.uid() == second.uid()
            && first.mode() == second.mode()
    }

    pub fn exchange(path: &Path, request: &[u8], budget: usize, deadline: Instant) -> Result<Vec<u8>, ApiError> {
        let checked = check_path(path)?;
        remaining(deadline)?;
        let mut stream = connect(path, deadline)?;
        let after = check_path(path)?;
        if !same_file(&checked.socket, &after.socket) || checked.directories.len() != after.directories.len() {
            return Err(invalid("debugger socket changed while connecting"));
        }
        for (before, after) in checked.directories.iter().zip(&after.directories) {
            if !same_file(&before.metadata().map_err(io_error)?, &after.metadata().map_err(io_error)?) {
                return Err(invalid("debugger socket directory changed while connecting"));
            }
        }
        verify_peer(&stream)?;
        let mut pending = request;
        while !pending.is_empty() {
            remaining(deadline)?;
            match stream.write(pending) {
                Ok(0) => return Err(io_error("socket closed during request")),
                Ok(count) => pending = &pending[count..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => wait(&stream, 4, deadline)?,
                Err(error) => return Err(io_error(error)),
            }
        }
        remaining(deadline)?;
        stream.shutdown(std::net::Shutdown::Write).map_err(io_error)?;
        let mut frame = Vec::new();
        let mut buffer = [0; 4096];
        let mut terminated = false;
        loop {
            remaining(deadline)?;
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if frame.len() + count > budget + 1 {
                        return Err(invalid("debugger response exceeds response byte budget"));
                    }
                    if terminated || buffer[..count].contains(&b'\r') {
                        return Err(invalid("trailing data after debugger response"));
                    }
                    if let Some(end) = buffer[..count].iter().position(|byte| *byte == b'\n') {
                        if end != count - 1 {
                            return Err(invalid("trailing data after debugger response"));
                        }
                        terminated = true;
                    }
                    frame.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => wait(&stream, 1, deadline)?,
                Err(error) => return Err(io_error(error)),
            }
        }
        if frame.pop() != Some(b'\n') || frame.is_empty() {
            return Err(invalid("truncated debugger response: expected one JSON line and EOF"));
        }
        Ok(frame)
    }

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    type PollCount = usize;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    type PollCount = u32;

    unsafe extern "C" {
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        #[link_name = "connect"]
        fn socket_connect(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn poll(fds: *mut PollFd, count: PollCount, timeout: c_int) -> c_int;
        fn getsockopt(fd: c_int, level: c_int, option: c_int, value: *mut c_void, length: *mut u32) -> c_int;
    }

    fn wait(stream: &UnixStream, events: i16, deadline: Instant) -> Result<(), ApiError> {
        loop {
            let timeout = remaining(deadline)?.as_millis().saturating_add(1).min(c_int::MAX as u128) as c_int;
            let mut descriptor = PollFd { fd: stream.as_raw_fd(), events, revents: 0 };
            // SAFETY: one initialized pollfd is borrowed for the duration of poll.
            let result = unsafe { poll(&mut descriptor, 1, timeout) };
            if result > 0 {
                remaining(deadline)?;
                return Ok(());
            }
            if result == 0 {
                return Err(io_error("debugger query deadline exceeded"));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(io_error(error));
            }
        }
    }

    fn connect(path: &Path, deadline: Instant) -> Result<UnixStream, ApiError> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const CAPACITY: usize = 108;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        const CAPACITY: usize = 104;
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() >= CAPACITY {
            return Err(invalid("debugger socket path exceeds Unix socket address capacity"));
        }
        // SAFETY: socket has no pointer arguments; the successful descriptor is immediately owned.
        let raw = unsafe { socket(1, 1, 0) };
        if raw < 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        // SAFETY: raw is a newly created descriptor owned by this function.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC).map_err(io_error)?;
        let stream = UnixStream::from(fd);
        stream.set_nonblocking(true).map_err(io_error)?;
        #[repr(C, align(2))]
        struct Address {
            header: [u8; 2],
            path: [u8; CAPACITY],
        }
        let length = 2 + bytes.len() + 1;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let header = 1u16.to_ne_bytes();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let header = [length as u8, 1];
        let mut address = Address { header, path: [0; CAPACITY] };
        address.path[..bytes.len()].copy_from_slice(bytes);
        // SAFETY: address is a sockaddr_un with initialized bytes and an in-bounds length.
        let result = unsafe { socket_connect(stream.as_raw_fd(), (&address as *const Address).cast(), length as u32) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let pending = error.raw_os_error() == Some(115);
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let pending = error.raw_os_error() == Some(36);
            if !pending {
                return Err(io_error(error));
            }
            wait(&stream, 4, deadline)?;
            let mut error: c_int = 0;
            let mut size = std::mem::size_of::<c_int>() as u32;
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let (level, option) = (1, 4);
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let (level, option) = (0xffff, 0x1007);
            // SAFETY: getsockopt writes only to the initialized integer and its length.
            let result =
                unsafe { getsockopt(stream.as_raw_fd(), level, option, (&mut error as *mut c_int).cast(), &mut size) };
            if result < 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            if error != 0 {
                return Err(io_error(std::io::Error::from_raw_os_error(error)));
            }
        }
        remaining(deadline)?;
        Ok(stream)
    }

    fn verify_peer(stream: &UnixStream) -> Result<(), ApiError> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let peer_uid = {
            #[repr(C)]
            struct Credentials {
                pid: c_int,
                uid: u32,
                gid: u32,
            }
            let mut credentials = Credentials { pid: 0, uid: 0, gid: 0 };
            let mut length = std::mem::size_of::<Credentials>() as u32;
            // SAFETY: SO_PEERCRED receives an initialized, correctly sized credentials structure.
            let result = unsafe {
                getsockopt(stream.as_raw_fd(), 1, 17, (&mut credentials as *mut Credentials).cast(), &mut length)
            };
            if result < 0 || length != std::mem::size_of::<Credentials>() as u32 {
                return Err(io_error("cannot verify debugger socket peer UID"));
            }
            credentials.uid
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let peer_uid = {
            unsafe extern "C" {
                fn getpeereid(fd: c_int, uid: *mut u32, gid: *mut u32) -> c_int;
            }
            let (mut uid, mut gid) = (0, 0);
            // SAFETY: getpeereid writes to two initialized IDs.
            if unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } < 0 {
                return Err(io_error("cannot verify debugger socket peer UID"));
            }
            uid
        };
        // SAFETY: geteuid takes no arguments and has no memory safety preconditions.
        if peer_uid != unsafe { geteuid() } {
            return Err(invalid("debugger socket peer is not the current user"));
        }
        Ok(())
    }
}
