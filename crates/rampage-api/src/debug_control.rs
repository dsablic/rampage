//! Read-only debug sessions with operator-started GDB remote stubs (phase 9.1): the per-connection registry the
//! `debug` tools use, and capture of a stopped target into a `rampage-snapshot-v1` file. Nothing here launches,
//! attaches to, resumes, steps, sets breakpoints in, writes to or kills a target; `rampage-debug` refuses to send
//! any packet that would.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rampage_arch::Arch;
use rampage_debug::{ByteOrder, Config, Endpoint, Family, Session, ThreadId};
use rampage_loaders::snapshot::{
    Snapshot, SnapshotModule, SnapshotPlatform, SnapshotRegion, SnapshotRegister, SnapshotTarget,
};
use serde::Serialize;

use crate::ApiError;
use crate::rows::{FittedPage, item_budget};

/// Most sessions one MCP connection may hold.
pub const MAX_DEBUG_SESSIONS: usize = 4;
/// Most bytes one snapshot range may capture.
pub const MAX_SNAPSHOT_RANGE_BYTES: u64 = 16 * 1024 * 1024;
/// Most bytes one snapshot may capture in all.
pub const MAX_SNAPSHOT_BYTES: u64 = rampage_loaders::snapshot::MAX_SNAPSHOT_BYTES as u64;
/// Most ranges in one snapshot.
pub const MAX_SNAPSHOT_RANGES: usize = 256;
/// Most threads whose registers a snapshot records.
pub const MAX_SNAPSHOT_THREADS: usize = 64;
/// Default threads per page.
const DEFAULT_THREAD_PAGE: usize = 64;
/// Most modules, and most register entries, the snapshot loader accepts.
const MAX_SNAPSHOT_ENTRIES: usize = 4096;
/// JSON bytes a snapshot may spend on everything but memory: the headroom above twice the 64 MiB memory limit.
const SNAPSHOT_METADATA_BYTES: usize =
    crate::debugger_capture::MAX_PRIVATE_DOCUMENT_BYTES - 2 * rampage_loaders::snapshot::MAX_SNAPSHOT_BYTES;
/// JSON bytes a memory result spends per chunk beyond its hex, at most: the chunk's own report with a stub error,
/// and a new run of bytes after it.
const MEMORY_CHUNK_JSON: usize = 220;
/// JSON bytes of a memory result besides its chunks and hex.
const MEMORY_RESULT_JSON: usize = 2000;

/// The most bytes one `debug_read_memory` call may read so its whole result, every chunk's report included, fits
/// the tool result budget, for a stub whose memory requests carry `chunk` bytes each.
pub fn tool_read_limit(chunk: usize) -> usize {
    let budget = crate::tools::MAX_RESULT_CHARS - MEMORY_RESULT_JSON;
    let per_chunk = 2 * chunk + MEMORY_CHUNK_JSON;
    let full = budget / per_chunk;
    let rest = budget % per_chunk;
    let partial = if rest > MEMORY_CHUNK_JSON { ((rest - MEMORY_CHUNK_JSON) / 2).min(chunk - 1) } else { 0 };
    (full * chunk + partial).clamp(1, rampage_debug::MAX_MEMORY_READ)
}

const NOT_ATOMIC: &str = "reads are separate requests to a stopped target, not an atomic snapshot: anything else \
                          attached to the stub (another debugger, DMA, other cores) can change memory between them";

/// The debug endpoints an operator allowed, and the sessions one MCP connection opened to them. Dropping the
/// registry detaches every session, as each session detaches when its last handle drops.
pub struct DebugRegistry {
    endpoints: Vec<(String, Endpoint)>,
    sessions: Mutex<BTreeMap<u32, Arc<Session>>>,
    /// Slots held by connections still in their handshake.
    reserved: Mutex<usize>,
    next: AtomicU32,
    config: Config,
}

impl std::fmt::Debug for DebugRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DebugRegistry").field("endpoints", &self.endpoints()).finish_non_exhaustive()
    }
}

fn failure(code: &str, message: impl std::fmt::Display) -> ApiError {
    let text = format!("{code}: {message}");
    match code {
        "unknown_session" => ApiError::NotFound(text),
        "timeout" | "connection_lost" | "session_limit" | "connect_failed" => ApiError::Unavailable(text),
        _ => ApiError::Invalid(text),
    }
}

fn debug_failure(error: rampage_debug::DebugError) -> ApiError {
    failure(error.code(), error)
}

impl DebugRegistry {
    /// A registry allowing exactly `endpoints` (`host:port` or `unix:/path`). Duplicates collapse.
    pub fn new(endpoints: &[String]) -> Result<Self, String> {
        let mut allowed: Vec<(String, Endpoint)> = Vec::new();
        for text in endpoints {
            let endpoint: Endpoint = text.parse()?;
            if !allowed.iter().any(|(_, known)| *known == endpoint) {
                allowed.push((text.trim().to_owned(), endpoint));
            }
        }
        Ok(Self {
            endpoints: allowed,
            sessions: Mutex::default(),
            reserved: Mutex::default(),
            next: AtomicU32::new(1),
            config: Config::default(),
        })
    }

    /// The same registry with other connection and per-request timeouts.
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// The most bytes one `debug_read_memory` call on session `id` may read; see [`tool_read_limit`].
    pub fn tool_read_limit(&self, id: &str) -> Result<usize, ApiError> {
        Ok(tool_read_limit(self.session(id)?.info().chunk_size()))
    }

    /// The allowed endpoints, as the operator wrote them.
    pub fn endpoints(&self) -> Vec<String> {
        self.endpoints.iter().map(|(text, _)| text.clone()).collect()
    }

    fn session(&self, id: &str) -> Result<Arc<Session>, ApiError> {
        let number = id.strip_prefix('s').and_then(|number| number.parse::<u32>().ok());
        let sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        number
            .and_then(|number| sessions.get(&number).cloned())
            .ok_or_else(|| failure("unknown_session", format!("no open debug session `{id}`; call debug_connect")))
    }

    /// Connects to `endpoint`, which must be one the operator allowed (it may be omitted when exactly one is).
    pub fn connect(&self, endpoint: Option<&str>) -> Result<DebugConnection, ApiError> {
        let allowed = self.endpoints();
        let endpoint = match endpoint {
            Some(requested) => self
                .endpoints
                .iter()
                .find(|(text, endpoint)| text == requested || endpoint.to_string() == requested)
                .map(|(_, endpoint)| endpoint)
                .ok_or_else(|| {
                    failure(
                        "endpoint_not_allowed",
                        format!("`{requested}` is not an allowed debug endpoint (allowed: {})", allowed.join(", ")),
                    )
                })?,
            None => match &self.endpoints[..] {
                [(_, endpoint)] => endpoint,
                _ => {
                    return Err(failure(
                        "invalid_argument",
                        format!("several debug endpoints are allowed; name one of: {}", allowed.join(", ")),
                    ));
                }
            },
        };
        // A slot is reserved before connecting, so concurrent connects cannot exceed the limit and the loser of a
        // race for the last slot never contacts its stub.
        {
            let sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
            let mut reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
            if sessions.len() + *reserved >= MAX_DEBUG_SESSIONS {
                return Err(failure(
                    "session_limit",
                    format!("at most {MAX_DEBUG_SESSIONS} debug sessions may be open; disconnect one first"),
                ));
            }
            *reserved += 1;
        }
        let connected = Session::connect(endpoint, self.config)
            .map_err(debug_failure)
            .and_then(|session| session.status().map_err(debug_failure).map(|status| (Arc::new(session), status)));
        // Only a connected session takes an ID, so a failed attempt does not shift the next one.
        let number = {
            let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
            *self.reserved.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
            connected.as_ref().ok().map(|(session, _)| {
                let number = self.next.fetch_add(1, Ordering::Relaxed);
                sessions.insert(number, Arc::clone(session));
                number
            })
        };
        let (session, status) = connected?;
        let number = number.expect("a connected session has an ID");
        let id = format!("s{number}");
        let info = session.info();
        let mut connection = DebugConnection {
            session: id,
            endpoint: info.endpoint.clone(),
            local_endpoint: info.local,
            architecture: info.architecture.clone(),
            family: info.family,
            endianness: info.byte_order,
            endianness_evidence: info.byte_order_evidence.clone(),
            pointer_size: info.pointer_size,
            register_count: info.layout.as_ref().map_or(0, |layout| layout.registers.len()),
            layout_source: info.layout.as_ref().map(|layout| layout.source.clone()),
            features: info.features.clone(),
            packet_size: info.packet_size,
            no_ack_mode: info.no_ack_mode,
            state: status.state.clone(),
            epoch: status.epoch,
            stop: status.stop.clone(),
            modules_available: info.modules_available,
            memory_map_available: info.memory_map_available,
            max_read_length: tool_read_limit(info.chunk_size()),
            limitations: info.limitations.clone(),
            threads: FittedPage::empty(),
        };
        let budget = item_budget(&connection)?;
        connection.threads = FittedPage::of(status.threads, None, Some(DEFAULT_THREAD_PAGE), budget)?;
        Ok(connection)
    }

    /// The session's state, stop and a page of its threads (refreshed from the stub while it is stopped).
    pub fn status(&self, id: &str, offset: Option<usize>, limit: Option<usize>) -> Result<DebugStatus, ApiError> {
        let session = self.session(id)?;
        let status = session.status().map_err(debug_failure)?;
        let mut result = DebugStatus {
            session: id.to_owned(),
            state: status.state,
            epoch: status.epoch,
            stop: status.stop,
            console: status.console,
            threads: FittedPage::empty(),
        };
        let budget = item_budget(&result)?;
        result.threads = FittedPage::of(status.threads, offset, Some(page(limit)), budget)?;
        Ok(result)
    }

    /// Registers of `thread` (the stub's current thread when omitted), all or the named ones.
    pub fn registers(
        &self,
        id: &str,
        thread: Option<&str>,
        names: Option<&[String]>,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<DebugRegisters, ApiError> {
        let session = self.session(id)?;
        let thread = thread.map(parse_thread).transpose()?;
        if let Some(names) = names {
            let unique: std::collections::BTreeSet<_> = names.iter().collect();
            if names.is_empty() || names.len() > 256 || unique.len() != names.len() {
                return Err(failure("invalid_argument", "names must be 1..=256 distinct register names"));
            }
            let layout = session.info().layout.as_ref();
            let unknown: Vec<&str> = names
                .iter()
                .filter(|name| layout.is_none_or(|layout| layout.register(name).is_none()))
                .map(String::as_str)
                .take(16)
                .collect();
            if !unknown.is_empty() {
                return Err(failure("invalid_argument", format!("unknown registers: {}", unknown.join(", "))));
            }
        }
        let registers = session.registers(thread).map_err(debug_failure)?;
        let selected: Vec<_> = registers
            .registers
            .into_iter()
            .filter(|register| names.is_none_or(|names| names.contains(&register.name)))
            .collect();
        let mut result = DebugRegisters {
            session: id.to_owned(),
            thread: registers.thread,
            epoch: registers.epoch,
            endianness: registers.byte_order,
            limitations: match registers.byte_order {
                ByteOrder::Unknown => vec![format!(
                    "data byte order is unknown ({}); `value` is null and `bytes` are as the stub sent them",
                    session.info().byte_order_evidence
                )],
                _ => Vec::new(),
            },
            registers: FittedPage::empty(),
        };
        let budget = item_budget(&result)?;
        result.registers = FittedPage::of(selected, offset, Some(limit.unwrap_or(256).min(4096)), budget)?;
        Ok(result)
    }

    /// Reads `length` (1..=65536) bytes at `address`. Unreadable parts are reported per chunk.
    pub fn read_memory(
        &self,
        id: &str,
        address: u64,
        length: usize,
        thread: Option<&str>,
    ) -> Result<DebugMemory, ApiError> {
        let session = self.session(id)?;
        let thread = thread.map(parse_thread).transpose()?;
        let read = session.read_memory(address, length, thread).map_err(debug_failure)?;
        let complete = read.complete();
        let mut data: Vec<DebugBytes> = Vec::new();
        for chunk in &read.chunks {
            // `end` is where a run would continue: `None` after a gap or at the top of the address space.
            match data.last_mut() {
                Some(run) if run.end == Some(chunk.address) && !chunk.bytes.is_empty() => {
                    run.hex.push_str(&rampage_arch::hex::bytes(&chunk.bytes));
                    run.end = chunk.address.checked_add(chunk.bytes.len() as u64);
                }
                _ if !chunk.bytes.is_empty() => data.push(DebugBytes {
                    address: chunk.address,
                    end: chunk.address.checked_add(chunk.bytes.len() as u64),
                    hex: rampage_arch::hex::bytes(&chunk.bytes),
                }),
                _ => {}
            }
            if chunk.read < chunk.requested
                && let Some(run) = data.last_mut()
            {
                run.end = None;
            }
        }
        Ok(DebugMemory {
            session: id.to_owned(),
            address: read.address,
            length: read.length,
            epoch: read.epoch,
            packet: read.packet,
            thread: read.thread,
            bytes_read: read.chunks.iter().map(|chunk| chunk.read).sum(),
            complete,
            data,
            chunks: read.chunks,
            atomic: false,
            limitations: vec![NOT_ATOMIC.to_owned()],
        })
    }

    /// Loaded modules and memory-map regions, as the stub reports them.
    pub fn modules(&self, id: &str, offset: Option<usize>, limit: Option<usize>) -> Result<DebugModules, ApiError> {
        let session = self.session(id)?;
        let modules = session.modules().map_err(debug_failure)?;
        let regions_total = modules.regions.len();
        let mut result = DebugModules {
            session: id.to_owned(),
            regions: modules.regions.into_iter().take(256).collect(),
            regions_total,
            exec_file: modules.exec_file,
            offsets: modules.offsets,
            limitations: modules.limitations,
            modules: FittedPage::empty(),
        };
        if regions_total > result.regions.len() {
            result.limitations.push(format!("only the first 256 of {regions_total} memory-map regions are listed"));
        }
        result.limitations.push(
            "modules are not matched to files on disk or to a project; l_addr is a load bias, not a header address"
                .into(),
        );
        let budget = item_budget(&result)?;
        result.modules = FittedPage::of(modules.modules, offset, Some(page(limit)), budget)?;
        Ok(result)
    }

    /// Detaches and closes the session, returning its final state. A stub that refuses to detach (`E nn`) leaves
    /// the session open and attached: the result says so, and disconnecting can be retried.
    pub fn disconnect(&self, id: &str) -> Result<DebugDisconnected, ApiError> {
        let session = self.session(id)?;
        let number = id.strip_prefix('s').and_then(|number| number.parse::<u32>().ok()).expect("a known session id");
        let (state, error, closed) = match session.detach() {
            Ok(state) => (state, None, true),
            Err(error @ rampage_debug::DebugError::Target(_)) => {
                (rampage_debug::State::Stopped, Some(format!("{}: {error}", error.code())), false)
            }
            Err(error) => (
                rampage_debug::State::Lost { reason: error.to_string() },
                Some(format!("{}: {error}", error.code())),
                true,
            ),
        };
        if closed {
            self.sessions.lock().unwrap_or_else(PoisonError::into_inner).remove(&number);
        }
        Ok(DebugDisconnected { session: id.to_owned(), state, detached: error.is_none(), closed, detach_error: error })
    }

    /// Captures `ranges` of the stopped target, every thread's registers and its modules into a new
    /// `rampage-snapshot-v1` file at `output`, which must not exist. Everything except memory is gathered and
    /// checked against the snapshot loader's limits before any memory is read.
    pub fn snapshot(&self, id: &str, output: &Path, ranges: &[DebugRange]) -> Result<DebugSnapshot, ApiError> {
        let session = self.session(id)?;
        let info = session.info();
        let arch = match info.family {
            Family::X86 => Arch::X86,
            Family::X86_64 => Arch::X86_64,
            Family::Aarch64 => Arch::Aarch64,
            Family::Arm => Arch::Arm,
            Family::Riscv32 => Arch::Riscv32,
            Family::Riscv64 => Arch::Riscv64,
            Family::Other => {
                return Err(failure(
                    "unsupported",
                    format!(
                        "the target architecture `{}` has no rampage snapshot architecture",
                        info.architecture.as_deref().unwrap_or("unknown")
                    ),
                ));
            }
        };
        let data_big_endian = match info.byte_order {
            ByteOrder::Little => false,
            ByteOrder::Big => true,
            ByteOrder::Unknown => {
                return Err(failure(
                    "unsupported",
                    format!(
                        "a snapshot must declare its data byte order and nothing establishes it for this target \
                         ({}); architecture defaults are not used",
                        info.byte_order_evidence
                    ),
                ));
            }
        };
        let ranges = validate_ranges(ranges)?;
        // Status re-reads the stop reply and threads, so comparing it before and after the capture detects a
        // target that stopped anew or changed threads in between.
        let status = session.status().map_err(debug_failure)?;
        if status.state != rampage_debug::State::Stopped {
            return Err(failure("session_not_stopped", "the session is not stopped"));
        }
        if status.threads.len() > MAX_SNAPSHOT_THREADS {
            return Err(failure(
                "unsupported",
                format!(
                    "the target has {} threads; a snapshot records at most {MAX_SNAPSHOT_THREADS}",
                    status.threads.len()
                ),
            ));
        }
        let threads: Vec<Option<ThreadId>> = if status.threads.is_empty() {
            vec![None]
        } else {
            status.threads.iter().map(|thread| Some(thread.id)).collect()
        };
        let pids: std::collections::BTreeSet<Option<u64>> =
            threads.iter().map(|thread| thread.and_then(|thread| thread.pid)).collect();
        let mut registers = Vec::new();
        let mut skipped = 0;
        for thread in threads {
            let values = session.registers(thread).map_err(debug_failure)?;
            let thread_id = snapshot_thread_id(values.thread.or(thread), pids.len() > 1)?;
            for register in values.registers {
                let representable = register.name.len() <= 32
                    && register.name.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    && register.bitsize <= 64;
                match register.integer() {
                    Some(value) if representable => registers.push(SnapshotRegister {
                        thread_id: thread_id.clone(),
                        name: register.name,
                        value: format!("{value:#x}"),
                    }),
                    _ => skipped += 1,
                }
            }
            if registers.len() > MAX_SNAPSHOT_ENTRIES {
                return Err(failure(
                    "unsupported",
                    format!(
                        "the threads' registers exceed the snapshot format's {MAX_SNAPSHOT_ENTRIES} register entries; \
                         nothing was read from memory or written"
                    ),
                ));
            }
        }
        let modules =
            if info.modules_available { session.modules().map_err(debug_failure)?.modules } else { Vec::new() };
        let snapshot_modules = snapshot_modules(&modules)?;
        let thumb_default = info.family == Family::Arm && rampage_debug::target::m_profile(info.layout.as_ref());
        let mut snapshot = Snapshot {
            format: "rampage-snapshot-v1".into(),
            arch: arch.to_string(),
            big_endian: false,
            data_big_endian,
            provenance: format!(
                "rampage debug_snapshot of GDB remote endpoint {} (session {id}, stop epoch {}); data byte order: {}; \
                 {NOT_ATOMIC}; module image_base 0 with runtime_base = svr4 l_addr records the load bias, not \
                 header addresses",
                info.endpoint, status.epoch, info.byte_order_evidence
            ),
            regions: ranges
                .iter()
                .map(|range| SnapshotRegion {
                    name: format!("debug-{:#x}", range.address),
                    address: format!("{:#x}", range.address),
                    permissions: range.permissions.clone(),
                    bytes: String::new(),
                    thumb: range.thumb.unwrap_or(thumb_default && range.permissions.ends_with('x')),
                })
                .collect(),
            seeds: Vec::new(),
            entry: None,
            modules: snapshot_modules,
            registers,
            target: Some(SnapshotTarget { platform: SnapshotPlatform::Default, compiler: None }),
        };
        // Memory takes at most 2 * 64 MiB of hex; everything else must fit the remaining MiB.
        let skeleton = serde_json::to_vec(&snapshot).map_err(|error| failure("invalid_argument", error))?.len();
        if skeleton > SNAPSHOT_METADATA_BYTES {
            return Err(failure(
                "unsupported",
                format!(
                    "the snapshot's registers, modules and paths take {skeleton} bytes, over its \
                     {SNAPSHOT_METADATA_BYTES}-byte budget; nothing was read from memory or written"
                ),
            ));
        }
        for (region, range) in snapshot.regions.iter_mut().zip(&ranges) {
            let mut hex = String::with_capacity(range.length as usize * 2);
            let mut done = 0u64;
            while done < range.length {
                let at = range.address + done;
                let size = (range.length - done).min(rampage_debug::MAX_MEMORY_READ as u64) as usize;
                let read = session.read_memory(at, size, None).map_err(debug_failure)?;
                if let Some(chunk) = read.chunks.iter().find(|chunk| chunk.error.is_some()) {
                    return Err(failure(
                        "target_error",
                        format!(
                            "memory at {:#x} is not fully readable ({}); a snapshot never records partial regions",
                            chunk.address,
                            chunk.error.as_deref().unwrap_or("")
                        ),
                    ));
                }
                for chunk in &read.chunks {
                    hex.push_str(&rampage_arch::hex::bytes(&chunk.bytes));
                }
                done += size as u64;
            }
            region.bytes = hex;
        }
        let after = session.status().map_err(debug_failure)?;
        let ids = |status: &rampage_debug::Status| status.threads.iter().map(|thread| thread.id).collect::<Vec<_>>();
        if after.state != rampage_debug::State::Stopped || after.epoch != status.epoch || ids(&after) != ids(&status) {
            return Err(failure(
                "session_not_stopped",
                "the target's stop reply or threads changed while capturing; nothing was written",
            ));
        }
        let captured: u64 = ranges.iter().map(|range| range.length).sum();
        let (registers_recorded, modules_recorded) = (snapshot.registers.len(), snapshot.modules.len());
        let document = serde_json::to_vec(&snapshot).map_err(|error| failure("invalid_argument", error))?;
        drop(snapshot);
        // The loader owns the document; publishing its retained copy avoids a second one in memory.
        let binary = rampage_loaders::Binary::from_snapshot_bytes(document).map_err(|error| {
            failure("invalid_argument", format!("the capture does not load as a snapshot: {error}"))
        })?;
        let outcome = crate::debugger_capture::publish_private_document_limited(
            output,
            binary.file_bytes(),
            crate::debugger_capture::MAX_PRIVATE_DOCUMENT_BYTES,
            |_| Ok(()),
        )?;
        Ok(DebugSnapshot {
            session: id.to_owned(),
            path: outcome.path.display().to_string(),
            document_sha256: outcome.document_sha256,
            status: outcome.status,
            warnings: outcome.warnings,
            retained_staging_paths: outcome
                .retained_staging_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            arch: arch.to_string(),
            data_big_endian,
            epoch: status.epoch,
            regions: ranges.len(),
            captured_bytes: captured,
            threads: status.threads.len().max(1),
            registers_recorded,
            registers_skipped: skipped,
            modules: modules_recorded,
            limitations: vec![
                NOT_ATOMIC.to_owned(),
                "registers wider than 64 bits, or with names that are not alphanumeric, are not recorded".into(),
                "no entry point or seeds are recorded; pass addresses to the analysis tools explicitly".into(),
            ],
        })
    }
}

impl Drop for DebugRegistry {
    fn drop(&mut self) {
        // Every session starts detaching at once and they share one deadline, so closing a connection with
        // several sessions takes no longer than closing one.
        let sessions = std::mem::take(&mut *self.sessions.lock().unwrap_or_else(PoisonError::into_inner));
        for session in sessions.values() {
            session.close();
        }
        let deadline = std::time::Instant::now() + rampage_debug::CLOSE_DETACH + std::time::Duration::from_millis(500);
        for session in sessions.values() {
            session.wait_closed(deadline);
        }
    }
}

/// The snapshot `thread_id` of `thread`: its thread ID, or with several processes `pid << 32 | tid`, so threads
/// of different processes with the same thread ID stay distinct. `0x0` stands for the stub's current thread when it
/// lists none.
fn snapshot_thread_id(thread: Option<ThreadId>, several_processes: bool) -> Result<String, ApiError> {
    let Some(thread) = thread else { return Ok("0x0".into()) };
    match (several_processes, thread.pid) {
        (true, Some(pid)) if pid <= u64::from(u32::MAX) && thread.tid <= u64::from(u32::MAX) => {
            Ok(format!("{:#x}", pid << 32 | thread.tid))
        }
        (true, _) => Err(failure(
            "unsupported",
            format!("thread {thread} cannot be told apart from other processes' threads in a snapshot thread ID"),
        )),
        (false, _) => Ok(format!("{:#x}", thread.tid)),
    }
}

/// The snapshot entries for svr4 modules, within the loader's limits: unique identities of at most 128 bytes,
/// names and paths of at most 4096 bytes, at most 4096 modules.
fn snapshot_modules(modules: &[rampage_debug::Module]) -> Result<Vec<SnapshotModule>, ApiError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut entries = Vec::new();
    for module in modules.iter().filter(|module| module.l_addr.is_some()) {
        let link_map = format!("gdb-link-map:{:#x}", module.lm.unwrap_or(0));
        let build_id = module.build_id.as_ref().map(|id| {
            let prefixed = format!("gnu-build-id:{id}");
            if prefixed.len() <= 128 { prefixed } else { id.clone() }
        });
        // The same image mapped twice shares a build ID; its link-map entry still tells the mappings apart.
        let uuid = match build_id {
            Some(id)
                if id.len() <= 128 && !seen.contains(&rampage_loaders::snapshot::canonical_module_identity(&id)) =>
            {
                id
            }
            _ => link_map,
        };
        if !seen.insert(rampage_loaders::snapshot::canonical_module_identity(&uuid)) {
            return Err(failure("unsupported", format!("two modules share the link-map entry in `{uuid}`")));
        }
        let path = truncate_bytes(&module.name, 4096);
        entries.push(SnapshotModule {
            name: path.rsplit('/').next().unwrap_or("").to_owned(),
            path,
            uuid,
            image_base: "0x0".into(),
            runtime_base: format!("{:#x}", module.l_addr.unwrap_or(0)),
        });
    }
    if entries.len() > MAX_SNAPSHOT_ENTRIES {
        return Err(failure(
            "unsupported",
            format!("{} modules exceed the snapshot format's {MAX_SNAPSHOT_ENTRIES}", entries.len()),
        ));
    }
    Ok(entries)
}

fn truncate_bytes(text: &str, limit: usize) -> String {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn page(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_THREAD_PAGE).clamp(1, 1000)
}

fn parse_thread(text: &str) -> Result<ThreadId, ApiError> {
    ThreadId::parse(text).ok_or_else(|| {
        failure("invalid_argument", format!("`{text}` is not a thread ID (hex `tid` or `p<pid>.<tid>`, as listed)"))
    })
}

/// A range for [`DebugRegistry::snapshot`].
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugRange {
    /// Runtime start address (hex string or integer).
    pub address: crate::FileOffset,
    /// Bytes to capture, 1..=16 MiB.
    pub length: crate::FileOffset,
    /// `rwx`-style permissions recorded for the region (default `rw-`: not asserted immutable or executable).
    pub permissions: Option<String>,
    /// Whether an executable ARM region holds Thumb code (default: true on M-profile targets, else false).
    pub thumb: Option<bool>,
}

struct CheckedRange {
    address: u64,
    length: u64,
    permissions: String,
    thumb: Option<bool>,
}

fn validate_ranges(ranges: &[DebugRange]) -> Result<Vec<CheckedRange>, ApiError> {
    if ranges.is_empty() || ranges.len() > MAX_SNAPSHOT_RANGES {
        return Err(failure("invalid_argument", format!("give 1..={MAX_SNAPSHOT_RANGES} ranges")));
    }
    let mut checked = Vec::with_capacity(ranges.len());
    let mut total = 0u64;
    for range in ranges {
        let (address, length) = (range.address.0, range.length.0);
        if length == 0 || length > MAX_SNAPSHOT_RANGE_BYTES || address.checked_add(length).is_none() {
            return Err(failure(
                "invalid_argument",
                format!("range at {address:#x}: length must be in 1..=16 MiB and must not overflow"),
            ));
        }
        total += length;
        let permissions = range.permissions.clone().unwrap_or_else(|| "rw-".into());
        if !matches!(permissions.as_bytes(), [b'r', b'w' | b'-', b'x' | b'-']) {
            return Err(failure("invalid_argument", "permissions must be r--, rw-, r-x or rwx"));
        }
        checked.push(CheckedRange { address, length, permissions, thumb: range.thumb });
    }
    if total > MAX_SNAPSHOT_BYTES {
        return Err(failure("invalid_argument", "ranges exceed 64 MiB in total"));
    }
    checked.sort_by_key(|range| range.address);
    if checked.windows(2).any(|pair| pair[0].address + pair[0].length > pair[1].address) {
        return Err(failure("invalid_argument", "ranges overlap"));
    }
    Ok(checked)
}

#[derive(Debug, Serialize)]
pub struct DebugConnection {
    pub session: String,
    pub endpoint: String,
    /// Whether the endpoint can only reach this machine (loopback or a Unix socket).
    pub local_endpoint: bool,
    pub architecture: Option<String>,
    pub family: Family,
    /// The data byte order, `unknown` unless stop-bound evidence fixes it.
    pub endianness: ByteOrder,
    pub endianness_evidence: String,
    pub pointer_size: Option<u8>,
    pub register_count: usize,
    pub layout_source: Option<rampage_debug::LayoutSource>,
    pub features: BTreeMap<String, String>,
    pub packet_size: usize,
    pub no_ack_mode: bool,
    #[serde(flatten)]
    pub state: rampage_debug::State,
    pub epoch: u64,
    pub stop: Option<rampage_debug::StopReply>,
    pub modules_available: bool,
    pub memory_map_available: bool,
    /// The most bytes one `debug_read_memory` call may read on this session.
    pub max_read_length: usize,
    pub limitations: Vec<String>,
    pub threads: FittedPage<rampage_debug::ThreadInfo>,
}

#[derive(Debug, Serialize)]
pub struct DebugStatus {
    pub session: String,
    #[serde(flatten)]
    pub state: rampage_debug::State,
    pub epoch: u64,
    pub stop: Option<rampage_debug::StopReply>,
    pub console: rampage_debug::Console,
    pub threads: FittedPage<rampage_debug::ThreadInfo>,
}

#[derive(Debug, Serialize)]
pub struct DebugRegisters {
    pub session: String,
    pub thread: Option<ThreadId>,
    pub epoch: u64,
    pub endianness: ByteOrder,
    pub limitations: Vec<String>,
    pub registers: FittedPage<rampage_debug::RegisterValue>,
}

#[derive(Debug, Serialize)]
pub struct DebugBytes {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(skip)]
    end: Option<u64>,
    pub hex: String,
}

#[derive(Debug, Serialize)]
pub struct DebugMemory {
    pub session: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub length: usize,
    pub epoch: u64,
    pub packet: &'static str,
    /// The thread selected for the read: the one asked for, else the stop's thread.
    pub thread: Option<ThreadId>,
    pub bytes_read: usize,
    pub complete: bool,
    /// The bytes read, as contiguous runs.
    pub data: Vec<DebugBytes>,
    /// Each request's outcome; `error` explains a short or failed read.
    pub chunks: Vec<rampage_debug::MemoryChunk>,
    pub atomic: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DebugModules {
    pub session: String,
    pub regions: Vec<rampage_debug::Region>,
    pub regions_total: usize,
    pub exec_file: Option<String>,
    pub offsets: Option<rampage_debug::Offsets>,
    pub limitations: Vec<String>,
    pub modules: FittedPage<rampage_debug::Module>,
}

#[derive(Debug, Serialize)]
pub struct DebugDisconnected {
    pub session: String,
    #[serde(flatten)]
    pub state: rampage_debug::State,
    /// Whether the stub accepted the detach.
    pub detached: bool,
    /// Whether the session is gone; a refused detach keeps it open (still attached) for a retry.
    pub closed: bool,
    pub detach_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DebugSnapshot {
    pub session: String,
    pub path: String,
    pub document_sha256: String,
    pub status: crate::DebuggerCapturePublicationStatus,
    pub warnings: Vec<String>,
    pub retained_staging_paths: Vec<String>,
    pub arch: String,
    pub data_big_endian: bool,
    pub epoch: u64,
    pub regions: usize,
    pub captured_bytes: u64,
    pub threads: usize,
    pub registers_recorded: usize,
    pub registers_skipped: usize,
    pub modules: usize,
    pub limitations: Vec<String>,
}
