//! A debug session: one thread owns the connection and serves typed requests over a channel, one at a time. While
//! the target runs, the thread keeps serving status, wait, interrupt and detach requests between reads of the stub.

use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::client::{Client, Console, Permit};
use crate::exec::{
    self, BreakKind, Breakpoint, Cancel, MAX_BREAKPOINTS, MAX_STEPS, MAX_WATCH_LENGTH, Origin, Placement, StopCause,
    StopEvent, TemporaryOutcome, VCont, stop_reasons,
};
use crate::lldb::{self, AddressMask, HostInfo, ThreadDetail};
use crate::maps::{self, Module, Offsets, Region};
use crate::packet::{self, decode_hex, encode_hex, parse_hex_u64};
use crate::pe;
use crate::stop::{StopReason, StopReply, ThreadId, hex_address};
use crate::target::{self, Family, Layout};
use crate::transport::{Endpoint, Transport};
use crate::{DebugError, MAX_MEMORY_READ};

/// Most threads listed.
const MAX_THREADS: usize = 4096;
/// Threads whose `qThreadExtraInfo` is asked for.
const MAX_EXTRA_INFO: usize = 64;
/// Most bytes of one `qXfer` object.
const MAX_XFER_BYTES: usize = 1024 * 1024;
/// Most bytes of a whole target description, across its includes.
const MAX_DESCRIPTION_BYTES: usize = 1024 * 1024;
/// Packet size assumed when the stub does not advertise one.
const DEFAULT_PACKET_SIZE: usize = 2048;
/// Modules whose build ID is looked for in target memory.
const MAX_BUILD_ID_MODULES: usize = 64;
/// Most modules whose PE headers a Windows module listing reads.
const MAX_PE_MODULES: usize = 64;
/// Most `qRegisterInfo<n>` queries in one handshake.
const MAX_REGISTER_INFO: usize = 1024;
/// Most threads whose `jThreadsInfo` is asked for: above it the reply (registers and stack memory of every thread)
/// could outgrow a packet.
const MAX_THREADS_INFO: usize = 64;
/// Most `qMemoryRegionInfo` queries one module listing makes.
const MAX_REGION_QUERIES: usize = 512;
/// Cortex-M Application Interrupt and Reset Control Register, whose ENDIANNESS bit and VECTKEYSTAT readback
/// (0xFA05) establish the data byte order.
const AIRCR: u64 = 0xe000_ed0c;
/// How long the session thread reads the stub at a time while the target runs, between requests.
const POLL_SLICE: Duration = Duration::from_millis(20);
/// No step of a request starts after this long; the step in flight may take up to the request timeout more.
const STEP_BUDGET: Duration = Duration::from_secs(60);
/// How long an interrupt first looks for a stop reply already on its way, so a stub that has just stopped is not
/// interrupted again.
const INTERRUPT_PEEK: Duration = Duration::from_millis(5);
/// How long an interrupt waits for the stop it asks for.
pub const INTERRUPT_WAIT: Duration = Duration::from_secs(3);
/// Most temporary breakpoints (of steps over or out) the table holds beyond [`MAX_BREAKPOINTS`].
pub const MAX_TEMPORARY: usize = 4;

/// Where [`Session::set_temporary`] put a step's temporary breakpoint.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "placed", rename_all = "snake_case")]
pub enum TemporaryPlacement {
    /// A new temporary entry, removed at the next stop.
    Inserted { breakpoint: Breakpoint },
    /// A breakpoint of the table already at that address stands in for it and stays.
    Existing { breakpoint: Breakpoint },
}

/// Most bytes one memory write request writes.
pub const MAX_WRITE: usize = 4096;
/// Time a memory write's deadline allows for each packet beyond the command timeout.
const WRITE_ROUND_TRIP: Duration = Duration::from_millis(250);
/// How long a kill waits for the stub's reply to `k` or `vKill`.
const KILL_WAIT: Duration = Duration::from_secs(3);

/// What the operator allowed beyond inspection and execution control. Both are off by default; a session refuses
/// write and kill requests it was not configured for, whatever its caller does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Consent {
    /// Memory and register writes (`--debug-writes`).
    pub writes: bool,
    /// Killing the target on disconnect (`--debug-kill`).
    pub kill: bool,
}

/// Why a session refuses writes it was not configured for.
const WRITES_NOT_ALLOWED: &str = "writes are not allowed: the operator did not start rampage with --debug-writes \
                                  (or RAMPAGE_DEBUG_WRITES=1); nothing was sent";
/// Why a session refuses a kill it was not configured for.
const KILL_NOT_ALLOWED: &str = "killing is not allowed: the operator did not start rampage with --debug-kill (or \
                                RAMPAGE_DEBUG_KILL=1); nothing was sent";

#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Bounds opening the connection.
    pub connect_timeout: Duration,
    /// Bounds each request, including every packet it sends, and the whole connection handshake.
    pub command_timeout: Duration,
    /// Whether write and kill requests are served.
    pub consent: Consent,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(10),
            consent: Consent::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    Little,
    Big,
    /// No stop-bound evidence establishes the order; register values are given only as transmitted bytes.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum State {
    Stopped,
    /// Resumed and not yet stopped. Only status, wait, interrupt and detach are served.
    Running,
    /// The process exited or was terminated; there is nothing left to read.
    Exited,
    /// rampage killed the target (`k` or `vKill`) and the stub confirmed it.
    Killed,
    Detached,
    Lost {
        reason: String,
    },
}

/// What the connection established. Fixed for the session's life.
#[derive(Debug, Clone, Serialize)]
pub struct Info {
    pub endpoint: String,
    /// Whether the endpoint can only reach this machine.
    pub local: bool,
    pub architecture: Option<String>,
    pub family: Family,
    /// Data byte order, and how it was established.
    pub byte_order: ByteOrder,
    pub byte_order_evidence: String,
    pub pointer_size: Option<u8>,
    /// The stub's `qSupported` features: `+`, `-`, `?` or a value.
    pub features: BTreeMap<String, String>,
    /// Packet size used for requests: the stub's `PacketSize`, capped at 1 MiB.
    pub packet_size: usize,
    pub no_ack_mode: bool,
    pub multiprocess: bool,
    pub layout: Option<Layout>,
    pub modules_available: bool,
    pub memory_map_available: bool,
    pub limitations: Vec<String>,
    /// LLDB's extensions, when the stub offers them (debugserver): what `qHostInfo` and `qProcessInfo` said.
    pub lldb: Option<LldbInfo>,
    /// How pointer authentication codes are taken off code addresses (arm64 return addresses); `None` when the
    /// address width is unknown and values are used as read.
    pub address_mask: Option<AddressMask>,
    /// A Windows target, and what shows it: gdbserver's target description names the `Windows` OS ABI,
    /// lldb-server's `qHostInfo`/`qProcessInfo` a Windows OS or triple.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowsTarget>,
}

/// What a Windows stub is, as far as its replies show.
#[derive(Debug, Clone, Serialize)]
pub struct WindowsTarget {
    /// `gdbserver` (a GDB stub: `gdbserver.exe` from MinGW-w64 or MSYS2) or `lldb-server` (an LLDB stub).
    pub stub: &'static str,
    pub evidence: String,
}

/// What an LLDB-style stub (debugserver) said about its host and process.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LldbInfo {
    pub host: Option<HostInfo>,
    pub process: Option<HostInfo>,
    /// Whether the stub is an Apple one (`vendor:apple` or an Apple `ostype`).
    pub apple: bool,
    /// Whether the process is arm64e, whose return addresses carry pointer authentication codes.
    pub arm64e: bool,
}

impl Info {
    /// Bytes per memory request: the most whose hex reply fits the packet size.
    pub fn chunk_size(&self) -> usize {
        chunk_size(self.packet_size)
    }

    fn feature(&self, name: &str) -> bool {
        self.features.get(name).is_some_and(|value| value == "+")
    }

    /// `value` as a code address: without its pointer authentication code when the session knows the address
    /// width, else unchanged.
    pub fn strip_code_address(&self, value: u64) -> u64 {
        self.address_mask.as_ref().map_or(value, |mask| mask.strip(value))
    }

    /// Whether the stub is Apple's debugserver (or another Apple LLDB stub).
    pub fn apple(&self) -> bool {
        self.lldb.as_ref().is_some_and(|lldb| lldb.apple)
    }

    /// Whether the target is a Windows process (gdbserver or lldb-server on Windows).
    pub fn is_windows(&self) -> bool {
        self.windows.is_some()
    }

    /// Whether the target is a Windows process under gdbserver (a GDB stub rather than lldb-server).
    pub fn windows_gdbserver(&self) -> bool {
        self.windows.as_ref().is_some_and(|windows| windows.stub == "gdbserver")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadInfo {
    pub id: ThreadId,
    /// The stub's `qThreadExtraInfo` description, when it gives one.
    pub extra: Option<String>,
    /// LLDB's `jThreadsInfo` for this thread: its name, dispatch queue and stop reason.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub detail: Option<ThreadDetail>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    #[serde(flatten)]
    pub state: State,
    /// Increments with each stop the session observes. Reads report the epoch they read at.
    pub epoch: u64,
    pub stop: Option<StopReply>,
    pub threads: Vec<ThreadInfo>,
    pub console: Console,
    /// Milliseconds since the last resume, while running.
    pub running_for_ms: Option<u64>,
    /// The last stop rampage observed after resuming, stepping or interrupting.
    pub last_stop: Option<StopEvent>,
    /// Callers waiting for the target to stop (continue, wait or interrupt calls in progress).
    pub waiting: usize,
}

/// The outcome of a continue, wait or interrupt: a new stop, or a target still running.
#[derive(Debug, Clone, Serialize)]
pub struct Run {
    #[serde(flatten)]
    pub state: State,
    pub epoch: u64,
    pub running_for_ms: Option<u64>,
    /// Whether the caller cancelled the wait. The target was not touched.
    pub cancelled: bool,
    /// The stop that ended the run; for a wait on a target that is not running, the last stop observed.
    pub event: Option<StopEvent>,
    /// Things that went wrong on the way without failing the call, such as a breakpoint not re-inserted.
    pub warnings: Vec<String>,
}

/// The outcome of a step request.
#[derive(Debug, Clone, Serialize)]
pub struct Steps {
    #[serde(flatten)]
    pub state: State,
    pub epoch: u64,
    pub thread: Option<ThreadId>,
    pub requested: u32,
    /// Steps that completed as steps; a stop for any other reason ends the request early and is not counted.
    pub completed: u32,
    /// The pc after each completed step, as hex; null where it could not be read or decoded.
    pub pcs: Vec<Option<String>>,
    /// The last stop observed.
    pub event: Option<StopEvent>,
    pub cancelled: bool,
    /// Why fewer steps than requested were taken without an early stop, if so.
    pub truncated: Option<String>,
    pub running_for_ms: Option<u64>,
}

/// The outcome of a detach.
#[derive(Debug, Clone, Serialize)]
pub struct Detached {
    #[serde(flatten)]
    pub state: State,
    /// Breakpoints and watchpoints removed before detaching.
    pub breakpoints_removed: usize,
    /// Entries the stub would not remove, or that could not be removed, each with the reason.
    pub removal_failures: Vec<String>,
    /// Why the stub refused `D` (`E nn`): the session stays open and attached, but the breakpoints counted above
    /// are already gone.
    pub refused: Option<String>,
}

/// The outcome of a kill.
#[derive(Debug, Clone, Serialize)]
pub struct Killed {
    /// `killed` when the stub confirmed it, `exited` when it reports the process exited, `lost` when the connection
    /// ended without a confirmation (stubs may close it in answer to `k`), or the state the target was already in.
    #[serde(flatten)]
    pub state: State,
    /// Breakpoints and watchpoints removed before killing.
    pub breakpoints_removed: usize,
    pub removal_failures: Vec<String>,
    /// The kill packets sent (`k`, or `vKill;<pid>` per process in multiprocess mode); empty when the target had
    /// already ended.
    pub packets: Vec<String>,
    /// The packets the stub confirmed with `OK`, `X` or `W`.
    pub confirmed: Vec<String>,
    /// The stub's reply to the last kill packet, when it sent one.
    pub reply: Option<String>,
    /// Why the stub refused (`E nn`) or does not support the kill: the session stays open and attached, but the
    /// breakpoints counted above are already gone, and the processes in `confirmed` are killed.
    pub refused: Option<String>,
    /// The target had ended before the kill, so nothing was sent.
    pub already_ended: bool,
}

/// One packet of a memory write.
#[derive(Debug, Clone, Serialize)]
pub struct WriteChunk {
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    pub length: usize,
    /// `X` (binary) or `M` (hex).
    pub packet: &'static str,
    /// Whether the stub answered `OK`.
    pub written: bool,
    pub error: Option<String>,
}

/// The outcome of a memory write: the bytes before, each packet's outcome, and the bytes read back.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryWrite {
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    pub length: usize,
    /// The epoch the write happened at; a write does not change it.
    pub epoch: u64,
    pub thread: Option<ThreadId>,
    #[serde(skip)]
    pub before: Vec<u8>,
    /// The bytes read back after writing; shorter than `length` when the read-back failed part-way.
    #[serde(skip)]
    pub after: Vec<u8>,
    /// Why the read-back is short, if it is.
    pub after_error: Option<String>,
    /// Packets sent, in order; writing stops at the first one the stub does not accept.
    pub chunks: Vec<WriteChunk>,
    /// Whether every packet was accepted.
    pub complete: bool,
    /// Whether the read-back equals the bytes written. A stub may accept a write it silently drops (flash, ROM).
    pub verified: bool,
}

/// The outcome of a register write.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterWrite {
    pub thread: Option<ThreadId>,
    pub epoch: u64,
    pub name: String,
    pub regnum: u32,
    pub bitsize: u32,
    /// `P`, or `G` after reading every register with `g` when the stub has no `P`.
    pub packet: &'static str,
    /// The register's bytes, as the stub sent them, before and after; `None` when unavailable.
    pub before: Option<String>,
    pub after: Option<String>,
    /// The values decoded in the session's byte order; `None` when it is unknown.
    pub before_value: Option<String>,
    pub after_value: Option<String>,
    /// Whether the read-back equals the bytes written.
    pub verified: bool,
}

/// `value` as the `bitsize`-bit register bytes a stub transfers in `order`, refused when the byte order is unknown
/// or the value does not fit. Registers wider than 64 bits are zero-extended.
pub fn encode_register_value(value: u64, bitsize: u32, order: ByteOrder) -> Result<Vec<u8>, String> {
    if bitsize == 0 || !bitsize.is_multiple_of(8) {
        return Err(format!("a {bitsize}-bit register cannot be written as whole bytes"));
    }
    if bitsize < 64 && value >> bitsize != 0 {
        return Err(format!("{value:#x} does not fit a {bitsize}-bit register"));
    }
    let size = bitsize as usize / 8;
    let mut bytes = vec![0; size];
    let little = value.to_le_bytes();
    let used = size.min(8);
    match order {
        ByteOrder::Little => bytes[..used].copy_from_slice(&little[..used]),
        ByteOrder::Big => {
            for (index, byte) in little[..used].iter().enumerate() {
                bytes[size - 1 - index] = *byte;
            }
        }
        ByteOrder::Unknown => {
            return Err("the target's byte order is unknown, so an integer cannot be encoded; give the value as \
                        target-endian hex bytes"
                .into());
        }
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterValue {
    pub name: String,
    pub regnum: u32,
    pub bitsize: u32,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub group: Option<String>,
    /// The bytes as the stub sent them, in hex; `None` when the stub marks the register unavailable.
    pub bytes: Option<String>,
    /// The value decoded in the session's byte order, as a full-width hex number; `None` when the bytes are
    /// unavailable or the byte order is unknown.
    pub value: Option<String>,
}

impl RegisterValue {
    /// The value as an integer, for registers of at most 64 bits.
    pub fn integer(&self) -> Option<u64> {
        self.value.as_deref().filter(|_| self.bitsize <= 64).and_then(parse_hex_u64)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Registers {
    pub thread: Option<ThreadId>,
    pub epoch: u64,
    pub byte_order: ByteOrder,
    pub registers: Vec<RegisterValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryChunk {
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    pub requested: usize,
    #[serde(skip)]
    pub bytes: Vec<u8>,
    pub read: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryRead {
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    pub length: usize,
    pub epoch: u64,
    /// `x` (binary) or `m` (hex).
    pub packet: &'static str,
    /// The thread selected for the read; `None` when the stub lists no threads.
    pub thread: Option<ThreadId>,
    pub chunks: Vec<MemoryChunk>,
}

impl MemoryRead {
    pub fn complete(&self) -> bool {
        self.chunks.iter().all(|chunk| chunk.error.is_none() && chunk.read == chunk.requested)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Modules {
    pub modules: Vec<Module>,
    pub regions: Vec<Region>,
    /// Whether `qMemoryRegionInfo` stopped before the end of the address space, so an address in no listed region
    /// may still be mapped.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub regions_partial: bool,
    pub exec_file: Option<String>,
    pub offsets: Option<Offsets>,
    pub limitations: Vec<String>,
}

enum Request {
    Status,
    Registers {
        thread: Option<ThreadId>,
        epoch: Option<u64>,
    },
    Memory {
        address: u64,
        length: usize,
        thread: Option<ThreadId>,
        epoch: Option<u64>,
        cancel: Cancel,
    },
    Modules {
        epoch: Option<u64>,
    },
    Continue {
        epoch: Option<u64>,
        wait: Duration,
        cancel: Cancel,
    },
    Wait {
        wait: Duration,
        cancel: Cancel,
    },
    Interrupt {
        wait: Duration,
        cancel: Cancel,
    },
    Step {
        epoch: Option<u64>,
        thread: Option<ThreadId>,
        count: u32,
        past: bool,
        cancel: Cancel,
    },
    SetBreakpoint {
        epoch: Option<u64>,
        kind: BreakKind,
        address: u64,
        size: Option<u64>,
        placement: Option<Placement>,
        temporary: bool,
    },
    ClearBreakpoint {
        epoch: Option<u64>,
        id: u32,
    },
    Breakpoints,
    Detach,
    WriteMemory {
        epoch: Option<u64>,
        address: u64,
        bytes: Vec<u8>,
        expect: Option<Vec<u8>>,
    },
    WriteRegister {
        epoch: Option<u64>,
        thread: Option<ThreadId>,
        name: String,
        value: Vec<u8>,
    },
    Kill,
}

impl Request {
    /// The packet classes the request may send.
    fn permit(&self) -> Permit {
        match self {
            Request::WriteMemory { .. } | Request::WriteRegister { .. } => Permit::WRITE,
            Request::Kill => Permit::KILL,
            Request::Status
            | Request::Registers { .. }
            | Request::Memory { .. }
            | Request::Modules { .. }
            | Request::Breakpoints => Permit::READ,
            Request::Continue { .. }
            | Request::Wait { .. }
            | Request::Interrupt { .. }
            | Request::Step { .. }
            | Request::SetBreakpoint { .. }
            | Request::ClearBreakpoint { .. } => Permit::EXECUTION,
            Request::Detach => Permit::DETACH,
        }
    }
}

enum Response {
    Status(Status),
    Registers(Registers),
    Memory(MemoryRead),
    Modules(Modules),
    Run(Run),
    Steps(Steps),
    Breakpoint(Breakpoint),
    Temporary(TemporaryPlacement),
    Breakpoints(Vec<Breakpoint>),
    Detached(Detached),
    MemoryWrite(MemoryWrite),
    RegisterWrite(RegisterWrite),
    Killed(Killed),
}

struct Job {
    request: Request,
    deadline: Instant,
    reply: Sender<Result<Response, DebugError>>,
}

/// A connected debug session. Dropping it detaches best-effort within a short timeout.
pub struct Session {
    info: Arc<Info>,
    jobs: Mutex<Option<Sender<Job>>>,
    done: Mutex<Receiver<()>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    config: Config,
}

impl Session {
    /// Connects to `endpoint` and reads the target's description, stop state and threads.
    pub fn connect(endpoint: &Endpoint, config: Config) -> Result<Self, DebugError> {
        // Opening the connection and the handshake share one deadline.
        let deadline = Instant::now() + config.connect_timeout + config.command_timeout;
        let transport = endpoint.connect(config.connect_timeout)?;
        Self::start_until(transport, endpoint.to_string(), endpoint.is_local(), config, deadline)
    }

    /// Runs a session over an already connected transport.
    pub fn start(
        transport: Box<dyn Transport>,
        endpoint: String,
        local: bool,
        config: Config,
    ) -> Result<Self, DebugError> {
        Self::start_until(
            transport,
            endpoint,
            local,
            config,
            Instant::now() + config.connect_timeout + config.command_timeout,
        )
    }

    fn start_until(
        transport: Box<dyn Transport>,
        endpoint: String,
        local: bool,
        config: Config,
        deadline: Instant,
    ) -> Result<Self, DebugError> {
        let (jobs, inbox) = mpsc::channel::<Job>();
        let (ready, connected) = mpsc::channel();
        let (finished, done) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("rampage-debug-session".into())
            .spawn(move || {
                let mut worker = Worker::new(transport, config.command_timeout, config.consent);
                match worker.handshake(endpoint, local, deadline) {
                    Ok(info) => {
                        let info = Arc::new(info);
                        worker.info = Some(Arc::clone(&info));
                        if ready.send(Ok(info)).is_ok() {
                            worker.serve(inbox);
                        }
                    }
                    Err(error) => {
                        // A stub that loses its inferior when the debugger disconnects (gdbserver --once) must be
                        // detached from whenever the stream is still in step.
                        if worker.client.in_sync() && worker.state == State::Stopped {
                            worker.client.set_permit(Permit::DETACH);
                            let _ = worker.detach(Instant::now() + Duration::from_secs(2));
                        }
                        let _ = ready.send(Err(error));
                    }
                }
                worker.client.shutdown();
                let _ = finished.send(());
            })
            .map_err(|error| DebugError::Connect(format!("cannot start the session thread: {error}")))?;
        let wait = deadline.saturating_duration_since(Instant::now()) + Duration::from_secs(1);
        let info = match connected.recv_timeout(wait) {
            Ok(result) => result?,
            Err(_) => return Err(DebugError::Timeout("connection handshake".into())),
        };
        Ok(Self {
            info,
            jobs: Mutex::new(Some(jobs)),
            done: Mutex::new(done),
            thread: Mutex::new(Some(thread)),
            config,
        })
    }

    pub fn info(&self) -> &Info {
        &self.info
    }

    fn call(&self, request: Request, timeout: Duration) -> Result<Response, DebugError> {
        let deadline = Instant::now() + timeout;
        let (reply, response) = mpsc::channel();
        let sent = {
            let jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
            jobs.as_ref().is_some_and(|jobs| jobs.send(Job { request, deadline, reply }).is_ok())
        };
        if !sent {
            return Err(DebugError::State("the session has ended".into()));
        }
        // The worker bounds each request by its deadline; the margin covers queueing behind another request.
        match response.recv_timeout(timeout * 2 + Duration::from_secs(1)) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(DebugError::Timeout("the session did not answer".into())),
            Err(RecvTimeoutError::Disconnected) => Err(DebugError::State("the session has ended".into())),
        }
    }

    pub fn status(&self) -> Result<Status, DebugError> {
        match self.call(Request::Status, self.config.command_timeout)? {
            Response::Status(status) => Ok(status),
            _ => unreachable!("status request"),
        }
    }

    /// Every register of `thread` (the stub's current thread when `None`).
    pub fn registers(&self, thread: Option<ThreadId>) -> Result<Registers, DebugError> {
        self.registers_at(thread, None)
    }

    /// [`Session::registers`], refused with [`DebugError::StaleEpoch`] unless the session is at `epoch` (when given).
    pub fn registers_at(&self, thread: Option<ThreadId>, epoch: Option<u64>) -> Result<Registers, DebugError> {
        match self.call(Request::Registers { thread, epoch }, self.config.command_timeout)? {
            Response::Registers(registers) => Ok(registers),
            _ => unreachable!("registers request"),
        }
    }

    /// Reads `length` (1..=65536) bytes at `address`. Unreadable parts are reported per chunk, not hidden.
    pub fn read_memory(&self, address: u64, length: usize, thread: Option<ThreadId>) -> Result<MemoryRead, DebugError> {
        self.read_memory_at(address, length, thread, None, &Cancel::default())
    }

    /// [`Session::read_memory`] at `epoch` (when given); `cancel` stops it between chunks.
    pub fn read_memory_at(
        &self,
        address: u64,
        length: usize,
        thread: Option<ThreadId>,
        epoch: Option<u64>,
        cancel: &Cancel,
    ) -> Result<MemoryRead, DebugError> {
        if !(1..=MAX_MEMORY_READ).contains(&length) || address.checked_add(length as u64 - 1).is_none() {
            return Err(DebugError::Invalid(format!(
                "length must be in 1..={MAX_MEMORY_READ} and the range must not overflow the address space"
            )));
        }
        let request = Request::Memory { address, length, thread, epoch, cancel: cancel.clone() };
        match self.call(request, self.config.command_timeout)? {
            Response::Memory(memory) => Ok(memory),
            _ => unreachable!("memory request"),
        }
    }

    pub fn modules(&self) -> Result<Modules, DebugError> {
        self.modules_at(None)
    }

    pub fn modules_at(&self, epoch: Option<u64>) -> Result<Modules, DebugError> {
        match self.call(Request::Modules { epoch }, self.config.command_timeout)? {
            Response::Modules(modules) => Ok(modules),
            _ => unreachable!("modules request"),
        }
    }

    fn run_call(&self, request: Request, timeout: Duration) -> Result<Run, DebugError> {
        match self.call(request, timeout)? {
            Response::Run(run) => Ok(run),
            _ => unreachable!("run request"),
        }
    }

    /// Resumes every thread (`vCont;c`, or `c` when the stub has no `vCont`) without delivering a signal, at
    /// `epoch`, and waits up to `wait` for the stop. Returns the stop, or a running state when none came in time
    /// or `cancel` was set.
    pub fn resume(&self, epoch: Option<u64>, wait: Duration, cancel: &Cancel) -> Result<Run, DebugError> {
        let request = Request::Continue { epoch, wait, cancel: cancel.clone() };
        self.run_call(request, self.config.command_timeout + wait)
    }

    /// Waits up to `wait` for a running target to stop. A target that is not running returns at once, with the
    /// last stop observed.
    pub fn wait(&self, wait: Duration, cancel: &Cancel) -> Result<Run, DebugError> {
        self.run_call(Request::Wait { wait, cancel: cancel.clone() }, self.config.command_timeout + wait)
    }

    /// Sends the interrupt byte to a running target and waits up to `wait` for its stop.
    pub fn interrupt(&self, wait: Duration, cancel: &Cancel) -> Result<Run, DebugError> {
        self.run_call(Request::Interrupt { wait, cancel: cancel.clone() }, self.config.command_timeout + wait)
    }

    /// Single-steps `thread` (the stop's thread when `None`) `count` (1..=1000) times at `epoch`, stopping early
    /// on any stop that is not the step's completion.
    pub fn step(
        &self,
        epoch: Option<u64>,
        thread: Option<ThreadId>,
        count: u32,
        cancel: &Cancel,
    ) -> Result<Steps, DebugError> {
        self.step_with(epoch, thread, count, false, cancel)
    }

    /// [`Session::step`]; with `past`, every step first takes out the inserted breakpoints at the thread's pc and
    /// puts them back at the step's stop, as a continue does, so a stub that would report one again at once (rather
    /// than execute the instruction) still steps.
    pub fn step_with(
        &self,
        epoch: Option<u64>,
        thread: Option<ThreadId>,
        count: u32,
        past: bool,
        cancel: &Cancel,
    ) -> Result<Steps, DebugError> {
        if !(1..=MAX_STEPS).contains(&count) {
            return Err(DebugError::Invalid(format!("count must be in 1..={MAX_STEPS}")));
        }
        let request = Request::Step { epoch, thread, count, past, cancel: cancel.clone() };
        match self.call(request, STEP_BUDGET + self.config.command_timeout)? {
            Response::Steps(steps) => Ok(steps),
            _ => unreachable!("step request"),
        }
    }

    /// Inserts a breakpoint (`size`: the instruction size, defaulting by architecture) or a watchpoint (`size`:
    /// the length watched, required) at a runtime `address`.
    pub fn set_breakpoint(
        &self,
        epoch: Option<u64>,
        kind: BreakKind,
        address: u64,
        size: Option<u64>,
    ) -> Result<Breakpoint, DebugError> {
        self.set_breakpoint_placed(epoch, kind, address, size, None)
    }

    /// [`Session::set_breakpoint`], recording the static location it was placed from with the entry.
    pub fn set_breakpoint_placed(
        &self,
        epoch: Option<u64>,
        kind: BreakKind,
        address: u64,
        size: Option<u64>,
        placement: Option<Placement>,
    ) -> Result<Breakpoint, DebugError> {
        let request = Request::SetBreakpoint { epoch, kind, address, size, placement, temporary: false };
        match self.call(request, self.config.command_timeout)? {
            Response::Breakpoint(breakpoint) => Ok(breakpoint),
            _ => unreachable!("breakpoint request"),
        }
    }

    /// Places a step's temporary breakpoint at `address` (`size` as for [`Session::set_breakpoint`]): a hardware
    /// breakpoint, else a software one the stub plants. A breakpoint of the table already at that address stands
    /// in for it instead, so the temporary one never takes out the caller's. A temporary entry is removed at the
    /// next stop, whatever the stop is, and by detaching.
    pub fn set_temporary(
        &self,
        epoch: Option<u64>,
        address: u64,
        size: Option<u64>,
        placement: Option<Placement>,
    ) -> Result<TemporaryPlacement, DebugError> {
        let request =
            Request::SetBreakpoint { epoch, kind: BreakKind::Hardware, address, size, placement, temporary: true };
        match self.call(request, self.config.command_timeout)? {
            Response::Temporary(placed) => Ok(placed),
            _ => unreachable!("temporary breakpoint request"),
        }
    }

    /// Removes table entry `id` from the stub and the table, returning it.
    pub fn clear_breakpoint(&self, epoch: Option<u64>, id: u32) -> Result<Breakpoint, DebugError> {
        match self.call(Request::ClearBreakpoint { epoch, id }, self.config.command_timeout)? {
            Response::Breakpoint(breakpoint) => Ok(breakpoint),
            _ => unreachable!("breakpoint request"),
        }
    }

    /// The breakpoint table, with hit counts.
    pub fn breakpoints(&self) -> Result<Vec<Breakpoint>, DebugError> {
        match self.call(Request::Breakpoints, self.config.command_timeout)? {
            Response::Breakpoints(table) => Ok(table),
            _ => unreachable!("breakpoints request"),
        }
    }

    /// Removes every inserted breakpoint and watchpoint (best effort), detaches (`D`) and ends the session. A
    /// running target is interrupted first; if it does not stop within [`INTERRUPT_WAIT`], the connection is closed
    /// and the session is lost. The target runs on under the stub. When the stub refuses `D` (`E nn`), the session
    /// stays open and still attached, so detaching can be retried.
    pub fn detach(&self) -> Result<Detached, DebugError> {
        let result = match self.call(Request::Detach, self.config.command_timeout + INTERRUPT_WAIT) {
            Ok(Response::Detached(detached)) => Ok(detached),
            Ok(_) => unreachable!("detach request"),
            Err(error) => Err(error),
        };
        if !matches!(result, Err(DebugError::Target(_)))
            && !matches!(result, Ok(ref detached) if detached.refused.is_some())
        {
            self.close();
            self.wait_closed(Instant::now() + Duration::from_secs(1));
        }
        result
    }

    /// Writes `bytes` (1..=[`MAX_WRITE`]) at `address` of a stopped target at `epoch` (when given), only in a session
    /// whose [`Consent`] allows writes. Reads the bytes there first and refuses, writing nothing, when `expect` is
    /// given and differs, or when a software breakpoint (`Z0`, temporary ones included) overlaps the range. Writes
    /// with `X` when the stub takes it, else `M`, one packet per chunk, stopping at the first refusal, then reads
    /// the range back. The epoch does not change.
    pub fn write_memory(
        &self,
        epoch: Option<u64>,
        address: u64,
        bytes: &[u8],
        expect: Option<&[u8]>,
    ) -> Result<MemoryWrite, DebugError> {
        let request =
            Request::WriteMemory { epoch, address, bytes: bytes.to_vec(), expect: expect.map(<[u8]>::to_vec) };
        // Each chunk is read, written and read back; a small packet size means many round trips. Each packet still
        // gets the command timeout of its own (a hung stub fails as fast as for any request), while the request as a
        // whole gets time for every round trip, so a slow but healthy stub does not lose the session.
        let chunks = bytes.len().div_ceil(self.info.chunk_size().min(MAX_WRITE)).max(1) as u32;
        let timeout = self.config.command_timeout + WRITE_ROUND_TRIP * 3 * chunks;
        match self.call(request, timeout)? {
            Response::MemoryWrite(write) => Ok(write),
            _ => unreachable!("memory write request"),
        }
    }

    /// Writes register `name` of `thread` (the stop's thread when `None`) of a stopped target at `epoch` (when given)
    /// with `value`, its bytes in the order the stub transfers them, only in a session whose [`Consent`] allows
    /// writes. Uses `P`, else `g` and `G` with only that register changed, then reads the registers back. Writing the
    /// pc does not resume; the epoch does not change.
    pub fn write_register(
        &self,
        epoch: Option<u64>,
        thread: Option<ThreadId>,
        name: &str,
        value: &[u8],
    ) -> Result<RegisterWrite, DebugError> {
        let request = Request::WriteRegister { epoch, thread, name: name.to_owned(), value: value.to_vec() };
        match self.call(request, self.config.command_timeout)? {
            Response::RegisterWrite(write) => Ok(write),
            _ => unreachable!("register write request"),
        }
    }

    /// Kills the target and ends the session, only when its [`Consent`] allows it: a running target is interrupted
    /// first (as for [`Session::detach`]), every breakpoint is removed, then `vKill;<pid>` per process in
    /// multiprocess mode, else `k`, is sent. When the stub refuses (`E nn`) or does not support it, the session
    /// stays open and attached.
    pub fn kill(&self) -> Result<Killed, DebugError> {
        let result = match self.call(Request::Kill, self.config.command_timeout + INTERRUPT_WAIT + KILL_WAIT) {
            Ok(Response::Killed(killed)) => Ok(killed),
            Ok(_) => unreachable!("kill request"),
            Err(error) => Err(error),
        };
        let keeps = match &result {
            Ok(killed) => killed.refused.is_some(),
            Err(error) => kill_keeps_session(error),
        };
        if !keeps {
            self.close();
            self.wait_closed(Instant::now() + Duration::from_secs(1));
        }
        result
    }

    /// Starts closing without waiting: the worker detaches best-effort (within [`CLOSE_DETACH`]) and exits.
    pub fn close(&self) {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner).take();
    }

    /// Waits until `deadline` for a closing worker to finish.
    pub fn wait_closed(&self, deadline: Instant) {
        let finished = self
            .done
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv_timeout(deadline.saturating_duration_since(Instant::now()));
        let handle = self.thread.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let (Ok(()) | Err(RecvTimeoutError::Disconnected), Some(handle)) = (finished, handle) {
            let _ = handle.join();
        }
    }
}

/// How long a closing worker tries to detach.
pub const CLOSE_DETACH: Duration = Duration::from_secs(2);

impl Drop for Session {
    fn drop(&mut self) {
        let running = self.jobs.lock().unwrap_or_else(PoisonError::into_inner).is_some();
        if running {
            self.close();
            self.wait_closed(Instant::now() + CLOSE_DETACH + Duration::from_millis(500));
        }
    }
}

/// A caller waiting for a running target to stop.
struct Waiter {
    reply: Sender<Result<Response, DebugError>>,
    deadline: Instant,
    cancel: Cancel,
    warnings: Vec<String>,
}

impl Waiter {
    fn new(reply: Sender<Result<Response, DebugError>>, wait: Duration, cancel: Cancel) -> Self {
        Self { reply, deadline: Instant::now() + wait, cancel, warnings: Vec::new() }
    }
}

/// Single steps taken one resume at a time through the session's main loop, so status, wait, interrupt and
/// detach are served between (and during) them.
struct Stepping {
    thread: Option<ThreadId>,
    packet: String,
    reply: Sender<Result<Response, DebugError>>,
    cancel: Cancel,
    /// When the step in flight must have stopped; past it the target is left running.
    step_deadline: Instant,
    /// An interrupt asked the steps to end.
    halt: bool,
    /// Each step first takes out the inserted breakpoints at the pc.
    past: bool,
    /// Decided once when a step's stop arrives, so the temporary breakpoints and the continue agree: whether the
    /// continue behind a step past breakpoints goes on (not halted, not cancelled).
    go_on: bool,
    purpose: Purpose,
}

enum Purpose {
    /// A step request.
    Steps { steps: Box<Steps>, budget: Instant },
    /// One step off the breakpoints at the pc before a continue, which then waits `wait`.
    PastBreakpoints { wait: Duration },
}

struct Worker {
    client: Client<Box<dyn Transport>>,
    info: Option<Arc<Info>>,
    state: State,
    epoch: u64,
    stop: Option<StopReply>,
    threads: Vec<ThreadInfo>,
    selected: Option<ThreadId>,
    extra_info: bool,
    multiprocess: bool,
    command_timeout: Duration,
    vcont: Option<VCont>,
    breakpoints: Vec<Breakpoint>,
    next_breakpoint: u32,
    waiters: Vec<Waiter>,
    resumed_at: Option<Instant>,
    /// What the outstanding resume was, and whether rampage interrupted it.
    origin: Origin,
    interrupted: bool,
    last_stop: Option<StopEvent>,
    stepping: Option<Stepping>,
    /// Breakpoints taken out to step past them, put back at the next stop.
    reinsert: Vec<u32>,
    /// Whether an `Hc<thread>` rampage sent is in effect, so a plain `c` might resume only that thread.
    hc_thread: bool,
    /// What the operator allowed; write and kill requests are refused without it.
    consent: Consent,
    /// Whether the stub takes `X` writes, once a write found out.
    x_write: Option<bool>,
    /// Whether the stub takes `P` writes, once a write found out.
    p_write: Option<bool>,
    /// Whether LLDB's extensions are worth asking for (the stub advertises `qEcho` or `native-signals`).
    lldb: bool,
    /// Whether the stub answers `jThreadsInfo` and `jGetLoadedDynamicLibrariesInfos`, once asked.
    threads_info: Option<bool>,
    dyld_info: Option<bool>,
    /// debugserver registers read one by one, kept for (epoch, selected thread) until a register write.
    register_cache: Option<(u64, Option<ThreadId>, Vec<Option<String>>)>,
    /// Windows: the thread the system created to answer rampage's interrupt (`DebugBreakProcess` or a console
    /// Ctrl-Break), which reads and steps without a thread pass over until the target runs again.
    breakin: Option<ThreadId>,
    /// Windows under gdbserver: break-in threads left suspended at the int3 gdbserver moved their pc back onto;
    /// continues resume every other thread (`vCont;c:<thread>...`).
    parked: Vec<ThreadId>,
    /// Windows: an interrupt whose stop has not come yet, because a DLL-load stop arrived first.
    interrupt_pending: bool,
}

impl Worker {
    fn new(transport: Box<dyn Transport>, command_timeout: Duration, consent: Consent) -> Self {
        Self {
            consent,
            x_write: None,
            p_write: None,
            lldb: false,
            threads_info: None,
            dyld_info: None,
            register_cache: None,
            breakin: None,
            parked: Vec::new(),
            interrupt_pending: false,
            client: Client::new(transport),
            info: None,
            state: State::Stopped,
            epoch: 0,
            stop: None,
            threads: Vec::new(),
            selected: None,
            extra_info: true,
            multiprocess: false,
            command_timeout,
            vcont: None,
            breakpoints: Vec::new(),
            next_breakpoint: 1,
            waiters: Vec::new(),
            resumed_at: None,
            origin: Origin::Continue,
            interrupted: false,
            last_stop: None,
            stepping: None,
            reinsert: Vec::new(),
            hc_thread: false,
        }
    }

    fn command(&mut self, packet: &str, deadline: Instant) -> Result<Vec<u8>, DebugError> {
        if Instant::now() >= deadline {
            return Err(DebugError::Timeout(format!("deadline passed before `{packet}`")));
        }
        self.client.command(packet, deadline)
    }

    fn handshake(&mut self, endpoint: String, local: bool, deadline: Instant) -> Result<Info, DebugError> {
        let mut limitations = Vec::new();
        let reply = self.command("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm", deadline)?;
        let features = parse_features(&reply)?;
        let packet_size = match features.get("PacketSize") {
            Some(size) => parse_hex_u64(size)
                .filter(|size| *size >= 64)
                .ok_or_else(|| DebugError::Protocol("invalid PacketSize".into()))?
                .min(packet::MAX_PACKET_BYTES as u64) as usize,
            None => {
                limitations.push(format!("the stub advertises no PacketSize; requests assume {DEFAULT_PACKET_SIZE}"));
                DEFAULT_PACKET_SIZE
            }
        };
        let plus = |name: &str| features.get(name).is_some_and(|value| value == "+");
        self.multiprocess = plus("multiprocess");
        if plus("QStartNoAckMode") && self.command("QStartNoAckMode", deadline)? == b"OK" {
            self.client.disable_acks();
        }
        // LLDB's extensions are asked for only from stubs whose features show they speak LLDB's dialect
        // (debugserver advertises `qEcho+` and `native-signals+`), so GDB stubs see no new packets.
        self.lldb = plus("qEcho") || plus("native-signals");
        let lldb = if self.lldb { Some(self.host_info(&mut limitations, deadline)?) } else { None };
        let mut info = Info {
            endpoint,
            local,
            architecture: None,
            family: Family::Other,
            byte_order: ByteOrder::Unknown,
            byte_order_evidence: String::new(),
            pointer_size: None,
            multiprocess: plus("multiprocess"),
            // An LLDB stub may answer jGetLoadedDynamicLibrariesInfos and qMemoryRegionInfo, which it does not
            // advertise; listing modules asks.
            modules_available: plus("qXfer:libraries-svr4:read") || plus("qXfer:libraries:read") || self.lldb,
            memory_map_available: plus("qXfer:memory-map:read") || self.lldb,
            features,
            packet_size,
            no_ack_mode: !self.client.ack_mode(),
            layout: None,
            limitations,
            lldb,
            address_mask: None,
            windows: None,
        };
        if info.feature("qXfer:features:read") {
            let mut total = 0;
            let mut fetch = |annex: &str| -> Result<String, String> {
                let bytes = self
                    .xfer("features", annex, packet_size, MAX_DESCRIPTION_BYTES - total, deadline)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("the stub has no `{annex}`"))?;
                total += bytes.len();
                String::from_utf8(bytes).map_err(|_| format!("`{annex}` is not UTF-8"))
            };
            let layout = fetch("target.xml").and_then(|root| target::parse_description(&root, &mut fetch));
            match layout {
                Ok(layout) => info.layout = Some(layout),
                // A description that cannot be used leaves the built-in layouts; a broken stream cannot go on.
                Err(error) if self.client.in_sync() => {
                    info.limitations.push(format!("the target description is unusable: {error}"))
                }
                Err(error) => return Err(DebugError::Lost(error)),
            }
        }
        // debugserver names no architecture; its CPU type does.
        let cpu_architecture = info.lldb.as_ref().and_then(|lldb| {
            let stated = |info: &Option<HostInfo>| info.as_ref().and_then(HostInfo::architecture);
            stated(&lldb.process).or_else(|| stated(&lldb.host))
        });
        if info.layout.is_none() && self.lldb {
            info.layout = self.register_info(cpu_architecture, &mut info.limitations, deadline)?;
        }
        if let Some(layout) = &mut info.layout
            && layout.architecture.is_none()
            && let Some(architecture) = cpu_architecture
        {
            layout.architecture = Some(architecture.to_owned());
        }
        let stop = StopReply::parse(&self.command("?", deadline)?).map_err(DebugError::Protocol)?;
        self.epoch = 1;
        if stop.ended() {
            self.state = State::Exited;
        }
        self.stop = Some(stop);
        if self.state == State::Stopped {
            self.threads = self.list_threads(deadline)?;
            if info.layout.is_none() && info.apple() {
                info.limitations.push(
                    "debugserver gave neither a target description nor qRegisterInfo, and its `g` cannot be matched \
                     to a layout; registers are unavailable"
                        .into(),
                );
            } else if info.layout.is_none() {
                let reply = self.command("g", deadline)?;
                info.layout = (reply.len() % 2 == 0 && !reply.starts_with(b"E"))
                    .then(|| target::fallback_for(reply.len() / 2))
                    .flatten();
                info.limitations.push(match &info.layout {
                    Some(layout) => format!(
                        "the stub has no target description; the built-in `{}` layout was chosen because the `g` \
                         reply is exactly its {} bytes",
                        layout.architecture.as_deref().unwrap_or(""),
                        layout.g_size
                    ),
                    None => "the stub has no target description and its `g` reply matches no built-in layout; \
                             registers are unavailable"
                        .to_owned(),
                });
            }
        }
        info.windows = windows_target(&info);
        info.family = Family::of(info.layout.as_ref());
        info.architecture = info.layout.as_ref().and_then(|layout| layout.architecture.clone());
        info.pointer_size = info.family.pointer_size(info.layout.as_ref());
        if info.family == Family::Other
            && let Some(size) = info.lldb.as_ref().and_then(|lldb| {
                lldb.process.as_ref().and_then(|process| process.ptrsize).or(lldb.host.as_ref()?.ptrsize)
            })
        {
            info.pointer_size = Some(size);
        }
        if info.windows.is_none() {
            info.windows = self.probe_windows_gdbserver(&info, deadline)?;
        }
        if info.windows_gdbserver() {
            self.client.allow_thread_continue();
        }
        let (mut order, mut evidence) = self.byte_order(&info, deadline)?;
        // An LLDB stub that states the byte order (`endian:little`) of the stopped process is evidence for it.
        if order == ByteOrder::Unknown
            && self.state == State::Stopped
            && let Some(lldb) = &info.lldb
        {
            let stated =
                [("qProcessInfo", &lldb.process), ("qHostInfo", &lldb.host)].into_iter().find_map(|(name, info)| {
                    let endian = info.as_ref()?.endian.as_deref()?;
                    match endian {
                        "little" => Some((ByteOrder::Little, format!("{name} states endian:little"))),
                        "big" => Some((ByteOrder::Big, format!("{name} states endian:big"))),
                        _ => None,
                    }
                });
            if let Some((stated, why)) = stated {
                (order, evidence) = (stated, why);
            }
        }
        info.byte_order = order;
        info.byte_order_evidence = evidence;
        if info.family == Family::Aarch64
            && let Some(lldb) = &info.lldb
        {
            info.address_mask = AddressMask::for_target(lldb.process.as_ref(), lldb.host.as_ref());
        }
        Ok(info)
    }

    /// gdbserver before 16 names no OS ABI in its description (`<osabi>` arrived with GDB 16's "gdbserver: pass
    /// osabi to GDB in more target descriptions"). A GDB stub on x86 that lists `qXfer:libraries:read` but not the
    /// svr4 list is taken for gdbserver on Windows when the stopped thread's TIB answers `qGetTIBAddr`, or else an
    /// `MZ` header lies at its first library's segment address minus 0x1000.
    fn probe_windows_gdbserver(&mut self, info: &Info, deadline: Instant) -> Result<Option<WindowsTarget>, DebugError> {
        let candidate = info.lldb.is_none()
            && info.feature("qXfer:libraries:read")
            && !info.feature("qXfer:libraries-svr4:read")
            && matches!(info.family, Family::X86 | Family::X86_64)
            && self.state == State::Stopped;
        let Some(thread) = self.stop_thread().or_else(|| self.threads.first().map(|thread| thread.id)) else {
            return Ok(None);
        };
        if !candidate {
            return Ok(None);
        }
        let reply = self.command(&format!("qGetTIBAddr:{thread}"), deadline)?;
        let text = String::from_utf8_lossy(&reply);
        if parse_hex_u64(text.strip_prefix("0x").unwrap_or(&text)).is_some_and(|tib| tib != 0) {
            return Ok(Some(WindowsTarget {
                stub: "gdbserver",
                evidence: "a GDB stub without an OS ABI that lists Windows-style libraries and answers qGetTIBAddr \
                           (gdbserver before 16)"
                    .into(),
            }));
        }
        let Some(bytes) = self.xfer("libraries", "", info.packet_size, MAX_XFER_BYTES, deadline)? else {
            return Ok(None);
        };
        let first = maps::parse_libraries(&String::from_utf8_lossy(&bytes))
            .ok()
            .and_then(|modules| modules.into_iter().find_map(|module| module.segments.first().copied()));
        let Some(segment) = first else { return Ok(None) };
        let header =
            self.read_small(segment.wrapping_sub(pe::GDBSERVER_SEGMENT_OFFSET), 2, info.packet_size, deadline)?;
        Ok((header.as_deref() == Some(b"MZ")).then(|| WindowsTarget {
            stub: "gdbserver",
            evidence: "a GDB stub without an OS ABI whose first library has an MZ header 0x1000 below its segment \
                       address (gdbserver before 16)"
                .into(),
        }))
    }

    /// `qHostInfo` and `qProcessInfo`, each when the stub answers it. A reply that does not parse is a limitation,
    /// not a failure: these only add information.
    fn host_info(&mut self, limitations: &mut Vec<String>, deadline: Instant) -> Result<LldbInfo, DebugError> {
        let mut lldb = LldbInfo::default();
        for (packet, hex) in [("qHostInfo", false), ("qProcessInfo", true)] {
            let reply = self.command(packet, deadline)?;
            if reply.is_empty() || is_error(&reply) {
                continue;
            }
            match lldb::parse_host_info(&reply, hex) {
                Ok(parsed) if packet == "qHostInfo" => lldb.host = Some(parsed),
                Ok(parsed) => lldb.process = Some(parsed),
                Err(error) => limitations.push(format!("the `{packet}` reply is unusable: {error}")),
            }
        }
        let any = |test: fn(&HostInfo) -> bool| {
            lldb.process.as_ref().is_some_and(test) || lldb.host.as_ref().is_some_and(test)
        };
        lldb.apple = any(HostInfo::apple);
        // The host's subtype says what the CPU supports; the process's what it runs.
        lldb.arm64e = match &lldb.process {
            Some(process) if process.cpusubtype.is_some() => process.arm64e(),
            _ => any(HostInfo::arm64e),
        };
        Ok(lldb)
    }

    /// The register layout from LLDB's `qRegisterInfo<n>`, asked for register 0, 1, ... until the stub answers
    /// with an error, at most [`MAX_REGISTER_INFO`] of them. `None` when the stub does not answer it.
    fn register_info(
        &mut self,
        architecture: Option<&str>,
        limitations: &mut Vec<String>,
        deadline: Instant,
    ) -> Result<Option<Layout>, DebugError> {
        let mut infos = Vec::new();
        for number in 0..MAX_REGISTER_INFO {
            let reply = self.command(&format!("qRegisterInfo{number:x}"), deadline)?;
            if reply.is_empty() || is_error(&reply) {
                break;
            }
            match lldb::parse_register_info(&reply) {
                Ok(info) => infos.push(info),
                Err(error) => {
                    limitations.push(format!("qRegisterInfo{number:x} is unusable ({error}); registers come from `g`"));
                    return Ok(None);
                }
            }
            if number + 1 == MAX_REGISTER_INFO {
                limitations.push(format!("only the first {MAX_REGISTER_INFO} registers are described"));
            }
        }
        if infos.is_empty() {
            return Ok(None);
        }
        match target::from_register_info(architecture.map(str::to_owned), &infos) {
            Ok(layout) => {
                limitations.push(format!(
                    "the stub has no target description; {} registers come from qRegisterInfo",
                    layout.registers.len()
                ));
                Ok(Some(layout))
            }
            Err(error) => {
                limitations.push(format!("the qRegisterInfo layout is unusable: {error}"));
                Ok(None)
            }
        }
    }

    /// The data byte order, only from evidence that fixes it: the architecture where it has a single order, or a
    /// stop-bound register whose layout pins its own transfer order. Architecture defaults are not evidence.
    fn byte_order(&mut self, info: &Info, deadline: Instant) -> Result<(ByteOrder, String), DebugError> {
        let unknown = |why: &str| Ok((ByteOrder::Unknown, why.to_owned()));
        if self.state != State::Stopped {
            return unknown("the process is not stopped");
        }
        match info.family {
            Family::X86 | Family::X86_64 => Ok((ByteOrder::Little, "x86 has no big-endian mode".into())),
            Family::Arm if target::m_profile(info.layout.as_ref()) => {
                let chunk = self.read_chunk(AIRCR, 4, false, info.packet_size, deadline)?;
                // The System Control Space is little-endian whatever the data order, so VECTKEYSTAT 0xFA05 always
                // reads back in its upper bytes and ENDIANNESS (bit 15) gives the data order.
                Ok(match chunk.bytes[..] {
                    [_, low, 0x05, 0xfa] if chunk.error.is_none() && low & 0x80 == 0 => {
                        (ByteOrder::Little, "Cortex-M AIRCR reads back VECTKEYSTAT 0xFA05 with ENDIANNESS clear".into())
                    }
                    [_, _, 0x05, 0xfa] if chunk.error.is_none() => (
                        ByteOrder::Big,
                        "Cortex-M AIRCR reads back VECTKEYSTAT 0xFA05 with ENDIANNESS set (BE8 data)".into(),
                    ),
                    _ => (ByteOrder::Unknown, "Cortex-M AIRCR did not read back VECTKEYSTAT 0xFA05".into()),
                })
            }
            Family::Arm => {
                let Some(cpsr) = info.layout.as_ref().and_then(|layout| layout.register("cpsr")).cloned() else {
                    return unknown("the ARM layout has no CPSR");
                };
                self.use_thread(None, deadline)?;
                let registers = self.read_registers(info, deadline)?;
                let bytes = registers
                    .iter()
                    .find(|register| register.name == cpsr.name)
                    .and_then(|register| register.bytes.as_deref())
                    .and_then(|bytes| decode_hex(bytes.as_bytes()))
                    .filter(|bytes| bytes.len() == 4);
                let Some(bytes) = bytes else { return unknown("CPSR is unavailable") };
                // CPSR.E (bit 9) is the data order; the mode field (bits 4:0) must be a valid mode for an order to
                // be consistent with the bytes.
                let consistent = |value: u32, big: bool| {
                    matches!(value & 0x1f, 0x10 | 0x11 | 0x12 | 0x13 | 0x16 | 0x17 | 0x1a | 0x1b | 0x1f)
                        && (value >> 9 & 1 == 1) == big
                };
                let little = consistent(u32::from_le_bytes(bytes[..].try_into().expect("4 bytes")), false);
                let big = consistent(u32::from_be_bytes(bytes[..].try_into().expect("4 bytes")), true);
                Ok(match (little, big) {
                    (true, false) => {
                        (ByteOrder::Little, "CPSR.E and its mode bits are consistent only with little-endian".into())
                    }
                    (false, true) => {
                        (ByteOrder::Big, "CPSR.E and its mode bits are consistent only with big-endian (BE8)".into())
                    }
                    _ => (ByteOrder::Unknown, "CPSR does not fix a single byte order".into()),
                })
            }
            Family::Aarch64 => unknown(
                "AArch64 registers do not expose EL0 data endianness (SCTLR_EL1.E0E); values are given as the \
                 bytes the stub sent",
            ),
            _ => unknown("no stop-bound evidence of this architecture's data byte order"),
        }
    }

    fn serve(&mut self, inbox: Receiver<Job>) {
        loop {
            let job = if self.state == State::Running {
                match inbox.try_recv() {
                    Ok(job) => Some(job),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => break,
                }
            } else {
                match inbox.recv() {
                    Ok(job) => Some(job),
                    Err(_) => break,
                }
            };
            match job {
                Some(job) => {
                    if self.handle(job) {
                        break;
                    }
                }
                None => {
                    // Handling the stop belongs to the resume that caused it: it may put back breakpoints stepped
                    // past, or take a request's next step.
                    self.client.set_permit(Permit::EXECUTION);
                    let deadline = Instant::now() + self.command_timeout;
                    match self.client.poll(POLL_SLICE) {
                        Ok(Some(reply)) => self.end_run(reply, deadline, true),
                        Ok(None) => {}
                        Err(error) => self.lose(error),
                    }
                }
            }
            self.expire_stepping();
            self.expire_waiters();
        }
        // The last handle dropped without detaching: stop a running target, remove breakpoints and detach,
        // best-effort, before closing.
        if self.client.in_sync() && matches!(self.state, State::Stopped | State::Running) {
            self.client.set_permit(Permit::DETACH);
            let _ = self.detach(Instant::now() + CLOSE_DETACH);
        }
        self.abandon_stepping("the session closed");
        self.answer_waiters();
    }

    /// Serves one request; true when the session is finished.
    fn handle(&mut self, job: Job) -> bool {
        let Job { request, deadline, reply } = job;
        // The session's own check, independent of the tools that list (or do not list) write and kill: a request
        // the operator did not allow is refused before its packet class is even permitted.
        let refusal = match &request {
            Request::WriteMemory { .. } | Request::WriteRegister { .. } if !self.consent.writes => {
                Some(WRITES_NOT_ALLOWED)
            }
            Request::Kill if !self.consent.kill => Some(KILL_NOT_ALLOWED),
            _ => None,
        };
        if let Some(refusal) = refusal {
            let _ = reply.send(Err(DebugError::NotAllowed(refusal.into())));
            return false;
        }
        // A request that waited in the queue past its deadline (behind a long step, say) sends nothing: its caller
        // may already have given up and reported the session lost. The connection is still in step, so it is kept.
        if Instant::now() >= deadline {
            let _ = reply.send(Err(DebugError::Timeout(
                "the request waited past its deadline before it was served; nothing was sent".into(),
            )));
            return false;
        }
        self.client.set_permit(request.permit());
        let detach = matches!(request, Request::Detach);
        let kill = matches!(request, Request::Kill);
        let result = match request {
            // A call cancelled before it was served resumes nothing.
            Request::Continue { cancel, .. } if cancel.is_cancelled() && self.state != State::Running => {
                Err(DebugError::Cancelled("the call was cancelled before the target was resumed".into()))
            }
            Request::Continue { epoch, wait, cancel } => {
                match self.start_continue(epoch, wait, &cancel, &reply, deadline) {
                    // Stepping past a breakpoint first: the step answers, or the continue that follows it does.
                    Ok(true) => return false,
                    Ok(false) => {
                        self.waiters.push(Waiter::new(reply, wait, cancel));
                        return false;
                    }
                    Err(error) => Err(error),
                }
            }
            Request::Wait { wait, cancel } if self.state == State::Running => {
                self.waiters.push(Waiter::new(reply, wait, cancel));
                return false;
            }
            Request::Wait { .. } => Ok(Response::Run(self.run_state(false))),
            Request::Interrupt { wait, cancel } if self.state == State::Running => {
                // A stop reply already on its way answers the interrupt without sending another one.
                match self.client.poll(INTERRUPT_PEEK) {
                    Ok(Some(stop)) => self.end_run(stop, Instant::now() + self.command_timeout, true),
                    Ok(None) => {}
                    Err(error) => self.lose(error),
                }
                if self.state != State::Running {
                    let _ = reply.send(Ok(Response::Run(self.run_state(false))));
                    return false;
                }
                // Each interrupt sends the byte again: an earlier one may have been lost or ignored.
                match self.client.interrupt() {
                    Ok(()) => {
                        self.interrupted = true;
                        if let Some(stepping) = &mut self.stepping {
                            stepping.halt = true;
                        }
                        self.waiters.push(Waiter::new(reply, wait, cancel));
                        return false;
                    }
                    Err(error) => Err(error),
                }
            }
            Request::Step { epoch, thread, count, past, cancel } if self.state != State::Running => {
                match self.start_steps(epoch, thread, count, past, cancel, &reply, deadline) {
                    Ok(()) => return false,
                    Err(error) => Err(error),
                }
            }
            Request::Interrupt { .. } => Err(DebugError::NotRunning(format!(
                "the target is not running ({}); there is nothing to interrupt",
                describe(&self.state)
            ))),
            Request::Status | Request::Detach | Request::Kill => self.run(request, deadline),
            _ if self.state == State::Running => Err(DebugError::Running(
                "only debug_status, debug_wait, debug_interrupt and debug_disconnect are served until it stops".into(),
            )),
            request => self.run(request, deadline),
        };
        // A refused detach or kill leaves the session attached and serving.
        let refused = match &result {
            Ok(Response::Detached(detached)) => detached.refused.is_some(),
            Ok(Response::Killed(killed)) => killed.refused.is_some(),
            _ => false,
        };
        let finished = !refused
            && ((detach && !matches!(result, Err(DebugError::Target(_))))
                || (kill && !matches!(result, Err(ref error) if kill_keeps_session(error))));
        if let Err(error) = &result
            && error.fatal()
        {
            self.lose(error.clone());
        }
        let _ = reply.send(result);
        finished
    }

    /// Marks the session lost and closes the connection; waiting callers get `error`.
    fn lose(&mut self, error: DebugError) {
        if !matches!(self.state, State::Lost { .. }) {
            self.state = State::Lost { reason: error.to_string() };
            self.client.shutdown();
        }
        self.resumed_at = None;
        if let Some(stepping) = self.stepping.take() {
            let _ = stepping.reply.send(Err(error.clone()));
        }
        for waiter in std::mem::take(&mut self.waiters) {
            let _ = waiter.reply.send(Err(error.clone()));
        }
    }

    /// Answers every waiter with the current state (used when the session ends).
    fn answer_waiters(&mut self) {
        let run = self.run_state(false);
        for waiter in std::mem::take(&mut self.waiters) {
            let mut run = run.clone();
            run.warnings = waiter.warnings;
            let _ = waiter.reply.send(Ok(Response::Run(run)));
        }
    }

    /// Answers the waiters whose time ran out or who cancelled: the target is still running.
    fn expire_waiters(&mut self) {
        let now = Instant::now();
        let waiters = std::mem::take(&mut self.waiters);
        for waiter in waiters {
            let cancelled = waiter.cancel.is_cancelled();
            if cancelled || now >= waiter.deadline {
                let mut run = self.run_state(cancelled);
                run.warnings = waiter.warnings;
                let _ = waiter.reply.send(Ok(Response::Run(run)));
            } else {
                self.waiters.push(waiter);
            }
        }
    }

    fn run_state(&self, cancelled: bool) -> Run {
        Run {
            state: self.state.clone(),
            epoch: self.epoch,
            running_for_ms: self.running_for_ms(),
            cancelled,
            event: if self.state == State::Running { None } else { self.last_stop.clone() },
            warnings: Vec::new(),
        }
    }

    fn running_for_ms(&self) -> Option<u64> {
        self.resumed_at.filter(|_| self.state == State::Running).map(|at| at.elapsed().as_millis() as u64)
    }

    fn check_epoch(&self, epoch: Option<u64>) -> Result<(), DebugError> {
        match epoch {
            Some(given) if given != self.epoch => {
                Err(DebugError::StaleEpoch { given, current: self.epoch, state: describe(&self.state) })
            }
            _ => Ok(()),
        }
    }

    /// The stub's `vCont` support, asked once.
    fn vcont(&mut self, deadline: Instant) -> Result<VCont, DebugError> {
        if let Some(vcont) = self.vcont {
            return Ok(vcont);
        }
        let vcont = VCont::parse(&self.command("vCont?", deadline)?);
        self.vcont = Some(vcont);
        Ok(vcont)
    }

    /// Resumes every thread, without a signal. A thread stopped at an inserted breakpoint would hit it again at
    /// once, so those breakpoints are removed, the thread steps off them, and they go back at the step's stop
    /// before the continue proper (true: the step is under way and answers `reply` itself).
    fn start_continue(
        &mut self,
        epoch: Option<u64>,
        wait: Duration,
        cancel: &Cancel,
        reply: &Sender<Result<Response, DebugError>>,
        deadline: Instant,
    ) -> Result<bool, DebugError> {
        self.check_epoch(epoch)?;
        self.require_stopped()?;
        let at_pc = self.breakpoints_at_pc(deadline)?;
        if at_pc.is_empty() {
            self.resume_all(deadline)?;
            return Ok(false);
        }
        self.lift(&at_pc, deadline)?;
        let thread = self.step_thread(None)?;
        let packet = self.step_packet(thread, deadline)?;
        self.stepping = Some(Stepping {
            thread,
            packet,
            reply: reply.clone(),
            cancel: cancel.clone(),
            step_deadline: Instant::now(),
            halt: false,
            past: false,
            go_on: true,
            purpose: Purpose::PastBreakpoints { wait },
        });
        if let Err(error) = self.next_step(deadline) {
            self.stepping = None;
            self.put_back(&error, deadline);
            return Err(error);
        }
        Ok(true)
    }

    /// Indices of the inserted breakpoints at the stopped thread's pc, and of the watchpoints the current stop hit
    /// when the stub stops before the access executes: either would stop the thread again at once.
    fn breakpoints_at_pc(&mut self, deadline: Instant) -> Result<Vec<usize>, DebugError> {
        let mut entries = self.watchpoints_hit();
        if !self.breakpoints.iter().any(|entry| entry.inserted && !entry.kind.is_watchpoint()) {
            return Ok(entries);
        }
        let pcs = match self.stop.clone() {
            Some(stop) => match self.stop_pc(&stop, deadline) {
                Ok((_, pcs)) => pcs,
                Err(error) if error.fatal() => return Err(error),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        entries.extend((0..self.breakpoints.len()).filter(|index| {
            let entry = &self.breakpoints[*index];
            entry.inserted && !entry.kind.is_watchpoint() && pcs.contains(&entry.address)
        }));
        Ok(entries)
    }

    /// Indices of the inserted watchpoints the current stop hit, when the stub reports watchpoint hits before the
    /// access executes (`watchpoint_exceptions_received:before`, as debugserver on ARM does): the thread is still at
    /// the accessing instruction, and resuming would hit them again at once.
    fn watchpoints_hit(&self) -> Vec<usize> {
        let before = self.info.as_ref().is_some_and(|info| {
            let stated = info.lldb.as_ref().and_then(|lldb| {
                [&lldb.process, &lldb.host]
                    .into_iter()
                    .find_map(|info| info.as_ref()?.watchpoint_exceptions_received.clone())
            });
            match stated.as_deref() {
                Some(stated) => stated == "before",
                None => info.apple() && matches!(info.family, Family::Aarch64 | Family::Arm),
            }
        });
        let Some(event) = self.last_stop.as_ref().filter(|event| {
            before && event.epoch == self.epoch && event.reason == StopCause::Watchpoint && self.state == State::Stopped
        }) else {
            return Vec::new();
        };
        (0..self.breakpoints.len())
            .filter(|index| {
                let entry = &self.breakpoints[*index];
                entry.inserted && entry.kind.is_watchpoint() && event.breakpoints.contains(&entry.id)
            })
            .collect()
    }

    /// Takes the breakpoints at `at_pc` out of the stub, to be put back at the next stop. If the stub refuses one,
    /// the ones already taken out go back and nothing runs.
    fn lift(&mut self, at_pc: &[usize], deadline: Instant) -> Result<(), DebugError> {
        for (done, index) in at_pc.iter().enumerate() {
            let packet = self.breakpoints[*index].remove_packet();
            let removed = self.command(&packet, deadline)?;
            if removed != b"OK" {
                let mut warnings = Vec::new();
                for earlier in &at_pc[..done] {
                    let insert = self.breakpoints[*earlier].insert_packet();
                    if self.command(&insert, deadline)? != b"OK" {
                        self.breakpoints[*earlier].inserted = false;
                        warnings.push(format!("breakpoint {} could not be re-inserted", self.breakpoints[*earlier].id));
                    }
                    self.reinsert.retain(|id| *id != self.breakpoints[*earlier].id);
                }
                return Err(DebugError::Target(format!(
                    "cannot step past breakpoint {}: the stub refused `{packet}` ({}){}",
                    self.breakpoints[*index].id,
                    reply_text(&removed),
                    if warnings.is_empty() { String::new() } else { format!("; {}", warnings.join("; ")) }
                )));
            }
            self.breakpoints[*index].inserted = false;
            self.reinsert.push(self.breakpoints[*index].id);
        }
        Ok(())
    }

    /// Puts back the breakpoints taken out to step past them when the step never ran because of `error`.
    fn put_back(&mut self, error: &DebugError, deadline: Instant) {
        for id in std::mem::take(&mut self.reinsert) {
            let Some(index) = self.breakpoints.iter().position(|entry| entry.id == id) else { continue };
            let packet = self.breakpoints[index].insert_packet();
            if !error.fatal() && self.command(&packet, deadline).is_ok_and(|reply| reply == b"OK") {
                self.breakpoints[index].inserted = true;
            }
        }
    }

    /// Resumes every thread: `vCont;c`, else `c` once no `Hc<thread>` limits it. On Windows under gdbserver, with
    /// break-in threads parked, every other thread by name (`vCont;c:<thread>;...`).
    fn resume_all(&mut self, deadline: Instant) -> Result<(), DebugError> {
        if !self.parked.is_empty() {
            self.threads = self.list_threads(deadline)?;
            self.parked.retain(|parked| self.threads.iter().any(|known| known.id == *parked));
        }
        if !self.parked.is_empty() {
            let packet_size = self.info.as_ref().map_or(DEFAULT_PACKET_SIZE, |info| info.packet_size);
            let others: Vec<String> = self
                .threads
                .iter()
                .filter(|thread| !self.parked.contains(&thread.id))
                .map(|thread| format!("c:{}", thread.id))
                .collect();
            let packet = format!("vCont;{}", others.join(";"));
            if others.is_empty() || packet.len() + 8 > packet_size || !self.vcont(deadline)?.continue_ {
                return Err(DebugError::Unsupported(format!(
                    "thread {} is parked at the int3 gdbserver moved its pc back onto, and the other threads cannot \
                     be resumed without it ({}); disconnect to let it go, or move its pc past the int3 with \
                     debug_write_register",
                    self.parked[0],
                    if others.is_empty() { "there are none" } else { "the vCont naming them does not fit a packet" }
                )));
            }
            return self.resume(&packet, Origin::Continue);
        }
        if self.vcont(deadline)?.continue_ {
            return self.resume("vCont;c", Origin::Continue);
        }
        if self.hc_thread {
            // Without vCont, a step selected its thread with Hc, and some stubs (gdbserver) then resume only that
            // thread on `c`. `Hc-1` selects all threads again.
            let reply = self.command("Hc-1", deadline)?;
            if reply != b"OK" {
                return Err(DebugError::Unsupported(format!(
                    "this stub has no vCont, and after a step selected one thread with Hc it refused Hc-1 ({}); a \
                     plain `c` could resume only that thread, so nothing was resumed",
                    reply_text(&reply)
                )));
            }
            self.hc_thread = false;
        }
        self.resume("c", Origin::Continue)
    }

    /// The thread a step uses: `thread` if the session lists it, else [the default](Self::default_thread).
    fn step_thread(&self, thread: Option<ThreadId>) -> Result<Option<ThreadId>, DebugError> {
        if let Some(thread) = thread {
            if !self.threads.iter().any(|known| known.id == thread) {
                return Err(DebugError::Invalid(format!("thread {thread} is not one of the session's threads")));
            }
            return Ok(Some(thread));
        }
        Ok(self.default_thread())
    }

    /// The stop reply's thread, when the session lists it.
    fn stop_thread(&self) -> Option<ThreadId> {
        match &self.stop {
            Some(StopReply::Signal { thread: Some(thread), .. }) => {
                Some(*thread).filter(|stop| self.threads.iter().any(|known| known.id == *stop))
            }
            _ => None,
        }
    }

    /// The thread reads and steps use when the caller names none: the stop's thread, else the first listed. On
    /// Windows, after an interrupt, the stop's thread is the one the system created for it (it runs
    /// `DbgUiRemoteBreakin` or the console control handler and ends when resumed), so the first other listed
    /// thread is used instead.
    fn default_thread(&self) -> Option<ThreadId> {
        let other = |id: &ThreadId| Some(*id) != self.breakin && !self.parked.contains(id);
        self.stop_thread()
            .filter(other)
            .or_else(|| self.threads.iter().map(|thread| thread.id).find(other))
            .or_else(|| self.stop_thread())
    }

    fn step_packet(&mut self, thread: Option<ThreadId>, deadline: Instant) -> Result<String, DebugError> {
        Ok(match thread {
            Some(thread) if self.vcont(deadline)?.step => format!("vCont;s:{thread}"),
            _ => "s".to_owned(),
        })
    }

    /// Starts a step request; its stops are handled in the main loop.
    #[allow(clippy::too_many_arguments)]
    fn start_steps(
        &mut self,
        epoch: Option<u64>,
        thread: Option<ThreadId>,
        count: u32,
        past: bool,
        cancel: Cancel,
        reply: &Sender<Result<Response, DebugError>>,
        deadline: Instant,
    ) -> Result<(), DebugError> {
        self.check_epoch(epoch)?;
        self.require_stopped()?;
        let thread = self.step_thread(thread)?;
        let packet = self.step_packet(thread, deadline)?;
        let steps = Steps {
            state: State::Stopped,
            epoch: self.epoch,
            thread,
            requested: count,
            completed: 0,
            pcs: Vec::new(),
            event: None,
            cancelled: false,
            truncated: None,
            running_for_ms: None,
        };
        self.stepping = Some(Stepping {
            thread,
            packet,
            reply: reply.clone(),
            cancel,
            step_deadline: Instant::now(),
            halt: false,
            past,
            go_on: true,
            purpose: Purpose::Steps { steps: Box::new(steps), budget: Instant::now() + STEP_BUDGET },
        });
        self.next_step(deadline).inspect_err(|_| self.stepping = None)
    }

    /// Sends the next step, or ends a step request that is done, cancelled, halted or out of time.
    fn next_step(&mut self, deadline: Instant) -> Result<(), DebugError> {
        let Some(stepping) = &mut self.stepping else { return Ok(()) };
        if let Purpose::Steps { steps, budget } = &mut stepping.purpose {
            let finished = if stepping.cancel.is_cancelled() {
                steps.cancelled = true;
                true
            } else if stepping.halt || steps.completed >= steps.requested {
                true
            } else if Instant::now() >= *budget {
                steps.truncated = Some(format!(
                    "no step starts {} s after the request; each step may take up to the {} s request timeout",
                    STEP_BUDGET.as_secs(),
                    self.command_timeout.as_secs()
                ));
                true
            } else {
                false
            };
            if finished {
                self.finish_steps(deadline);
                return Ok(());
            }
        }
        let (packet, thread, past) = (stepping.packet.clone(), stepping.thread, stepping.past);
        if past {
            // The pc is the stepped thread's only when it is the stop's thread; otherwise nothing is taken out.
            let stop_thread = match &self.stop {
                Some(StopReply::Signal { thread, .. }) => *thread,
                _ => None,
            };
            if stop_thread.is_none() || thread.is_none() || stop_thread == thread {
                let at_pc = match self.breakpoints_at_pc(deadline) {
                    Ok(at_pc) => at_pc,
                    Err(error) => {
                        self.stepping = None;
                        return Err(error);
                    }
                };
                if let Err(error) = self.lift(&at_pc, deadline) {
                    self.stepping = None;
                    return Err(error);
                }
            }
        }
        if packet == "s"
            && let Some(thread) = thread
        {
            let reply = match self.command(&format!("Hc{thread}"), deadline) {
                Ok(reply) => reply,
                Err(error) => {
                    self.stepping = None;
                    self.put_back(&error, deadline);
                    return Err(error);
                }
            };
            if reply != b"OK" {
                self.stepping = None;
                let error =
                    DebugError::Target(format!("cannot select thread {thread} to step: {}", reply_text(&reply)));
                self.put_back(&error, deadline);
                return Err(error);
            }
            self.hc_thread = true;
        }
        if let Err(error) = self.resume(&packet, Origin::Step(thread)) {
            self.stepping = None;
            self.put_back(&error, deadline);
            return Err(error);
        }
        if let Some(stepping) = &mut self.stepping {
            stepping.step_deadline = Instant::now() + self.command_timeout;
        }
        Ok(())
    }

    /// Answers a step request with what it did, refreshing the threads when the target is stopped.
    fn finish_steps(&mut self, deadline: Instant) {
        let Some(stepping) = self.stepping.take() else { return };
        let Purpose::Steps { steps, .. } = stepping.purpose else {
            self.stepping = Some(stepping);
            return;
        };
        if self.state == State::Stopped && steps.event.is_some() {
            match self.list_threads(deadline) {
                Ok(threads) => self.threads = threads,
                Err(error) => {
                    let _ = stepping.reply.send(Err(error.clone()));
                    if error.fatal() {
                        self.lose(error);
                    }
                    return;
                }
            }
        }
        let mut steps = *steps;
        steps.state = self.state.clone();
        steps.epoch = self.epoch;
        steps.running_for_ms = self.running_for_ms();
        let _ = stepping.reply.send(Ok(Response::Steps(steps)));
    }

    /// A step's stop: counts it, then takes the next step, finishes the request, or (past a breakpoint) goes on
    /// to the continue.
    fn step_stopped(&mut self, reply: Vec<u8>, deadline: Instant) {
        let event = match self.finish_run(reply, deadline, false) {
            Ok(event) => event,
            Err(error) => {
                if let Some(stepping) = self.stepping.take() {
                    let _ = stepping.reply.send(Err(error.clone()));
                }
                if error.fatal() {
                    self.lose(error);
                }
                return;
            }
        };
        let completed = event.reason == StopCause::Step && self.state == State::Stopped;
        let Some(stepping) = &mut self.stepping else { return };
        match &mut stepping.purpose {
            Purpose::Steps { steps, .. } => {
                if completed {
                    steps.completed += 1;
                    steps.pcs.push(event.pc.map(|pc| format!("{pc:#x}")));
                }
                steps.event = Some(event);
                let result = if completed {
                    self.next_step(deadline)
                } else {
                    self.finish_steps(deadline);
                    Ok(())
                };
                if let Err(error) = result {
                    if let Some(stepping) = self.stepping.take() {
                        let _ = stepping.reply.send(Err(error.clone()));
                    }
                    if error.fatal() {
                        self.lose(error);
                    }
                }
            }
            Purpose::PastBreakpoints { wait } => {
                let wait = *wait;
                let stepping = self.stepping.take().expect("stepping");
                let warnings = event.warnings.clone();
                if !completed || !stepping.go_on {
                    // The step stopped for its own reason (or was halted): that stop is the continue's answer.
                    let mut run = self.run_state(stepping.cancel.is_cancelled());
                    run.warnings = warnings;
                    let _ = stepping.reply.send(Ok(Response::Run(run)));
                    return;
                }
                match self.resume_all(deadline) {
                    Ok(()) => {
                        let mut waiter = Waiter::new(stepping.reply, wait, stepping.cancel);
                        waiter.warnings = warnings;
                        self.waiters.push(waiter);
                    }
                    Err(error) => {
                        let _ = stepping.reply.send(Err(error.clone()));
                        if error.fatal() {
                            self.lose(error);
                        }
                    }
                }
            }
        }
    }

    /// Answers a step whose stop has not come in time, or whose caller cancelled: the target is left running and
    /// the step's stop, when it comes, is an ordinary stop.
    fn expire_stepping(&mut self) {
        let Some(stepping) = &self.stepping else { return };
        let cancelled = stepping.cancel.is_cancelled();
        if self.state != State::Running || !(cancelled || Instant::now() >= stepping.step_deadline) {
            return;
        }
        let why = if cancelled { "the call was cancelled" } else { "the step did not finish in time" };
        self.abandon_stepping(why);
    }

    /// Answers the step in progress, if any, with the target as it is.
    fn abandon_stepping(&mut self, why: &str) {
        let Some(stepping) = self.stepping.take() else { return };
        let cancelled = stepping.cancel.is_cancelled();
        let response = match stepping.purpose {
            Purpose::Steps { steps, .. } => {
                let mut steps = *steps;
                steps.cancelled = cancelled;
                steps.state = self.state.clone();
                steps.epoch = self.epoch;
                steps.running_for_ms = self.running_for_ms();
                if !cancelled {
                    steps.truncated = Some(format!("{why}; the target was left running"));
                }
                Response::Steps(steps)
            }
            Purpose::PastBreakpoints { .. } => {
                let mut run = self.run_state(cancelled);
                run.warnings
                    .push(format!("{why} while stepping past a breakpoint; it is re-inserted at the next stop"));
                Response::Run(run)
            }
        };
        let _ = stepping.reply.send(Ok(response));
    }

    fn resume(&mut self, packet: &str, origin: Origin) -> Result<(), DebugError> {
        self.client.resume(packet)?;
        self.origin = origin;
        // An interrupt a DLL-load stop got ahead of is still to be answered (Windows).
        self.interrupted = std::mem::take(&mut self.interrupt_pending);
        self.breakin = None;
        self.state = State::Running;
        self.resumed_at = Some(Instant::now());
        Ok(())
    }

    /// Records the packet that ended a run and answers the waiters with it.
    fn end_run(&mut self, reply: Vec<u8>, deadline: Instant, list_threads: bool) {
        if self.stepping.is_some() {
            self.step_stopped(reply, deadline);
            if self.stepping.is_none() && self.state != State::Running {
                self.answer_waiters();
            }
            return;
        }
        match self.finish_run(reply, deadline, list_threads) {
            Ok(_) => {
                let run = self.run_state(false);
                for waiter in std::mem::take(&mut self.waiters) {
                    let mut run = run.clone();
                    run.warnings = waiter.warnings;
                    let _ = waiter.reply.send(Ok(Response::Run(run)));
                }
            }
            Err(error) if error.fatal() => self.lose(error),
            Err(error) => {
                for waiter in std::mem::take(&mut self.waiters) {
                    let _ = waiter.reply.send(Err(error.clone()));
                }
            }
        }
    }

    /// Turns the packet that ended a run into a stop event: a new epoch, the pc, the table entries it matched, and
    /// (with `list_threads`) the threads. An error or empty reply means the stub refused to resume; the target is
    /// stopped as before.
    fn finish_run(&mut self, reply: Vec<u8>, deadline: Instant, list_threads: bool) -> Result<StopEvent, DebugError> {
        let interrupted = std::mem::take(&mut self.interrupted);
        self.resumed_at = None;
        if let Some(stepping) = &mut self.stepping {
            stepping.go_on = !stepping.halt && !stepping.cancel.is_cancelled();
        }
        if reply.is_empty() || is_error(&reply) {
            self.state = State::Stopped;
            return Err(if reply.is_empty() {
                DebugError::Unsupported("the stub does not support the resume packet".into())
            } else {
                DebugError::Target(format!("the stub refused to resume: {}", reply_text(&reply)))
            });
        }
        let mut stop = StopReply::parse(&reply).map_err(DebugError::Protocol)?;
        self.epoch += 1;
        // Stubs select the stopped thread themselves; nothing an earlier request selected can be relied on.
        self.selected = None;
        self.state = if stop.ended() { State::Exited } else { State::Stopped };
        if stop.ended() {
            for entry in &mut self.breakpoints {
                entry.inserted = false;
            }
            self.reinsert.clear();
        }
        self.stop = Some(stop.clone());
        let (thread, signal, exit_status) = match &stop {
            StopReply::Signal { thread, signal, .. } => (*thread, Some(*signal), None),
            StopReply::Exited { status, .. } => (None, None, Some(*status)),
            StopReply::Terminated { signal, .. } => (None, u8::try_from(*signal).ok(), None),
        };
        let stale = thread.is_some_and(|thread| !self.threads.iter().any(|known| known.id == thread));
        if self.state == State::Stopped && (list_threads || stale) {
            self.threads = self.list_threads(deadline)?;
        }
        let info = Arc::clone(self.info.as_ref().expect("the handshake sets the session info"));
        // gdbserver on Windows reports exceptions as signals (`gdb/nat/windows-nat.c`, `handle_exception`); the
        // exception record itself comes from `qXfer:siginfo:read` (`windows_thread_info::xfer_siginfo`). A SIGTRAP
        // after a single step is not asked about, so stepping costs no extra round trips.
        let stepped = matches!(self.origin, Origin::Step(_)) && signal == Some(5);
        if info.windows_gdbserver()
            && info.feature("qXfer:siginfo:read")
            && signal.is_some_and(|signal| signal != 0)
            && !stepped
            && let Some(thread) = thread
            && let Some(exception) = self.siginfo(thread, deadline)?
            && let StopReply::Signal { reasons, .. } = &mut stop
        {
            reasons.insert(0, StopReason::WindowsException(exception));
            self.stop = Some(stop.clone());
        }
        // The stop happened whether or not its pc can be read; only a broken stream fails it.
        let (pc_bytes, pcs) = match self.state {
            State::Stopped => match self.stop_pc(&stop, deadline) {
                Ok(pc) => pc,
                Err(error) if error.fatal() => return Err(error),
                Err(_) => (None, Vec::new()),
            },
            _ => (None, Vec::new()),
        };
        // gdbserver stops for DLL loads with signal 0 and `library` (`gdbserver/target.cc`, `mywait`); one that
        // arrives after an interrupt is not its answer, which comes after the next resume.
        let library = matches!(&stop, StopReply::Signal { reasons, .. } if reasons.contains(&StopReason::Library));
        let interrupted = if info.is_windows() && interrupted && library {
            self.interrupt_pending = true;
            false
        } else {
            interrupted
        };
        let (mut reason, breakpoints, watch) =
            exec::classify(&stop, self.origin, interrupted, &pcs, &mut self.breakpoints);
        // debugserver answers the interrupt byte by stopping the process with SIGSTOP (17), reported as such
        // (`native-signals`), not as SIGINT; so does lldb-server on Windows, whose own `DebugBreakProcess`
        // injection is "treated as Halt SIGSTOP" (`NativeProcessWindows.cpp`, `HandleBreakpointException`).
        if reason == StopCause::Signal
            && interrupted
            && signal == Some(17)
            && (info.apple() || (info.is_windows() && info.lldb.is_some()))
        {
            reason = StopCause::Interrupted;
        }
        let mut warnings = Vec::new();
        // gdbserver on Windows interrupts with a console Ctrl-Break (DBG_CONTROL_BREAK, SIGINT) or, when that
        // fails, `DebugBreakProcess`, whose int3 in a new thread arrives as a SIGTRAP with `swbreak`
        // (`gdbserver/win32-low.cc`, `request_interrupt`). Either way the stop is in a thread the system created.
        let new_thread = stale && thread.is_some();
        if info.is_windows() && interrupted && new_thread && breakpoints.is_empty() && signal == Some(5) {
            reason = StopCause::Interrupted;
        }
        if info.is_windows() && reason == StopCause::Interrupted && new_thread {
            self.breakin = thread;
            let others = self.default_thread().map(|other| format!("; reads and steps without a thread use {other}"));
            warnings.push(format!(
                "the interrupt stopped in thread {}, which Windows created to deliver it and which ends when \
                 resumed{}",
                thread.map(|thread| thread.to_string()).unwrap_or_default(),
                others.unwrap_or_default()
            ));
        }
        // gdbserver rewinds the pc of every thread stopped by an int3 onto it (`win32-low.cc`, `maybe_adjust_pc`),
        // its own breakpoints' or not, so a continue executes that int3 again.
        let rewound = reason != StopCause::Watchpoint
            && signal == Some(5)
            && matches!(&stop, StopReply::Signal { reasons, .. } if reasons.contains(&StopReason::SwBreak));
        let ours =
            self.breakpoints.iter().any(|entry| entry.kind == BreakKind::Software && pcs.contains(&entry.address));
        if info.windows_gdbserver()
            && rewound
            && !ours
            && reason == StopCause::Interrupted
            && let Some(thread) = thread
            && new_thread
        {
            // gdbserver's resume continues only the threads a vCont names (`win32-low.cc`,
            // `win32_process_target::resume`), so the break-in thread can stay suspended at its int3; it exists
            // only to trap. Detaching lets it run, and `DbgUiRemoteBreakin`'s exception handler absorbs the int3.
            if !self.parked.contains(&thread) {
                self.parked.push(thread);
            }
            warnings.push(format!(
                "gdbserver moved thread {thread}'s pc back onto DebugBreakProcess's int3; rampage leaves that thread \
                 suspended, and continues resume every other thread by name until it is gone or rampage detaches"
            ));
        } else if info.windows_gdbserver() && rewound && !ours {
            warnings.push(
                "gdbserver moved this thread's pc back onto an int3 that is not one of rampage's breakpoints \
                 (DebugBreakProcess's, or one compiled into the program); continuing executes it again and stops \
                 here, unless the pc is moved past it (debug_write_register, with --debug-writes)"
                    .into(),
            );
        }
        let exception = exec::exception(&stop);
        // Breakpoints stepped past go back now, whatever stopped the step.
        for id in std::mem::take(&mut self.reinsert) {
            let Some(index) = self.breakpoints.iter().position(|entry| entry.id == id) else { continue };
            let packet = self.breakpoints[index].insert_packet();
            match self.command(&packet, deadline) {
                Ok(reply) if reply == b"OK" => self.breakpoints[index].inserted = true,
                Ok(reply) => warnings.push(format!(
                    "breakpoint {id} was taken out to step past it and the stub refused to re-insert it ({}); it is \
                     no longer inserted",
                    reply_text(&reply)
                )),
                Err(error) if error.fatal() => return Err(error),
                Err(error) => warnings.push(format!("breakpoint {id} could not be re-inserted: {error}")),
            }
        }
        let (reason, breakpoints, temporary) = self.settle_temporary(reason, breakpoints, &pcs, deadline)?;
        let event = StopEvent {
            epoch: self.epoch,
            reason,
            signal,
            exit_status,
            thread,
            pc: if pcs.len() == 1 { Some(pcs[0]) } else { None },
            pc_bytes,
            breakpoints,
            watch,
            exception,
            reasons: stop_reasons(&stop),
            stop,
            console: self.client.run_console.clone(),
            warnings,
            temporary,
        };
        self.last_stop = Some(event.clone());
        Ok(event)
    }

    /// Takes the temporary breakpoints of a step over or out out of the stub and the table at this stop, whatever
    /// the stop is, and tells their hit apart from the table's breakpoints: a stop only they explain is
    /// [`StopCause::Temporary`]. The one stop that keeps them is the single step a continue takes past breakpoints at
    /// the pc on its way, unless that step lands on one. A temporary breakpoint the stub will not take out stays in
    /// the table (marked temporary) and is tried again at the next stop.
    fn settle_temporary(
        &mut self,
        reason: StopCause,
        mut breakpoints: Vec<u32>,
        pcs: &[u64],
        deadline: Instant,
    ) -> Result<(StopCause, Vec<u32>, Vec<TemporaryOutcome>), DebugError> {
        if !self.breakpoints.iter().any(|entry| entry.temporary) {
            return Ok((reason, breakpoints, Vec::new()));
        }
        let temporary: Vec<(u32, u64)> =
            self.breakpoints.iter().filter(|entry| entry.temporary).map(|entry| (entry.id, entry.address)).collect();
        let past_step =
            matches!(&self.stepping, Some(Stepping { purpose: Purpose::PastBreakpoints { .. }, go_on: true, .. }));
        // A step past breakpoints that completes on a temporary breakpoint's address has arrived (a call to the
        // next instruction, say): the continue does not go on.
        let landed = past_step && reason == StopCause::Step;
        let hit: Vec<u32> = temporary
            .iter()
            .filter(|(id, address)| breakpoints.contains(id) || (landed && pcs.contains(address)))
            .map(|(id, _)| *id)
            .collect();
        breakpoints.retain(|id| !temporary.iter().any(|(temporary, _)| temporary == id));
        let reason =
            if !hit.is_empty() && breakpoints.is_empty() && matches!(reason, StopCause::Breakpoint | StopCause::Step) {
                StopCause::Temporary
            } else {
                reason
            };
        if past_step && reason == StopCause::Step {
            return Ok((reason, breakpoints, Vec::new()));
        }
        let mut outcomes = Vec::new();
        for (id, address) in temporary {
            let Some(index) = self.breakpoints.iter().position(|entry| entry.id == id) else { continue };
            let mut outcome = TemporaryOutcome { id, address, hit: hit.contains(&id), removed: true, error: None };
            if self.breakpoints[index].inserted && self.state == State::Stopped {
                let packet = self.breakpoints[index].remove_packet();
                match self.command(&packet, deadline) {
                    Ok(reply) if reply == b"OK" => {}
                    Ok(reply) => {
                        outcome.removed = false;
                        outcome.error = Some(format!(
                            "the stub refused `{packet}` ({}); it stays in the table and is taken out at the next stop \
                             or when disconnecting",
                            reply_text(&reply)
                        ));
                    }
                    Err(error) if error.fatal() => return Err(error),
                    Err(error) => {
                        outcome.removed = false;
                        outcome.error = Some(format!("`{packet}` failed: {error}"));
                    }
                }
            }
            if outcome.removed {
                self.breakpoints.remove(index);
                self.reinsert.retain(|pending| *pending != id);
            }
            outcomes.push(outcome);
        }
        Ok((reason, breakpoints, outcomes))
    }

    /// The stopped thread's pc: its bytes as sent, and its value in the session's byte order (both orders when the
    /// order is unknown, none when unreadable). Taken from the stop reply's expedited registers when present, else
    /// read with `p` (or `g`).
    fn stop_pc(&mut self, stop: &StopReply, deadline: Instant) -> Result<(Option<String>, Vec<u64>), DebugError> {
        let info = Arc::clone(self.info.as_ref().expect("the handshake sets the session info"));
        let Some(pc) =
            info.layout.as_ref().and_then(|layout| ["pc", "rip", "eip"].iter().find_map(|name| layout.register(name)))
        else {
            return Ok((None, Vec::new()));
        };
        let expedited = match stop {
            StopReply::Signal { registers, .. } => {
                registers.iter().find(|register| register.regnum == pc.regnum).map(|register| register.bytes.clone())
            }
            _ => None,
        };
        let bytes = match expedited {
            Some(bytes) => Some(bytes),
            None => {
                let thread = match stop {
                    StopReply::Signal { thread, .. } => *thread,
                    _ => None,
                };
                self.use_thread(
                    thread.filter(|thread| self.threads.iter().any(|known| known.id == *thread)),
                    deadline,
                )?;
                let reply = self.command(&format!("p{:x}", pc.regnum), deadline)?;
                if reply.len() == pc.bytes() * 2 && reply.iter().all(|byte| is_register_digit(*byte)) {
                    Some(String::from_utf8_lossy(&reply).to_ascii_lowercase())
                } else {
                    self.read_registers(&info, deadline)?
                        .into_iter()
                        .find(|register| register.regnum == pc.regnum)
                        .and_then(|register| register.bytes)
                }
            }
        };
        let Some(bytes) = bytes.filter(|bytes| !bytes.contains(['x', 'X'])) else { return Ok((None, Vec::new())) };
        let Some(raw) = decode_hex(bytes.as_bytes()).filter(|raw| !raw.is_empty() && raw.len() <= 8) else {
            return Ok((Some(bytes), Vec::new()));
        };
        let little = raw.iter().rev().fold(0u64, |value, byte| value << 8 | u64::from(*byte));
        let big = raw.iter().fold(0u64, |value, byte| value << 8 | u64::from(*byte));
        let mut pcs = match info.byte_order {
            ByteOrder::Little => vec![little],
            ByteOrder::Big => vec![big],
            ByteOrder::Unknown => vec![little, big],
        };
        pcs.dedup();
        Ok((Some(bytes), pcs))
    }

    /// Places a step's temporary breakpoint: a breakpoint of the table already at `address` stands in for it, else
    /// a new temporary hardware breakpoint, else a software one.
    fn set_temporary(
        &mut self,
        info: &Info,
        epoch: Option<u64>,
        address: u64,
        size: Option<u64>,
        placement: Option<Placement>,
        deadline: Instant,
    ) -> Result<TemporaryPlacement, DebugError> {
        self.check_epoch(epoch)?;
        self.require_stopped()?;
        let (at, _) = self.breakpoint_address(info, BreakKind::Hardware, address, size, deadline)?;
        if let Some(existing) =
            self.breakpoints.iter().find(|entry| entry.inserted && !entry.kind.is_watchpoint() && entry.address == at)
        {
            return Ok(TemporaryPlacement::Existing { breakpoint: existing.clone() });
        }
        if self.breakpoints.iter().filter(|entry| entry.temporary).count() >= MAX_TEMPORARY {
            return Err(DebugError::Invalid(format!(
                "{MAX_TEMPORARY} temporary breakpoints are still waiting to be taken out; stop the target first"
            )));
        }
        match self.set_breakpoint(info, None, BreakKind::Hardware, address, size, placement.clone(), true, deadline) {
            Ok(breakpoint) => Ok(TemporaryPlacement::Inserted { breakpoint }),
            Err(DebugError::Unsupported(_) | DebugError::Target(_)) => self
                .set_breakpoint(info, None, BreakKind::Software, address, size, placement, true, deadline)
                .map(|breakpoint| TemporaryPlacement::Inserted { breakpoint })
                .map_err(|error| match error {
                    DebugError::Unsupported(message) | DebugError::Target(message) => DebugError::Unsupported(format!(
                        "neither a hardware nor a software breakpoint could be placed for the step: {message}"
                    )),
                    other => other,
                }),
            Err(error) => Err(error),
        }
    }

    /// The address and `Z` size of a breakpoint (not a watchpoint) at `address`: on ARM an odd address is Thumb
    /// code at the even one, and the size defaults by architecture and instruction set state.
    fn breakpoint_address(
        &mut self,
        info: &Info,
        kind: BreakKind,
        address: u64,
        size: Option<u64>,
        deadline: Instant,
    ) -> Result<(u64, u64), DebugError> {
        debug_assert!(!kind.is_watchpoint());
        let m_profile = target::m_profile(info.layout.as_ref());
        let mut address = address;
        let mut thumb = None;
        if info.family == Family::Arm && address & 1 == 1 {
            // An odd ARM address names Thumb code; the stub takes the instruction's address.
            address &= !1;
            thumb = Some(true);
            if size == Some(4) {
                return Err(DebugError::Invalid("an odd (Thumb) address cannot take an ARM-state size 4".into()));
            }
        }
        if info.family == Family::Arm && !m_profile && thumb.is_none() && size.is_none() {
            thumb = self.cpsr_thumb(info, deadline)?;
        }
        let size = exec::breakpoint_size(info.family, m_profile, thumb, size).map_err(DebugError::Invalid)?;
        Ok((address, size))
    }

    /// Inserts a breakpoint or watchpoint and adds it to the table.
    #[allow(clippy::too_many_arguments)]
    fn set_breakpoint(
        &mut self,
        info: &Info,
        epoch: Option<u64>,
        kind: BreakKind,
        address: u64,
        size: Option<u64>,
        placement: Option<Placement>,
        temporary: bool,
        deadline: Instant,
    ) -> Result<Breakpoint, DebugError> {
        self.check_epoch(epoch)?;
        self.require_stopped()?;
        let held = self.breakpoints.iter().filter(|entry| !entry.temporary).count();
        if !temporary && held >= MAX_BREAKPOINTS {
            return Err(DebugError::Invalid(format!(
                "the session already holds {MAX_BREAKPOINTS} breakpoints and watchpoints; clear one first"
            )));
        }
        let (address, size) = if kind.is_watchpoint() {
            let length = size.ok_or_else(|| DebugError::Invalid("a watchpoint needs a length".into()))?;
            if !(1..=MAX_WATCH_LENGTH).contains(&length) || address.checked_add(length - 1).is_none() {
                return Err(DebugError::Invalid(format!(
                    "a watchpoint length must be in 1..={MAX_WATCH_LENGTH} and must not overflow the address space"
                )));
            }
            (address, length)
        } else {
            self.breakpoint_address(info, kind, address, size, deadline)?
        };
        if let Some(existing) =
            self.breakpoints.iter().find(|entry| entry.kind == kind && entry.address == address && entry.size == size)
        {
            return Err(DebugError::Invalid(format!(
                "this is already set as {}breakpoint {}",
                if existing.temporary { "temporary " } else { "" },
                existing.id
            )));
        }
        let entry =
            Breakpoint { id: self.next_breakpoint, kind, address, size, hits: 0, inserted: true, temporary, placement };
        let packet = entry.insert_packet();
        let reply = self.command(&packet, deadline)?;
        if reply == b"OK" {
            self.next_breakpoint += 1;
            self.breakpoints.push(entry.clone());
            return Ok(entry);
        }
        let what = match kind {
            BreakKind::Software => "software breakpoints",
            BreakKind::Hardware => "hardware breakpoints",
            BreakKind::Write => "write watchpoints",
            BreakKind::Read => "read watchpoints",
            BreakKind::Access => "access watchpoints",
        };
        Err(if reply.is_empty() {
            DebugError::Unsupported(format!(
                "the stub does not support {what} (`Z{}`); nothing was inserted{}",
                kind.number(),
                if kind == BreakKind::Software {
                    ", and rampage does not plant breakpoints by writing memory; try kind hardware"
                } else {
                    ""
                }
            ))
        } else if is_error(&reply) {
            DebugError::Target(format!("the stub refused `{packet}`: {}", reply_text(&reply)))
        } else {
            protocol(&format!("unexpected reply to `{packet}`: {}", reply_text(&reply)))
        })
    }

    /// Whether an A-profile ARM target is in Thumb state (CPSR.T), when its CPSR can be read and decoded.
    fn cpsr_thumb(&mut self, info: &Info, deadline: Instant) -> Result<Option<bool>, DebugError> {
        if info.layout.as_ref().and_then(|layout| layout.register("cpsr")).is_none() {
            return Ok(None);
        }
        self.use_thread(None, deadline)?;
        let registers = self.read_registers(info, deadline)?;
        Ok(registers
            .iter()
            .find(|register| register.name == "cpsr")
            .and_then(|register| register.integer())
            .map(|cpsr| cpsr & 0x20 != 0))
    }

    fn clear_breakpoint(&mut self, epoch: Option<u64>, id: u32, deadline: Instant) -> Result<Breakpoint, DebugError> {
        self.check_epoch(epoch)?;
        let index = self
            .breakpoints
            .iter()
            .position(|entry| entry.id == id)
            .ok_or_else(|| DebugError::Invalid(format!("there is no breakpoint {id}")))?;
        if self.breakpoints[index].inserted {
            self.require_stopped()?;
            let packet = self.breakpoints[index].remove_packet();
            let reply = self.command(&packet, deadline)?;
            if reply != b"OK" {
                return Err(if reply.is_empty() {
                    DebugError::Unsupported(format!("the stub does not support `{packet}`; breakpoint {id} stays"))
                } else {
                    DebugError::Target(format!(
                        "the stub refused `{packet}`: {}; breakpoint {id} stays",
                        reply_text(&reply)
                    ))
                });
            }
        }
        let mut entry = self.breakpoints.remove(index);
        entry.inserted = false;
        Ok(entry)
    }

    fn require_stopped(&self) -> Result<(), DebugError> {
        match &self.state {
            State::Stopped => Ok(()),
            State::Running => Err(DebugError::Running("wait for it to stop or interrupt it".into())),
            State::Exited => Err(DebugError::State("the process has exited".into())),
            State::Killed => Err(DebugError::State("the target was killed".into())),
            State::Detached => Err(DebugError::State("the session is detached".into())),
            State::Lost { reason } => Err(DebugError::State(format!("the connection was lost: {reason}"))),
        }
    }

    fn run(&mut self, request: Request, deadline: Instant) -> Result<Response, DebugError> {
        let info = Arc::clone(self.info.as_ref().expect("the handshake sets the session info"));
        match request {
            Request::Status => {
                if self.state == State::Stopped {
                    match self.refresh(deadline) {
                        Ok(()) => {}
                        // A lost connection is the status to report, not an error.
                        Err(error) if error.fatal() => self.lose(error),
                        Err(error) => return Err(error),
                    }
                }
                Ok(Response::Status(Status {
                    state: self.state.clone(),
                    epoch: self.epoch,
                    stop: self.stop.clone(),
                    threads: self.threads.clone(),
                    console: self.client.console.clone(),
                    running_for_ms: self.running_for_ms(),
                    last_stop: self.last_stop.clone(),
                    waiting: self.waiters.len(),
                }))
            }
            Request::Registers { thread, epoch } => {
                self.check_epoch(epoch)?;
                self.require_stopped()?;
                let used = self.use_thread(thread, deadline)?;
                let registers = self.read_registers(&info, deadline)?;
                Ok(Response::Registers(Registers {
                    thread: used,
                    epoch: self.epoch,
                    byte_order: info.byte_order,
                    registers,
                }))
            }
            Request::Memory { address, length, thread, epoch, cancel } => {
                self.check_epoch(epoch)?;
                self.require_stopped()?;
                let used = self.use_thread(thread, deadline)?;
                let binary = info.feature("binary-upload");
                let mut chunks = Vec::new();
                // Counting down the length, not up to an end address, so a range that ends at the top of the
                // address space cannot overflow.
                let mut at = address;
                let mut remaining = length;
                while remaining > 0 {
                    if cancel.is_cancelled() {
                        return Err(DebugError::Cancelled(format!("the read stopped at {at:#x}")));
                    }
                    let size = remaining.min(chunk_size(info.packet_size));
                    chunks.push(self.read_chunk(at, size, binary, info.packet_size, deadline)?);
                    remaining -= size;
                    at = at.wrapping_add(size as u64);
                }
                Ok(Response::Memory(MemoryRead {
                    address,
                    length,
                    epoch: self.epoch,
                    packet: if binary { "x" } else { "m" },
                    thread: used,
                    chunks,
                }))
            }
            Request::Modules { epoch } => {
                self.check_epoch(epoch)?;
                self.require_stopped()?;
                self.use_thread(None, deadline)?;
                self.modules(&info, deadline).map(Response::Modules)
            }
            Request::SetBreakpoint { epoch, kind, address, size, placement, temporary: false } => self
                .set_breakpoint(&info, epoch, kind, address, size, placement, false, deadline)
                .map(Response::Breakpoint),
            Request::SetBreakpoint { epoch, address, size, placement, temporary: true, .. } => {
                self.set_temporary(&info, epoch, address, size, placement, deadline).map(Response::Temporary)
            }
            Request::ClearBreakpoint { epoch, id } => {
                self.clear_breakpoint(epoch, id, deadline).map(Response::Breakpoint)
            }
            Request::Breakpoints => Ok(Response::Breakpoints(self.breakpoints.clone())),
            Request::Detach => self.detach(deadline).map(Response::Detached),
            Request::Kill => self.kill(deadline).map(Response::Killed),
            Request::WriteMemory { epoch, address, bytes, expect } => {
                self.write_memory(&info, epoch, address, &bytes, expect.as_deref(), deadline).map(Response::MemoryWrite)
            }
            Request::WriteRegister { epoch, thread, name, value } => {
                self.write_register(&info, epoch, thread, &name, &value, deadline).map(Response::RegisterWrite)
            }
            Request::Continue { .. } | Request::Wait { .. } | Request::Interrupt { .. } | Request::Step { .. } => {
                unreachable!("served by handle")
            }
        }
    }

    /// Stops a running target (interrupt, then a bounded wait), removes every inserted breakpoint and watchpoint,
    /// and detaches. A target that does not stop is abandoned: the connection is closed and the session is lost.
    fn detach(&mut self, deadline: Instant) -> Result<Detached, DebugError> {
        let (removed, failures) = match self.wind_down("detaching", deadline)? {
            WindDown::Ended(detached) => return Ok(detached),
            WindDown::Cleared { removed, failures } => (removed, failures),
        };
        let pids = self.pids();
        let packets: Vec<String> =
            if pids.is_empty() { vec!["D".to_owned()] } else { pids.iter().map(|pid| format!("D;{pid:x}")).collect() };
        for (index, packet) in packets.iter().enumerate() {
            let reply = self.command(packet, deadline)?;
            if reply != b"OK" {
                // The breakpoints are already out of the stub, and earlier processes may already be detached.
                return Ok(Detached {
                    state: self.state.clone(),
                    breakpoints_removed: removed,
                    removal_failures: failures,
                    refused: Some(format!(
                        "`{packet}` was refused: {}; the session stays open and attached, without its breakpoints \
                         ({removed} removed before detaching){}",
                        reply_text(&reply),
                        if index == 0 {
                            String::new()
                        } else {
                            format!(", and {} already detached", packets[..index].join(", "))
                        }
                    )),
                });
            }
            // A process detached from is gone from this session; a retry detaches only the others.
            if let Some(pid) = pids.get(index) {
                self.forget_process(*pid);
            }
        }
        self.state = State::Detached;
        Ok(Detached { state: State::Detached, breakpoints_removed: removed, removal_failures: failures, refused: None })
    }

    /// The processes to detach from or kill one by one: in multiprocess mode, every pid the thread list names.
    fn pids(&self) -> Vec<u64> {
        if !self.multiprocess {
            return Vec::new();
        }
        let mut pids: Vec<u64> = self.threads.iter().filter_map(|thread| thread.id.pid).collect();
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    fn forget_process(&mut self, pid: u64) {
        self.threads.retain(|thread| thread.id.pid != Some(pid));
        if self.selected.is_some_and(|selected| selected.pid == Some(pid)) {
            self.selected = None;
        }
    }

    /// Stops a running target, removes every breakpoint and kills the target: `vKill;<pid>` per process in
    /// multiprocess mode, else `k`. `OK` or an `X` reply is a kill and a `W` reply an exit. A connection the stub
    /// closes, or a reply that does not come within [`KILL_WAIT`], is reported as lost: GDB takes either as success,
    /// but rampage did not see the target end. An `E` reply or an empty one (unsupported) leaves the session attached.
    fn kill(&mut self, deadline: Instant) -> Result<Killed, DebugError> {
        let (removed, failures) = match self.wind_down("killing", deadline)? {
            WindDown::Ended(ended) => {
                return Ok(Killed {
                    // Exited (or otherwise ended) before anything was sent; a lost session ended nothing.
                    already_ended: !matches!(ended.state, State::Lost { .. }),
                    state: ended.state,
                    breakpoints_removed: 0,
                    removal_failures: ended.removal_failures,
                    packets: Vec::new(),
                    confirmed: Vec::new(),
                    reply: None,
                    refused: None,
                });
            }
            WindDown::Cleared { removed, failures } => (removed, failures),
        };
        let pids = self.pids();
        let packets: Vec<String> = if pids.is_empty() {
            vec!["k".to_owned()]
        } else {
            pids.iter().map(|pid| format!("vKill;{pid:x}")).collect()
        };
        let mut killed = Killed {
            state: State::Killed,
            breakpoints_removed: removed,
            removal_failures: failures,
            packets: Vec::new(),
            confirmed: Vec::new(),
            reply: None,
            refused: None,
            already_ended: false,
        };
        for (index, packet) in packets.iter().enumerate() {
            killed.packets.push(packet.clone());
            let reply = match self.command(packet, deadline.min(Instant::now() + KILL_WAIT)) {
                Ok(reply) => reply,
                Err(error) if error.fatal() => {
                    self.lose(DebugError::Lost(format!(
                        "no reply to `{packet}` ({error}); GDB takes a stub closing the connection as a successful \
                         kill, but rampage did not see the target end"
                    )));
                    for entry in &mut self.breakpoints {
                        entry.inserted = false;
                    }
                    killed.state = self.state.clone();
                    return Ok(killed);
                }
                Err(error) => return Err(error),
            };
            killed.reply = Some(reply_text(&reply));
            let refusal = match reply.first() {
                _ if reply == b"OK" => None,
                Some(b'X') => None,
                Some(b'W') => {
                    killed.state = State::Exited;
                    None
                }
                None => Some(format!("unsupported: the stub does not support `{packet}`")),
                _ if is_error(&reply) => Some(format!("target_error: `{packet}` was refused: {}", reply_text(&reply))),
                _ => return Err(protocol(&format!("unexpected reply to `{packet}`: {}", reply_text(&reply)))),
            };
            if let Some(refusal) = refusal {
                // The breakpoints are already out of the stub, and earlier processes may already be killed.
                killed.state = self.state.clone();
                killed.refused = Some(format!(
                    "{refusal}; the session stays open and attached, without its breakpoints ({removed} removed before \
                     killing){}",
                    if killed.confirmed.is_empty() {
                        String::new()
                    } else {
                        format!(", and {} was already confirmed", killed.confirmed.join(", "))
                    }
                ));
                return Ok(killed);
            }
            killed.confirmed.push(packet.clone());
            if let Some(pid) = pids.get(index) {
                self.forget_process(*pid);
            }
        }
        for entry in &mut self.breakpoints {
            entry.inserted = false;
        }
        self.state = killed.state.clone();
        Ok(killed)
    }

    /// Writes `bytes` at `address`, between a read of the bytes there and a read-back; see [`Session::write_memory`].
    fn write_memory(
        &mut self,
        info: &Info,
        epoch: Option<u64>,
        address: u64,
        bytes: &[u8],
        expect: Option<&[u8]>,
        deadline: Instant,
    ) -> Result<MemoryWrite, DebugError> {
        self.check_epoch(epoch)?;
        self.require_stopped()?;
        let length = bytes.len();
        if !(1..=MAX_WRITE).contains(&length) || address.checked_add(length as u64 - 1).is_none() {
            return Err(DebugError::Invalid(format!(
                "a write takes 1..={MAX_WRITE} bytes and must not overflow the address space"
            )));
        }
        if expect.is_some_and(|expect| expect.len() != length) {
            return Err(DebugError::Invalid("expect must be as long as the bytes written".into()));
        }
        let last = address + (length as u64 - 1);
        // The stub keeps the bytes a software breakpoint replaced and puts them back when it is removed, so a write
        // under one would be undone, or would corrupt what it saved.
        if let Some(entry) = self.breakpoints.iter().find(|entry| {
            entry.kind == BreakKind::Software
                && entry.address <= last
                && entry.address.saturating_add(exec::replaced_bytes(info.family, entry.size) - 1) >= address
        }) {
            return Err(DebugError::Invalid(format!(
                "{}software breakpoint {} at {:#x} ({} bytes) overlaps the write: the stub keeps the original bytes \
                 there and restores them when it removes the breakpoint, so writing under it would be undone or \
                 corrupt them; {}. Nothing was written",
                if entry.temporary { "the temporary " } else { "" },
                entry.id,
                entry.address,
                exec::replaced_bytes(info.family, entry.size),
                if entry.temporary {
                    "it is taken out at the next stop"
                } else {
                    "clear it first (debug_breakpoints action clear) and set it again after writing"
                }
            )));
        }
        let thread = self.use_thread(None, deadline)?;
        let binary = info.feature("binary-upload");
        let chunk = chunk_size(info.packet_size).min(MAX_WRITE);
        let before = match self.read_range(address, length, binary, info.packet_size, deadline)? {
            (bytes, None) => bytes,
            (_, Some(error)) => {
                return Err(DebugError::Target(format!(
                    "the bytes at {address:#x} could not be read before writing ({error}); nothing was written"
                )));
            }
        };
        if let Some(expect) = expect
            && expect != before
        {
            return Err(DebugError::ExpectMismatch(format!(
                "the target holds {} at {address:#x}, not the expected bytes; nothing was written",
                encode_hex(&before)
            )));
        }
        let mut chunks: Vec<WriteChunk> = Vec::new();
        let mut offset = 0;
        while offset < length {
            let size = (length - offset).min(chunk);
            let at = address + offset as u64;
            let data = &bytes[offset..offset + size];
            let packet_deadline = deadline.min(Instant::now() + self.command_timeout);
            // Chunks are written in order and the first refusal stops the write, so what was written is one run.
            let (packet, reply) = self.write_chunk(at, data, packet_deadline).map_err(|error| {
                let context = if offset == 0 {
                    format!("while writing {size} bytes at {at:#x}; nothing was written before it")
                } else {
                    format!(
                        "while writing {size} bytes at {at:#x}; the {} chunks before it ({offset} bytes from \
                         {address:#x}) were written",
                        chunks.len()
                    )
                };
                with_context(error, &context)
            })?;
            let written = reply == b"OK";
            let error = (!written).then(|| {
                if reply.is_empty() {
                    format!("the stub does not support `{packet}`")
                } else {
                    format!("the stub answered {}", reply_text(&reply))
                }
            });
            chunks.push(WriteChunk { address: at, length: size, packet, written, error });
            if !written {
                break;
            }
            offset += size;
        }
        let complete = offset == length;
        let (after, after_error) = self.read_range(address, length, binary, info.packet_size, deadline)?;
        Ok(MemoryWrite {
            address,
            length,
            epoch: self.epoch,
            thread,
            verified: complete && after == bytes,
            before,
            after,
            after_error,
            chunks,
            complete,
        })
    }

    /// Writes one chunk with `X` while the stub may take it (an empty reply means it does not, and nothing was
    /// written), else with `M`.
    fn write_chunk(
        &mut self,
        address: u64,
        data: &[u8],
        deadline: Instant,
    ) -> Result<(&'static str, Vec<u8>), DebugError> {
        if self.x_write != Some(false) {
            let mut packet = format!("X{address:x},{:x}:", data.len()).into_bytes();
            packet.extend_from_slice(data);
            if Instant::now() >= deadline {
                return Err(DebugError::Timeout(format!("deadline passed before writing at {address:#x}")));
            }
            let reply = self.client.command_bytes(&packet, deadline)?;
            if !reply.is_empty() {
                self.x_write = Some(true);
                return Ok(("X", reply));
            }
            self.x_write = Some(false);
        }
        let reply = self.command(&format!("M{address:x},{:x}:{}", data.len(), encode_hex(data)), deadline)?;
        Ok(("M", reply))
    }

    /// `length` bytes at `address`, read chunk by chunk, with why they stop short if they do.
    fn read_range(
        &mut self,
        address: u64,
        length: usize,
        binary: bool,
        packet_size: usize,
        deadline: Instant,
    ) -> Result<(Vec<u8>, Option<String>), DebugError> {
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let at = address + bytes.len() as u64;
            let chunk = self.read_chunk(
                at,
                (length - bytes.len()).min(chunk_size(packet_size)),
                binary,
                packet_size,
                deadline.min(Instant::now() + self.command_timeout),
            )?;
            bytes.extend_from_slice(&chunk.bytes);
            if let Some(error) = chunk.error {
                return Ok((bytes, Some(format!("at {at:#x}: {error}"))));
            }
        }
        Ok((bytes, None))
    }

    /// Writes register `name`; see [`Session::write_register`].
    fn write_register(
        &mut self,
        info: &Info,
        epoch: Option<u64>,
        thread: Option<ThreadId>,
        name: &str,
        value: &[u8],
        deadline: Instant,
    ) -> Result<RegisterWrite, DebugError> {
        self.check_epoch(epoch)?;
        self.require_stopped()?;
        let layout = info.layout.as_ref().ok_or_else(|| {
            DebugError::Unsupported("no register layout: no target description and no matching built-in one".into())
        })?;
        let register = layout
            .register(name)
            .cloned()
            .ok_or_else(|| DebugError::Invalid(format!("`{name}` is not a register of the target description")))?;
        if register.bitsize == 0 || !register.bitsize.is_multiple_of(8) || value.len() != register.bytes() {
            return Err(DebugError::Invalid(format!(
                "`{name}` is {} bits: the value must be exactly {} bytes",
                register.bitsize,
                register.bytes()
            )));
        }
        let thread = self.use_thread(thread, deadline)?;
        let find = |registers: &[RegisterValue]| registers.iter().find(|entry| entry.name == register.name).cloned();
        let before = find(&self.read_registers(info, deadline)?);
        let hex = encode_hex(value);
        let mut packet = None;
        if self.p_write != Some(false) {
            let request = format!("P{:x}={hex}", register.regnum);
            let reply = self.command(&request, deadline);
            // Whatever the stub answered, registers read before the write are no longer known to be current.
            self.register_cache = None;
            let reply = reply?;
            if reply == b"OK" {
                self.p_write = Some(true);
                packet = Some("P");
            } else if reply.is_empty() {
                self.p_write = Some(false);
            } else {
                return Err(DebugError::Target(format!("the stub refused `{request}`: {}", reply_text(&reply))));
            }
        }
        if packet.is_none() && info.apple() {
            // debugserver's `g` is its raw register context (or gone, in newer ones), which its stated offsets do
            // not describe, so writing it back with `G` could corrupt other registers.
            return Err(DebugError::Unsupported(
                "this debugserver does not take `P`, and its `g`/`G` cannot be used to write one register; nothing \
                 was written"
                    .into(),
            ));
        }
        if packet.is_none() {
            let reply = self.command("g", deadline)?;
            if is_error(&reply) {
                return Err(DebugError::Target(format!("`g` failed: {}; nothing was written", reply_text(&reply))));
            }
            if reply.len() % 2 != 0 || reply.len() / 2 > layout.g_size || !reply.iter().all(|b| b.is_ascii_hexdigit()) {
                return Err(DebugError::Unsupported(
                    "the stub has no `P`, and its `g` reply marks registers unavailable or does not fit the layout, \
                     so writing it back with `G` could write values nobody read; nothing was written"
                        .into(),
                ));
            }
            let (start, end) = (register.offset * 2, (register.offset + register.bytes()) * 2);
            if end > reply.len() {
                return Err(DebugError::Unsupported(format!(
                    "the stub has no `P`, and `{name}` is not in its `g` reply, so `G` cannot write it; nothing was \
                     written"
                )));
            }
            let mut registers = String::from_utf8_lossy(&reply).to_ascii_lowercase();
            registers.replace_range(start..end, &hex);
            let reply = self.command(&format!("G{registers}"), deadline)?;
            if reply != b"OK" {
                return Err(if reply.is_empty() {
                    DebugError::Unsupported("the stub supports neither `P` nor `G`; nothing was written".into())
                } else {
                    DebugError::Target(format!("the stub refused `G`: {}", reply_text(&reply)))
                });
            }
            packet = Some("G");
        }
        // The stop reply's expedited registers (gdbserver sends the pc) describe the target before this write; drop
        // them so whatever needs the pc next (a continue stepping past a breakpoint) reads it again with `p`.
        if let Some(StopReply::Signal { registers, .. }) = &mut self.stop {
            registers.clear();
        }
        let after = find(&self.read_registers(info, deadline)?);
        let bytes = |entry: &Option<RegisterValue>| entry.as_ref().and_then(|entry| entry.bytes.clone());
        let value_of = |entry: &Option<RegisterValue>| entry.as_ref().and_then(|entry| entry.value.clone());
        Ok(RegisterWrite {
            thread,
            epoch: self.epoch,
            name: register.name.clone(),
            regnum: register.regnum,
            bitsize: register.bitsize,
            packet: packet.unwrap_or("P"),
            verified: bytes(&after).as_deref() == Some(hex.as_str()),
            before: bytes(&before),
            after: bytes(&after),
            before_value: value_of(&before),
            after_value: value_of(&after),
        })
    }

    /// Stops a running target and removes every breakpoint and watchpoint, before detaching or killing. `Ended`
    /// when nothing is attached any more: the target ended, or never stopped and the connection was closed.
    fn wind_down(&mut self, purpose: &str, deadline: Instant) -> Result<WindDown, DebugError> {
        self.abandon_stepping(&format!("the session is {purpose}"));
        // Breakpoints stepped past are not in the stub; there is nothing to put back before detaching.
        for id in std::mem::take(&mut self.reinsert) {
            self.breakpoints.retain(|entry| entry.id != id);
        }
        if self.state == State::Running
            && let Some(stop) = self.client.poll(INTERRUPT_PEEK)?
        {
            self.end_run(stop, deadline, false);
        }
        if self.state == State::Running {
            self.client.interrupt()?;
            self.interrupted = true;
            let wait = INTERRUPT_WAIT.min(deadline.saturating_duration_since(Instant::now()) / 2);
            let until = Instant::now() + wait;
            loop {
                if let Some(reply) = self.client.poll(POLL_SLICE)? {
                    self.end_run(reply, deadline, false);
                    break;
                }
                if Instant::now() >= until {
                    let reason = format!(
                        "the target did not stop within {} ms of an interrupt; the connection was closed without \
                         removing breakpoints or {purpose}",
                        wait.as_millis()
                    );
                    self.lose(DebugError::Lost(reason));
                    let failures = self
                        .breakpoints
                        .iter()
                        .filter(|entry| entry.inserted)
                        .map(|entry| format!("breakpoint {}: not removed, the target never stopped", entry.id))
                        .collect();
                    return Ok(WindDown::Ended(Detached {
                        state: self.state.clone(),
                        breakpoints_removed: 0,
                        removal_failures: failures,
                        refused: None,
                    }));
                }
            }
        }
        match self.state {
            State::Stopped => {}
            // Nothing is attached any more; just close.
            _ => {
                return Ok(WindDown::Ended(Detached {
                    state: self.state.clone(),
                    breakpoints_removed: 0,
                    removal_failures: Vec::new(),
                    refused: None,
                }));
            }
        }
        let mut removed = 0;
        let mut failures = Vec::new();
        for index in (0..self.breakpoints.len()).rev() {
            if !self.breakpoints[index].inserted {
                continue;
            }
            let packet = self.breakpoints[index].remove_packet();
            let id = self.breakpoints[index].id;
            let reply = self.command(&packet, deadline)?;
            if reply == b"OK" {
                self.breakpoints[index].inserted = false;
                removed += 1;
            } else if reply.is_empty() {
                failures.push(format!("breakpoint {id}: the stub does not support `{packet}`"));
            } else {
                failures.push(format!("breakpoint {id}: the stub refused `{packet}`: {}", reply_text(&reply)));
            }
        }
        self.breakpoints.retain(|entry| entry.inserted);
        Ok(WindDown::Cleared { removed, failures })
    }

    fn list_threads(&mut self, deadline: Instant) -> Result<Vec<ThreadInfo>, DebugError> {
        let mut ids = Vec::new();
        let mut reply = self.command("qfThreadInfo", deadline)?;
        if reply.is_empty() {
            // No thread listing: the stop reply's thread, if any, is all that is known.
            if let Some(StopReply::Signal { thread: Some(thread), .. }) = &self.stop {
                ids.push(*thread);
            }
        } else {
            for _ in 0..MAX_THREADS {
                match reply.split_first() {
                    Some((b'm', list)) => {
                        let text = std::str::from_utf8(list).map_err(|_| protocol("thread list is not ASCII"))?;
                        for id in text.split(',') {
                            ids.push(ThreadId::parse(id).ok_or_else(|| protocol("malformed thread ID"))?);
                            if ids.len() > MAX_THREADS {
                                return Err(protocol("the stub lists too many threads"));
                            }
                        }
                    }
                    Some((b'l', _)) => break,
                    _ => return Err(protocol(&format!("unexpected thread list reply `{}`", reply_text(&reply)))),
                }
                reply = self.command("qsThreadInfo", deadline)?;
            }
        }
        let mut threads = Vec::with_capacity(ids.len());
        for (index, id) in ids.into_iter().enumerate() {
            let extra = if self.extra_info && index < MAX_EXTRA_INFO {
                let reply = self.command(&format!("qThreadExtraInfo,{id}"), deadline)?;
                if reply.is_empty() {
                    self.extra_info = false;
                }
                decode_hex(&reply)
                    .filter(|bytes| !bytes.is_empty())
                    .map(|bytes| String::from_utf8_lossy(&bytes).chars().take(256).collect())
            } else {
                None
            };
            threads.push(ThreadInfo { id, extra, detail: None });
        }
        self.thread_details(&mut threads, deadline)?;
        Ok(threads)
    }

    /// Adds LLDB's `jThreadsInfo` (names, dispatch queues, stop reasons) to `threads`, when the stub offers it and
    /// lists at most [`MAX_THREADS_INFO`] threads. A reply that does not parse leaves the threads as they are.
    fn thread_details(&mut self, threads: &mut [ThreadInfo], deadline: Instant) -> Result<(), DebugError> {
        if !self.lldb || self.threads_info == Some(false) || threads.is_empty() || threads.len() > MAX_THREADS_INFO {
            return Ok(());
        }
        let reply = self.command("jThreadsInfo", deadline)?;
        if reply.is_empty() {
            self.threads_info = Some(false);
            return Ok(());
        }
        self.threads_info = Some(true);
        if is_error(&reply) {
            return Ok(());
        }
        let Ok(details) = lldb::parse_threads_info(&reply) else { return Ok(()) };
        for thread in threads {
            thread.detail = details.iter().find(|detail| detail.tid == thread.id.tid).cloned();
        }
        Ok(())
    }

    /// Re-reads the threads of a stopped target, which also shows the connection is alive. The stop itself is the
    /// session's own record: `?` is sent only in the handshake, because QEMU removes every breakpoint and watchpoint
    /// when it is asked (it takes `?` for a new debugger connecting), and in all-stop mode a stopped target cannot
    /// stop again without being resumed.
    fn refresh(&mut self, deadline: Instant) -> Result<(), DebugError> {
        if self.state == State::Stopped {
            self.threads = self.list_threads(deadline)?;
            if self.selected.is_some_and(|selected| !self.threads.iter().any(|thread| thread.id == selected)) {
                self.selected = None;
            }
        }
        Ok(())
    }

    /// Selects `thread`, or the stop's thread (else the first listed) when `None`, so no read depends on a
    /// selection an earlier request left behind. `None` when the stub lists no threads.
    fn use_thread(&mut self, thread: Option<ThreadId>, deadline: Instant) -> Result<Option<ThreadId>, DebugError> {
        let Some(thread) = thread.or_else(|| self.default_thread()) else { return Ok(None) };
        self.select(thread, deadline)?;
        Ok(Some(thread))
    }

    fn select(&mut self, thread: ThreadId, deadline: Instant) -> Result<(), DebugError> {
        if self.selected == Some(thread) {
            return Ok(());
        }
        if !self.threads.iter().any(|known| known.id == thread) {
            return Err(DebugError::Invalid(format!("thread {thread} is not one of the session's threads")));
        }
        let reply = self.command(&format!("Hg{thread}"), deadline)?;
        if reply != b"OK" {
            return Err(DebugError::Target(format!("cannot select thread {thread}: {}", reply_text(&reply))));
        }
        self.selected = Some(thread);
        Ok(())
    }

    /// Every register of the selected thread.
    fn read_registers(&mut self, info: &Info, deadline: Instant) -> Result<Vec<RegisterValue>, DebugError> {
        let layout = info.layout.as_ref().ok_or_else(|| {
            DebugError::Unsupported("no register layout: no target description and no matching built-in one".into())
        })?;
        let raw = if info.apple() {
            self.read_registers_one_by_one(layout, deadline)?
        } else {
            self.read_g(layout, deadline)?
        };
        Ok(layout
            .registers
            .iter()
            .zip(raw)
            .map(|(register, bytes)| {
                let bytes = bytes.filter(|bytes| !bytes.contains('x'));
                let value = bytes.as_deref().and_then(|bytes| decode_value(bytes, info.byte_order));
                RegisterValue {
                    name: register.name.clone(),
                    regnum: register.regnum,
                    bitsize: register.bitsize,
                    kind: register.kind.clone(),
                    group: register.group.clone(),
                    bytes,
                    value,
                }
            })
            .collect())
    }

    /// The selected thread's registers from debugserver, which serves no usable `g` (newer ones dropped `g` and
    /// `G`; older ones send their raw register context, whose padding the offsets they state leave out, and without
    /// clearing pointer authentication codes). The stop reply's expedited registers stand in for the stopped
    /// thread's general registers; the rest are read with `p`, and kept for the stop epoch and thread, since only a
    /// register write changes them before the target runs again.
    fn read_registers_one_by_one(
        &mut self,
        layout: &Layout,
        deadline: Instant,
    ) -> Result<Vec<Option<String>>, DebugError> {
        if let Some((epoch, thread, raw)) = &self.register_cache
            && *epoch == self.epoch
            && *thread == self.selected
            && raw.len() == layout.registers.len()
        {
            return Ok(raw.clone());
        }
        let expedited = match &self.stop {
            Some(StopReply::Signal { thread, registers, .. }) if *thread == self.selected || thread.is_none() => {
                registers.clone()
            }
            _ => Vec::new(),
        };
        let mut raw = Vec::with_capacity(layout.registers.len());
        for register in &layout.registers {
            let sent = expedited
                .iter()
                .find(|sent| sent.regnum == register.regnum && sent.bytes.len() == register.bytes() * 2)
                .map(|sent| sent.bytes.clone());
            if sent.is_some() {
                raw.push(sent);
                continue;
            }
            raw.push(self.read_one(register, deadline)?);
        }
        self.register_cache = Some((self.epoch, self.selected, raw.clone()));
        Ok(raw)
    }

    /// One register with `p`: `None` when the stub cannot read it.
    fn read_one(&mut self, register: &target::Register, deadline: Instant) -> Result<Option<String>, DebugError> {
        let reply = self.command(&format!("p{:x}", register.regnum), deadline)?;
        if reply.is_empty() || is_error(&reply) {
            return Ok(None);
        }
        if reply.len() != register.bytes() * 2 || !reply.iter().all(|b| is_register_digit(*b)) {
            return Err(protocol(&format!("`p` reply for `{}` has the wrong size", register.name)));
        }
        Ok(Some(String::from_utf8_lossy(&reply).to_ascii_lowercase()))
    }

    /// The selected thread's registers from a `g` reply, and with `p` those it leaves out.
    fn read_g(&mut self, layout: &Layout, deadline: Instant) -> Result<Vec<Option<String>>, DebugError> {
        let reply = self.command("g", deadline)?;
        let mut raw: Vec<Option<String>> = vec![None; layout.registers.len()];
        let mut fetched = 0;
        if !reply.is_empty() && !is_error(&reply) {
            if reply.len() % 2 != 0 || reply.len() / 2 > layout.g_size || !reply.iter().all(|b| is_register_digit(*b)) {
                return Err(protocol(&format!(
                    "`g` reply of {} digits does not fit the {}-byte register layout",
                    reply.len(),
                    layout.g_size
                )));
            }
            let text = String::from_utf8_lossy(&reply).to_ascii_lowercase();
            for (slot, register) in raw.iter_mut().zip(&layout.registers) {
                let (start, end) = (register.offset * 2, (register.offset + register.bytes()) * 2);
                if end <= text.len() {
                    *slot = Some(text[start..end].to_owned());
                    fetched += 1;
                } else if start < text.len() {
                    return Err(protocol("`g` reply ends inside a register"));
                }
            }
        } else if is_error(&reply) {
            return Err(DebugError::Target(format!("`g` failed: {}", reply_text(&reply))));
        }
        // Registers the `g` reply leaves out (or all of them, when `g` is unsupported) are read one at a time.
        for (slot, register) in raw.iter_mut().zip(&layout.registers).skip(fetched) {
            *slot = self.read_one(register, deadline)?;
        }
        Ok(raw)
    }

    /// Reads one chunk that fits a packet. Stub errors and short reads are reported in the chunk.
    fn read_chunk(
        &mut self,
        address: u64,
        size: usize,
        binary: bool,
        packet_size: usize,
        deadline: Instant,
    ) -> Result<MemoryChunk, DebugError> {
        debug_assert!(size <= chunk_size(packet_size));
        let packet = format!("{}{address:x},{size:x}", if binary { 'x' } else { 'm' });
        let reply = self.command(&packet, deadline)?;
        let mut chunk = MemoryChunk { address, requested: size, bytes: Vec::new(), read: 0, error: None };
        if is_error(&reply) {
            chunk.error = Some(reply_text(&reply));
            return Ok(chunk);
        }
        let bytes = if binary {
            match reply.split_first() {
                Some((b'b', data)) => packet::unescape(data).map_err(protocol)?,
                _ if reply.is_empty() => {
                    chunk.error = Some("empty reply".into());
                    return Ok(chunk);
                }
                _ => return Err(protocol("binary memory reply does not start with `b`")),
            }
        } else {
            if reply.is_empty() {
                chunk.error = Some("empty reply".into());
                return Ok(chunk);
            }
            decode_hex(&reply).ok_or_else(|| protocol("memory reply is not hex"))?
        };
        if bytes.len() > size {
            return Err(protocol("memory reply is longer than requested"));
        }
        if bytes.len() < size {
            chunk.error = Some(format!("the stub returned {} of {size} bytes", bytes.len()));
        }
        chunk.read = bytes.len();
        chunk.bytes = bytes;
        Ok(chunk)
    }

    /// Reads a whole `qXfer` object, `None` when the stub does not support it.
    fn xfer(
        &mut self,
        object: &str,
        annex: &str,
        packet_size: usize,
        limit: usize,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, DebugError> {
        let request = packet_size.saturating_sub(32).clamp(16, 64 * 1024);
        let mut data = Vec::new();
        loop {
            let reply = self.command(&format!("qXfer:{object}:read:{annex}:{:x},{request:x}", data.len()), deadline)?;
            let (kind, payload) = match reply.split_first() {
                None => return Ok(None),
                Some((b'E', _)) if data.is_empty() => {
                    return Err(DebugError::Target(format!("reading `{object}` failed: {}", reply_text(&reply))));
                }
                Some((kind @ (b'm' | b'l'), payload)) => (*kind, packet::unescape(payload).map_err(protocol)?),
                _ => return Err(protocol(&format!("unexpected qXfer reply `{}`", reply_text(&reply)))),
            };
            if data.len() + payload.len() > limit.min(MAX_XFER_BYTES) {
                return Err(protocol(&format!("`{object}` exceeds its size limit")));
            }
            if kind == b'm' && payload.is_empty() {
                return Err(protocol(&format!("`{object}` read made no progress")));
            }
            data.extend_from_slice(&payload);
            if kind == b'l' {
                return Ok(Some(data));
            }
        }
    }

    fn modules(&mut self, info: &Info, deadline: Instant) -> Result<Modules, DebugError> {
        let mut result = Modules::default();
        let size = info.packet_size;
        let text = |bytes: Vec<u8>| String::from_utf8(bytes).map_err(|_| protocol("XML is not UTF-8"));
        let dyld = self.dyld_images(&mut result.limitations, deadline)?;
        if let Some(images) = dyld {
            result.modules = images;
        } else if info.feature("qXfer:libraries-svr4:read")
            && let Some(bytes) = self.xfer("libraries-svr4", "", size, MAX_XFER_BYTES, deadline)?
        {
            result.modules = maps::parse_svr4(&text(bytes)?).map_err(DebugError::Protocol)?;
        } else if info.feature("qXfer:libraries:read")
            && let Some(bytes) = self.xfer("libraries", "", size, MAX_XFER_BYTES, deadline)?
        {
            result.modules = maps::parse_libraries(&text(bytes)?).map_err(DebugError::Protocol)?;
        } else {
            result.limitations.push("the stub reports no loaded-module list".into());
        }
        if info.feature("qXfer:memory-map:read")
            && let Some(bytes) = self.xfer("memory-map", "", size, MAX_XFER_BYTES, deadline)?
        {
            result.regions = maps::parse_memory_map(&text(bytes)?).map_err(DebugError::Protocol)?;
        } else if let Some((regions, complete)) = self.memory_regions(&mut result.limitations, deadline)? {
            result.regions = regions;
            result.regions_partial = !complete;
        } else {
            result.limitations.push("the stub reports no memory map".into());
        }
        if result.modules.iter().any(|module| module.dyld.as_ref().is_some_and(|image| image.in_shared_cache)) {
            result.limitations.push(
                "modules marked in_shared_cache live in the dyld shared cache, not in a file at their path; bind one \
                 only with an image extracted from the cache (its UUID must match)"
                    .into(),
            );
        }
        if info.feature("qXfer:exec-file:read") {
            let pid = self.threads.iter().find_map(|thread| thread.id.pid);
            let annex = pid.map(|pid| format!("{pid:x}")).unwrap_or_default();
            if let Some(bytes) = self.xfer("exec-file", &annex, size, 4096, deadline)? {
                result.exec_file = Some(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        if info.is_windows() {
            self.windows_images(info, &mut result, deadline)?;
        }
        let offsets = self.command("qOffsets", deadline)?;
        if !offsets.is_empty() && !is_error(&offsets) {
            let reply = String::from_utf8_lossy(&offsets).into_owned();
            result.offsets = Some(maps::parse_offsets(&reply).map_err(DebugError::Protocol)?);
        }
        for (searched, module) in result.modules.iter_mut().filter(|module| module.l_addr.is_some()).enumerate() {
            if searched == MAX_BUILD_ID_MODULES {
                result
                    .limitations
                    .push(format!("build IDs were looked for in the first {MAX_BUILD_ID_MODULES} modules only"));
                break;
            }
            module.build_id = self.build_id(module.l_addr.unwrap_or(0), size, deadline)?;
        }
        if result.modules.iter().any(|module| module.source == "libraries-svr4" && module.build_id.is_none()) {
            result.limitations.push(
                "a build ID is reported only when the module's ELF header is mapped at its load bias (shared \
                 objects and PIE executables) and carries an NT_GNU_BUILD_ID note"
                    .into(),
            );
        }
        Ok(result)
    }

    /// Windows: reads each listed module's PE headers at the base its address gives, and adds the main executable
    /// when the list leaves it out.
    ///
    /// - gdbserver lists every module but the executable (`gdb/nat/windows-nat.c`, `add_dll`, enumerates from
    ///   index 1) as `<segment address>`, the base plus 0x1000 (`gdbserver/win32-low.cc`, `handle_load_dll`).
    /// - lldb-server lists every module, the executable included, as `<section address>`, the base itself
    ///   (`GDBRemoteCommunicationServerLLGS.cpp`, `libraries`; `NativeProcessWindows.cpp`,
    ///   `GetLoadedLibraries`).
    ///
    /// Each address's own reading is tried first, then the other, and a base counts only where an `MZ` and `PE`
    /// header parse. The image that is not a DLL is the main executable. When none is listed, its base is found as
    /// GDB finds it (`gdb/windows-tdep.c`, `create_inferior_hook`): `qGetTIBAddr` gives a thread's TIB, whose
    /// process environment block pointer (at 0x60, or 0x30 in a 32-bit process) leads to `ImageBaseAddress` (at
    /// 0x10, or 0x8).
    fn windows_images(&mut self, info: &Info, result: &mut Modules, deadline: Instant) -> Result<(), DebugError> {
        let size = info.packet_size;
        let mut unreadable = Vec::new();
        for (index, module) in result.modules.iter_mut().filter(|module| module.source == "libraries").enumerate() {
            if index == MAX_PE_MODULES {
                result.limitations.push(format!("PE headers were read for the first {MAX_PE_MODULES} modules only"));
                break;
            }
            let candidates = match (module.segments.first(), module.sections.first()) {
                (Some(segment), _) => [
                    (segment.wrapping_sub(pe::GDBSERVER_SEGMENT_OFFSET), "segment_minus_0x1000"),
                    (*segment, "segment"),
                ],
                (None, Some(section)) => [
                    (*section, "section"),
                    (section.wrapping_sub(pe::GDBSERVER_SEGMENT_OFFSET), "section_minus_0x1000"),
                ],
                (None, None) => continue,
            };
            for (base, from) in candidates {
                if let Some(image) = self.pe_image(base, from, size, deadline)? {
                    module.pe = Some(image);
                    break;
                }
            }
            if module.pe.is_none() {
                unreadable.push(module.name.clone());
            }
        }
        if !unreadable.is_empty() {
            result.limitations.push(format!(
                "no PE header could be read at the address the stub gives for {} module(s), such as {}",
                unreadable.len(),
                unreadable[0]
            ));
        }
        // lldb-server lists the executable: the image that is not a DLL. gdbserver never does (an `.exe` it lists
        // was loaded as a library), so there the PEB says which image is the program.
        if !info.windows_gdbserver()
            && let Some(main) = result.modules.iter_mut().find(|module| module.pe.as_ref().is_some_and(|pe| !pe.dll))
        {
            main.main = true;
            return Ok(());
        }
        match self.peb_image(info, deadline)? {
            Some(image) => result.modules.insert(
                0,
                Module {
                    name: result.exec_file.clone().unwrap_or_default(),
                    source: "peb",
                    l_addr: None,
                    l_ld: None,
                    lm: None,
                    segments: Vec::new(),
                    sections: Vec::new(),
                    build_id: None,
                    main: true,
                    dyld: None,
                    pe: Some(image),
                },
            ),
            None => result.limitations.push(
                "the main executable is not in the module list and its base could not be found (qGetTIBAddr and the \
                 process environment block); bind it with an explicit slide"
                    .into(),
            ),
        }
        Ok(())
    }

    /// The PE image whose `MZ` header is at `base`: its headers and the CodeView record of its mapped debug
    /// directory. `None` when no PE header parses there.
    fn pe_image(
        &mut self,
        base: u64,
        from: &'static str,
        packet_size: usize,
        deadline: Instant,
    ) -> Result<Option<pe::PeImage>, DebugError> {
        let mut header = None;
        for length in [pe::HEADER_READ, 4096] {
            let Some(bytes) = self.read_small(base, length, packet_size, deadline)? else { break };
            header = pe::PeHeader::parse(&bytes);
            // A section table past the first read needs the whole header page.
            if header.is_some() || !bytes.starts_with(b"MZ") {
                break;
            }
        }
        let Some(header) = header else { return Ok(None) };
        let mut codeview = None;
        if let Some((rva, length)) = header.directory(pe::DIRECTORY_DEBUG)
            && let Some(directory) = self.read_small(
                base.wrapping_add(u64::from(rva)),
                (length as usize).min(28 * 16),
                packet_size,
                deadline,
            )?
            && let Some((rva, _, length)) = pe::codeview_entry(&directory)
            && let Some(record) =
                self.read_small(base.wrapping_add(u64::from(rva)), (length as usize).min(1048), packet_size, deadline)?
        {
            codeview = pe::parse_rsds(&record);
        }
        Ok(Some(pe::PeImage {
            base,
            base_from: from,
            machine: header.machine_name(),
            dll: header.dll(),
            size_of_image: header.size_of_image,
            timestamp: header.timestamp,
            aslr: header.dll_characteristics & pe::DYNAMIC_BASE != 0,
            codeview,
        }))
    }

    /// The main executable's image, from the process environment block (`gdb/windows-tdep.c`,
    /// `create_inferior_hook`), when the stub answers `qGetTIBAddr`.
    fn peb_image(&mut self, info: &Info, deadline: Instant) -> Result<Option<pe::PeImage>, DebugError> {
        let Some(thread) = self.stop_thread().or_else(|| self.threads.first().map(|thread| thread.id)) else {
            return Ok(None);
        };
        let reply = self.command(&format!("qGetTIBAddr:{thread}"), deadline)?;
        let text = String::from_utf8_lossy(&reply);
        let Some(tib) = parse_hex_u64(text.strip_prefix("0x").unwrap_or(&text)) else { return Ok(None) };
        let (width, peb_offset, base_offset) = match info.pointer_size {
            Some(4) => (4usize, 0x30u64, 0x8u64),
            _ => (8, 0x60, 0x10),
        };
        let pointer = |bytes: Option<Vec<u8>>| bytes.map(|bytes| maps::read_uint(&bytes, true));
        let size = info.packet_size;
        let Some(peb) = pointer(self.read_small(tib.wrapping_add(peb_offset), width, size, deadline)?) else {
            return Ok(None);
        };
        let Some(base) = pointer(self.read_small(peb.wrapping_add(base_offset), width, size, deadline)?) else {
            return Ok(None);
        };
        self.pe_image(base, "peb", size, deadline)
    }

    /// The Windows exception record of `thread`'s stop, from gdbserver's `qXfer:siginfo:read`. `None` when the stub
    /// has none (the stop was not an exception) or it does not parse.
    fn siginfo(&mut self, thread: ThreadId, deadline: Instant) -> Result<Option<pe::WindowsException>, DebugError> {
        let packet_size = self.info.as_ref().map_or(DEFAULT_PACKET_SIZE, |info| info.packet_size);
        // Only a broken connection fails the stop; a stub that refuses either packet leaves it without a record.
        let read = self.select(thread, deadline).and_then(|()| self.xfer("siginfo", "", packet_size, 4096, deadline));
        match read {
            Ok(bytes) => Ok(bytes.and_then(|bytes| pe::parse_exception_record(&bytes))),
            Err(error @ (DebugError::Timeout(_) | DebugError::Lost(_))) => Err(error),
            Err(_) => Ok(None),
        }
    }

    /// The loaded Mach-O images from LLDB's `jGetLoadedDynamicLibrariesInfos`, when the stub answers it. `None`
    /// sends the caller on to the `qXfer` lists.
    fn dyld_images(
        &mut self,
        limitations: &mut Vec<String>,
        deadline: Instant,
    ) -> Result<Option<Vec<Module>>, DebugError> {
        if !self.lldb || self.dyld_info == Some(false) {
            return Ok(None);
        }
        // As LLDB does: the header addresses of every image first (a small reply however many images are loaded),
        // then full information in batches, so no reply outgrows a packet.
        let reply = self.command(lldb::FETCH_ALL_SOLIBS, deadline)?;
        if reply.is_empty() {
            self.dyld_info = Some(false);
            return Ok(None);
        }
        self.dyld_info = Some(true);
        // debugserver answers `OK` when it has no list to give (dyld has not started yet).
        if reply == b"OK" {
            limitations.push(
                "dyld reported no images yet (a process stopped at launch, before dyld ran); list modules again \
                 after the first continue"
                    .into(),
            );
            return Ok(None);
        }
        if is_error(&reply) {
            limitations.push(format!("jGetLoadedDynamicLibrariesInfos failed: {}", reply_text(&reply)));
            return Ok(None);
        }
        let addresses = match lldb::parse_image_addresses(&reply) {
            Ok(addresses) => addresses,
            Err(error) => {
                limitations.push(format!("the dyld image list is unusable: {error}"));
                return Ok(None);
            }
        };
        let mut modules = Vec::with_capacity(addresses.len());
        for batch in addresses.chunks(lldb::SOLIB_BATCH) {
            let reply = self.command(&lldb::solib_request(batch), deadline)?;
            match lldb::parse_dyld_images(&reply) {
                Ok(images) => modules.extend(images),
                Err(error) => {
                    limitations.push(format!(
                        "dyld's information for {} images is unusable ({}): {error}",
                        batch.len(),
                        reply_text(&reply)
                    ));
                }
            }
        }
        if modules.len() < addresses.len() {
            limitations.push(format!(
                "dyld lists {} images and described {}; images whose Mach-O header is unreadable are left out",
                addresses.len(),
                modules.len()
            ));
        }
        Ok(Some(modules))
    }

    /// Mapped regions from LLDB's `qMemoryRegionInfo`, walking the address space from 0, at most
    /// [`MAX_REGION_QUERIES`] queries. Unmapped gaps are left out. `None` when the stub does not answer it.
    fn memory_regions(
        &mut self,
        limitations: &mut Vec<String>,
        deadline: Instant,
    ) -> Result<Option<(Vec<Region>, bool)>, DebugError> {
        if !self.lldb {
            return Ok(None);
        }
        let mut regions = Vec::new();
        let mut address = 0u64;
        // Whether the walk reached the end of the address space, so an address in no listed region is unmapped.
        let mut complete = false;
        for query in 0..MAX_REGION_QUERIES {
            let reply = self.command(&format!("qMemoryRegionInfo:{address:x}"), deadline)?;
            if reply.is_empty() && query == 0 {
                return Ok(None);
            }
            if reply.is_empty() || is_error(&reply) {
                limitations.push(format!("qMemoryRegionInfo at {address:#x} failed; the regions above it are unknown"));
                break;
            }
            let region = match lldb::parse_region_info(&reply) {
                Ok(region) => region,
                Err(error) => {
                    limitations.push(format!("qMemoryRegionInfo at {address:#x} is unusable: {error}"));
                    break;
                }
            };
            // An unmapped address with no size: nothing is mapped from there to the end.
            let Some(size) = region.size.filter(|size| *size > 0) else {
                complete = region.start <= address;
                break;
            };
            let Some(end) = region.start.checked_add(size) else {
                regions.extend(region.mapped());
                complete = region.start <= address;
                break;
            };
            // The reply's region must hold the address asked for, or the walk could go backwards or stall.
            if region.start > address || end <= address {
                limitations.push(format!("qMemoryRegionInfo at {address:#x} answered a region that does not hold it"));
                break;
            }
            regions.extend(region.mapped());
            address = end;
            if query + 1 == MAX_REGION_QUERIES {
                limitations.push(format!(
                    "memory regions were listed with {MAX_REGION_QUERIES} queries, up to {address:#x}; the rest is \
                     not listed"
                ));
            }
        }
        Ok(Some((regions, complete)))
    }

    /// The GNU build ID of the ELF image whose header is at `base`, read from target memory; `None` when the bytes
    /// there are not one or carry no build-ID note.
    fn build_id(&mut self, base: u64, packet_size: usize, deadline: Instant) -> Result<Option<String>, DebugError> {
        let Some(header) = self.read_small(base, 64, packet_size, deadline)?.as_deref().and_then(maps::elf_header)
        else {
            return Ok(None);
        };
        let size = (header.phentsize * header.phnum) as usize;
        let Some(headers) = self.read_small(base.wrapping_add(header.phoff), size, packet_size, deadline)? else {
            return Ok(None);
        };
        for (offset, length) in maps::note_segments(&header, &headers).into_iter().take(4) {
            if length == 0 || length > 4096 {
                continue;
            }
            if let Some(notes) = self.read_small(base.wrapping_add(offset), length as usize, packet_size, deadline)?
                && let Some(id) = maps::build_id(&notes, header.little)
            {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Exactly `size` (at most 4096) bytes at `address`, or `None` when any of them is unreadable.
    fn read_small(
        &mut self,
        address: u64,
        size: usize,
        packet_size: usize,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, DebugError> {
        if size == 0 || size > 4096 || address.checked_add(size as u64).is_none() {
            return Ok(None);
        }
        let mut bytes = Vec::with_capacity(size);
        while bytes.len() < size {
            let at = address + bytes.len() as u64;
            let chunk =
                self.read_chunk(at, (size - bytes.len()).min(chunk_size(packet_size)), false, packet_size, deadline)?;
            if chunk.error.is_some() {
                return Ok(None);
            }
            bytes.extend_from_slice(&chunk.bytes);
        }
        Ok(Some(bytes))
    }
}

/// Where stopping and clearing a target for a detach or kill left it.
enum WindDown {
    /// Nothing is attached any more; this is the final state.
    Ended(Detached),
    /// Stopped, with every breakpoint the stub would remove removed.
    Cleared { removed: usize, failures: Vec<String> },
}

/// Whether `info` describes a Windows target, and what shows it: the `Windows` (or `Cygwin`) OS ABI in a GDB
/// stub's target description (gdbserver sets it, `gdbserver/win32-i386-low.cc`, `i386_arch_setup`), or a Windows
/// OS or triple in an LLDB stub's `qProcessInfo` or `qHostInfo` (lldb-server).
fn windows_target(info: &Info) -> Option<WindowsTarget> {
    let lldb = info.lldb.is_some();
    let stub = if lldb { "lldb-server" } else { "gdbserver" };
    if let Some(osabi) = info.layout.as_ref().and_then(|layout| layout.osabi.as_deref())
        && (osabi.starts_with("Windows") || osabi == "Cygwin")
    {
        return Some(WindowsTarget { stub, evidence: format!("the target description names the OS ABI `{osabi}`") });
    }
    let lldb = info.lldb.as_ref()?;
    [("qProcessInfo", &lldb.process), ("qHostInfo", &lldb.host)].into_iter().find_map(|(packet, host)| {
        let host = host.as_ref().filter(|host| host.windows())?;
        let what = match (&host.ostype, &host.triple) {
            (Some(os), _) if os == "windows" => "ostype:windows".to_owned(),
            (_, Some(triple)) => format!("the triple `{triple}`"),
            _ => "a Windows target".to_owned(),
        };
        Some(WindowsTarget { stub, evidence: format!("{packet} states {what}") })
    })
}

/// Whether a kill that failed with `error` left the session open and attached.
fn kill_keeps_session(error: &DebugError) -> bool {
    matches!(error, DebugError::Target(_) | DebugError::Unsupported(_) | DebugError::NotAllowed(_))
}

/// `error` with `context` appended, keeping its kind.
fn with_context(error: DebugError, context: &str) -> DebugError {
    match error {
        DebugError::Timeout(message) => DebugError::Timeout(format!("{message} ({context})")),
        DebugError::Lost(message) => DebugError::Lost(format!("{message} ({context})")),
        DebugError::Protocol(message) => DebugError::Protocol(format!("{message} ({context})")),
        DebugError::Target(message) => DebugError::Target(format!("{message} ({context})")),
        other => other,
    }
}

/// A state as words, for errors.
fn describe(state: &State) -> String {
    match state {
        State::Stopped => "stopped".into(),
        State::Running => "running".into(),
        State::Exited => "exited".into(),
        State::Killed => "killed".into(),
        State::Detached => "detached".into(),
        State::Lost { reason } => format!("lost ({reason})"),
    }
}

/// Bytes per memory request that keep a hex reply within `packet_size`.
fn chunk_size(packet_size: usize) -> usize {
    (packet_size.saturating_sub(32) / 2).clamp(16, MAX_MEMORY_READ)
}

fn is_register_digit(byte: u8) -> bool {
    byte.is_ascii_hexdigit() || byte == b'x' || byte == b'X'
}

fn is_error(reply: &[u8]) -> bool {
    matches!(reply, [b'E', a, b] if a.is_ascii_hexdigit() && b.is_ascii_hexdigit()) || reply.starts_with(b"E.")
}

/// At most 64 bytes of a reply, as printable ASCII, for error messages whose size callers budget for.
fn reply_text(reply: &[u8]) -> String {
    reply[..reply.len().min(64)]
        .iter()
        .map(|&byte| if byte.is_ascii_graphic() || byte == b' ' { byte as char } else { '?' })
        .collect()
}

fn protocol(message: &str) -> DebugError {
    DebugError::Protocol(message.to_owned())
}

fn decode_value(bytes: &str, order: ByteOrder) -> Option<String> {
    let mut bytes = decode_hex(bytes.as_bytes())?;
    match order {
        ByteOrder::Little => bytes.reverse(),
        ByteOrder::Big => {}
        ByteOrder::Unknown => return None,
    }
    Some(format!("0x{}", encode_hex(&bytes)))
}

fn parse_features(reply: &[u8]) -> Result<BTreeMap<String, String>, DebugError> {
    let text = std::str::from_utf8(reply).map_err(|_| protocol("qSupported reply is not ASCII"))?;
    if is_error(reply) {
        return Err(DebugError::Target(format!("qSupported failed: {}", reply_text(reply))));
    }
    let mut features = BTreeMap::new();
    for feature in text.split(';').filter(|feature| !feature.is_empty()).take(256) {
        let (name, value) = match feature.split_once('=') {
            Some((name, value)) => (name, value),
            None => match feature.char_indices().last() {
                Some((at, sign @ ('+' | '-' | '?'))) => (
                    &feature[..at],
                    if sign == '+' {
                        "+"
                    } else if sign == '-' {
                        "-"
                    } else {
                        "?"
                    },
                ),
                _ => (feature, "+"),
            },
        };
        if !name.is_empty() && name.len() <= 128 {
            features.insert(name.to_owned(), value.chars().take(256).collect());
        }
    }
    Ok(features)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_features() {
        let features =
            parse_features(b"PacketSize=20020;qXfer:features:read+;vContSupported+;multiprocess-;foo?").unwrap();
        assert_eq!(features["PacketSize"], "20020");
        assert_eq!(features["qXfer:features:read"], "+");
        assert_eq!(features["multiprocess"], "-");
        assert_eq!(features["foo"], "?");
        assert!(parse_features(b"E01").is_err());
    }

    #[test]
    fn decodes_register_values_only_with_a_known_order() {
        assert_eq!(decode_value("48000000", ByteOrder::Little).as_deref(), Some("0x00000048"));
        assert_eq!(decode_value("00000048", ByteOrder::Big).as_deref(), Some("0x00000048"));
        assert_eq!(decode_value("48000000", ByteOrder::Unknown), None);
    }

    /// Any value that fits a register encodes to its size and decodes back to itself in the same order; one that
    /// does not fit, an unknown order and a partial-byte register are refused.
    #[test]
    fn register_values_encode_to_their_bitsize_in_the_session_order() {
        let mut rng = crate::packet::tests::Rng::new(29);
        for _ in 0..20_000 {
            let bitsize = [8, 16, 32, 64, 128][rng.below(5)];
            let raw = rng.next() >> rng.below(64);
            let value = if bitsize < 64 { raw & ((1 << bitsize) - 1) } else { raw };
            for order in [ByteOrder::Little, ByteOrder::Big] {
                let bytes = encode_register_value(value, bitsize, order).unwrap();
                assert_eq!(bytes.len(), bitsize as usize / 8);
                let decoded = decode_value(&encode_hex(&bytes), order).unwrap();
                assert_eq!(parse_hex_u64(&decoded[decoded.len().saturating_sub(16)..]), Some(value), "{decoded}");
                assert!(decoded[2..decoded.len().saturating_sub(16).max(2)].bytes().all(|digit| digit == b'0'));
            }
            assert!(encode_register_value(value, bitsize, ByteOrder::Unknown).is_err());
            if bitsize < 64 {
                let wide = value | 1 << (bitsize + rng.below(64 - bitsize as usize) as u32);
                assert!(encode_register_value(wide, bitsize, ByteOrder::Little).is_err(), "{wide:#x} in {bitsize}");
            }
        }
        assert_eq!(encode_register_value(0x1234, 16, ByteOrder::Little).unwrap(), [0x34, 0x12]);
        assert_eq!(encode_register_value(0x1234, 32, ByteOrder::Big).unwrap(), [0, 0, 0x12, 0x34]);
        assert_eq!(encode_register_value(1, 128, ByteOrder::Big).unwrap()[15], 1);
        for bitsize in [0, 1, 12] {
            assert!(encode_register_value(0, bitsize, ByteOrder::Little).is_err());
        }
    }

    #[test]
    fn sizes_chunks_to_the_packet_size() {
        assert_eq!(chunk_size(0x20020), MAX_MEMORY_READ);
        assert_eq!(chunk_size(2048), 1008);
        assert_eq!(chunk_size(0), 16);
        assert!(is_error(b"E14") && is_error(b"E.text") && !is_error(b"E") && !is_error(b"Exx"));
    }
}
