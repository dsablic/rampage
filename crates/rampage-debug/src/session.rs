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
    self, BreakKind, Breakpoint, Cancel, MAX_BREAKPOINTS, MAX_STEPS, MAX_WATCH_LENGTH, Origin, StopCause, StopEvent,
    VCont, stop_reasons,
};
use crate::maps::{self, Module, Offsets, Region};
use crate::packet::{self, decode_hex, encode_hex, parse_hex_u64};
use crate::stop::{StopReply, ThreadId, hex_address};
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

#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Bounds opening the connection.
    pub connect_timeout: Duration,
    /// Bounds each request, including every packet it sends, and the whole connection handshake.
    pub command_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self { connect_timeout: Duration::from_secs(5), command_timeout: Duration::from_secs(10) }
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
}

impl Info {
    /// Bytes per memory request: the most whose hex reply fits the packet size.
    pub fn chunk_size(&self) -> usize {
        chunk_size(self.packet_size)
    }

    fn feature(&self, name: &str) -> bool {
        self.features.get(name).is_some_and(|value| value == "+")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadInfo {
    pub id: ThreadId,
    /// The stub's `qThreadExtraInfo` description, when it gives one.
    pub extra: Option<String>,
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
    pub exec_file: Option<String>,
    pub offsets: Option<Offsets>,
    pub limitations: Vec<String>,
}

enum Request {
    Status,
    Registers { thread: Option<ThreadId>, epoch: Option<u64> },
    Memory { address: u64, length: usize, thread: Option<ThreadId>, epoch: Option<u64>, cancel: Cancel },
    Modules { epoch: Option<u64> },
    Continue { epoch: Option<u64>, wait: Duration, cancel: Cancel },
    Wait { wait: Duration, cancel: Cancel },
    Interrupt { wait: Duration, cancel: Cancel },
    Step { epoch: Option<u64>, thread: Option<ThreadId>, count: u32, cancel: Cancel },
    SetBreakpoint { epoch: Option<u64>, kind: BreakKind, address: u64, size: Option<u64> },
    ClearBreakpoint { epoch: Option<u64>, id: u32 },
    Breakpoints,
    Detach,
}

impl Request {
    /// The packet classes the request may send.
    fn permit(&self) -> Permit {
        match self {
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
    Breakpoints(Vec<Breakpoint>),
    Detached(Detached),
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
                let mut worker = Worker::new(transport, config.command_timeout);
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
        if !(1..=MAX_STEPS).contains(&count) {
            return Err(DebugError::Invalid(format!("count must be in 1..={MAX_STEPS}")));
        }
        let request = Request::Step { epoch, thread, count, cancel: cancel.clone() };
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
        let request = Request::SetBreakpoint { epoch, kind, address, size };
        match self.call(request, self.config.command_timeout)? {
            Response::Breakpoint(breakpoint) => Ok(breakpoint),
            _ => unreachable!("breakpoint request"),
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
        if !matches!(result, Err(DebugError::Target(_))) {
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
    /// The last `?` reply while stopped; a different one later is a stop rampage did not cause.
    question: Option<StopReply>,
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
}

impl Worker {
    fn new(transport: Box<dyn Transport>, command_timeout: Duration) -> Self {
        Self {
            client: Client::new(transport),
            info: None,
            state: State::Stopped,
            epoch: 0,
            stop: None,
            question: None,
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
        let mut info = Info {
            endpoint,
            local,
            architecture: None,
            family: Family::Other,
            byte_order: ByteOrder::Unknown,
            byte_order_evidence: String::new(),
            pointer_size: None,
            multiprocess: plus("multiprocess"),
            modules_available: plus("qXfer:libraries-svr4:read") || plus("qXfer:libraries:read"),
            memory_map_available: plus("qXfer:memory-map:read"),
            features,
            packet_size,
            no_ack_mode: !self.client.ack_mode(),
            layout: None,
            limitations,
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
        let stop = StopReply::parse(&self.command("?", deadline)?).map_err(DebugError::Protocol)?;
        self.epoch = 1;
        if stop.ended() {
            self.state = State::Exited;
        }
        self.question = Some(stop.clone());
        self.stop = Some(stop);
        if self.state == State::Stopped {
            self.threads = self.list_threads(deadline)?;
            if info.layout.is_none() {
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
        info.family = Family::of(info.layout.as_ref());
        info.architecture = info.layout.as_ref().and_then(|layout| layout.architecture.clone());
        info.pointer_size = info.family.pointer_size(info.layout.as_ref());
        let (order, evidence) = self.byte_order(&info, deadline)?;
        info.byte_order = order;
        info.byte_order_evidence = evidence;
        Ok(info)
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
        self.client.set_permit(request.permit());
        let detach = matches!(request, Request::Detach);
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
            Request::Step { epoch, thread, count, cancel } if self.state != State::Running => {
                match self.start_steps(epoch, thread, count, cancel, &reply, deadline) {
                    Ok(()) => return false,
                    Err(error) => Err(error),
                }
            }
            Request::Interrupt { .. } => Err(DebugError::NotRunning(format!(
                "the target is not running ({}); there is nothing to interrupt",
                describe(&self.state)
            ))),
            Request::Status | Request::Detach => self.run(request, deadline),
            _ if self.state == State::Running => Err(DebugError::Running(
                "only debug_status, debug_wait, debug_interrupt and debug_disconnect are served until it stops".into(),
            )),
            request => self.run(request, deadline),
        };
        // A refused detach leaves the session attached and serving.
        let finished = detach && !matches!(result, Err(DebugError::Target(_)));
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
        let stop = self.stop.clone();
        let at_pc: Vec<usize> = if self.breakpoints.iter().any(|entry| entry.inserted && !entry.kind.is_watchpoint()) {
            let pcs = match &stop {
                Some(stop) => match self.stop_pc(stop, deadline) {
                    Ok((_, pcs)) => pcs,
                    Err(error) if error.fatal() => return Err(error),
                    Err(_) => Vec::new(),
                },
                None => Vec::new(),
            };
            (0..self.breakpoints.len())
                .filter(|index| {
                    let entry = &self.breakpoints[*index];
                    entry.inserted && !entry.kind.is_watchpoint() && pcs.contains(&entry.address)
                })
                .collect()
        } else {
            Vec::new()
        };
        if at_pc.is_empty() {
            self.resume_all(deadline)?;
            return Ok(false);
        }
        for (done, index) in at_pc.iter().enumerate() {
            let packet = self.breakpoints[*index].remove_packet();
            let removed = self.command(&packet, deadline)?;
            if removed != b"OK" {
                // Put back the ones already taken out; the continue does not go ahead.
                let mut warnings = Vec::new();
                for earlier in &at_pc[..done] {
                    let insert = self.breakpoints[*earlier].insert_packet();
                    if self.command(&insert, deadline)? != b"OK" {
                        self.breakpoints[*earlier].inserted = false;
                        warnings.push(format!("breakpoint {} could not be re-inserted", self.breakpoints[*earlier].id));
                    }
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
        let thread = self.step_thread(None)?;
        let packet = self.step_packet(thread, deadline)?;
        self.stepping = Some(Stepping {
            thread,
            packet,
            reply: reply.clone(),
            cancel: cancel.clone(),
            step_deadline: Instant::now(),
            halt: false,
            purpose: Purpose::PastBreakpoints { wait },
        });
        if let Err(error) = self.next_step(deadline) {
            self.stepping = None;
            // Nothing ran: put the breakpoints back before failing.
            for id in std::mem::take(&mut self.reinsert) {
                let Some(index) = self.breakpoints.iter().position(|entry| entry.id == id) else { continue };
                let packet = self.breakpoints[index].insert_packet();
                if !error.fatal() && self.command(&packet, deadline).is_ok_and(|reply| reply == b"OK") {
                    self.breakpoints[index].inserted = true;
                }
            }
            return Err(error);
        }
        Ok(true)
    }

    /// Resumes every thread: `vCont;c`, else `c` once no `Hc<thread>` limits it.
    fn resume_all(&mut self, deadline: Instant) -> Result<(), DebugError> {
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

    /// The thread a step uses: `thread` if the session lists it, else the stop's thread, else the first listed.
    fn step_thread(&self, thread: Option<ThreadId>) -> Result<Option<ThreadId>, DebugError> {
        if let Some(thread) = thread {
            if !self.threads.iter().any(|known| known.id == thread) {
                return Err(DebugError::Invalid(format!("thread {thread} is not one of the session's threads")));
            }
            return Ok(Some(thread));
        }
        let stop_thread = match &self.stop {
            Some(StopReply::Signal { thread: Some(thread), .. }) => Some(*thread),
            _ => None,
        };
        Ok(stop_thread
            .filter(|stop| self.threads.iter().any(|known| known.id == *stop))
            .or_else(|| self.threads.first().map(|thread| thread.id)))
    }

    fn step_packet(&mut self, thread: Option<ThreadId>, deadline: Instant) -> Result<String, DebugError> {
        Ok(match thread {
            Some(thread) if self.vcont(deadline)?.step => format!("vCont;s:{thread}"),
            _ => "s".to_owned(),
        })
    }

    /// Starts a step request; its stops are handled in the main loop.
    fn start_steps(
        &mut self,
        epoch: Option<u64>,
        thread: Option<ThreadId>,
        count: u32,
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
        let (packet, thread) = (stepping.packet.clone(), stepping.thread);
        if packet == "s"
            && let Some(thread) = thread
        {
            let reply = self.command(&format!("Hc{thread}"), deadline)?;
            if reply != b"OK" {
                self.stepping = None;
                return Err(DebugError::Target(format!(
                    "cannot select thread {thread} to step: {}",
                    reply_text(&reply)
                )));
            }
            self.hc_thread = true;
        }
        if let Err(error) = self.resume(&packet, Origin::Step(thread)) {
            self.stepping = None;
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
                if !completed || stepping.halt || stepping.cancel.is_cancelled() {
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
        self.interrupted = false;
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
        if reply.is_empty() || is_error(&reply) {
            self.state = State::Stopped;
            return Err(if reply.is_empty() {
                DebugError::Unsupported("the stub does not support the resume packet".into())
            } else {
                DebugError::Target(format!("the stub refused to resume: {}", reply_text(&reply)))
            });
        }
        let stop = StopReply::parse(&reply).map_err(DebugError::Protocol)?;
        self.epoch += 1;
        self.question = None;
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
        // The stop happened whether or not its pc can be read; only a broken stream fails it.
        let (pc_bytes, pcs) = match self.state {
            State::Stopped => match self.stop_pc(&stop, deadline) {
                Ok(pc) => pc,
                Err(error) if error.fatal() => return Err(error),
                Err(_) => (None, Vec::new()),
            },
            _ => (None, Vec::new()),
        };
        let (reason, breakpoints, watch) = exec::classify(&stop, self.origin, interrupted, &pcs, &mut self.breakpoints);
        // Breakpoints stepped past go back now, whatever stopped the step.
        let mut warnings = Vec::new();
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
            reasons: stop_reasons(&stop),
            stop,
            console: self.client.run_console.clone(),
            warnings,
        };
        self.last_stop = Some(event.clone());
        Ok(event)
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
                self.use_thread(None, deadline)?;
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

    /// Inserts a breakpoint or watchpoint and adds it to the table.
    fn set_breakpoint(
        &mut self,
        info: &Info,
        epoch: Option<u64>,
        kind: BreakKind,
        address: u64,
        size: Option<u64>,
        deadline: Instant,
    ) -> Result<Breakpoint, DebugError> {
        self.check_epoch(epoch)?;
        self.require_stopped()?;
        if self.breakpoints.len() >= MAX_BREAKPOINTS {
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
            (address, size)
        };
        if let Some(existing) =
            self.breakpoints.iter().find(|entry| entry.kind == kind && entry.address == address && entry.size == size)
        {
            return Err(DebugError::Invalid(format!("this is already set as breakpoint {}", existing.id)));
        }
        let entry = Breakpoint { id: self.next_breakpoint, kind, address, size, hits: 0, inserted: true };
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
            Request::SetBreakpoint { epoch, kind, address, size } => {
                self.set_breakpoint(&info, epoch, kind, address, size, deadline).map(Response::Breakpoint)
            }
            Request::ClearBreakpoint { epoch, id } => {
                self.clear_breakpoint(epoch, id, deadline).map(Response::Breakpoint)
            }
            Request::Breakpoints => Ok(Response::Breakpoints(self.breakpoints.clone())),
            Request::Detach => self.detach(deadline).map(Response::Detached),
            Request::Continue { .. } | Request::Wait { .. } | Request::Interrupt { .. } | Request::Step { .. } => {
                unreachable!("served by handle")
            }
        }
    }

    /// Stops a running target (interrupt, then a bounded wait), removes every inserted breakpoint and watchpoint,
    /// and detaches. A target that does not stop is abandoned: the connection is closed and the session is lost.
    fn detach(&mut self, deadline: Instant) -> Result<Detached, DebugError> {
        self.abandon_stepping("the session is detaching");
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
                         removing breakpoints or detaching",
                        wait.as_millis()
                    );
                    self.lose(DebugError::Lost(reason));
                    let failures = self
                        .breakpoints
                        .iter()
                        .filter(|entry| entry.inserted)
                        .map(|entry| format!("breakpoint {}: not removed, the target never stopped", entry.id))
                        .collect();
                    return Ok(Detached {
                        state: self.state.clone(),
                        breakpoints_removed: 0,
                        removal_failures: failures,
                    });
                }
            }
        }
        match self.state {
            State::Stopped => {}
            // Nothing is attached any more; just close.
            _ => {
                return Ok(Detached {
                    state: self.state.clone(),
                    breakpoints_removed: 0,
                    removal_failures: Vec::new(),
                });
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
        let pids: Vec<u64> = if self.multiprocess {
            let mut pids: Vec<u64> = self.threads.iter().filter_map(|thread| thread.id.pid).collect();
            pids.sort_unstable();
            pids.dedup();
            pids
        } else {
            Vec::new()
        };
        let packets: Vec<String> =
            if pids.is_empty() { vec!["D".to_owned()] } else { pids.iter().map(|pid| format!("D;{pid:x}")).collect() };
        for (index, packet) in packets.iter().enumerate() {
            let reply = self.command(packet, deadline)?;
            if reply != b"OK" {
                return Err(DebugError::Target(format!("`{packet}` was refused: {}", reply_text(&reply))));
            }
            // A process detached from is gone from this session; a retry detaches only the others.
            if let Some(pid) = pids.get(index) {
                self.threads.retain(|thread| thread.id.pid != Some(*pid));
                if self.selected.is_some_and(|selected| selected.pid == Some(*pid)) {
                    self.selected = None;
                }
            }
        }
        self.state = State::Detached;
        Ok(Detached { state: State::Detached, breakpoints_removed: removed, removal_failures: failures })
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
            threads.push(ThreadInfo { id, extra });
        }
        Ok(threads)
    }

    /// Re-reads the stop (`?`) and threads. A `?` reply that differs from the previous one is a stop rampage did not
    /// cause, and a new epoch. The first `?` after a stop rampage observed only sets the baseline: stubs answer `?`
    /// in their own words (QEMU always says SIGTRAP), not with the stop reply they sent.
    fn refresh(&mut self, deadline: Instant) -> Result<(), DebugError> {
        let stop = StopReply::parse(&self.command("?", deadline)?).map_err(DebugError::Protocol)?;
        let changed = match &self.question {
            Some(previous) => *previous != stop,
            None => stop.ended(),
        };
        self.question = Some(stop.clone());
        if changed {
            self.epoch += 1;
            if stop.ended() {
                self.state = State::Exited;
                for entry in &mut self.breakpoints {
                    entry.inserted = false;
                }
            }
            self.stop = Some(stop);
        }
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
        let stop_thread = match &self.stop {
            Some(StopReply::Signal { thread: Some(thread), .. }) => Some(*thread),
            _ => None,
        };
        let default = stop_thread
            .filter(|stop| self.threads.iter().any(|known| known.id == *stop))
            .or_else(|| self.threads.first().map(|thread| thread.id));
        let Some(thread) = thread.or(default) else { return Ok(None) };
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
            let reply = self.command(&format!("p{:x}", register.regnum), deadline)?;
            if reply.is_empty() || is_error(&reply) {
                continue;
            }
            if reply.len() != register.bytes() * 2 || !reply.iter().all(|b| is_register_digit(*b)) {
                return Err(protocol(&format!("`p` reply for `{}` has the wrong size", register.name)));
            }
            *slot = Some(String::from_utf8_lossy(&reply).to_ascii_lowercase());
        }
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
        if info.feature("qXfer:libraries-svr4:read")
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
        } else {
            result.limitations.push("the stub reports no memory map".into());
        }
        if info.feature("qXfer:exec-file:read") {
            let pid = self.threads.iter().find_map(|thread| thread.id.pid);
            let annex = pid.map(|pid| format!("{pid:x}")).unwrap_or_default();
            if let Some(bytes) = self.xfer("exec-file", &annex, size, 4096, deadline)? {
                result.exec_file = Some(String::from_utf8_lossy(&bytes).into_owned());
            }
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

/// A state as words, for errors.
fn describe(state: &State) -> String {
    match state {
        State::Stopped => "stopped".into(),
        State::Running => "running".into(),
        State::Exited => "exited".into(),
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

    #[test]
    fn sizes_chunks_to_the_packet_size() {
        assert_eq!(chunk_size(0x20020), MAX_MEMORY_READ);
        assert_eq!(chunk_size(2048), 1008);
        assert_eq!(chunk_size(0), 16);
        assert!(is_error(b"E14") && is_error(b"E.text") && !is_error(b"E") && !is_error(b"Exx"));
    }
}
