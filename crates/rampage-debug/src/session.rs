//! A debug session: one thread owns the connection and serves typed requests over a channel, one at a time.

use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::client::{Client, Console};
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
    Registers(Option<ThreadId>),
    Memory { address: u64, length: usize, thread: Option<ThreadId> },
    Modules,
    Detach,
}

enum Response {
    Status(Status),
    Registers(Registers),
    Memory(MemoryRead),
    Modules(Modules),
    Detached(State),
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
                let mut worker = Worker::new(transport);
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
        match self.call(Request::Registers(thread), self.config.command_timeout)? {
            Response::Registers(registers) => Ok(registers),
            _ => unreachable!("registers request"),
        }
    }

    /// Reads `length` (1..=65536) bytes at `address`. Unreadable parts are reported per chunk, not hidden.
    pub fn read_memory(&self, address: u64, length: usize, thread: Option<ThreadId>) -> Result<MemoryRead, DebugError> {
        if !(1..=MAX_MEMORY_READ).contains(&length) || address.checked_add(length as u64 - 1).is_none() {
            return Err(DebugError::Invalid(format!(
                "length must be in 1..={MAX_MEMORY_READ} and the range must not overflow the address space"
            )));
        }
        match self.call(Request::Memory { address, length, thread }, self.config.command_timeout)? {
            Response::Memory(memory) => Ok(memory),
            _ => unreachable!("memory request"),
        }
    }

    pub fn modules(&self) -> Result<Modules, DebugError> {
        match self.call(Request::Modules, self.config.command_timeout)? {
            Response::Modules(modules) => Ok(modules),
            _ => unreachable!("modules request"),
        }
    }

    /// Detaches (`D`) and ends the session, returning its final state. The target runs on under the stub. When
    /// the stub refuses (`E nn`), the session stays open and still attached, so detaching can be retried.
    pub fn detach(&self) -> Result<State, DebugError> {
        let result = match self.call(Request::Detach, self.config.command_timeout) {
            Ok(Response::Detached(state)) => Ok(state),
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
}

impl Worker {
    fn new(transport: Box<dyn Transport>) -> Self {
        Self {
            client: Client::new(transport),
            info: None,
            state: State::Stopped,
            epoch: 0,
            stop: None,
            threads: Vec::new(),
            selected: None,
            extra_info: true,
            multiprocess: false,
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
        while let Ok(job) = inbox.recv() {
            let detach = matches!(job.request, Request::Detach);
            let result = self.run(job.request, job.deadline);
            // A refused detach leaves the session attached and serving.
            let detach = detach && !matches!(result, Err(DebugError::Target(_)));
            if let Err(error) = &result
                && error.fatal()
                && !matches!(self.state, State::Lost { .. })
            {
                self.state = State::Lost { reason: error.to_string() };
                self.client.shutdown();
            }
            let _ = job.reply.send(result);
            if detach {
                break;
            }
        }
        // The last handle dropped without detaching: detach best-effort before closing.
        if self.state == State::Stopped && self.client.in_sync() {
            let _ = self.detach(Instant::now() + CLOSE_DETACH);
        }
    }

    fn require_stopped(&self) -> Result<(), DebugError> {
        match &self.state {
            State::Stopped => Ok(()),
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
                        Err(error) if error.fatal() => {
                            self.state = State::Lost { reason: error.to_string() };
                            self.client.shutdown();
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(Response::Status(Status {
                    state: self.state.clone(),
                    epoch: self.epoch,
                    stop: self.stop.clone(),
                    threads: self.threads.clone(),
                    console: self.client.console.clone(),
                }))
            }
            Request::Registers(thread) => {
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
            Request::Memory { address, length, thread } => {
                self.require_stopped()?;
                let used = self.use_thread(thread, deadline)?;
                let binary = info.feature("binary-upload");
                let mut chunks = Vec::new();
                // Counting down the length, not up to an end address, so a range that ends at the top of the
                // address space cannot overflow.
                let mut at = address;
                let mut remaining = length;
                while remaining > 0 {
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
            Request::Modules => {
                self.require_stopped()?;
                self.use_thread(None, deadline)?;
                self.modules(&info, deadline).map(Response::Modules)
            }
            Request::Detach => self.detach(deadline).map(Response::Detached),
        }
    }

    fn detach(&mut self, deadline: Instant) -> Result<State, DebugError> {
        match self.state {
            State::Stopped => {}
            // Nothing is attached any more; just close.
            _ => return Ok(self.state.clone()),
        }
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
        Ok(State::Detached)
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

    /// Re-reads the stop (`?`) and threads; a stop reply that differs from the last one is a new stop.
    fn refresh(&mut self, deadline: Instant) -> Result<(), DebugError> {
        let stop = StopReply::parse(&self.command("?", deadline)?).map_err(DebugError::Protocol)?;
        if self.stop.as_ref() != Some(&stop) {
            self.epoch += 1;
            if stop.ended() {
                self.state = State::Exited;
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
