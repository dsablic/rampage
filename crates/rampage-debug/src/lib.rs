//! A GDB Remote Serial Protocol client for operator-started stubs (gdbserver, QEMU, OpenOCD, probe-rs...).
//!
//! The operator starts the stub and lists its endpoint; this crate connects, negotiates features, reads the target
//! description, the stop state, threads, registers, memory, loaded modules and memory maps, controls execution in
//! all-stop mode (continue, wait, interrupt, single-step, breakpoints and watchpoints the stub inserts) and detaches.
//! Nothing here launches or attaches to a target, delivers a signal on resume, enters non-stop mode or plants a
//! breakpoint by writing memory: the client refuses to put any such packet on the wire, and each session command
//! may send only the packet classes it declares ([`client::classify`], [`client::Permit`]). Memory and register
//! writes and kill exist only as their own requests, and a session refuses them unless its [`Consent`] (the
//! operator's `--debug-writes` and `--debug-kill`) allows them; nothing is ever written or killed on the side.
//!
//! A [`Session`] is a thread that owns the connection and serves typed requests one at a time; while the target
//! runs it keeps serving status, wait, interrupt and detach requests.

pub mod client;
pub mod exec;
#[cfg(feature = "fake-stub")]
pub mod fake;
pub mod lldb;
pub mod maps;
pub mod packet;
pub mod pe;
mod session;
pub mod stop;
pub mod target;
pub mod transport;
mod xml;

pub use client::{Console, PacketClass, Permit};
pub use exec::{
    BreakKind, Breakpoint, Cancel, MAX_BREAKPOINTS, MAX_STEPS, MAX_WATCH_LENGTH, Placement, StopCause, StopEvent,
    TemporaryOutcome, WatchHit,
};
pub use lldb::{AddressMask, DyldImage, HostInfo, ThreadDetail};
pub use maps::{Module, Offsets, Region};
pub use pe::{CodeView, PeImage, WindowsException};
pub use session::{
    ByteOrder, CLOSE_DETACH, Config, Consent, Detached, INTERRUPT_WAIT, Info, Killed, LldbInfo, MAX_TEMPORARY,
    MAX_WRITE, MemoryChunk, MemoryRead, MemoryWrite, Modules, RegisterValue, RegisterWrite, Registers, Run, Session,
    State, Status, Steps, TemporaryPlacement, ThreadInfo, WindowsTarget, WriteChunk, encode_register_value,
};
pub use stop::{Exception, MachException, StopReason, StopReply, ThreadId};
pub use target::{Family, Layout, LayoutSource, Register};
pub use transport::{Endpoint, Transport};

/// Most bytes one memory read returns.
pub const MAX_MEMORY_READ: usize = 65_536;
/// Most console-output bytes kept per session.
pub const MAX_CONSOLE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DebugError {
    #[error("cannot connect: {0}")]
    Connect(String),
    #[error("timed out: {0}")]
    Timeout(String),
    #[error("connection lost: {0}")]
    Lost(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The stub answered with an error (`E nn`) or refused a request it supports.
    #[error("target error: {0}")]
    Target(String),
    #[error("unsupported by the stub: {0}")]
    Unsupported(String),
    /// The session is not in a state that allows the request (it ended, was detached or was lost).
    #[error("{0}")]
    State(String),
    #[error("{0}")]
    Invalid(String),
    /// A packet outside the classes the command declared; never sent.
    #[error("refused to send `{0}`: not a packet this command may send")]
    Forbidden(String),
    /// The target is running; only status, wait, interrupt and disconnect are served.
    #[error("the target is running: {0}")]
    Running(String),
    /// An interrupt or other running-only request reached a target that is not running.
    #[error("{0}")]
    NotRunning(String),
    /// The caller's epoch is not the session's: the target stopped again (or ran) since the caller looked.
    #[error("epoch {given} is stale: the session is at epoch {current} and {state}")]
    StaleEpoch { given: u64, current: u64, state: String },
    /// The caller cancelled the request; the target was not touched.
    #[error("cancelled: {0}")]
    Cancelled(String),
    /// A write or kill the operator did not allow for this session; nothing was sent.
    #[error("{0}")]
    NotAllowed(String),
    /// A write's `expect` bytes differ from what the target holds; nothing was written.
    #[error("{0}")]
    ExpectMismatch(String),
}

impl DebugError {
    /// A stable code for the error's kind.
    pub fn code(&self) -> &'static str {
        match self {
            DebugError::Connect(_) => "connect_failed",
            DebugError::Timeout(_) => "timeout",
            DebugError::Lost(_) => "connection_lost",
            DebugError::Protocol(_) => "protocol_error",
            DebugError::Target(_) => "target_error",
            DebugError::Unsupported(_) => "unsupported",
            DebugError::State(_) => "session_not_stopped",
            DebugError::Invalid(_) => "invalid_argument",
            DebugError::Forbidden(_) => "forbidden_packet",
            DebugError::Running(_) => "target_running",
            DebugError::NotRunning(_) => "not_running",
            DebugError::StaleEpoch { .. } => "stale_epoch",
            DebugError::Cancelled(_) => "cancelled",
            DebugError::NotAllowed(_) => "not_allowed",
            DebugError::ExpectMismatch(_) => "expect_mismatch",
        }
    }

    /// Whether the connection can no longer be trusted to be in step with the stub.
    pub(crate) fn fatal(&self) -> bool {
        matches!(self, DebugError::Timeout(_) | DebugError::Lost(_) | DebugError::Protocol(_))
    }
}
