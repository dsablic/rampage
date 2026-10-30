//! A read-only GDB Remote Serial Protocol client for operator-started stubs (gdbserver, QEMU, OpenOCD, probe-rs...).
//!
//! The operator starts the stub and lists its endpoint; this crate connects, negotiates features, reads the target
//! description, the stop state, threads, registers, memory, loaded modules and memory maps, and detaches. Nothing
//! here launches, attaches to, resumes, steps, sets breakpoints in, writes to or kills a target: the client refuses
//! to put any such packet on the wire ([`client::allowed`]). `D` (detach) is the one packet that lets a target run
//! on, because detaching hands it back to the stub.
//!
//! A [`Session`] is a thread that owns the connection and serves typed requests one at a time.

pub mod client;
#[cfg(feature = "fake-stub")]
pub mod fake;
pub mod maps;
pub mod packet;
mod session;
pub mod stop;
pub mod target;
pub mod transport;
mod xml;

pub use client::Console;
pub use maps::{Module, Offsets, Region};
pub use session::{
    ByteOrder, CLOSE_DETACH, Config, Info, MemoryChunk, MemoryRead, Modules, RegisterValue, Registers, Session, State,
    Status, ThreadInfo,
};
pub use stop::{StopReason, StopReply, ThreadId};
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
    /// A packet outside the read-only allowlist; never sent.
    #[error("refused to send `{0}`: not a read-only packet")]
    Forbidden(String),
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
        }
    }

    /// Whether the connection can no longer be trusted to be in step with the stub.
    pub(crate) fn fatal(&self) -> bool {
        matches!(self, DebugError::Timeout(_) | DebugError::Lost(_) | DebugError::Protocol(_))
    }
}
