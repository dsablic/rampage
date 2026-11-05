//! The request/reply layer over a transport: acknowledgements and retransmission, no-ack mode, console output,
//! deadlines and the read-only packet allowlist.

use std::io::ErrorKind;
use std::time::{Duration, Instant};

use crate::packet::{self, Frame, Framer};
use crate::transport::Transport;
use crate::{DebugError, MAX_CONSOLE_BYTES};

/// Times a packet is sent again after the stub NAKs it, and damaged replies tolerated per command.
const RETRANSMITS: usize = 3;
/// Bytes outside any packet tolerated per command before the stream is declared desynchronized.
const MAX_NOISE: usize = 4096;
/// Console-output and notification frames tolerated per command, so a chatty stub cannot hold a command open.
pub const MAX_ASYNC_FRAMES: usize = 256;

/// The classes of packet a session command may send. Each command declares the classes it needs, and
/// [`Client::command`] refuses any packet outside them before it reaches the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketClass {
    /// Queries, register and memory reads, thread selection for reads and no-ack negotiation.
    Read,
    /// `vCont?`, `vCont;c`, `vCont;s:<thread>`, `c`, `s`, `Hc<thread>` and `Z0`..`Z4`/`z0`..`z4`
    /// `<address>,<kind>`. Never a signal-delivering resume, a write, a kill, a launch or an attach.
    Execution,
    /// `D` and `D;<pid>`.
    Detach,
    /// Memory and register writes: `M<address>,<length>:<hex>`, `X<address>,<length>:<binary>`,
    /// `P<regnum>=<hex>` and `G<hex>`. Only a write tool's request sends them, and only in a session whose operator
    /// allowed writes.
    Write,
    /// `k` and `vKill;<pid>`. Only a kill request sends them, and only in a session whose operator allowed it.
    Kill,
}

/// The set of [`PacketClass`]es a command may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permit {
    pub read: bool,
    pub execution: bool,
    pub detach: bool,
    pub write: bool,
    pub kill: bool,
}

impl Permit {
    /// Reads only: what every 9.1 inspection command declares.
    pub const READ: Permit = Permit { read: true, execution: false, detach: false, write: false, kill: false };
    /// Reads and execution control: resume, step, interrupt and breakpoints.
    pub const EXECUTION: Permit = Permit { read: true, execution: true, detach: false, write: false, kill: false };
    /// Everything detaching needs: stopping a running target, removing breakpoints, then `D`.
    pub const DETACH: Permit = Permit { read: true, execution: true, detach: true, write: false, kill: false };
    /// A write request: reads around one memory or register write. No execution control.
    pub const WRITE: Permit = Permit { read: true, execution: false, detach: false, write: true, kill: false };
    /// Everything killing needs: stopping a running target, removing breakpoints, then `k` or `vKill`. Never `D`.
    pub const KILL: Permit = Permit { read: true, execution: true, detach: false, write: false, kill: true };

    fn allows(self, class: PacketClass) -> bool {
        match class {
            PacketClass::Read => self.read,
            PacketClass::Execution => self.execution,
            PacketClass::Detach => self.detach,
            PacketClass::Write => self.write,
            PacketClass::Kill => self.kill,
        }
    }
}

/// The class of `payload`, or `None` when this client never sends it: launch and attach (`vRun`, `vAttach`, `R`,
/// `!`), signal-delivering resumes (`C`, `S`, `vCont;C`/`S`), non-stop mode, monitor commands, malformed writes and
/// anything else unlisted. An `X` write carries binary data; see [`classify_bytes`].
pub fn classify(payload: &str) -> Option<PacketClass> {
    classify_bytes(payload.as_bytes())
}

/// [`classify`] for a payload as bytes: an `X` write's data may be any bytes (exactly its length of them); every
/// other packet must be ASCII text.
pub fn classify_bytes(payload: &[u8]) -> Option<PacketClass> {
    if let Some(rest) = payload.strip_prefix(b"X") {
        let at = rest.iter().position(|byte| *byte == b':')?;
        let (header, data) = (std::str::from_utf8(&rest[..at]).ok()?, &rest[at + 1..]);
        let (address, length) = header.split_once(',')?;
        let hex = |text: &str| !text.is_empty() && text.len() <= 16 && text.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex(address) || !hex(length) {
            return None;
        }
        let length = u64::from_str_radix(length, 16).ok()?;
        return (length > 0 && length == data.len() as u64).then_some(PacketClass::Write);
    }
    std::str::from_utf8(payload).ok().filter(|text| text.is_ascii()).and_then(classify_text)
}

fn classify_text(payload: &str) -> Option<PacketClass> {
    let hex = |text: &str| !text.is_empty() && text.len() <= 16 && text.bytes().all(|byte| byte.is_ascii_hexdigit());
    let range = |text: &str| text.split_once(',').is_some_and(|(address, length)| hex(address) && hex(length));
    let annex = |text: &str| {
        let Some((annex, offsets)) = text.split_once(':') else { return false };
        annex.len() <= 64
            && annex.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
            && range(offsets)
    };
    let thread = |text: &str| crate::ThreadId::parse(text).is_some();
    let read = |yes: bool| yes.then_some(PacketClass::Read);
    match payload {
        "?" | "g" | "qfThreadInfo" | "qsThreadInfo" | "qOffsets" | "qAttached" | "QStartNoAckMode" => {
            Some(PacketClass::Read)
        }
        "D" => Some(PacketClass::Detach),
        "k" => Some(PacketClass::Kill),
        "vCont?" | "vCont;c" | "c" | "s" => Some(PacketClass::Execution),
        // Windows under gdbserver only (the client refuses it elsewhere): continue the listed threads, leaving a
        // break-in thread suspended.
        _ if thread_continue(payload) => Some(PacketClass::Execution),
        // LLDB's queries (debugserver), each only in the exact form rampage sends.
        _ if crate::lldb::read_query(payload) => Some(PacketClass::Read),
        _ if payload.starts_with("qSupported") => read(
            payload.len() <= 512 && payload.bytes().all(|byte| byte.is_ascii_graphic() && byte != b'#' && byte != b'$'),
        ),
        _ => {
            if let Some(rest) = payload.strip_prefix("qXfer:") {
                let (object, rest) = rest.split_once(":read:")?;
                return read(
                    matches!(
                        object,
                        "features" | "libraries-svr4" | "libraries" | "exec-file" | "memory-map" | "siginfo"
                    ) && annex(rest),
                );
            }
            // gdbserver on Windows: a thread's TIB address, which leads to the process environment block.
            if let Some(id) = payload.strip_prefix("qGetTIBAddr:") {
                return read(thread(id));
            }
            if let Some(id) = payload.strip_prefix("qThreadExtraInfo,").or_else(|| payload.strip_prefix("Hg")) {
                return read(thread(id) || id == "0");
            }
            if let Some(id) = payload.strip_prefix("vCont;s:").or_else(|| payload.strip_prefix("Hc")) {
                // `Hc-1` (all threads) undoes an `Hc<thread>` before a plain `c`.
                return (thread(id) || payload == "Hc-1").then_some(PacketClass::Execution);
            }
            if let Some(rest) = payload.strip_prefix('Z').or_else(|| payload.strip_prefix('z')) {
                let (kind, rest) = rest.split_at_checked(1)?;
                let insert = matches!(kind, "0" | "1" | "2" | "3" | "4");
                return (insert && rest.strip_prefix(',').is_some_and(range)).then_some(PacketClass::Execution);
            }
            if let Some(pid) = payload.strip_prefix("D;") {
                return hex(pid).then_some(PacketClass::Detach);
            }
            if let Some(pid) = payload.strip_prefix("vKill;") {
                return hex(pid).then_some(PacketClass::Kill);
            }
            let digits = |text: &str| {
                !text.is_empty() && text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit())
            };
            if let Some(rest) = payload.strip_prefix('M') {
                let (target, data) = rest.split_once(':')?;
                let length = target.split_once(',').filter(|_| range(target))?.1;
                let length = u64::from_str_radix(length, 16).ok()?;
                return (length > 0 && digits(data) && data.len() as u64 == 2 * length).then_some(PacketClass::Write);
            }
            if let Some((register, value)) = payload.strip_prefix('P').and_then(|rest| rest.split_once('=')) {
                return (hex(register) && digits(value)).then_some(PacketClass::Write);
            }
            if let Some(registers) = payload.strip_prefix('G') {
                return digits(registers).then_some(PacketClass::Write);
            }
            if let Some(register) = payload.strip_prefix('p') {
                return read(hex(register));
            }
            match payload.strip_prefix('m').or_else(|| payload.strip_prefix('x')) {
                Some(rest) => read(range(rest)),
                None => None,
            }
        }
    }
}

/// Whether `payload` is a packet this client may send under `permit`.
pub fn allowed(payload: &str, permit: Permit) -> bool {
    classify(payload).is_some_and(|class| permit.allows(class))
}

/// Whether `payload` resumes the target, so its reply is a stop reply that may come much later.
pub fn resumes(payload: &str) -> bool {
    matches!(payload, "c" | "s" | "vCont;c") || payload.starts_with("vCont;s:") || thread_continue(payload)
}

/// Whether `payload` is `vCont;c:<thread>[;c:<thread>...]`: continue exactly these threads (at most 4096), each a
/// specific thread. Rampage sends it only on Windows under gdbserver, which resumes only the threads a `vCont`
/// names (`gdbserver/win32-low.cc`, `win32_process_target::resume`), so a thread can stay suspended.
pub fn thread_continue(payload: &str) -> bool {
    let Some(actions) = payload.strip_prefix("vCont;") else { return false };
    let actions: Vec<&str> = actions.split(';').collect();
    actions.len() <= 4096
        && actions
            .iter()
            .all(|action| action.strip_prefix("c:").is_some_and(|thread| crate::ThreadId::parse(thread).is_some()))
}

/// Console output (`O` packets) collected from the stub, bounded.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Console {
    pub text: String,
    /// Bytes dropped once `text` reached its bound.
    pub dropped_bytes: usize,
}

impl Console {
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        let room = MAX_CONSOLE_BYTES.saturating_sub(self.text.len());
        let kept = &bytes[..bytes.len().min(room)];
        self.text.push_str(&String::from_utf8_lossy(kept));
        self.dropped_bytes += bytes.len() - kept.len();
    }
}

pub struct Client<T: Transport> {
    transport: T,
    framer: Framer,
    ack_mode: bool,
    in_sync: bool,
    pub console: Console,
    /// Console output received since the last resume.
    pub run_console: Console,
    permit: Permit,
    /// Whether per-thread continues ([`thread_continue`]) may be sent: a Windows session under gdbserver.
    thread_continue: bool,
    /// The resume packet whose stop reply is outstanding; the target is running.
    running: Option<Vec<u8>>,
    /// Whether the outstanding resume packet is still waiting for its acknowledgement.
    unacknowledged: bool,
    run_naks: usize,
    run_noise: usize,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            framer: Framer::new(packet::MAX_PACKET_BYTES),
            ack_mode: true,
            in_sync: true,
            console: Console::default(),
            run_console: Console::default(),
            permit: Permit::READ,
            thread_continue: false,
            running: None,
            unacknowledged: false,
            run_naks: 0,
            run_noise: 0,
        }
    }

    /// Allows per-thread continues ([`thread_continue`]), which only a Windows session under gdbserver sends.
    pub fn allow_thread_continue(&mut self) {
        self.thread_continue = true;
    }

    /// Sets the packet classes the following commands may send.
    pub fn set_permit(&mut self, permit: Permit) {
        self.permit = permit;
    }

    /// Whether a resume is outstanding: no stop reply has arrived since.
    pub fn running(&self) -> bool {
        self.running.is_some()
    }

    /// Whether every command so far got its reply, so the next reply belongs to the next request.
    pub fn in_sync(&self) -> bool {
        self.in_sync
    }

    pub fn ack_mode(&self) -> bool {
        self.ack_mode
    }

    /// Stops sending and expecting acknowledgements, after the stub accepted `QStartNoAckMode`.
    pub fn disable_acks(&mut self) {
        self.ack_mode = false;
    }

    /// Closes the connection and releases any buffered bytes.
    pub fn shutdown(&mut self) {
        self.transport.shutdown();
        self.in_sync = false;
        self.running = None;
        self.framer = Framer::new(0);
    }

    /// Sends `payload` and returns the stub's reply, collecting console output on the way. Any error other than a
    /// refused packet leaves the stream in an unknown state, so the caller must treat the connection as lost.
    pub fn command(&mut self, payload: &str, deadline: Instant) -> Result<Vec<u8>, DebugError> {
        self.command_bytes(payload.as_bytes(), deadline)
    }

    /// [`Client::command`] for a payload as bytes, as an `X` write's binary data needs.
    pub fn command_bytes(&mut self, payload: &[u8], deadline: Instant) -> Result<Vec<u8>, DebugError> {
        let permitted = classify_bytes(payload).is_some_and(|class| self.permit.allows(class));
        if !permitted || std::str::from_utf8(payload).is_ok_and(resumes) {
            return Err(DebugError::Forbidden(printable(payload)));
        }
        if self.running.is_some() {
            return Err(DebugError::Running("no request can be sent while the target runs".into()));
        }
        if !self.in_sync {
            return Err(DebugError::Lost("the reply stream is out of step with requests".into()));
        }
        let result = self.exchange(payload, deadline);
        if result.is_err() {
            self.in_sync = false;
        }
        result
    }

    fn exchange(&mut self, payload: &[u8], deadline: Instant) -> Result<Vec<u8>, DebugError> {
        let request = packet::encode(payload);
        self.write(&request)?;
        let mut naks = 0;
        let mut corrupt = 0;
        let mut noise = 0;
        let mut asynchronous = 0;
        let mut acknowledged = !self.ack_mode;
        loop {
            let next = match self.framer.next_frame() {
                Ok(next) => next,
                Err(error) => return Err(DebugError::Protocol(error.to_string())),
            };
            let Some(frame) = next else {
                self.fill(deadline)?;
                continue;
            };
            match frame {
                Frame::Ack => acknowledged = true,
                Frame::Nak if !acknowledged => {
                    naks += 1;
                    if naks > RETRANSMITS {
                        let shown = printable(payload);
                        return Err(DebugError::Protocol(format!("stub refused `{shown}` {naks} times")));
                    }
                    self.write(&request)?;
                }
                // A NAK after the acknowledgement, or in no-ack mode, has nothing to retransmit.
                Frame::Nak => {}
                Frame::Notification => {
                    asynchronous += 1;
                    if asynchronous > MAX_ASYNC_FRAMES {
                        return Err(DebugError::Protocol("too many notifications during one command".into()));
                    }
                }
                Frame::Noise(_) => {
                    noise += 1;
                    if noise > MAX_NOISE {
                        return Err(DebugError::Protocol("too many bytes outside packets".into()));
                    }
                }
                Frame::Corrupt => {
                    corrupt += 1;
                    if !self.ack_mode || corrupt > RETRANSMITS {
                        return Err(DebugError::Protocol("reply checksum mismatch".into()));
                    }
                    self.write(b"-")?;
                }
                Frame::Packet(reply) => {
                    // Some stubs reply without acknowledging first; the reply implies the request arrived.
                    if self.ack_mode {
                        self.write(b"+")?;
                    }
                    if let Some(output) = console_output(&reply) {
                        self.console.push(&output);
                        asynchronous += 1;
                        if asynchronous > MAX_ASYNC_FRAMES {
                            return Err(DebugError::Protocol("too much console output during one command".into()));
                        }
                        continue;
                    }
                    return Ok(reply);
                }
            }
        }
    }

    /// Sends a resume packet (`c`, `s`, `vCont;c` or `vCont;s:<thread>`) without waiting for its stop reply, which
    /// [`Client::poll`] collects. Requires the execution class.
    pub fn resume(&mut self, payload: &str) -> Result<(), DebugError> {
        if !resumes(payload) || !allowed(payload, self.permit) || (thread_continue(payload) && !self.thread_continue) {
            return Err(DebugError::Forbidden(payload.chars().take(64).collect()));
        }
        if self.running.is_some() {
            return Err(DebugError::Running("the target is already running".into()));
        }
        if !self.in_sync {
            return Err(DebugError::Lost("the reply stream is out of step with requests".into()));
        }
        let request = packet::encode(payload.as_bytes());
        if let Err(error) = self.write(&request) {
            self.in_sync = false;
            return Err(error);
        }
        self.running = Some(request);
        self.unacknowledged = self.ack_mode;
        self.run_naks = 0;
        self.run_noise = 0;
        self.run_console = Console::default();
        Ok(())
    }

    /// Sends the out-of-band interrupt byte (`0x03`), only while a resume is outstanding.
    pub fn interrupt(&mut self) -> Result<(), DebugError> {
        if !self.permit.execution {
            return Err(DebugError::Forbidden("\\x03".into()));
        }
        if self.running.is_none() {
            return Err(DebugError::NotRunning("the target is not running".into()));
        }
        self.write(&[0x03]).inspect_err(|_| self.in_sync = false)
    }

    /// Reads the stub for up to `wait` while the target runs: acknowledgements, console output (kept, bounded),
    /// notifications (ignored) and finally the packet that ends the run, normally a stop reply. `None` when nothing
    /// ended the run in time. Any error leaves the stream in an unknown state.
    pub fn poll(&mut self, wait: Duration) -> Result<Option<Vec<u8>>, DebugError> {
        if self.running.is_none() {
            return Err(DebugError::NotRunning("the target is not running".into()));
        }
        let result = self.poll_frames(Instant::now() + wait);
        match &result {
            Ok(Some(_)) => self.running = None,
            Ok(None) => {}
            Err(_) => {
                self.in_sync = false;
                self.running = None;
            }
        }
        result
    }

    fn poll_frames(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>, DebugError> {
        loop {
            let frame = self.framer.next_frame().map_err(|error| DebugError::Protocol(error.to_string()))?;
            let Some(frame) = frame else {
                if !self.fill_until(deadline)? {
                    return Ok(None);
                }
                continue;
            };
            match frame {
                Frame::Ack => self.unacknowledged = false,
                Frame::Nak if self.unacknowledged => {
                    self.run_naks += 1;
                    if self.run_naks > RETRANSMITS {
                        return Err(DebugError::Protocol("the stub refused the resume packet repeatedly".into()));
                    }
                    let request = self.running.clone().unwrap_or_default();
                    self.write(&request)?;
                }
                Frame::Nak | Frame::Notification => {}
                Frame::Noise(_) => {
                    self.run_noise += 1;
                    if self.run_noise > MAX_NOISE {
                        return Err(DebugError::Protocol("too many bytes outside packets".into()));
                    }
                }
                Frame::Corrupt => {
                    if !self.ack_mode {
                        return Err(DebugError::Protocol("reply checksum mismatch".into()));
                    }
                    self.run_naks += 1;
                    if self.run_naks > RETRANSMITS {
                        return Err(DebugError::Protocol("reply checksum mismatch".into()));
                    }
                    self.write(b"-")?;
                }
                Frame::Packet(reply) => {
                    self.unacknowledged = false;
                    if self.ack_mode {
                        self.write(b"+")?;
                    }
                    if let Some(output) = console_output(&reply) {
                        self.console.push(&output);
                        self.run_console.push(&output);
                        continue;
                    }
                    return Ok(Some(reply));
                }
            }
        }
    }

    /// Reads what arrives before `deadline`; false when nothing did.
    fn fill_until(&mut self, deadline: Instant) -> Result<bool, DebugError> {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|remaining| !remaining.is_zero())
        else {
            return Ok(false);
        };
        self.transport.set_read_timeout(remaining).map_err(|error| DebugError::Lost(error.to_string()))?;
        let mut buffer = [0; 16 * 1024];
        loop {
            match self.transport.read(&mut buffer) {
                Ok(0) => return Err(DebugError::Lost("the stub closed the connection".into())),
                Ok(count) => {
                    self.framer.push(&buffer[..count]);
                    return Ok(true);
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Ok(false),
                Err(error) => return Err(DebugError::Lost(format!("read failed: {error}"))),
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), DebugError> {
        self.transport.write_all(bytes).and_then(|()| self.transport.flush()).map_err(|error| match error.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => DebugError::Timeout("writing to the stub".into()),
            _ => DebugError::Lost(format!("write failed: {error}")),
        })
    }

    fn fill(&mut self, deadline: Instant) -> Result<(), DebugError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| DebugError::Timeout("no reply before the command deadline".into()))?;
        self.transport.set_read_timeout(remaining).map_err(|error| DebugError::Lost(error.to_string()))?;
        let mut buffer = [0; 16 * 1024];
        loop {
            match self.transport.read(&mut buffer) {
                Ok(0) => return Err(DebugError::Lost("the stub closed the connection".into())),
                Ok(count) => {
                    self.framer.push(&buffer[..count]);
                    return Ok(());
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Err(DebugError::Timeout("no reply before the command deadline".into()));
                }
                Err(error) => return Err(DebugError::Lost(format!("read failed: {error}"))),
            }
        }
    }
}

/// At most 64 bytes of a payload as printable ASCII, for errors.
fn printable(payload: &[u8]) -> String {
    payload[..payload.len().min(64)]
        .iter()
        .map(|&byte| if byte.is_ascii_graphic() || byte == b' ' { byte as char } else { '?' })
        .collect()
}

/// The text of an `O` console-output packet: `O` then a nonempty even run of hex digits. `OK` is not one.
fn console_output(reply: &[u8]) -> Option<Vec<u8>> {
    let hex = reply.strip_prefix(b"O")?;
    if hex.is_empty() {
        return None;
    }
    packet::decode_hex(hex)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{self, Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// An in-memory transport: reads come from scripted chunks, writes are recorded.
    #[derive(Clone, Default)]
    pub(crate) struct Pipe {
        pub(crate) input: Arc<Mutex<VecDeque<Vec<u8>>>>,
        pub(crate) output: Arc<Mutex<Vec<u8>>>,
    }

    impl Pipe {
        pub(crate) fn with(chunks: &[&[u8]]) -> Self {
            let pipe = Pipe::default();
            pipe.input.lock().unwrap().extend(chunks.iter().map(|chunk| chunk.to_vec()));
            pipe
        }

        pub(crate) fn written(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }
    }

    impl Read for Pipe {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.input.lock().unwrap().pop_front() {
                Some(chunk) => {
                    assert!(chunk.len() <= buffer.len());
                    buffer[..chunk.len()].copy_from_slice(&chunk);
                    Ok(chunk.len())
                }
                None => Err(io::Error::new(ErrorKind::WouldBlock, "no more scripted input")),
            }
        }
    }

    impl Write for Pipe {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Transport for Pipe {
        fn set_read_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn shutdown(&mut self) {}
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn packets_are_classified_and_held_to_the_command_permit() {
        for packet in [
            "?",
            "g",
            "p19",
            "m20000000,40",
            "x1000,10",
            "Hgp1.1",
            "Hg1f",
            "qfThreadInfo",
            "qThreadExtraInfo,p2a.2b",
            "qXfer:features:read:target.xml:0,ffb",
            "qXfer:libraries-svr4:read::0,fff",
            "qXfer:exec-file:read:2a:0,fff",
            "qXfer:libraries:read::0,fff",
            "qXfer:siginfo:read::0,fff",
            "qGetTIBAddr:1a2c",
            "qSupported:multiprocess+;swbreak+",
            "QStartNoAckMode",
            "qHostInfo",
            "qProcessInfo",
            "qRegisterInfo1f",
            "jThreadsInfo",
            "qMemoryRegionInfo:16fdff000",
            "jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true,\"report_load_commands\":false}",
            "jGetLoadedDynamicLibrariesInfos:{\"solib_addresses\":[4294967296]}",
        ] {
            assert_eq!(classify(packet), Some(PacketClass::Read), "{packet}");
            assert!(allowed(packet, Permit::READ), "{packet}");
        }
        for packet in [
            "c",
            "s",
            "vCont?",
            "vCont;c",
            "vCont;s:1",
            "vCont;s:p1.1",
            "Hc1",
            "Hcp2a.2b",
            "Hc-1",
            "Z0,1000,4",
            "z0,1000,4",
            "Z1,8000000000000000,2",
            "Z2,20000200,4",
            "z4,0,1",
            // Recognized everywhere, sent only on Windows under gdbserver: `Client::resume` refuses it elsewhere.
            "vCont;c:1",
            "vCont;c:1a2c;c:1b30",
        ] {
            assert_eq!(classify(packet), Some(PacketClass::Execution), "{packet}");
            assert!(!allowed(packet, Permit::READ), "{packet}");
            assert!(allowed(packet, Permit::EXECUTION), "{packet}");
        }
        for packet in ["D", "D;2a"] {
            assert_eq!(classify(packet), Some(PacketClass::Detach), "{packet}");
            assert!(!allowed(packet, Permit::READ) && !allowed(packet, Permit::EXECUTION), "{packet}");
            assert!(allowed(packet, Permit::DETACH), "{packet}");
            assert!(!allowed(packet, Permit::WRITE) && !allowed(packet, Permit::KILL), "{packet}");
        }
        for packet in ["M1000,1:00", "M20000000,4:deadBEEF", "X1000,1:\0", "P1=00", "Pf=78563412", "G0011"] {
            assert_eq!(classify(packet), Some(PacketClass::Write), "{packet:?}");
            for permit in [Permit::READ, Permit::EXECUTION, Permit::DETACH, Permit::KILL] {
                assert!(!allowed(packet, permit), "{packet:?}");
            }
            assert!(allowed(packet, Permit::WRITE), "{packet:?}");
        }
        // Binary data: the length counts bytes, whatever they are.
        assert_eq!(classify_bytes(b"X10,3:\xff$#"), Some(PacketClass::Write));
        assert_eq!(classify_bytes(b"X10,3:\xff$"), None);
        assert_eq!(classify_bytes(b"M10,1:\xff\xff"), None);
        for packet in ["k", "vKill;1", "vKill;2a"] {
            assert_eq!(classify(packet), Some(PacketClass::Kill), "{packet}");
            for permit in [Permit::READ, Permit::EXECUTION, Permit::DETACH, Permit::WRITE] {
                assert!(!allowed(packet, permit), "{packet}");
            }
            assert!(allowed(packet, Permit::KILL), "{packet}");
        }
        // Execution-only packets stay out of a write request, and detach out of a kill.
        assert!(!allowed("c", Permit::WRITE) && !allowed("Z0,1000,2", Permit::WRITE) && !allowed("D", Permit::KILL));
        for packet in [
            "C05",
            "S05",
            "vCont;C05",
            "vCont;S05:1",
            "vCont;c:-1",
            "vCont;c:1;s:2",
            "vCont;c:0",
            "vCont;s",
            "vCont;s:-1",
            "vCont;s:1;c",
            "vCont;t",
            "vCont;r1000,2000",
            "Hc0",
            "vCont;s:-1",
            "qGetTIBAddr:",
            "qGetTIBAddr:-1",
            "qXfer:siginfo:write::0:00",
            "Z5,1000,4",
            "Z0,1000",
            "Z0,1000,4;X2,0a",
            "Z0,zz,4",
            "M1000,2:00",
            "M1000,0:",
            "M1000,1:0g",
            "M1000,1",
            "Mzz,1:00",
            "X1000,2:\0",
            "X1000,0:",
            "Xzz,1:\0",
            "G0",
            "G",
            "Gzz",
            "P1=0",
            "P=00",
            "Pzz=00",
            "P1",
            "k1",
            "vKill",
            "vKill;",
            "vKill;zz",
            "vRun;",
            "vAttach;1",
            "R00",
            "r",
            "!",
            "QNonStop:1",
            "qRcmd,7265736574",
            "qXfer:features:write:target.xml:0,1",
            "qXfer:threads:read::0,1",
            "qXfer:features:read:a:b:0,1",
            "m1000",
            "pzz",
            "D;zz",
            "i",
            "",
            "jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true}",
            "jGetLoadedDynamicLibrariesInfos:{\"image_count\":1,\"image_list_address\":140734800075128}",
            "jThreadExtendedInfo:{\"thread\":1}",
            "qRegisterInfo",
            "qMemoryRegionInfo:zz",
            "QListThreadsInStopReply",
            "QSetDisableASLR:1",
            "qLaunchSuccess",
            "vAttachWait;70726f67",
            "_M1000,rwx",
        ] {
            assert_eq!(classify(packet), None, "{packet:?}");
            let every = Permit { read: true, execution: true, detach: true, write: true, kill: true };
            assert!(!allowed(packet, every), "{packet:?}");
        }
    }

    #[test]
    fn random_packets_never_panic_when_classified() {
        let mut rng = crate::packet::tests::Rng::new(13);
        for _ in 0..20_000 {
            let alphabet = b"vCont?;csSCZzHDp0123459a,:.-\xff";
            let length = rng.below(20);
            let packet: String = (0..length).map(|_| alphabet[rng.below(alphabet.len())] as char).collect();
            if let Some(PacketClass::Execution) = classify(&packet) {
                let known = resumes(&packet)
                    || packet == "vCont?"
                    || ["Hc", "Z", "z"].iter().any(|prefix| packet.starts_with(prefix));
                assert!(known, "{packet}");
                assert!(!packet.starts_with("vCont;C") && !packet.starts_with("vCont;S"), "{packet}");
            }
        }
    }

    #[test]
    fn a_resume_waits_for_its_stop_reply_across_pieces_and_console_output() {
        let output = packet::encode(format!("O{}", packet::encode_hex(b"tick\n")).as_bytes());
        let reply = packet::encode(b"T05thread:p1.1;hwbreak:;");
        let (head, tail) = reply.split_at(7);
        let pipe = Pipe::with(&[b"+", &output[..3], &output[3..], b"%Stop:T05#00", head, tail]);
        let mut client = Client::new(pipe.clone());
        assert!(matches!(client.resume("c"), Err(DebugError::Forbidden(_))));
        client.set_permit(Permit::EXECUTION);
        assert!(matches!(client.interrupt(), Err(DebugError::NotRunning(_))));
        client.resume("vCont;c").unwrap();
        assert!(client.running());
        assert!(matches!(client.command("g", deadline()), Err(DebugError::Running(_))));
        let mut stop = None;
        for _ in 0..8 {
            if let Some(reply) = client.poll(Duration::from_millis(10)).unwrap() {
                stop = Some(reply);
                break;
            }
        }
        assert_eq!(stop.as_deref(), Some(&b"T05thread:p1.1;hwbreak:;"[..]));
        assert!(!client.running());
        assert_eq!(client.run_console.text, "tick\n");
        assert_eq!(pipe.written(), "$vCont;c#a8++");
        assert!(client.in_sync());
    }

    #[test]
    fn an_interrupt_is_one_byte_sent_only_while_running() {
        let pipe = Pipe::with(&[b"+"]);
        let mut client = Client::new(pipe.clone());
        client.set_permit(Permit::EXECUTION);
        client.resume("c").unwrap();
        assert_eq!(client.poll(Duration::from_millis(5)).unwrap(), None);
        client.interrupt().unwrap();
        assert!(pipe.written().ends_with('\u{3}'));
        client.set_permit(Permit::READ);
        assert!(matches!(client.interrupt(), Err(DebugError::Forbidden(_))));
    }

    #[test]
    fn forbidden_packets_are_refused_before_anything_is_written() {
        let pipe = Pipe::default();
        let mut client = Client::new(pipe.clone());
        assert!(matches!(client.command("c", deadline()), Err(DebugError::Forbidden(_))));
        assert!(pipe.written().is_empty());
    }

    #[test]
    fn retransmits_on_nak_and_acknowledges_replies() {
        let pipe = Pipe::with(&[b"-", b"+$OK#9a"]);
        let mut client = Client::new(pipe.clone());
        assert_eq!(client.command("?", deadline()).unwrap(), b"OK");
        assert_eq!(pipe.written(), "$?#3f$?#3f+");
    }

    #[test]
    fn gives_up_after_repeated_naks() {
        let pipe = Pipe::with(&[b"-", b"-", b"-", b"-"]);
        let mut client = Client::new(pipe);
        assert!(matches!(client.command("?", deadline()), Err(DebugError::Protocol(_))));
    }

    #[test]
    fn naks_corrupt_replies_and_accepts_the_retransmission() {
        let pipe = Pipe::with(&[b"+$OK#00", b"$OK#9a"]);
        let mut client = Client::new(pipe.clone());
        assert_eq!(client.command("?", deadline()).unwrap(), b"OK");
        assert_eq!(pipe.written(), "$?#3f-+");
    }

    #[test]
    fn corrupt_replies_in_no_ack_mode_are_fatal() {
        let pipe = Pipe::with(&[b"$OK#00"]);
        let mut client = Client::new(pipe.clone());
        client.disable_acks();
        assert!(matches!(client.command("?", deadline()), Err(DebugError::Protocol(_))));
        assert_eq!(pipe.written(), "$?#3f");
    }

    #[test]
    fn collects_console_output_without_ending_the_command() {
        let output = packet::encode(format!("O{}", packet::encode_hex(b"hello\n")).as_bytes());
        let reply = packet::encode(b"T05thread:1;");
        let pipe = Pipe::with(&[b"+", &output, &reply]);
        let mut client = Client::new(pipe);
        assert_eq!(client.command("?", deadline()).unwrap(), b"T05thread:1;");
        assert_eq!(client.console.text, "hello\n");
        assert_eq!(console_output(b"OK"), None);
        assert_eq!(console_output(b"O"), None);
    }

    #[test]
    fn ignores_notifications_and_reports_silence_as_a_timeout() {
        let pipe = Pipe::with(&[b"+%Stop:T05#00", b"$OK#9a"]);
        let mut client = Client::new(pipe);
        assert_eq!(client.command("?", deadline()).unwrap(), b"OK");
        let mut client = Client::new(Pipe::with(&[b"+"]));
        assert!(matches!(client.command("?", deadline()), Err(DebugError::Timeout(_))));
    }

    /// A stub that floods console output split mid-packet is cut off after a bounded number of frames, holding
    /// at most a partial frame and one read.
    #[test]
    fn console_floods_end_the_command_with_bounded_memory() {
        let output = packet::encode(format!("O{}", packet::encode_hex(&[b'x'; 1000])).as_bytes());
        let stream: Vec<u8> = output.iter().copied().cycle().take(output.len() * 1000).collect();
        let mut chunks: Vec<&[u8]> = vec![b"+"];
        chunks.extend(stream.chunks(output.len() / 2 + 3));
        let mut client = Client::new(Pipe::with(&chunks));
        let error = client.command("?", deadline()).unwrap_err();
        assert!(matches!(error, DebugError::Protocol(ref message) if message.contains("console")), "{error:?}");
        assert!(client.framer.buffered() < 3 * output.len());
        assert!(!client.in_sync());
        assert!(matches!(client.command("?", deadline()), Err(DebugError::Lost(_))));
        let notification = b"%Stop:T05#00";
        let flood: Vec<u8> = notification.iter().copied().cycle().take(notification.len() * 300).collect();
        let mut client = Client::new(Pipe::with(&[b"+", &flood]));
        assert!(matches!(client.command("?", deadline()), Err(DebugError::Protocol(_))));
        assert!(client.console.text.len() <= MAX_CONSOLE_BYTES);
    }

    #[test]
    fn console_output_is_bounded() {
        let mut console = Console::default();
        console.push(&vec![b'a'; MAX_CONSOLE_BYTES + 10]);
        assert_eq!(console.text.len(), MAX_CONSOLE_BYTES);
        assert_eq!(console.dropped_bytes, 10);
    }
}
