//! A scripted gdbserver for tests: it accepts one connection over TCP or a Unix socket, answers packets from a
//! script, and records every packet it receives. Any packet that could resume, step, set a breakpoint, write to
//! or kill the target is a violation that fails [`Report::assert_clean`], and the stub closes the connection.
//! A script marked [`Script::execution`] accepts the execution-control packets of step 9.2 (`vCont?`, `vCont;c`,
//! `vCont;s:<thread>`, `c`, `s`, `Hc<thread>`, `Z0`..`Z4`/`z0`..`z4`) and the interrupt byte, which it records as
//! [`INTERRUPT`]; writes, kill, launch, attach, signal-delivering resumes and non-stop mode stay violations.
//! A script marked [`Script::writes`] also accepts well-formed memory and register writes (`M`, `X`, `P`, `G`),
//! applying memory writes to its memory, and one marked [`Script::kill`] accepts `k` and `vKill;<pid>`; launch,
//! attach, signal-delivering resumes and non-stop mode are violations in every script.

use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::packet::{self, Frame, Framer, decode_hex, encode_hex, parse_hex_u64};

/// Windows stubs (gdbserver and lldb-server), built from their sources.
#[path = "fake_windows.rs"]
pub mod windows;

/// What the stub does in answer to a packet.
#[derive(Debug, Clone)]
pub enum Action {
    /// A normal reply packet (escaped as needed).
    Reply(String),
    /// Exact bytes, framing included, for malformed and oversized replies.
    Raw(Vec<u8>),
    /// A reply with a wrong checksum; a NAK from the client gets the correct one.
    Corrupt(String),
    /// Waits before the next action.
    Sleep(Duration),
    /// Drops the connection.
    Close,
}

#[derive(Debug, Clone)]
enum Matcher {
    Exact(String),
    Prefix(String),
}

#[derive(Debug, Clone)]
struct Rule {
    matcher: Matcher,
    actions: Vec<Action>,
    /// NAKs sent for this packet before it is accepted.
    naks: usize,
    /// Only while this thread is selected with `Hg`.
    thread: Option<String>,
    /// Matches left; `None` is unlimited.
    remaining: Option<usize>,
    /// Only once the client has sent this packet (the interrupt byte, a resume); such rules answer before the
    /// others.
    after: Option<String>,
}

/// The stub's behavior: rules tried in order (the first match with uses left answers, rules limited with
/// [`Script::once`] or [`Script::nak`] before unlimited ones), plus target memory.
#[derive(Debug, Clone, Default)]
pub struct Script {
    rules: Vec<Rule>,
    memory: Vec<(u64, Vec<u8>)>,
    lenient: bool,
    execution: bool,
    writes: bool,
    kill: bool,
    /// Ranges whose writes are answered `OK` and dropped, as flash or ROM may be.
    ignored: Vec<(u64, u64)>,
    /// Ranges whose writes are answered `E0e`.
    refused: Vec<(u64, u64)>,
    /// Like QEMU, `?` removes every breakpoint and watchpoint the stub holds.
    question_clears_points: bool,
}

/// How the fake stub records the out-of-band interrupt byte (`0x03`) and how scripts match it.
pub const INTERRUPT: &str = "\u{3}";

impl Script {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers `packet` with `reply`, every time.
    pub fn on(self, packet: &str, reply: &str) -> Self {
        self.rule(Matcher::Exact(packet.into()), vec![Action::Reply(reply.into())], 0, None)
    }

    /// Answers `packet` with `actions`, every time.
    pub fn on_actions(self, packet: &str, actions: Vec<Action>) -> Self {
        self.rule(Matcher::Exact(packet.into()), actions, 0, None)
    }

    /// Answers `packet` with `actions` once; later matches fall through to the following rules.
    pub fn once(self, packet: &str, actions: Vec<Action>) -> Self {
        self.rule(Matcher::Exact(packet.into()), actions, 0, Some(1))
    }

    /// Answers any packet starting with `prefix` with `reply`.
    pub fn on_prefix(self, prefix: &str, actions: Vec<Action>) -> Self {
        self.rule(Matcher::Prefix(prefix.into()), actions, 0, None)
    }

    /// NAKs `packet` `naks` times before accepting it and answering `reply`.
    pub fn nak(self, packet: &str, naks: usize, reply: &str) -> Self {
        self.rule(Matcher::Exact(packet.into()), vec![Action::Reply(reply.into())], naks, Some(1))
    }

    /// Answers `packet` with `reply` while `thread` is selected with `Hg`; add these before thread-independent
    /// rules for the same packet.
    pub fn on_thread(mut self, thread: &str, packet: &str, reply: &str) -> Self {
        self.rules.push(Rule {
            matcher: Matcher::Exact(packet.into()),
            actions: vec![Action::Reply(reply.into())],
            naks: 0,
            thread: Some(thread.into()),
            remaining: None,
            after: None,
        });
        self
    }

    /// Answers `packet` with `reply` once the client has sent the interrupt byte, before any other rule: a
    /// thread list that grows when an interrupt creates a thread, as on Windows.
    pub fn after_interrupt(self, packet: &str, reply: &str) -> Self {
        self.after(INTERRUPT, packet, reply)
    }

    /// Answers `packet` with `reply` once the client has sent `trigger`, before any other rule (the latest such
    /// rule first): registers that change when the target runs.
    pub fn after(mut self, trigger: &str, packet: &str, reply: &str) -> Self {
        self.rules.insert(
            0,
            Rule {
                matcher: Matcher::Exact(packet.into()),
                actions: vec![Action::Reply(reply.into())],
                naks: 0,
                thread: None,
                remaining: None,
                after: Some(trigger.into()),
            },
        );
        self
    }

    fn rule(mut self, matcher: Matcher, actions: Vec<Action>, naks: usize, remaining: Option<usize>) -> Self {
        self.rules.push(Rule { matcher, actions, naks, thread: None, remaining, after: None });
        self
    }

    /// Target memory answering `m` and `x` reads; reads beyond it fail with `E14`, or return the readable prefix.
    /// A later region overrides earlier ones where they overlap.
    pub fn memory(mut self, base: u64, bytes: &[u8]) -> Self {
        self.memory.push((base, bytes.to_vec()));
        self
    }

    /// Serves `qXfer:<object>:read:<annex>:` from `document`, honoring offset and length.
    pub fn xfer(self, object: &str, annex: &str, document: &str) -> Self {
        let prefix = format!("qXfer:{object}:read:{annex}:");
        let document = document.to_owned();
        let mut script = self;
        script.rules.push(Rule {
            matcher: Matcher::Prefix(prefix),
            actions: vec![Action::Reply(format!("\u{0}xfer\u{0}{document}"))],
            naks: 0,
            thread: None,
            remaining: None,
            after: None,
        });
        script
    }

    /// Accepts step 9.2's execution-control packets and the interrupt byte, instead of failing on them.
    pub fn execution(mut self) -> Self {
        self.execution = true;
        self
    }

    /// Accepts well-formed memory and register writes (`M`, `X`, `P`, `G`) instead of failing on them. Memory
    /// writes no rule answers change the script's memory and are answered `OK`; a write that is not all inside it
    /// gets `E14`.
    pub fn writes(mut self) -> Self {
        self.writes = true;
        self
    }

    /// Accepts `k` and `vKill;<pid>` instead of failing on them; rules give the replies.
    pub fn kill(mut self) -> Self {
        self.kill = true;
        self
    }

    /// Answers writes touching `length` bytes at `base` with `OK` and drops them, as a stub may for flash.
    pub fn ignore_writes(mut self, base: u64, length: u64) -> Self {
        self.ignored.push((base, length));
        self
    }

    /// Behaves like QEMU, whose `?` removes every inserted breakpoint and watchpoint: a `?` while the stub holds one
    /// (inserted with `Z` answered `OK` and not removed) is a violation, since the client would go on believing it
    /// is there.
    pub fn question_clears_points(mut self) -> Self {
        self.question_clears_points = true;
        self
    }

    /// Answers writes touching `length` bytes at `base` with `E0e`, writing nothing.
    pub fn refuse_writes(mut self, base: u64, length: u64) -> Self {
        self.refused.push((base, length));
        self
    }

    /// Answers the interrupt byte with `actions` (none: the target never stops), every time.
    pub fn on_interrupt(self, actions: Vec<Action>) -> Self {
        self.rule(Matcher::Exact(INTERRUPT.into()), actions, 0, None)
    }

    /// Answers unexpected packets with an empty (unsupported) reply instead of recording a violation.
    pub fn lenient(mut self) -> Self {
        self.lenient = true;
        self
    }

    fn read_memory(&self, address: u64, length: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < length {
            let at = address.checked_add(out.len() as u64)?;
            let Some((base, bytes)) =
                self.memory.iter().rev().find(|(base, bytes)| at >= *base && at - base < bytes.len() as u64)
            else {
                break;
            };
            let start = (at - base) as usize;
            let take = (bytes.len() - start).min(length - out.len());
            out.extend_from_slice(&bytes[start..start + take]);
        }
        (!out.is_empty()).then_some(out)
    }

    /// Applies a memory write and gives the reply: `E14` unless every byte is in the script's memory, `E0e` or a
    /// dropped `OK` in refused and ignored ranges.
    fn write_memory(&mut self, address: u64, data: &[u8]) -> &'static str {
        let end = address.saturating_add(data.len() as u64);
        let touches = |ranges: &[(u64, u64)]| {
            ranges.iter().any(|(base, length)| address < base.saturating_add(*length) && *base < end)
        };
        let mapped = (0..data.len() as u64).all(|offset| {
            let Some(at) = address.checked_add(offset) else { return false };
            self.memory.iter().any(|(base, bytes)| at >= *base && at - base < bytes.len() as u64)
        });
        if !mapped {
            return "E14";
        }
        if touches(&self.refused) {
            return "E0e";
        }
        if touches(&self.ignored) {
            return "OK";
        }
        for (offset, byte) in data.iter().enumerate() {
            let at = address.wrapping_add(offset as u64);
            if let Some((base, bytes)) =
                self.memory.iter_mut().rev().find(|(base, bytes)| at >= *base && at - *base < bytes.len() as u64)
            {
                bytes[(at - *base) as usize] = *byte;
            }
        }
        "OK"
    }
}

/// The address and data of a well-formed memory write (`M<address>,<length>:<hex>` or
/// `X<address>,<length>:<binary>`). Written independently of the client's allowlist, so the two check each other.
pub fn memory_write(packet: &[u8]) -> Option<(u64, Vec<u8>)> {
    let kind = *packet.first()?;
    if kind != b'M' && kind != b'X' {
        return None;
    }
    let colon = packet.iter().position(|byte| *byte == b':')?;
    let header = std::str::from_utf8(&packet[1..colon]).ok()?;
    let mut fields = header.split(',');
    let (address, length) = (fields.next()?, fields.next()?);
    let digits = |text: &str| !text.is_empty() && text.len() <= 16 && text.bytes().all(|b| b.is_ascii_hexdigit());
    if fields.next().is_some() || !digits(address) || !digits(length) {
        return None;
    }
    let (address, length) = (parse_hex_u64(address)?, parse_hex_u64(length)? as usize);
    let data = &packet[colon + 1..];
    let bytes = if kind == b'M' { decode_hex(data)? } else { data.to_vec() };
    (length > 0 && bytes.len() == length).then_some((address, bytes))
}

/// Whether `packet` is a well-formed register write: `P<regnum>=<hex>` or `G<hex>`.
pub fn register_write(packet: &str) -> bool {
    let even_hex =
        |text: &str| !text.is_empty() && text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit());
    match (packet.strip_prefix('P'), packet.strip_prefix('G')) {
        (Some(rest), _) => rest.split_once('=').is_some_and(|(regnum, value)| {
            !regnum.is_empty() && regnum.len() <= 8 && regnum.bytes().all(|b| b.is_ascii_hexdigit()) && even_hex(value)
        }),
        (_, Some(registers)) => even_hex(registers),
        _ => false,
    }
}

/// Whether `packet` is `k` or `vKill;<pid>`.
pub fn kill_packet(packet: &str) -> bool {
    packet == "k"
        || packet
            .strip_prefix("vKill;")
            .is_some_and(|pid| !pid.is_empty() && pid.len() <= 16 && pid.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Whether `packet` could change the target's execution or state (`vCont?` included). A read-only script never
/// answers one.
pub fn execution_control(packet: &str) -> bool {
    let first = packet.as_bytes().first().copied().unwrap_or(0);
    matches!(first, b'c' | b'C' | b's' | b'S' | b'Z' | b'z' | b'M' | b'X' | b'G' | b'P' | b'k' | b'R' | b'r' | b'!')
        || matches!(first, b'i' | b'I' | b'A' | b'b' | b'B' | b'W' | 0x03)
        || packet.starts_with("vCont")
        || ["vKill", "vRun", "vAttach", "vFile", "vFlash", "vStopped", "Hc", "qRcmd", "QNonStop", "QAllow"]
            .iter()
            .any(|prefix| packet.starts_with(prefix))
        || packet.contains(":write:")
}

/// Whether `packet` is one of step 9.2's execution-control packets, which a [`Script::execution`] script accepts.
/// Written independently of the client's allowlist, so the two check each other.
pub fn step_9_2_execution(packet: &str) -> bool {
    let thread = |text: &str| {
        let ids: Vec<&str> = match text.strip_prefix('p') {
            Some(rest) => rest.split('.').collect(),
            None => vec![text],
        };
        (1..=2).contains(&ids.len())
            && ids.iter().all(|id| !id.is_empty() && id.len() <= 16 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            && ids.iter().all(|id| id.bytes().any(|b| b != b'0'))
            && (ids.len() == 2) == text.starts_with('p')
    };
    let point = |rest: &str| {
        let fields: Vec<&str> = rest.split(',').collect();
        fields.len() == 3
            && matches!(fields[0], "0" | "1" | "2" | "3" | "4")
            && fields[1..].iter().all(|field| !field.is_empty() && field.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    match packet {
        INTERRUPT | "vCont?" | "vCont;c" | "c" | "s" | "Hc-1" => true,
        _ => {
            packet.strip_prefix("vCont;s:").is_some_and(thread)
                || packet.strip_prefix("Hc").is_some_and(thread)
                || packet.strip_prefix('Z').or_else(|| packet.strip_prefix('z')).is_some_and(point)
        }
    }
}

/// For LLDB's queries (`qHostInfo`, `qProcessInfo`, `qRegisterInfo<n>`, `qMemoryRegionInfo:<address>`,
/// `jThreadsInfo` and every `j` packet): whether `packet` has exactly the form rampage may send. `None` for other
/// packets. Written independently of the client's allowlist, so the two check each other.
pub fn lldb_query(packet: &str) -> Option<bool> {
    let hex_number =
        |text: &str, most: usize| (1..=most).contains(&text.len()) && text.chars().all(|c| c.is_ascii_hexdigit());
    if packet == "qHostInfo" || packet == "qProcessInfo" || packet == "jThreadsInfo" {
        return Some(true);
    }
    for family in ["qHostInfo", "qProcessInfo", "jThreadsInfo"] {
        if packet.starts_with(family) {
            return Some(false);
        }
    }
    if let Some(number) = packet.strip_prefix("qRegisterInfo") {
        return Some(hex_number(number, 8));
    }
    if let Some(rest) = packet.strip_prefix("qMemoryRegionInfo") {
        return Some(rest.strip_prefix(':').is_some_and(|address| hex_number(address, 16)));
    }
    if packet.starts_with('j') {
        let Some(argument) = packet.strip_prefix("jGetLoadedDynamicLibrariesInfos:") else { return Some(false) };
        if argument == r#"{"fetch_all_solibs":true,"report_load_commands":false}"# {
            return Some(true);
        }
        let list = argument.strip_prefix(r#"{"solib_addresses":["#).and_then(|rest| rest.strip_suffix("]}"));
        return Some(list.is_some_and(|list| {
            let items: Vec<&str> = list.split(',').collect();
            items.len() <= 512
                && items.iter().all(|item| !item.is_empty() && item.parse::<u64>().is_ok() && !item.starts_with('+'))
        }));
    }
    None
}

/// What the stub saw.
#[derive(Debug, Default)]
pub struct Report {
    pub received: Vec<String>,
    pub violations: Vec<String>,
}

impl Report {
    pub fn assert_clean(&self) {
        assert!(
            self.violations.is_empty(),
            "fake stub violations: {:?}\nreceived: {:?}",
            self.violations,
            self.received
        );
    }
}

/// A running fake stub. [`FakeStub::finish`] waits for the client to disconnect and returns the report.
pub struct FakeStub {
    endpoint: String,
    handle: JoinHandle<Report>,
}

impl FakeStub {
    /// Listens on a fresh loopback TCP port.
    pub fn tcp(script: Script) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let endpoint = listener.local_addr().expect("listener address").to_string();
        listener.set_nonblocking(true).expect("nonblocking listener");
        let handle = std::thread::spawn(move || {
            let accepted = accept(|| listener.accept().map(|(stream, _)| stream));
            match accepted {
                Some(stream) => {
                    stream.set_nonblocking(false).expect("blocking stream");
                    serve(stream, script)
                }
                None => Report { violations: vec!["no client connected".into()], ..Report::default() },
            }
        });
        Self { endpoint, handle }
    }

    /// Listens on a Unix socket at `path`, which must not exist.
    #[cfg(unix)]
    pub fn unix(path: &Path, script: Script) -> Self {
        let listener = std::os::unix::net::UnixListener::bind(path).expect("bind the Unix socket");
        listener.set_nonblocking(true).expect("nonblocking listener");
        let endpoint = format!("unix:{}", path.display());
        let handle = std::thread::spawn(move || {
            let accepted = accept(|| listener.accept().map(|(stream, _)| stream));
            match accepted {
                Some(stream) => {
                    stream.set_nonblocking(false).expect("blocking stream");
                    serve(stream, script)
                }
                None => Report { violations: vec!["no client connected".into()], ..Report::default() },
            }
        });
        Self { endpoint, handle }
    }

    /// The endpoint text a client connects to (`127.0.0.1:port` or `unix:/path`).
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn finish(self) -> Report {
        self.handle.join().expect("fake stub thread")
    }
}

fn accept<S>(mut attempt: impl FnMut() -> std::io::Result<S>) -> Option<S> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match attempt() {
            Ok(stream) => return Some(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => return None,
        }
    }
    None
}

trait Stream: Read + Write {
    fn set_timeout(&self, timeout: Duration);
}

impl Stream for std::net::TcpStream {
    fn set_timeout(&self, timeout: Duration) {
        let _ = self.set_read_timeout(Some(timeout));
    }
}

#[cfg(unix)]
impl Stream for std::os::unix::net::UnixStream {
    fn set_timeout(&self, timeout: Duration) {
        let _ = self.set_read_timeout(Some(timeout));
    }
}

fn serve(mut stream: impl Stream, mut script: Script) -> Report {
    let mut report = Report::default();
    let mut framer = Framer::new(packet::MAX_PACKET_BYTES);
    let mut acks = true;
    let mut last: Vec<u8> = Vec::new();
    let mut naks_sent: usize = 0;
    let mut selected: Option<String> = None;
    let mut sent = std::collections::BTreeSet::<String>::new();
    // Breakpoints and watchpoints inserted and not removed, as `<type>,<address>,<kind>`.
    let mut points = std::collections::BTreeSet::<String>::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    stream.set_timeout(Duration::from_millis(200));
    let mut buffer = [0; 64 * 1024];
    'connection: while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => framer.push(&buffer[..count]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(_) => break,
        }
        loop {
            let frame = match framer.next_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    report.violations.push(format!("client framing error: {error}"));
                    break 'connection;
                }
            };
            let raw = match frame {
                Frame::Packet(raw) => raw,
                Frame::Nak => {
                    let _ = stream.write_all(&last);
                    continue;
                }
                Frame::Corrupt => {
                    report.violations.push("client sent a packet with a bad checksum".into());
                    continue;
                }
                Frame::Ack | Frame::Notification => continue,
                Frame::Noise(0x03) => INTERRUPT.as_bytes().to_vec(),
                Frame::Noise(byte) => {
                    report.violations.push(format!("client sent a stray byte {byte:#04x}"));
                    continue;
                }
            };
            let bytes = packet::unescape(&raw).unwrap_or(raw);
            let packet = String::from_utf8_lossy(&bytes).into_owned();
            report.received.push(packet.clone());
            sent.insert(packet.clone());
            let write = memory_write(&bytes);
            let permitted = (script.execution && step_9_2_execution(&packet))
                || (script.writes && (write.is_some() || register_write(&packet)))
                || (script.kill && kill_packet(&packet));
            if execution_control(&packet) && !permitted {
                let kind = if script.execution || script.writes || script.kill {
                    "forbidden"
                } else {
                    "forbidden (read-only script)"
                };
                report.violations.push(format!("{kind} execution-control packet `{packet:?}`"));
                break 'connection;
            }
            if lldb_query(&packet) == Some(false) {
                report.violations.push(format!("malformed or unexpected LLDB query `{packet}`"));
                break 'connection;
            }
            if packet == "?" && script.question_clears_points {
                if !points.is_empty() {
                    report.violations.push(format!("`?` removed inserted points the client still holds: {points:?}"));
                }
                points.clear();
            }
            let matches = |rule: &Rule| {
                rule.remaining != Some(0)
                    && rule.after.as_ref().is_none_or(|trigger| sent.contains(trigger))
                    && rule.thread.as_ref().is_none_or(|thread| selected.as_ref() == Some(thread))
                    && match &rule.matcher {
                        Matcher::Exact(exact) => *exact == packet,
                        Matcher::Prefix(prefix) => packet.starts_with(prefix.as_str()),
                    }
            };
            // Rules with a limited number of uses answer before unlimited ones, so a script can override a
            // transcript's answer for the next few packets.
            let rule = script
                .rules
                .iter()
                .position(|rule| rule.after.is_some() && matches(rule))
                .or_else(|| script.rules.iter().position(|rule| rule.remaining.is_some() && matches(rule)))
                .or_else(|| script.rules.iter().position(matches));
            let actions = match rule {
                Some(index) => {
                    let rule = &mut script.rules[index];
                    if naks_sent < rule.naks {
                        naks_sent += 1;
                        let _ = stream.write_all(b"-");
                        report.received.pop();
                        continue;
                    }
                    naks_sent = 0;
                    if let Some(remaining) = &mut rule.remaining {
                        *remaining -= 1;
                    }
                    rule.actions.clone()
                }
                None if packet.starts_with('m') || packet.starts_with('x') => vec![memory_reply(&script, &packet)],
                None if write.is_some() => {
                    let (address, data) = write.expect("a memory write");
                    vec![Action::Reply(script.write_memory(address, &data).into())]
                }
                None => {
                    if !script.lenient {
                        report.violations.push(format!("unexpected packet `{packet}`"));
                    }
                    vec![Action::Reply(String::new())]
                }
            };
            // The interrupt byte is not a packet and is never acknowledged.
            if acks && packet != INTERRUPT {
                let _ = stream.write_all(b"+");
            }
            for action in actions {
                match action {
                    Action::Reply(reply) => {
                        let reply = xfer_reply(&packet, &reply);
                        last = packet::encode(reply.as_bytes());
                        let _ = stream.write_all(&last);
                        if packet == "QStartNoAckMode" && reply == "OK" {
                            acks = false;
                        }
                        if let Some(thread) = packet.strip_prefix("Hg")
                            && reply == "OK"
                        {
                            selected = Some(thread.to_owned());
                        }
                        if let Some(point) = packet.strip_prefix('Z')
                            && reply == "OK"
                        {
                            points.insert(point.to_owned());
                        }
                        if let Some(point) = packet.strip_prefix('z')
                            && reply == "OK"
                        {
                            points.remove(point);
                        }
                    }
                    Action::Raw(bytes) => {
                        let _ = stream.write_all(&bytes);
                    }
                    Action::Corrupt(reply) => {
                        last = packet::encode(reply.as_bytes());
                        let mut corrupt = last.clone();
                        let at = corrupt.len() - 1;
                        corrupt[at] = if corrupt[at] == b'0' { b'1' } else { b'0' };
                        let _ = stream.write_all(&corrupt);
                    }
                    Action::Sleep(duration) => std::thread::sleep(duration),
                    Action::Close => break 'connection,
                }
            }
        }
    }
    report
}

/// A `qXfer` window of a document registered with [`Script::xfer`]; other replies pass through.
fn xfer_reply(packet: &str, reply: &str) -> String {
    let Some(document) = reply.strip_prefix("\u{0}xfer\u{0}") else { return reply.to_owned() };
    let window = packet.rsplit(':').next().and_then(|range| range.split_once(','));
    let Some((offset, length)) =
        window.and_then(|(offset, length)| Some((parse_hex_u64(offset)?, parse_hex_u64(length)?)))
    else {
        return "E00".into();
    };
    let bytes = document.as_bytes();
    let start = (offset as usize).min(bytes.len());
    let end = start.saturating_add(length as usize).min(bytes.len());
    let kind = if end == bytes.len() { 'l' } else { 'm' };
    format!("{kind}{}", String::from_utf8_lossy(&bytes[start..end]))
}

fn memory_reply(script: &Script, packet: &str) -> Action {
    let binary = packet.starts_with('x');
    let Some((address, length)) = packet[1..].split_once(',') else { return Action::Reply("E01".into()) };
    let (Some(address), Some(length)) = (parse_hex_u64(address), parse_hex_u64(length)) else {
        return Action::Reply("E01".into());
    };
    match script.read_memory(address, length as usize) {
        Some(bytes) if binary => {
            let mut reply = vec![b'b'];
            reply.extend_from_slice(&bytes);
            Action::Raw(packet::encode(&reply))
        }
        Some(bytes) => Action::Reply(encode_hex(&bytes)),
        None => Action::Reply("E14".into()),
    }
}

/// Little-endian hex of `value` in `bytes` bytes, as a register in a `g` reply.
pub fn le_hex(value: u64, bytes: usize) -> String {
    encode_hex(&value.to_le_bytes()[..bytes.min(8)]) + &"00".repeat(bytes.saturating_sub(8))
}

/// Decodes a register's hex bytes as a little-endian integer (test convenience).
pub fn le_value(hex: &str) -> u64 {
    decode_hex(hex.as_bytes()).expect("hex").iter().rev().fold(0, |value, byte| value << 8 | u64::from(*byte))
}

/// Scripts modeled on real stub transcripts.
pub mod transcripts {
    use super::*;

    /// The firmware image the Cortex-M transcript serves: initial SP and reset vector, then code.
    pub const CORTEX_M_FLASH: [u8; 8] = [0x00, 0x00, 0x01, 0x20, 0x49, 0x00, 0x00, 0x00];
    /// The RAM pattern the firmware writes.
    pub const CORTEX_M_PATTERN: &[u8; 16] = b"RAMPAGE-DEBUG-91";

    /// QEMU 11 `lm3s6965evb` (Cortex-M3) halted at reset, as recorded with `qemu-system-arm -S -gdb`, plus an
    /// OpenOCD-style memory map (QEMU itself serves none). Multiprocess is on, so QEMU refuses a bare `D` and
    /// accepts `D;1`. Like QEMU, its `?` removes every breakpoint and watchpoint ([`Script::question_clears_points`]).
    pub fn qemu_cortex_m3() -> Script {
        let mut profile = String::from(
            "<?xml version=\"1.0\"?><!DOCTYPE feature SYSTEM \"gdb-target.dtd\"><feature name=\"org.gnu.gdb.arm.m-profile\">",
        );
        for index in 0..13 {
            profile.push_str(&format!("<reg name=\"r{index}\" bitsize=\"32\"/>"));
        }
        profile.push_str(
            "<reg name=\"sp\" bitsize=\"32\" type=\"data_ptr\"/><reg name=\"lr\" bitsize=\"32\"/>\
             <reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\"/><reg name=\"xpsr\" bitsize=\"32\" regnum=\"25\"/>\
             </feature>",
        );
        let system = "<?xml version=\"1.0\"?><!DOCTYPE feature SYSTEM \"gdb-target.dtd\">\
            <feature name=\"org.gnu.gdb.arm.m-system\"><reg name=\"msp\" bitsize=\"32\" regnum=\"26\" type=\"int\"/>\
            <reg name=\"psp\" bitsize=\"32\" regnum=\"27\" type=\"int\"/>\
            <reg name=\"primask\" bitsize=\"32\" regnum=\"28\" type=\"int\"/>\
            <reg name=\"control\" bitsize=\"32\" regnum=\"29\" type=\"int\"/>\
            <reg name=\"basepri\" bitsize=\"32\" regnum=\"30\" type=\"int\"/>\
            <reg name=\"faultmask\" bitsize=\"32\" regnum=\"31\" type=\"int\"/></feature>";
        let mut g = "00000000".repeat(13);
        g.push_str("00000120ffffffff4800000000000041");
        let mut script = Script::new()
            .question_clears_points()
            .on(
                "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
                "PacketSize=20020;qXfer:features:read+;vContSupported+;multiprocess+;qXfer:memory-map:read+",
            )
            .xfer(
                "features",
                "target.xml",
                "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target>\
                 <architecture>arm</architecture><xi:include href=\"arm-m-profile.xml\"/>\
                 <xi:include href=\"system-registers.xml\"/><xi:include href=\"arm-m-system.xml\"/></target>",
            )
            .xfer("features", "arm-m-profile.xml", &profile)
            .xfer("features", "system-registers.xml", "<?xml version=\"1.0\"?><feature name=\"org.qemu.gdb.arm.sys.regs\"></feature>")
            .xfer("features", "arm-m-system.xml", system)
            .xfer(
                "memory-map",
                "",
                "<?xml version=\"1.0\"?><!DOCTYPE memory-map PUBLIC \"+//IDN gnu.org//DTD GDB Memory Map V1.0//EN\" \
                 \"http://sourceware.org/gdb/gdb-memory-map.dtd\"><memory-map>\
                 <memory type=\"flash\" start=\"0x0\" length=\"0x40000\"><property name=\"blocksize\">0x400</property></memory>\
                 <memory type=\"ram\" start=\"0x20000000\" length=\"0x10000\"/></memory-map>",
            )
            .on("?", "T05core:01;")
            .on("qfThreadInfo", "mp01.01")
            .on("qsThreadInfo", "l")
            .on("qThreadExtraInfo,p1.1", &encode_hex(b"CPU#0 [halted ]"))
            .on("Hgp1.1", "OK")
            .on("g", &g)
            .on("p1a", "00000120")
            .on("qOffsets", "")
            .on("D", "E22")
            .on("D;1", "OK")
            .memory(0, &CORTEX_M_FLASH)
            .memory(0x2000_0000, &[0; 0x200])
            .memory(0xe000_ed0c, &[0x00, 0x00, 0x05, 0xfa]);
        for regnum in 0x1b..=0x1f {
            script = script.on(&format!("p{regnum:x}"), "00000000");
        }
        script
    }

    /// The register values of the AArch64 transcript's first thread: x0..x30, sp, pc, cpsr.
    pub fn aarch64_values() -> (Vec<u64>, u64, u64, u64) {
        let x: Vec<u64> = (0..31).map(|index| 0x1000 + index).collect();
        (x, 0x7fff_ffff_f6a0, 0x5555_5555_0794, 0x6000_0000)
    }

    /// gdbserver 15 on AArch64 Linux, stopped at `main` of a PIE program, with svr4 libraries, two threads and
    /// a libc ELF header (with a build ID note) mapped at its load bias.
    pub fn gdbserver_aarch64() -> Script {
        let mut core = String::from(
            "<?xml version=\"1.0\"?><!DOCTYPE feature SYSTEM \"gdb-target.dtd\"><feature name=\"org.gnu.gdb.aarch64.core\">\
             <flags id=\"cpsr_flags\" size=\"4\"><field name=\"SP\" start=\"0\" end=\"0\"/><field name=\"N\" start=\"31\" end=\"31\"/></flags>",
        );
        for index in 0..31 {
            core.push_str(&format!("<reg name=\"x{index}\" bitsize=\"64\"/>"));
        }
        core.push_str(
            "<reg name=\"sp\" bitsize=\"64\" type=\"data_ptr\"/><reg name=\"pc\" bitsize=\"64\" type=\"code_ptr\"/>\
             <reg name=\"cpsr\" bitsize=\"32\" type=\"cpsr_flags\"/></feature>",
        );
        let mut fpu = String::from(
            "<?xml version=\"1.0\"?><!DOCTYPE feature SYSTEM \"gdb-target.dtd\"><feature name=\"org.gnu.gdb.aarch64.fpu\">\
             <vector id=\"v2d\" type=\"ieee_double\" count=\"2\"/><union id=\"aarch64v\"><field name=\"d\" type=\"v2d\"/></union>",
        );
        for index in 0..32 {
            fpu.push_str(&format!(
                "<reg name=\"v{index}\" bitsize=\"128\" type=\"aarch64v\" regnum=\"{}\"/>",
                34 + index
            ));
        }
        fpu.push_str("<reg name=\"fpsr\" bitsize=\"32\"/><reg name=\"fpcr\" bitsize=\"32\"/></feature>");
        let (x, sp, pc, cpsr) = aarch64_values();
        let mut g: String = x.iter().map(|value| le_hex(*value, 8)).collect();
        g += &(le_hex(sp, 8) + &le_hex(pc, 8) + &le_hex(cpsr, 4));
        g += &"00".repeat(32 * 16 + 8);
        let mut second: String = (0..31).map(|index| le_hex(0x2000 + index, 8)).collect();
        second += &(le_hex(0x7fff_f7ff_e000, 8) + &le_hex(0x7fff_f7e8_1234, 8) + &le_hex(0x8000_0000, 4));
        second += &"00".repeat(32 * 16 + 8);
        // A 64-bit little-endian ELF header with one PT_NOTE program header pointing at a GNU build-ID note.
        let libc = 0x7fff_f7e0_0000u64;
        let mut image = vec![0u8; 0x200];
        image[..6].copy_from_slice(b"\x7fELF\x02\x01");
        image[32..40].copy_from_slice(&64u64.to_le_bytes());
        image[54..56].copy_from_slice(&56u16.to_le_bytes());
        image[56..58].copy_from_slice(&1u16.to_le_bytes());
        image[64..68].copy_from_slice(&4u32.to_le_bytes());
        image[64 + 16..64 + 24].copy_from_slice(&0x100u64.to_le_bytes());
        image[64 + 32..64 + 40].copy_from_slice(&24u64.to_le_bytes());
        image[0x100..0x10c].copy_from_slice(&[4, 0, 0, 0, 8, 0, 0, 0, 3, 0, 0, 0]);
        image[0x10c..0x118].copy_from_slice(b"GNU\0\xde\xad\xbe\xef\x01\x02\x03\x04");
        Script::new()
            .on(
                "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
                "PacketSize=3fff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;\
                 qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:siginfo:read+;\
                 qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;\
                 fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;\
                 ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;\
                 vContSupported+;QThreadEvents+;no-resumed+;memory-tagging+;binary-upload+",
            )
            .on("QStartNoAckMode", "OK")
            .xfer(
                "features",
                "target.xml",
                "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target>\
                 <architecture>aarch64</architecture><osabi>GNU/Linux</osabi>\
                 <xi:include href=\"aarch64-core.xml\"/><xi:include href=\"aarch64-fpu.xml\"/></target>",
            )
            .xfer("features", "aarch64-core.xml", &core)
            .xfer("features", "aarch64-fpu.xml", &fpu)
            .on(
                "?",
                &format!(
                    "T051d:{};1f:{};20:{};thread:p6a1b.6a1b;core:2;",
                    le_hex(x[29], 8),
                    le_hex(sp, 8),
                    le_hex(pc, 8)
                ),
            )
            .on("qfThreadInfo", "mp6a1b.6a1b,p6a1b.6a1c")
            .on("qsThreadInfo", "l")
            .on("qThreadExtraInfo,p6a1b.6a1b", "")
            .on("Hgp6a1b.6a1b", "OK")
            .on("Hgp6a1b.6a1c", "OK")
            .on_thread("p6a1b.6a1c", "g", &second)
            .on("g", &g)
            .xfer(
                "libraries-svr4",
                "",
                "<library-list-svr4 version=\"1.0\" main-lm=\"0x7ffff7ffe190\">\
                 <library name=\"\" lm=\"0x7ffff7ffe190\" l_addr=\"0x555555550000\" l_ld=\"0x55555556fdb8\" lmid=\"0x0\"/>\
                 <library name=\"/lib/ld-linux-aarch64.so.1\" lm=\"0x7ffff7ffda08\" l_addr=\"0x7ffff7fc3000\" \
                 l_ld=\"0x7ffff7ffce48\" lmid=\"0x0\"/>\
                 <library name=\"/lib/aarch64-linux-gnu/libc.so.6\" lm=\"0x7ffff7fc1530\" l_addr=\"0x7ffff7e00000\" \
                 l_ld=\"0x7ffff7f9ab58\" lmid=\"0x0\"/></library-list-svr4>",
            )
            .xfer("exec-file", "6a1b", "/home/user/prog")
            .on("qOffsets", "")
            .on("D;6a1b", "OK")
            .memory(libc, &image)
            .memory(sp, &[0x5a; 0x100])
    }

    /// The program counter of the AArch64 transcript's second thread.
    pub fn aarch64_second_thread_pc() -> u64 {
        0x7fff_f7e8_1234
    }

    /// A Mach-O image the debugserver transcript lists in its `jGetLoadedDynamicLibrariesInfos` reply.
    #[derive(Debug, Clone)]
    pub struct DebugserverImage {
        pub path: String,
        /// Upper case with dashes, as debugserver formats it.
        pub uuid: String,
        /// The runtime address of the Mach-O header.
        pub load_address: u64,
        /// `__TEXT`'s link-time address and size.
        pub text_vmaddr: u64,
        pub text_size: u64,
        /// 2 `MH_EXECUTE`, 6 `MH_DYLIB`, 7 `MH_DYLINKER`.
        pub filetype: u32,
        /// Sets `MH_DYLIB_IN_CACHE` in the header flags.
        pub in_shared_cache: bool,
    }

    /// The process the debugserver transcript serves.
    #[derive(Debug, Clone)]
    pub struct DebugserverTarget {
        pub images: Vec<DebugserverImage>,
        /// x0..x28, fp, lr, sp, pc, cpsr of the main thread.
        pub registers: [u64; 34],
        /// Serve `target.xml` (debugserver since about 2020); otherwise only `qRegisterInfo<n>`, as older ones.
        pub target_xml: bool,
        /// The stop reply's Mach exception: `metype` and `medata`, and the signal.
        pub signal: u8,
        pub exception: (u32, Vec<u64>),
    }

    /// debugserver's main thread and second thread.
    pub const DEBUGSERVER_THREAD: u64 = 0x2f3a1;
    pub const DEBUGSERVER_SECOND_THREAD: u64 = 0x2f3b0;
    /// The pid the transcript reports.
    pub const DEBUGSERVER_PID: u64 = 0x1a2b;
    /// Register numbers in debugserver's arm64 numbering: x0..x28 are 0..28.
    pub const DEBUGSERVER_LR: u32 = 30;
    pub const DEBUGSERVER_SP: u32 = 31;
    pub const DEBUGSERVER_PC: u32 = 32;
    pub const DEBUGSERVER_CPSR: u32 = 33;

    impl Default for DebugserverTarget {
        fn default() -> Self {
            let mut registers = [0u64; 34];
            for (index, register) in registers.iter_mut().enumerate().take(29) {
                *register = 0x100 + index as u64;
            }
            registers[29] = 0x16fd_ff3b0;
            registers[30] = 0x1_8c4a_6e8c; // lr: in dyld (start)
            registers[31] = 0x16fd_ff3a0;
            registers[32] = 0x1_0000_3f50;
            registers[33] = 0x6000_0000;
            Self {
                images: vec![
                    DebugserverImage {
                        path: "/Users/op/debug-macho/macho-loop".into(),
                        uuid: "4C4C44A5-5555-3144-A1C2-3B6E5D7E8F90".into(),
                        load_address: 0x1_0000_0000,
                        text_vmaddr: 0x1_0000_0000,
                        text_size: 0x4000,
                        filetype: 2,
                        in_shared_cache: false,
                    },
                    DebugserverImage {
                        path: "/usr/lib/dyld".into(),
                        uuid: "B5C3F2A1-1D2E-3F40-8A9B-0C1D2E3F4A5B".into(),
                        load_address: 0x1_8c4a_0000,
                        text_vmaddr: 0x1_8c4a_0000,
                        text_size: 0x6_4000,
                        filetype: 7,
                        in_shared_cache: false,
                    },
                    DebugserverImage {
                        path: "/usr/lib/system/libsystem_c.dylib".into(),
                        uuid: "A1B2C3D4-E5F6-3708-9A1B-2C3D4E5F6A7B".into(),
                        load_address: 0x1_8c56_8000,
                        text_vmaddr: 0x1_8051_8000,
                        text_size: 0x8_4000,
                        filetype: 6,
                        in_shared_cache: true,
                    },
                ],
                registers,
                target_xml: true,
                signal: 0x11,
                exception: (5, vec![0x10003, 0x11]),
            }
        }
    }

    /// A debugserver register: name, alternative name, generic role, bitsize and offset, and for views (`w0`) the
    /// register they view.
    type DebugserverRegister = (String, Option<String>, Option<&'static str>, u32, usize, Option<u32>);

    /// debugserver's arm64 registers. Its stated offsets follow each other with no gaps ("no gaps between
    /// registers", `RNBRemote.cpp`), whatever its register context's own layout; a view takes the running offset
    /// and adds no bytes.
    fn debugserver_registers() -> Vec<DebugserverRegister> {
        let mut registers: Vec<DebugserverRegister> = Vec::new();
        let mut offset = 0usize;
        let mut push =
            |name: String, alt: Option<&str>, generic: Option<&'static str>, bits: u32, view: Option<u32>| {
                registers.push((name, alt.map(str::to_owned), generic, bits, offset, view));
                if view.is_none() {
                    offset += bits as usize / 8;
                }
            };
        for index in 0..29u32 {
            let generic = match index {
                0..=7 => Some(["arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7", "arg8"][index as usize]),
                _ => None,
            };
            push(format!("x{index}"), None, generic, 64, None);
        }
        push("fp".into(), Some("x29"), Some("fp"), 64, None);
        push("lr".into(), Some("x30"), Some("ra"), 64, None);
        push("sp".into(), Some("xsp"), Some("sp"), 64, None);
        push("pc".into(), None, Some("pc"), 64, None);
        push("cpsr".into(), Some("flags"), Some("flags"), 32, None);
        for index in 0..29u32 {
            push(format!("w{index}"), None, None, 32, Some(index));
        }
        for index in 0..32 {
            push(format!("v{index}"), None, None, 128, None);
        }
        push("fpsr".into(), None, None, 32, None);
        push("fpcr".into(), None, None, 32, None);
        push("far".into(), None, None, 64, None);
        push("esr".into(), None, None, 32, None);
        push("exception".into(), None, None, 32, None);
        registers
    }

    /// A debugserver stop reply for the main thread: the signal, its name, the general registers expedited by
    /// debugserver register number, the Mach exception and a stack memory chunk, in debugserver's field order.
    pub fn debugserver_stop(target: &DebugserverTarget, thread: u64, extra: &str) -> String {
        let mut reply = format!("T{:02x}thread:{thread:x};name:macho-loop;", target.signal);
        for (regnum, value) in target.registers.iter().enumerate() {
            let width = if regnum == 33 { 4 } else { 8 };
            reply += &format!("{regnum:02x}:{};", le_hex(*value, width));
        }
        // A watchpoint stop (exception type 0 here) carries `reason:watchpoint` in `extra` and no exception.
        let (kind, codes) = &target.exception;
        if *kind != 0 {
            reply += &format!("metype:{kind:x};mecount:{:x};", codes.len());
            for code in codes {
                reply += &format!("medata:{code:x};");
            }
        }
        reply += extra;
        reply += &format!("memory:0x{:x}=b0f3df6f01000000{};", target.registers[29], le_hex(target.registers[30], 8));
        reply
    }

    /// The reply to the address-only `jGetLoadedDynamicLibrariesInfos` request for `images`.
    pub fn debugserver_image_addresses(images: &[DebugserverImage]) -> String {
        let entries: Vec<String> =
            images.iter().map(|image| format!(r#"{{"load_address":{}}}"#, image.load_address)).collect();
        format!(r#"{{"images":[{}]}}"#, entries.join(","))
    }

    /// The `jGetLoadedDynamicLibrariesInfos` reply with full information for `images`.
    pub fn debugserver_images(images: &[DebugserverImage]) -> String {
        let entries: Vec<String> = images
            .iter()
            .map(|image| {
                let flags: u64 = 0x0020_0085 | if image.in_shared_cache { 0x8000_0000 } else { 0 };
                let mut segments = Vec::new();
                if image.filetype == 2 {
                    segments.push(format!(
                        r#"{{"name":"__PAGEZERO","vmaddr":0,"vmsize":{},"fileoff":0,"filesize":0,"maxprot":0}}"#,
                        image.text_vmaddr
                    ));
                }
                segments.push(format!(
                    r#"{{"name":"__TEXT","vmaddr":{},"vmsize":{},"fileoff":0,"filesize":{},"maxprot":5}}"#,
                    image.text_vmaddr, image.text_size, image.text_size
                ));
                segments.push(format!(
                    r#"{{"name":"__LINKEDIT","vmaddr":{},"vmsize":16384,"fileoff":{},"filesize":800,"maxprot":1}}"#,
                    image.text_vmaddr + image.text_size,
                    image.text_size
                ));
                format!(
                    r#"{{"load_address":{},"mod_date":0,"pathname":"{}","uuid":"{}","min_version_os_name":"macosx","min_version_os_sdk":"15.0","mach_header":{{"magic":4277009103,"cputype":16777228,"cpusubtype":0,"filetype":{},"flags":{flags},"sizeof_mh_and_loadcmds":1496}},"segments":[{}]}}"#,
                    image.load_address,
                    image.path,
                    image.uuid,
                    image.filetype,
                    segments.join(",")
                )
            })
            .collect();
        format!(r#"{{"images":[{}]}}"#, entries.join(","))
    }

    /// Apple's `debugserver` on an arm64 Mac, attached to a stopped process, modeled on debugserver's source
    /// (`lldb/tools/debugserver/source/RNBRemote.cpp`) and LLDB's `lldbgdbremote.md` rather than recorded: the
    /// machine the tests were written on could not run debugserver (developer mode was off). Its features advertise
    /// `qEcho+` and `native-signals+` but not `QStartNoAckMode`, multiprocess or any `qXfer` object but
    /// `features`; its target description names no architecture, states gapless register offsets and declares
    /// views (`w0`); like debugserver since LLVM 21 it answers `g` as unsupported, so registers are read with `p`;
    /// its stop replies carry Mach exceptions; it answers `qHostInfo`, `qProcessInfo`, `qRegisterInfo<n>`,
    /// `jThreadsInfo`, `jGetLoadedDynamicLibrariesInfos` (addresses first, then one batch) and `qMemoryRegionInfo`
    /// (with a busy stack whose dirty-page list runs past 4 KiB), and leaves `qOffsets` unsupported. Thread `2f3b0`
    /// is a second, unnamed thread.
    pub fn debugserver_arm64(target: &DebugserverTarget) -> Script {
        let registers = debugserver_registers();
        let mut features = String::from("PacketSize=20000;qEcho+;native-signals+;");
        if target.target_xml {
            features = String::from("qXfer:features:read+;") + &features;
        }
        features += "SupportedWatchpointTypes=aarch64-mask,aarch64-bas;MultiMemRead+;jMultiBreakpoint+;";
        let mut script = Script::new()
            .on("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm", &features)
            .on(
                "qHostInfo",
                "cputype:16777228;cpusubtype:2;addressing_bits:47;ostype:macosx;\
                 watchpoint_exceptions_received:before;vendor:apple;os_version:15.1.0;endian:little;ptrsize:8;\
                 vm-page-size:16384;",
            )
            .on(
                "qProcessInfo",
                &format!(
                    "pid:{DEBUGSERVER_PID:x};parent-pid:1a20;real-uid:1f5;real-gid:14;effective-uid:1f5;\
                     effective-gid:14;cputype:100000c;cpusubtype:0;ptrsize:8;ostype:macosx;vendor:apple;\
                     endian:little;"
                ),
            );
        if target.target_xml {
            let mut xml = String::from(
                "<?xml version=\"1.0\"?>\n<target version=\"1.0\">\n<feature name=\"com.apple.debugserver.arm64\">\n",
            );
            for (regnum, (name, alt, generic, bits, offset, view)) in registers.iter().enumerate() {
                xml += &format!("<reg name=\"{name}\" regnum=\"{regnum}\" offset=\"{offset}\" bitsize=\"{bits}\"");
                if let Some(alt) = alt {
                    xml += &format!(" altname=\"{alt}\"");
                }
                let group = if *bits == 128 { "float" } else { "general" };
                xml += &format!(" group=\"{group}\" type=\"{}\"", if *bits == 128 { "vec128" } else { "int" });
                if let Some(generic) = generic {
                    xml += &format!(" generic=\"{generic}\"");
                }
                if let Some(view) = view {
                    xml += &format!(" value_regnums=\"{view}\"");
                }
                xml += "/>\n";
            }
            xml += "</feature>\n</target>\n";
            script = script.xfer("features", "target.xml", &xml);
        } else {
            for (regnum, (name, alt, generic, bits, offset, view)) in registers.iter().enumerate() {
                let set = if *bits == 128 { "Floating Point Registers" } else { "General Purpose Registers" };
                let mut reply = format!("name:{name};");
                if let Some(alt) = alt {
                    reply += &format!("alt-name:{alt};");
                }
                reply += &format!("bitsize:{bits};offset:{offset};encoding:uint;format:hex;set:{set};");
                if let Some(generic) = generic {
                    reply += &format!("generic:{generic};");
                }
                if let Some(view) = view {
                    reply += &format!("container-regs:{view:x};invalidate-regs:{view:x};");
                }
                script = script.on(&format!("qRegisterInfo{regnum:x}"), &reply);
            }
            script = script.on(&format!("qRegisterInfo{:x}", registers.len()), "E45");
        }
        let thread = DEBUGSERVER_THREAD;
        let second = DEBUGSERVER_SECOND_THREAD;
        let mut second_registers = target.registers;
        second_registers[31] = 0x16fe_8b000;
        second_registers[32] = 0x1_8c5a_1234;
        let threads_info = format!(
            r#"[{{"tid":{thread},"metype":{},"medata":[{}],"reason":"exception","qaddr":8445239080,"name":"macho-loop","qname":"com.apple.main-thread","qkind":"serial","qserialnum":1,"registers":{{"32":"{}"}},"memory":[{{"address":{},"bytes":"b0f3df6f01000000"}}]}},{{"tid":{second},"reason":"none","registers":{{"32":"{}"}}}}]"#,
            target.exception.0,
            target.exception.1.iter().map(u64::to_string).collect::<Vec<_>>().join(","),
            le_hex(target.registers[32], 8),
            target.registers[29],
            le_hex(second_registers[32], 8)
        );
        // Memory regions from 0: the page-zero gap, then each image's __TEXT (r-x) and __LINKEDIT (r--), the
        // stack, and the gaps between them.
        let mut mapped: Vec<(u64, u64, &str)> = Vec::new();
        for image in &target.images {
            mapped.push((image.load_address, image.text_size, "rx"));
            mapped.push((image.load_address + image.text_size, 0x4000, "r"));
        }
        mapped.push((STACK_REGION, 0x80_0000, "rw"));
        mapped.sort();
        let mut at = 0u64;
        for (start, size, permissions) in mapped {
            if start > at {
                script =
                    script.on(&format!("qMemoryRegionInfo:{at:x}"), &format!("start:{at:x};size:{:x};", start - at));
            }
            // debugserver lists every dirty page of a region; a busy stack has hundreds.
            let dirty: Vec<String> = if start == STACK_REGION {
                (0..600u64).map(|page| format!("{:x}", start + (page * 0x4000) % size)).collect()
            } else {
                Vec::new()
            };
            script = script.on(
                &format!("qMemoryRegionInfo:{start:x}"),
                &format!(
                    "start:{start:x};size:{size:x};permissions:{permissions};dirty-pages:{};type:;",
                    dirty.join(",")
                ),
            );
            at = start + size;
        }
        script = script.on(&format!("qMemoryRegionInfo:{at:x}"), &format!("start:{at:x};"));
        // Registers with `p`: the second thread's while it is selected, else the main thread's.
        let value = |values: &[u64; 34], regnum: usize, bits: u32| match regnum {
            0..=32 => le_hex(values[regnum], 8),
            33 => le_hex(values[33], 4),
            _ => "00".repeat(bits as usize / 8),
        };
        for (regnum, (_, _, _, bits, _, view)) in registers.iter().enumerate() {
            if view.is_none() {
                let second_value = value(&second_registers, regnum, *bits);
                script = script.on_thread(&format!("{second:x}"), &format!("p{regnum:x}"), &second_value);
            }
        }
        for (regnum, (_, _, _, bits, _, view)) in registers.iter().enumerate() {
            if view.is_none() {
                script = script.on(&format!("p{regnum:x}"), &value(&target.registers, regnum, *bits));
            }
        }
        let addresses: Vec<u64> = target.images.iter().map(|image| image.load_address).collect();
        script
            .on("?", &debugserver_stop(target, thread, ""))
            .on("qfThreadInfo", &format!("m{thread:x},{second:x}"))
            .on("qsThreadInfo", "l")
            .on(&format!("qThreadExtraInfo,{thread:x}"), "")
            .on("jThreadsInfo", &threads_info)
            .on(&format!("Hg{thread:x}"), "OK")
            .on(&format!("Hg{second:x}"), "OK")
            .on("g", "")
            .on(crate::lldb::FETCH_ALL_SOLIBS, &debugserver_image_addresses(&target.images))
            .on(&crate::lldb::solib_request(&addresses), &debugserver_images(&target.images))
            .on("qOffsets", "")
            .on("D", "OK")
            .memory(target.registers[31], &[0x5a; 0x100])
    }

    /// The stack region of the debugserver transcript.
    const STACK_REGION: u64 = 0x16f6_00000;
}
