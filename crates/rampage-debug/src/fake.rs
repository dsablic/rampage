//! A scripted gdbserver for tests: it accepts one connection over TCP or a Unix socket, answers packets from a
//! script, and records every packet it receives. Any packet that could resume, step, set a breakpoint, write to
//! or kill the target is a violation that fails [`Report::assert_clean`], and the stub closes the connection.

use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::packet::{self, Frame, Framer, decode_hex, encode_hex, parse_hex_u64};

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
}

/// The stub's behavior: rules tried in order (the first match with uses left answers, rules limited with
/// [`Script::once`] or [`Script::nak`] before unlimited ones), plus target memory.
#[derive(Debug, Clone, Default)]
pub struct Script {
    rules: Vec<Rule>,
    memory: Vec<(u64, Vec<u8>)>,
    lenient: bool,
}

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
        });
        self
    }

    fn rule(mut self, matcher: Matcher, actions: Vec<Action>, naks: usize, remaining: Option<usize>) -> Self {
        self.rules.push(Rule { matcher, actions, naks, thread: None, remaining });
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
        });
        script
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
}

/// Whether `packet` could change the target's execution or state. The fake stub never answers one.
pub fn execution_control(packet: &str) -> bool {
    let first = packet.as_bytes().first().copied().unwrap_or(0);
    matches!(first, b'c' | b'C' | b's' | b'S' | b'Z' | b'z' | b'M' | b'X' | b'G' | b'P' | b'k' | b'R' | b'r' | b'!')
        || matches!(first, b'i' | b'I' | b'A' | b'b' | b'B' | b'W')
        || (packet.starts_with("vCont") && packet != "vCont?")
        || ["vKill", "vRun", "vAttach", "vFile", "vFlash", "vStopped", "Hc", "qRcmd", "QNonStop", "QAllow"]
            .iter()
            .any(|prefix| packet.starts_with(prefix))
        || packet.contains(":write:")
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
                Frame::Noise(byte) => {
                    report.violations.push(format!("client sent a stray byte {byte:#04x}"));
                    continue;
                }
            };
            let packet = String::from_utf8_lossy(&packet::unescape(&raw).unwrap_or(raw)).into_owned();
            report.received.push(packet.clone());
            if execution_control(&packet) {
                report.violations.push(format!("forbidden execution-control packet `{packet}`"));
                break 'connection;
            }
            let matches = |rule: &Rule| {
                rule.remaining != Some(0)
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
                .position(|rule| rule.remaining.is_some() && matches(rule))
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
                None => {
                    if !script.lenient {
                        report.violations.push(format!("unexpected packet `{packet}`"));
                    }
                    vec![Action::Reply(String::new())]
                }
            };
            if acks {
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
    /// accepts `D;1`.
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
}
