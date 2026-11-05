//! Thread identifiers and stop replies (`S`, `T`, `W`, `X`).

use serde::Serialize;

use crate::packet::{decode_hex, parse_hex_u64};

/// Most `n:r` pairs read from one stop reply.
const MAX_STOP_FIELDS: usize = 1024;
/// Stop-reply fields this client interprets, which must arrive whole.
const KNOWN_FIELDS: &[&str] = &[
    "thread",
    "core",
    "watch",
    "rwatch",
    "awatch",
    "swbreak",
    "hwbreak",
    "library",
    "replaylog",
    "metype",
    "mecount",
    "medata",
    "description",
    "reason",
    "watch_addr",
];
/// Most `medata` codes kept from one exception.
const MAX_EXCEPTION_CODES: usize = 16;

/// A thread as the protocol names it: a thread ID, with a process ID in multiprocess mode (`p<pid>.<tid>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId {
    pub pid: Option<u64>,
    pub tid: u64,
}

impl ThreadId {
    /// Parses a specific thread: hex IDs, not the `-1` (all) or `0` (any) wildcards.
    pub fn parse(text: &str) -> Option<Self> {
        let id = |text: &str| parse_hex_u64(text).filter(|id| *id != 0 && !text.starts_with("0x"));
        match text.strip_prefix('p') {
            Some(rest) => {
                let (pid, tid) = rest.split_once('.')?;
                Some(Self { pid: Some(id(pid)?), tid: id(tid)? })
            }
            None => Some(Self { pid: None, tid: id(text)? }),
        }
    }
}

impl std::fmt::Display for ThreadId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pid {
            Some(pid) => write!(formatter, "p{pid:x}.{:x}", self.tid),
            None => write!(formatter, "{:x}", self.tid),
        }
    }
}

impl Serialize for ThreadId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Why a thread stopped, beyond its signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StopReason {
    Watch {
        access: &'static str,
        #[serde(serialize_with = "hex_address")]
        address: u64,
    },
    SwBreak,
    HwBreak,
    Library,
    ReplayLog {
        position: String,
    },
    /// debugserver's Mach exception (`metype`, `mecount`, `medata`).
    Exception(MachException),
    /// debugserver's `description` field, decoded from hex.
    Description {
        text: String,
    },
    Other {
        name: String,
        value: String,
    },
}

/// A Mach exception as debugserver reports it in a stop reply (`metype`, `medata`, hex) or in `jThreadsInfo`
/// (decimal JSON). The codes are the exception's raw `code` and `subcode` words; their meaning depends on the
/// exception type and the architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachException {
    /// The `exception_type_t`: 1 `EXC_BAD_ACCESS`, 2 `EXC_BAD_INSTRUCTION`, 6 `EXC_BREAKPOINT`...
    #[serde(rename = "type")]
    pub exc_type: u32,
    /// The type's name, `EXC_UNKNOWN` for a type this client does not know.
    pub name: &'static str,
    #[serde(serialize_with = "hex_list")]
    pub codes: Vec<u64>,
    /// `EXC_BAD_ACCESS`: the faulting data address (the subcode).
    #[serde(serialize_with = "optional_hex", skip_serializing_if = "Option::is_none")]
    pub fault_address: Option<u64>,
    /// `EXC_BAD_ACCESS`: what the code word says (`KERN_INVALID_ADDRESS`, `KERN_PROTECTION_FAILURE`, or arm64's
    /// `EXC_ARM_DA_ALIGN`); `EXC_SOFTWARE`: `EXC_SOFT_SIGNAL` when it carries a Unix signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_name: Option<&'static str>,
    /// `EXC_SOFTWARE` with `EXC_SOFT_SIGNAL`: the Unix signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<u64>,
}

/// arm64's `EXC_ARM_DA_DEBUG`: an `EXC_BREAKPOINT` code older debugservers report watchpoint hits with, the
/// subcode being the address accessed.
pub const EXC_ARM_DA_DEBUG: u64 = 0x102;
/// `EXC_SOFT_SIGNAL`: an `EXC_SOFTWARE` code carrying a Unix signal in the subcode.
pub const EXC_SOFT_SIGNAL: u64 = 0x10003;

impl MachException {
    pub fn new(exc_type: u32, codes: &[u64]) -> Self {
        let name = match exc_type {
            1 => "EXC_BAD_ACCESS",
            2 => "EXC_BAD_INSTRUCTION",
            3 => "EXC_ARITHMETIC",
            4 => "EXC_EMULATION",
            5 => "EXC_SOFTWARE",
            6 => "EXC_BREAKPOINT",
            7 => "EXC_SYSCALL",
            8 => "EXC_MACH_SYSCALL",
            9 => "EXC_RPC_ALERT",
            10 => "EXC_CRASH",
            11 => "EXC_RESOURCE",
            12 => "EXC_GUARD",
            13 => "EXC_CORPSE_NOTIFY",
            _ => "EXC_UNKNOWN",
        };
        let codes: Vec<u64> = codes.iter().take(MAX_EXCEPTION_CODES).copied().collect();
        let (mut fault_address, mut code_name, mut signal) = (None, None, None);
        match (exc_type, codes.first()) {
            (1, Some(code)) => {
                fault_address = codes.get(1).copied();
                code_name = match code {
                    1 => Some("KERN_INVALID_ADDRESS"),
                    2 => Some("KERN_PROTECTION_FAILURE"),
                    0x101 => Some("EXC_ARM_DA_ALIGN"),
                    _ => None,
                };
            }
            (5, Some(&EXC_SOFT_SIGNAL)) => {
                code_name = Some("EXC_SOFT_SIGNAL");
                signal = codes.get(1).copied();
            }
            _ => {}
        }
        Self { exc_type, name, codes, fault_address, code_name, signal }
    }
}

fn hex_list<S: serde::Serializer>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(values.iter().map(|value| format!("{value:#x}")))
}

fn optional_hex<S: serde::Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.collect_str(&format_args!("{value:#x}")),
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpeditedRegister {
    pub regnum: u32,
    /// The value's bytes as the stub sent them, in hex; `x` digits mark unavailable bytes.
    pub bytes: String,
}

/// A parsed stop reply. Nothing here resumes the target; this client only asks `?` for the current stop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StopReply {
    /// `S` or `T`: stopped with a signal.
    Signal {
        signal: u8,
        thread: Option<ThreadId>,
        core: Option<u64>,
        reasons: Vec<StopReason>,
        registers: Vec<ExpeditedRegister>,
    },
    /// `W`: the process exited with a status.
    Exited { status: u64, pid: Option<u64> },
    /// `X`: the process was terminated by a signal.
    Terminated { signal: u64, pid: Option<u64> },
}

impl StopReply {
    pub fn parse(reply: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(reply).map_err(|_| "stop reply is not ASCII")?;
        let malformed = || format!("malformed stop reply `{}`", text.chars().take(64).collect::<String>());
        let (kind, rest) = text.split_at_checked(1).ok_or_else(malformed)?;
        match kind {
            "S" | "T" => {
                let signal = rest.get(..2).and_then(parse_hex_u64).ok_or_else(malformed)? as u8;
                let fields = &rest[2..];
                if kind == "S" && !fields.is_empty() {
                    return Err(malformed());
                }
                let mut thread = None;
                let mut core = None;
                let mut reasons = Vec::new();
                let mut registers = Vec::new();
                // debugserver's Mach exception and watchpoint fields, typed once every field is read.
                let mut exception: Option<u32> = None;
                let mut codes = Vec::new();
                let mut watchpoint_reason = false;
                let mut watch_address = None;
                for (index, field) in fields.split(';').filter(|field| !field.is_empty()).enumerate() {
                    if index >= MAX_STOP_FIELDS {
                        return Err("stop reply has too many fields".into());
                    }
                    let (name, value) = field.split_once(':').ok_or_else(malformed)?;
                    let register = !name.is_empty() && name.len() <= 8 && name.bytes().all(|b| b.is_ascii_hexdigit());
                    if value.len() > 4096 {
                        // A register or a field rampage reads must be whole; debugserver's informational fields
                        // (`jstopinfo`, `detailed-binaries-info`) may be long and are only listed by name.
                        if register || KNOWN_FIELDS.contains(&name) {
                            return Err("stop reply field exceeds 4096 bytes".into());
                        }
                        reasons.push(StopReason::Other {
                            name: name.chars().take(64).collect(),
                            value: format!("<{} bytes omitted>", value.len()),
                        });
                        continue;
                    }
                    let address = || parse_hex_u64(value).ok_or_else(malformed);
                    let other =
                        || StopReason::Other { name: name.to_owned(), value: value.chars().take(256).collect() };
                    match name {
                        "metype" => exception = Some(u32::try_from(address()?).map_err(|_| malformed())?),
                        "mecount" => {
                            address()?;
                        }
                        "medata" => {
                            let code = address()?;
                            if codes.len() < MAX_EXCEPTION_CODES {
                                codes.push(code);
                            }
                        }
                        "description" => {
                            let text = decode_hex(value.as_bytes())
                                .map(|bytes| String::from_utf8_lossy(&bytes).chars().take(256).collect())
                                .unwrap_or_else(|| value.chars().take(256).collect());
                            reasons.push(StopReason::Description { text });
                        }
                        "reason" => {
                            watchpoint_reason |= value == "watchpoint";
                            reasons.push(other());
                        }
                        "watch_addr" => {
                            watch_address = Some(address()?);
                            reasons.push(other());
                        }
                        "thread" => thread = Some(ThreadId::parse(value).ok_or_else(malformed)?),
                        "core" => core = Some(address()?),
                        "watch" => reasons.push(StopReason::Watch { access: "write", address: address()? }),
                        "rwatch" => reasons.push(StopReason::Watch { access: "read", address: address()? }),
                        "awatch" => reasons.push(StopReason::Watch { access: "access", address: address()? }),
                        "swbreak" => reasons.push(StopReason::SwBreak),
                        "hwbreak" => reasons.push(StopReason::HwBreak),
                        "library" => reasons.push(StopReason::Library),
                        "replaylog" => reasons.push(StopReason::ReplayLog { position: value.to_owned() }),
                        _ if register => {
                            let regnum = u32::from_str_radix(name, 16).map_err(|_| malformed())?;
                            let digits = value.replace(['x', 'X'], "0");
                            if decode_hex(digits.as_bytes()).is_none() {
                                return Err(malformed());
                            }
                            registers.push(ExpeditedRegister { regnum, bytes: value.to_ascii_lowercase() });
                        }
                        _ => reasons.push(StopReason::Other {
                            name: name.chars().take(64).collect(),
                            value: value.chars().take(256).collect(),
                        }),
                    }
                }
                let watched = reasons.iter().any(|reason| matches!(reason, StopReason::Watch { .. }));
                if let Some(exc_type) = exception {
                    // Older debugservers report a watchpoint hit as EXC_BREAKPOINT with code EXC_ARM_DA_DEBUG and
                    // the address accessed as the subcode.
                    if exc_type == 6
                        && watch_address.is_none()
                        && codes.first() == Some(&EXC_ARM_DA_DEBUG)
                        && let Some(&address) = codes.get(1)
                    {
                        watch_address = Some(address);
                        watchpoint_reason = true;
                    }
                    reasons.insert(0, StopReason::Exception(MachException::new(exc_type, &codes)));
                }
                // debugserver reports `reason:watchpoint` with `watch_addr`, the address accessed, and does not say
                // whether it was a read or a write, so the hit is an access.
                if !watched
                    && watchpoint_reason
                    && let Some(address) = watch_address
                {
                    reasons.insert(0, StopReason::Watch { access: "access", address });
                }
                Ok(StopReply::Signal { signal, thread, core, reasons, registers })
            }
            "W" | "X" => {
                let (code, process) = match rest.split_once(';') {
                    Some((code, process)) => {
                        let pid = process.strip_prefix("process:").and_then(parse_hex_u64).ok_or_else(malformed)?;
                        (code, Some(pid))
                    }
                    None => (rest, None),
                };
                let code = parse_hex_u64(code).ok_or_else(malformed)?;
                Ok(if kind == "W" {
                    StopReply::Exited { status: code, pid: process }
                } else {
                    StopReply::Terminated { signal: code, pid: process }
                })
            }
            _ => Err(malformed()),
        }
    }

    /// The reply with at most 32 expedited registers of at most 128 hex digits and at most 16 reasons, for results
    /// whose size is budgeted. A stub may send 1,024 fields of 4 KiB each.
    pub fn bounded(&self) -> Self {
        match self {
            StopReply::Signal { signal, thread, core, reasons, registers } => StopReply::Signal {
                signal: *signal,
                thread: *thread,
                core: *core,
                reasons: reasons.iter().take(16).cloned().collect(),
                registers: registers.iter().filter(|register| register.bytes.len() <= 128).take(32).cloned().collect(),
            },
            other => other.clone(),
        }
    }

    /// Whether the process no longer exists.
    pub fn ended(&self) -> bool {
        matches!(self, StopReply::Exited { .. } | StopReply::Terminated { .. })
    }
}

pub(crate) fn hex_address<S: serde::Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{value:#x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_thread_ids() {
        assert_eq!(ThreadId::parse("p1.2"), Some(ThreadId { pid: Some(1), tid: 2 }));
        assert_eq!(ThreadId::parse("p2a.2b").unwrap().to_string(), "p2a.2b");
        assert_eq!(ThreadId::parse("1f"), Some(ThreadId { pid: None, tid: 0x1f }));
        for text in ["", "0", "-1", "p-1.-1", "p1", "p1.", "zz", "0x1", "p.1", "11111111111111111"] {
            assert_eq!(ThreadId::parse(text), None, "{text}");
        }
    }

    #[test]
    fn parses_stop_replies() {
        let reply = StopReply::parse(b"T05thread:p2a.2b;core:1;swbreak:;20:0010000000000000;1f:xxxxxxxx;").unwrap();
        let StopReply::Signal { signal, thread, core, reasons, registers } = reply else { panic!() };
        assert_eq!(signal, 5);
        assert_eq!(thread, ThreadId::parse("p2a.2b"));
        assert_eq!(core, Some(1));
        assert_eq!(reasons, vec![StopReason::SwBreak]);
        assert_eq!(registers[0], ExpeditedRegister { regnum: 0x20, bytes: "0010000000000000".into() });
        assert_eq!(registers[1].bytes, "xxxxxxxx");
        let reply = StopReply::parse(b"T05watch:1000;library:;create:;").unwrap();
        let StopReply::Signal { reasons, .. } = reply else { panic!() };
        assert_eq!(reasons[0], StopReason::Watch { access: "write", address: 0x1000 });
        assert_eq!(reasons[1], StopReason::Library);
        assert!(matches!(&reasons[2], StopReason::Other { name, .. } if name == "create"));
        assert_eq!(
            StopReply::parse(b"S0b").unwrap(),
            StopReply::Signal { signal: 11, thread: None, core: None, reasons: vec![], registers: vec![] }
        );
        assert_eq!(StopReply::parse(b"W00;process:2a").unwrap(), StopReply::Exited { status: 0, pid: Some(0x2a) });
        assert_eq!(StopReply::parse(b"X09").unwrap(), StopReply::Terminated { signal: 9, pid: None });
        assert!(StopReply::parse(b"X09").unwrap().ended());
    }

    #[test]
    fn types_debugserver_exceptions_and_watchpoints() {
        // EXC_BAD_ACCESS (KERN_INVALID_ADDRESS at 0x10), as debugserver sends it: TARGET_EXC_BAD_ACCESS, hex codes.
        let reply = StopReply::parse(
            b"T91thread:1d2e3;name:prog;00:1000000000000000;metype:1;mecount:2;medata:1;medata:10;\
              memory:0x16fdff3a0=b0f3df6f01000000;",
        )
        .unwrap();
        let StopReply::Signal { signal, reasons, registers, .. } = reply else { panic!() };
        assert_eq!((signal, registers.len()), (0x91, 1));
        let StopReason::Exception(exception) = &reasons[0] else { panic!("{reasons:?}") };
        assert_eq!(
            (exception.name, exception.fault_address, exception.code_name),
            ("EXC_BAD_ACCESS", Some(0x10), Some("KERN_INVALID_ADDRESS"))
        );
        // A newer debugserver's watchpoint stop, and an older one's EXC_ARM_DA_DEBUG.
        let reply = StopReply::parse(
            b"T05thread:1d2e3;metype:6;mecount:2;medata:102;medata:100004000;reason:watchpoint;\
              description:34323934393833323936203020343239343938333239363b;watch_addr:100004000;",
        )
        .unwrap();
        let StopReply::Signal { reasons, .. } = reply else { panic!() };
        assert_eq!(reasons[0], StopReason::Watch { access: "access", address: 0x1_0000_4000 });
        assert!(
            reasons
                .iter()
                .any(|reason| matches!(reason, StopReason::Description { text } if text.starts_with("4294983296")))
        );
        let reply = StopReply::parse(b"T05thread:1d2e3;metype:6;mecount:2;medata:102;medata:100004004;").unwrap();
        let StopReply::Signal { reasons, .. } = reply else { panic!() };
        assert_eq!(reasons[0], StopReason::Watch { access: "access", address: 0x1_0000_4004 });
        // An interrupt: EXC_SOFTWARE carrying SIGSTOP.
        let reply = StopReply::parse(b"T11thread:1d2e3;metype:5;mecount:2;medata:10003;medata:11;").unwrap();
        let StopReply::Signal { reasons, .. } = reply else { panic!() };
        let StopReason::Exception(exception) = &reasons[0] else { panic!() };
        assert_eq!((exception.code_name, exception.signal), (Some("EXC_SOFT_SIGNAL"), Some(0x11)));
        // Long informational fields are listed, not refused; long fields rampage reads still are.
        let long = format!("T05thread:1;jstopinfo:{};", "5b".repeat(4000));
        let StopReply::Signal { reasons, .. } = StopReply::parse(long.as_bytes()).unwrap() else { panic!() };
        assert!(
            matches!(&reasons[0], StopReason::Other { name, value } if name == "jstopinfo" && value.contains("omitted"))
        );
        assert!(StopReply::parse(format!("T05medata:{};", "1".repeat(5000)).as_bytes()).is_err());
        assert!(StopReply::parse(b"T05metype:zz;").is_err());
        assert!(StopReply::parse(b"T05metype:100000000;").is_err());
    }

    #[test]
    fn refuses_malformed_stop_replies() {
        for reply in [
            &b""[..],
            b"T",
            b"T0",
            b"Tzz",
            b"S05x",
            b"T05thread",
            b"T05thread:zz;",
            b"T0520:abc;",
            b"T05watch:zz;",
            b"W",
            b"W00;process:",
            b"OK",
            b"E01",
            b"\xff",
        ] {
            assert!(StopReply::parse(reply).is_err(), "{reply:?}");
        }
    }

    #[test]
    fn random_stop_replies_never_panic() {
        let mut rng = crate::packet::tests::Rng::new(5);
        for _ in 0..5000 {
            let length = rng.below(60);
            let alphabet = b"TSWX05afp.;:-xthreadcorewatch\xff";
            let reply: Vec<u8> = (0..length).map(|_| alphabet[rng.below(alphabet.len())]).collect();
            let _ = StopReply::parse(&reply);
        }
    }
}
