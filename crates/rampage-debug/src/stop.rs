//! Thread identifiers and stop replies (`S`, `T`, `W`, `X`).

use serde::Serialize;

use crate::packet::{decode_hex, parse_hex_u64};

/// Most `n:r` pairs read from one stop reply.
const MAX_STOP_FIELDS: usize = 1024;

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
    Other {
        name: String,
        value: String,
    },
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
                for (index, field) in fields.split(';').filter(|field| !field.is_empty()).enumerate() {
                    if index >= MAX_STOP_FIELDS {
                        return Err("stop reply has too many fields".into());
                    }
                    let (name, value) = field.split_once(':').ok_or_else(malformed)?;
                    if value.len() > 4096 {
                        return Err("stop reply field exceeds 4096 bytes".into());
                    }
                    let address = || parse_hex_u64(value).ok_or_else(malformed);
                    match name {
                        "thread" => thread = Some(ThreadId::parse(value).ok_or_else(malformed)?),
                        "core" => core = Some(address()?),
                        "watch" => reasons.push(StopReason::Watch { access: "write", address: address()? }),
                        "rwatch" => reasons.push(StopReason::Watch { access: "read", address: address()? }),
                        "awatch" => reasons.push(StopReason::Watch { access: "access", address: address()? }),
                        "swbreak" => reasons.push(StopReason::SwBreak),
                        "hwbreak" => reasons.push(StopReason::HwBreak),
                        "library" => reasons.push(StopReason::Library),
                        "replaylog" => reasons.push(StopReason::ReplayLog { position: value.to_owned() }),
                        _ if !name.is_empty() && name.len() <= 8 && name.bytes().all(|b| b.is_ascii_hexdigit()) => {
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
