//! Execution control: `vCont?` support, breakpoint and watchpoint kinds, the breakpoint table, typed stop events and
//! the matching of stops to table entries. Everything here is pure; the session thread does the I/O.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use crate::client::Console;
use crate::stop::{Exception, StopReason, StopReply, ThreadId, hex_address};
use crate::target::Family;

/// Most breakpoints and watchpoints one session holds.
pub const MAX_BREAKPOINTS: usize = 64;
/// Most bytes one watchpoint covers.
pub const MAX_WATCH_LENGTH: u64 = 4096;
/// Most instructions one step request executes.
pub const MAX_STEPS: u32 = 1000;

/// A flag a caller sets to stop waiting. Cancelling a wait never touches the target: it keeps running or stays
/// stopped, and the session records the stop whenever it arrives.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The resume actions a stub's `vCont?` reply advertises. Only `c` and `s` are ever used.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct VCont {
    pub continue_: bool,
    pub step: bool,
}

impl VCont {
    /// Parses a `vCont?` reply (`vCont;c;C;s;S;t;r`). An empty reply means `vCont` is unsupported; anything that is
    /// not a `vCont` list is treated the same way, so the plain `c` and `s` packets are used.
    pub fn parse(reply: &[u8]) -> Self {
        let Some(actions) = reply.strip_prefix(b"vCont") else { return Self::default() };
        let mut support = Self::default();
        if !actions.is_empty() && !actions.starts_with(b";") {
            return support;
        }
        for action in actions.split(|byte| *byte == b';').skip(1).take(64) {
            match action {
                b"c" => support.continue_ = true,
                b"s" => support.step = true,
                _ => {}
            }
        }
        support
    }
}

/// What a `Z`/`z` packet inserts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakKind {
    /// `Z0`: a software breakpoint the stub plants (rampage never writes the instruction itself).
    Software,
    /// `Z1`: a hardware breakpoint.
    Hardware,
    /// `Z2`: a write watchpoint.
    Write,
    /// `Z3`: a read watchpoint.
    Read,
    /// `Z4`: an access (read or write) watchpoint.
    Access,
}

impl BreakKind {
    /// The `Z`/`z` type digit.
    pub fn number(self) -> u8 {
        match self {
            BreakKind::Software => 0,
            BreakKind::Hardware => 1,
            BreakKind::Write => 2,
            BreakKind::Read => 3,
            BreakKind::Access => 4,
        }
    }

    pub fn is_watchpoint(self) -> bool {
        matches!(self, BreakKind::Write | BreakKind::Read | BreakKind::Access)
    }

    /// Whether a stop reported as a `watch` (write), `rwatch` (read) or `awatch` (access) hit can come from this
    /// watchpoint. Stubs report access watchpoints as `awatch`, and some report any hit of one as `awatch`.
    fn matches_access(self, access: &str) -> bool {
        match self {
            BreakKind::Write => access == "write" || access == "access",
            BreakKind::Read => access == "read" || access == "access",
            BreakKind::Access => true,
            _ => false,
        }
    }
}

/// One entry of a session's breakpoint table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Breakpoint {
    pub id: u32,
    pub kind: BreakKind,
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    /// For breakpoints, the `kind` field sent to the stub (the instruction size in bytes); for watchpoints, the
    /// length watched.
    pub size: u64,
    pub hits: u64,
    /// Whether the stub holds it. A process that exited takes its breakpoints with it.
    pub inserted: bool,
    /// A temporary breakpoint of a step over or out: removed at the next stop, whatever stops the target.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub temporary: bool,
    /// Where the caller placed it from, when it gave a static location rather than a runtime address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement: Option<Placement>,
}

/// The static location a breakpoint was placed from: a bound project's address, its module and the function there.
/// It is recorded with the entry as given; this crate does not interpret it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Placement {
    #[serde(serialize_with = "hex_address")]
    pub static_address: u64,
    /// The bound project's path.
    pub path: String,
    pub module: String,
    pub function: Option<String>,
    pub offset_in_function: Option<u64>,
}

/// What became of a temporary breakpoint at the stop that removed it (or tried to).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporaryOutcome {
    pub id: u32,
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    /// Whether this stop is the temporary breakpoint's hit.
    pub hit: bool,
    /// Whether it is gone from the stub and the table.
    pub removed: bool,
    pub error: Option<String>,
}

impl Breakpoint {
    pub fn insert_packet(&self) -> String {
        format!("Z{},{:x},{:x}", self.kind.number(), self.address, self.size)
    }

    pub fn remove_packet(&self) -> String {
        format!("z{},{:x},{:x}", self.kind.number(), self.address, self.size)
    }
}

/// The breakpoint size (the `kind` field of `Z0`/`Z1`) for `family`, as the rule in `docs/debug-control.md` states:
/// x86 1, AArch64 4, RISC-V 4 (or 2 for a compressed instruction, when asked), Cortex-M 2 (Thumb), A-profile ARM 2
/// in Thumb state and 4 in ARM state (`thumb` from CPSR.T). An explicit `size` must be one the architecture has;
/// targets of other architectures need one.
pub fn breakpoint_size(family: Family, m_profile: bool, thumb: Option<bool>, size: Option<u64>) -> Result<u64, String> {
    let allowed: &[u64] = match family {
        Family::X86 | Family::X86_64 => &[1],
        Family::Aarch64 => &[4],
        Family::Riscv32 | Family::Riscv64 => &[2, 4],
        // GDB's ARM kinds: 2 for 16-bit Thumb, 3 for 32-bit Thumb-2, 4 for ARM.
        Family::Arm if m_profile => &[2, 3],
        Family::Arm => &[2, 3, 4],
        Family::Other => &[1, 2, 3, 4, 8],
    };
    let default = match family {
        Family::X86 | Family::X86_64 => Some(1),
        Family::Aarch64 | Family::Riscv32 | Family::Riscv64 => Some(4),
        Family::Arm if m_profile => Some(2),
        Family::Arm => thumb.map(|thumb| if thumb { 2 } else { 4 }),
        Family::Other => None,
    };
    match size {
        Some(size) if allowed.contains(&size) => Ok(size),
        Some(size) => Err(format!(
            "size {size} is not a breakpoint size of this architecture (allowed: {})",
            allowed.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
        )),
        None => default.ok_or_else(|| match family {
            Family::Arm => "the ARM instruction set state (CPSR.T) is unknown; pass size 2 (Thumb) or 4 (ARM)".into(),
            _ => "this architecture has no known breakpoint size; pass size".into(),
        }),
    }
}

/// How many bytes a software breakpoint of `Z` kind `size` may replace in memory: ARM's kind 3 (32-bit Thumb-2) is 4
/// bytes, and for an architecture rampage does not know at least 4, so a write is never let under one.
pub fn replaced_bytes(family: Family, size: u64) -> u64 {
    match family {
        Family::Arm if size == 3 => 4,
        Family::Other => size.max(4),
        _ => size.max(1),
    }
}

/// Why the target stopped, as rampage classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopCause {
    /// A breakpoint in the table: the stub reported `swbreak`/`hwbreak`, or the pc of a SIGTRAP stop after a
    /// continue is a breakpoint's address.
    Breakpoint,
    /// A watchpoint hit (`watch`, `rwatch` or `awatch`).
    Watchpoint,
    /// A single step completed.
    Step,
    /// The temporary breakpoint of a step over or out, and no breakpoint of the table.
    #[serde(rename = "temporary_breakpoint")]
    Temporary,
    /// The stop that answered rampage's interrupt.
    Interrupted,
    /// Any other signal: a fault, a SIGTRAP no table entry explains, a signal from elsewhere.
    Signal,
    Exited,
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WatchHit {
    pub access: &'static str,
    /// The address the stub reports: GDB stubs the address accessed; debugserver the start of the watchpoint
    /// nearest to it (`watch_addr`).
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    /// debugserver: the address the access touched (`me_watch_addr`), which may lie next to the watched range,
    /// since debugserver widens watchpoints to what the hardware can watch.
    #[serde(serialize_with = "optional_hex_address", skip_serializing_if = "Option::is_none")]
    pub accessed: Option<u64>,
}

/// A stop rampage observed after resuming, stepping or interrupting.
#[derive(Debug, Clone, Serialize)]
pub struct StopEvent {
    /// The epoch this stop started.
    pub epoch: u64,
    pub reason: StopCause,
    pub signal: Option<u8>,
    pub exit_status: Option<u64>,
    pub thread: Option<ThreadId>,
    /// The stopped thread's pc, decoded in the session's byte order; `None` when it could not be read or the byte
    /// order is unknown.
    #[serde(serialize_with = "optional_hex_address")]
    pub pc: Option<u64>,
    /// The pc's bytes as the stub sent them.
    pub pc_bytes: Option<String>,
    /// IDs of the table entries this stop matched; their hit counts were incremented.
    pub breakpoints: Vec<u32>,
    pub watch: Option<WatchHit>,
    /// debugserver's Mach exception (`EXC_BREAKPOINT`, `EXC_BAD_ACCESS` with the faulting address,
    /// `EXC_BAD_INSTRUCTION`...), or a Windows stub's exception (`EXCEPTION_ACCESS_VIOLATION` with the access and
    /// address, `EXCEPTION_BREAKPOINT`...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<Exception>,
    /// The stop reply's reasons (at most 16), such as `swbreak`, `library` or a stub's own; its expedited
    /// registers are not repeated here.
    pub reasons: Vec<StopReason>,
    /// The stop reply as parsed, expedited registers included; kept out of results, whose size it could exceed.
    #[serde(skip)]
    pub stop: StopReply,
    /// Console output (`O` packets) received while the target ran.
    pub console: Console,
    /// Things that went wrong without failing the stop, such as a breakpoint not re-inserted after a step past it.
    pub warnings: Vec<String>,
    /// Temporary breakpoints this stop removed (or failed to), and whether it was their hit.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub temporary: Vec<TemporaryOutcome>,
}

/// The exception a stop reply carries: debugserver's Mach exception, or a Windows stub's.
pub fn exception(stop: &StopReply) -> Option<Exception> {
    match stop {
        StopReply::Signal { reasons, .. } => reasons.iter().find_map(|reason| match reason {
            StopReason::Exception(exception) => Some(Exception::Mach(exception.clone())),
            StopReason::WindowsException(exception) => Some(Exception::Windows(exception.clone())),
            _ => None,
        }),
        _ => None,
    }
}

/// At most [`MAX_EVENT_REASONS`] of `stop`'s reasons.
pub fn stop_reasons(stop: &StopReply) -> Vec<StopReason> {
    match stop {
        StopReply::Signal { reasons, .. } => reasons.iter().take(MAX_EVENT_REASONS).cloned().collect(),
        _ => Vec::new(),
    }
}

/// Most stop-reply reasons a stop event repeats.
pub const MAX_EVENT_REASONS: usize = 16;

pub(crate) fn optional_hex_address<S: serde::Serializer>(
    value: &Option<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.collect_str(&format_args!("{value:#x}")),
        None => serializer.serialize_none(),
    }
}

/// How a stop came about, for classifying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Continue,
    /// A single step of this thread (`None` when the stub lists no threads).
    Step(Option<ThreadId>),
}

/// Classifies `stop`, matching it against `table` and incrementing the hit counts of the entries it matched.
/// `pcs` are the stopped thread's possible pc values: one when the byte order is known, both decodings when it is
/// not, none when the pc is unreadable. Returns the cause, the matched IDs and the watch hit.
///
/// - A watch hit matches watchpoints whose access fits and whose range holds the reported address.
/// - `swbreak`/`hwbreak` match software/hardware breakpoints at the pc.
/// - Without either, a SIGTRAP after a continue matches every breakpoint at the pc. After a step it matches none,
///   because a completed step and a breakpoint at the next instruction look the same.
/// - A step completes when the same thread stops with SIGTRAP and no watch or breakpoint reason.
pub fn classify(
    stop: &StopReply,
    origin: Origin,
    interrupted: bool,
    pcs: &[u64],
    table: &mut [Breakpoint],
) -> (StopCause, Vec<u32>, Option<WatchHit>) {
    let (signal, thread, reasons) = match stop {
        StopReply::Signal { signal, thread, reasons, .. } => (*signal, *thread, reasons),
        StopReply::Exited { .. } => return (StopCause::Exited, Vec::new(), None),
        StopReply::Terminated { .. } => return (StopCause::Terminated, Vec::new(), None),
    };
    let mut matched = Vec::new();
    let accessed = reasons.iter().find_map(|reason| match reason {
        StopReason::Other { name, value } if name == "me_watch_addr" => crate::packet::parse_hex_u64(value),
        _ => None,
    });
    let watch = reasons.iter().find_map(|reason| match reason {
        StopReason::Watch { access, address } => Some(WatchHit { access, address: *address, accessed }),
        _ => None,
    });
    if let Some(hit) = &watch {
        for entry in table.iter_mut().filter(|entry| entry.inserted && entry.kind.matches_access(hit.access)) {
            if hit.address >= entry.address && hit.address - entry.address < entry.size.max(1) {
                entry.hits += 1;
                matched.push(entry.id);
            }
        }
        return (StopCause::Watchpoint, matched, watch);
    }
    // A Windows breakpoint trap (`EXCEPTION_BREAKPOINT`, the WoW64 one too) is a breakpoint, whether or not the
    // stub says `swbreak`: lldb-server reports an int3 that is not its own as `reason:exception`.
    let windows_breakpoint = reasons.iter().any(|reason| {
        matches!(reason, StopReason::WindowsException(exception)
            if matches!(exception.code, crate::pe::EXCEPTION_BREAKPOINT | crate::pe::STATUS_WX86_BREAKPOINT))
    });
    let software = reasons.contains(&StopReason::SwBreak) || windows_breakpoint;
    let hardware = reasons.contains(&StopReason::HwBreak);
    let by_pc = !software && !hardware && signal == 5 && origin == Origin::Continue;
    if software || hardware || by_pc {
        for entry in table.iter_mut().filter(|entry| entry.inserted && !entry.kind.is_watchpoint()) {
            let kind_fits = by_pc
                || (software && entry.kind == BreakKind::Software)
                || (hardware && entry.kind == BreakKind::Hardware);
            if kind_fits && pcs.contains(&entry.address) {
                entry.hits += 1;
                matched.push(entry.id);
            }
        }
    }
    let cause = if !matched.is_empty() || software || hardware {
        StopCause::Breakpoint
    } else if let Origin::Step(stepped) = origin {
        let same_thread = thread.is_none() || stepped.is_none() || thread == stepped;
        if signal == 5 && same_thread { StopCause::Step } else { StopCause::Signal }
    } else if interrupted && matches!(signal, 0 | 2) {
        // Only SIGINT (or no signal) is the interrupt's answer; a fault arriving meanwhile stays a signal.
        StopCause::Interrupted
    } else {
        StopCause::Signal
    };
    (cause, matched, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u32, kind: BreakKind, address: u64, size: u64) -> Breakpoint {
        Breakpoint { id, kind, address, size, hits: 0, inserted: true, temporary: false, placement: None }
    }

    fn signal(text: &str) -> StopReply {
        StopReply::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn parses_vcont_support() {
        assert_eq!(VCont::parse(b"vCont;c;C;s;S"), VCont { continue_: true, step: true });
        assert_eq!(VCont::parse(b"vCont;c;C;t"), VCont { continue_: true, step: false });
        assert_eq!(VCont::parse(b""), VCont::default());
        assert_eq!(VCont::parse(b"vContc;s"), VCont::default());
        assert_eq!(VCont::parse(b"E01"), VCont::default());
        assert_eq!(VCont::parse(b"vCont"), VCont::default());
    }

    #[test]
    fn random_vcont_replies_never_panic_and_only_advertise_listed_actions() {
        let mut rng = crate::packet::tests::Rng::new(9);
        for _ in 0..5000 {
            let alphabet = b"vCont;csCSrt\xff:";
            let length = rng.below(24);
            let reply: Vec<u8> = (0..length).map(|_| alphabet[rng.below(alphabet.len())]).collect();
            let support = VCont::parse(&reply);
            let actions: Vec<&[u8]> = reply.strip_prefix(b"vCont").unwrap_or(b"").split(|b| *b == b';').collect();
            if support.continue_ {
                assert!(actions.contains(&&b"c"[..]), "{reply:?}");
            }
            if support.step {
                assert!(actions.contains(&&b"s"[..]), "{reply:?}");
            }
        }
    }

    #[test]
    fn breakpoint_sizes_follow_the_architecture() {
        assert_eq!(breakpoint_size(Family::X86_64, false, None, None), Ok(1));
        assert_eq!(breakpoint_size(Family::Aarch64, false, None, None), Ok(4));
        assert_eq!(breakpoint_size(Family::Riscv64, false, None, Some(2)), Ok(2));
        assert_eq!(breakpoint_size(Family::Riscv32, false, None, None), Ok(4));
        assert_eq!(breakpoint_size(Family::Arm, true, None, None), Ok(2));
        assert_eq!(breakpoint_size(Family::Arm, false, Some(true), None), Ok(2));
        assert_eq!(breakpoint_size(Family::Arm, false, Some(false), None), Ok(4));
        assert!(breakpoint_size(Family::Arm, false, None, None).is_err());
        assert!(breakpoint_size(Family::Arm, true, None, Some(4)).is_err());
        assert!(breakpoint_size(Family::X86, false, None, Some(4)).is_err());
        assert!(breakpoint_size(Family::Other, false, None, None).is_err());
    }

    #[test]
    fn stops_match_table_entries_and_count_hits() {
        let mut table = vec![
            entry(1, BreakKind::Hardware, 0x100, 2),
            entry(2, BreakKind::Software, 0x100, 2),
            entry(3, BreakKind::Write, 0x2000_0200, 4),
            entry(4, BreakKind::Read, 0x2000_0200, 4),
        ];
        // QEMU reports breakpoint hits as a bare SIGTRAP: matched by pc after a continue.
        let (cause, ids, _) = classify(&signal("T05thread:p1.1;"), Origin::Continue, false, &[0x100], &mut table);
        assert_eq!((cause, ids), (StopCause::Breakpoint, vec![1, 2]));
        let (cause, ids, _) =
            classify(&signal("T05thread:p1.1;hwbreak:;"), Origin::Continue, false, &[0x100], &mut table);
        assert_eq!((cause, ids), (StopCause::Breakpoint, vec![1]));
        let (cause, ids, watch) =
            classify(&signal("T05thread:p1.1;watch:20000202;"), Origin::Continue, false, &[0x80], &mut table);
        assert_eq!((cause, ids), (StopCause::Watchpoint, vec![3]));
        assert_eq!(watch, Some(WatchHit { access: "write", address: 0x2000_0202, accessed: None }));
        assert_eq!(table.iter().map(|entry| entry.hits).collect::<Vec<_>>(), [2, 1, 1, 0]);
        // A step landing on a breakpoint address is a completed step, not a hit.
        let thread = ThreadId::parse("p1.1");
        let (cause, ids, _) = classify(&signal("T05thread:p1.1;"), Origin::Step(thread), false, &[0x100], &mut table);
        assert_eq!((cause, ids), (StopCause::Step, vec![]));
        let (cause, _, _) = classify(&signal("T05thread:p1.2;"), Origin::Step(thread), false, &[0x4], &mut table);
        assert_eq!(cause, StopCause::Signal);
        let (cause, _, _) = classify(&signal("T0bthread:p1.1;"), Origin::Step(thread), false, &[0x4], &mut table);
        assert_eq!(cause, StopCause::Signal);
        let (cause, _, _) = classify(&signal("T02thread:p1.1;"), Origin::Continue, true, &[0x4], &mut table);
        assert_eq!(cause, StopCause::Interrupted);
        let (cause, _, _) = classify(&signal("T0bthread:p1.1;"), Origin::Continue, true, &[0x4], &mut table);
        assert_eq!(cause, StopCause::Signal);
        let (cause, _, _) = classify(&signal("W00"), Origin::Continue, false, &[], &mut table);
        assert_eq!(cause, StopCause::Exited);
        // Entries the stub no longer holds match nothing.
        table.iter_mut().for_each(|entry| entry.inserted = false);
        let (cause, ids, _) = classify(&signal("T05thread:p1.1;"), Origin::Continue, false, &[0x100], &mut table);
        assert_eq!((cause, ids), (StopCause::Signal, vec![]));
    }

    #[test]
    fn random_stops_never_panic_when_classified() {
        let mut rng = crate::packet::tests::Rng::new(11);
        let mut table = vec![entry(1, BreakKind::Access, 0, u64::MAX), entry(2, BreakKind::Software, u64::MAX, 1)];
        for _ in 0..5000 {
            let length = rng.below(48);
            let alphabet = b"TSWX05afp.;:-xthreadwatchrawswbreakhw";
            let reply: Vec<u8> = (0..length).map(|_| alphabet[rng.below(alphabet.len())]).collect();
            if let Ok(stop) = StopReply::parse(&reply) {
                let pcs = [rng.below(4) as u64, u64::MAX];
                let _ = classify(&stop, Origin::Step(None), rng.below(2) == 0, &pcs, &mut table);
                let _ = classify(&stop, Origin::Continue, false, &pcs, &mut table);
            }
        }
    }
}
