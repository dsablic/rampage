//! The `debug` group: sessions with operator-started GDB remote stubs, inspection and all-stop execution control.
//! These tools need the per-connection [`DebugRegistry`], so they are a kind of their own, served only by an MCP
//! server started with debug endpoints.

use rampage_debug::Cancel;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

use super::{Effect, MAX_RESULT_CHARS, arguments, error_chain, schema};
use crate::{DebugBreakKind, DebugRange, DebugRegistry, FileOffset};

/// A tool that works on the debug sessions of one MCP connection.
pub struct DebugTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub effect: Effect,
    handler: fn(&DebugRegistry, Value, &Cancel) -> Result<Value, String>,
}

impl DebugTool {
    pub fn call(&self, registry: &DebugRegistry, input: Value) -> Result<Value, String> {
        self.call_cancellable(registry, input, &Cancel::default())
    }

    /// Calls the tool; setting `cancel` ends a wait early (the target is not touched) and stops a long read or
    /// snapshot between chunks.
    pub fn call_cancellable(&self, registry: &DebugRegistry, input: Value, cancel: &Cancel) -> Result<Value, String> {
        if input.to_string().len() > 65_536 {
            return Err("invalid_argument: debug tool arguments exceed 65536 bytes".into());
        }
        (self.handler)(registry, input, cancel)
    }
}

fn output(result: Result<impl Serialize, crate::ApiError>) -> Result<Value, String> {
    let value =
        serde_json::to_value(result.map_err(|error| error_chain(&error))?).map_err(|error| error.to_string())?;
    if value.to_string().len() > MAX_RESULT_CHARS {
        return Err("result_too_large: the result exceeds 60000 bytes; request a smaller page or range".into());
    }
    Ok(value)
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ConnectArgs {
    /// One of the endpoints the operator allowed, exactly as listed (`host:port` or `unix:/path`). May be omitted
    /// when exactly one is allowed.
    endpoint: Option<String>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StatusArgs {
    /// A session ID from debug_connect, such as "s1".
    session: String,
    /// Threads to skip, for paging.
    offset: Option<usize>,
    /// Threads per page, 1..=1000 (default 64), additionally bounded to 60000 JSON bytes.
    limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RegistersArgs {
    session: String,
    /// A thread ID as debug_status lists it ("p1.1" or "1f"); the stub's current thread when omitted.
    thread: Option<String>,
    /// Only these registers, by the target description's names.
    names: Option<Vec<String>>,
    /// Registers to skip, for paging.
    offset: Option<usize>,
    /// Registers per page, 1..=4096 (default 256), additionally bounded to 60000 JSON bytes.
    limit: Option<usize>,
    /// The stop epoch the caller expects; refused with stale_epoch when the session has moved on.
    epoch: Option<u64>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadMemoryArgs {
    session: String,
    /// Runtime address (hex string or integer).
    address: FileOffset,
    /// Bytes to read: 1 up to the session's `max_read_length` from debug_connect (at most 65536).
    length: usize,
    /// The thread whose address space to read (selected with Hg); the stub's current thread when omitted.
    thread: Option<String>,
    /// The stop epoch the caller expects; refused with stale_epoch when the session has moved on.
    epoch: Option<u64>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ModulesArgs {
    session: String,
    /// Modules to skip, for paging.
    offset: Option<usize>,
    /// Modules per page, 1..=1000 (default 64), additionally bounded to 60000 JSON bytes.
    limit: Option<usize>,
    /// The stop epoch the caller expects; refused with stale_epoch when the session has moved on.
    epoch: Option<u64>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SnapshotArgs {
    session: String,
    /// Absolute path of the new snapshot file, in an existing same-user 0700 directory; an existing path is refused.
    output: std::path::PathBuf,
    /// 1..=256 non-overlapping ranges to capture, each at most 16 MiB and 64 MiB in all.
    ranges: Vec<DebugRange>,
    /// The stop epoch the caller expects; refused with stale_epoch when the session has moved on.
    epoch: Option<u64>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ContinueArgs {
    session: String,
    /// The stop epoch the caller last saw (debug_status or the last stop event); refused with stale_epoch otherwise.
    epoch: u64,
    /// How long to wait for the stop, 0..=60000 ms (default 5000). The target keeps running after the wait ends.
    timeout_ms: Option<u64>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WaitArgs {
    session: String,
    /// How long to wait for the stop, 0..=60000 ms (default 5000).
    timeout_ms: Option<u64>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StepArgs {
    session: String,
    /// The stop epoch the caller last saw; refused with stale_epoch otherwise.
    epoch: u64,
    /// The thread to step, as debug_status lists it; the stop's thread (else the first listed) when omitted.
    thread: Option<String>,
    /// Instructions to step, 1..=1000 (default 1).
    count: Option<u32>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum BreakpointAction {
    Set,
    Clear,
    List,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct BreakpointsArgs {
    session: String,
    action: BreakpointAction,
    /// set and clear: the stop epoch the caller last saw; refused with stale_epoch otherwise.
    epoch: Option<u64>,
    /// set: software (Z0, planted by the stub), hardware (Z1), or a write, read or access watchpoint (Z2..Z4).
    kind: Option<DebugBreakKind>,
    /// set: the runtime address (hex string or integer). On ARM an odd address means Thumb code.
    address: Option<FileOffset>,
    /// set, breakpoints: the instruction size sent as the Z kind; by default x86 1, AArch64 4, RISC-V 4 (pass 2
    /// for a compressed instruction), Cortex-M 2, A-profile ARM 2 or 4 from CPSR.T.
    size: Option<u64>,
    /// set, watchpoints: bytes watched, 1..=4096 (required).
    length: Option<u64>,
    /// clear: the breakpoint ID from set or list.
    id: Option<u32>,
    /// list: entries to skip, for paging.
    offset: Option<usize>,
    /// list: entries per page, 1..=64 (default 64), additionally bounded to 60000 JSON bytes.
    limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SessionArgs {
    session: String,
}

/// Every debug tool.
pub fn debug_tools() -> Vec<DebugTool> {
    vec![
        DebugTool {
            name: "debug_connect",
            description: "Connect to an operator-started GDB remote stub (gdbserver, QEMU -s, OpenOCD, probe-rs...) at \
                an endpoint the operator allowed with --debug-endpoint or RAMPAGE_DEBUG_ENDPOINTS; no other address \
                can be reached and rampage launches or attaches to nothing. Negotiates features, reads the target \
                description, stop state and threads, and returns a session ID (at most 4 open per connection; all \
                detach when the MCP connection ends) with architecture, endianness (unknown unless stop-bound \
                evidence fixes it: x86, Cortex-M AIRCR or ARM CPSR.E), pointer size, the stub's features, state, \
                typed stop reason, stop epoch, a page of threads and whether modules and a memory map are available. \
                Connecting does not resume the target; execution control is debug_continue, debug_step, \
                debug_interrupt and debug_breakpoints. Never writes or kills.",
            input_schema: schema::<ConnectArgs>(),
            effect: Effect::None,
            handler: |registry, input, _cancel| {
                let args: ConnectArgs = arguments(input)?;
                output(registry.connect(args.endpoint.as_deref()))
            },
        },
        DebugTool {
            name: "debug_status",
            description: "A debug session's state (stopped, running, exited, detached or lost with its reason), stop \
                epoch, typed stop reply, the last stop event rampage observed (reason, pc, matched breakpoint IDs, \
                watch address), milliseconds since the last resume while running, bounded console output and a page \
                of threads (offset/limit, byte-fitted). While stopped it re-asks the stub for the stop reply (?) and \
                threads; a different reply than the previous ? is a stop rampage did not cause and a new epoch. While \
                running it reports without touching the stub. Does not resume, wait or interrupt.",
            input_schema: schema::<StatusArgs>(),
            effect: Effect::None,
            handler: |registry, input, _cancel| {
                let args: StatusArgs = arguments(input)?;
                output(registry.status(&args.session, args.offset, args.limit))
            },
        },
        DebugTool {
            name: "debug_registers",
            description: "Registers of a stopped thread (the stub's current one by default; select with thread), \
                all or by name: name, regnum, bitsize, type and group from the target description, bytes exactly \
                as the stub sent them, and value decoded in the session's byte order (null when the byte order is \
                unknown or the stub marks the register unavailable). Reports the stop epoch it read at; pass epoch to \
                refuse (stale_epoch) if the target stopped again since. Refused with target_running while the target \
                runs. Paged with offset/limit within 60000 JSON bytes. No writes, no expression evaluation.",
            input_schema: schema::<RegistersArgs>(),
            effect: Effect::None,
            handler: |registry, input, _cancel| {
                let args: RegistersArgs = arguments(input)?;
                output(registry.registers_at(
                    &args.session,
                    args.thread.as_deref(),
                    args.names.as_deref(),
                    args.offset,
                    args.limit,
                    args.epoch,
                ))
            },
        },
        DebugTool {
            name: "debug_read_memory",
            description: "Read bytes of a stopped target's memory at a runtime address: 1 up to the session's \
                max_read_length (debug_connect reports it; it shrinks with the stub's packet size so every chunk's \
                report fits the 60000-byte result, about 28 KiB with large packets), in chunks that fit \
                the stub's packet size (binary x reads when the stub offers them, else m). Returns the bytes read \
                as hex runs, and every chunk's outcome: short reads and stub errors are reported per chunk, never \
                filled in. Reports the stop epoch it read at (pass epoch to refuse a stale one); reads are not \
                atomic. Refused with target_running while the target runs; cancelling stops between chunks. No \
                writes; MMIO reads go to the device as the stub performs them.",
            input_schema: schema::<ReadMemoryArgs>(),
            effect: Effect::None,
            handler: |registry, input, cancel| {
                let args: ReadMemoryArgs = arguments(input)?;
                let limit = registry.tool_read_limit(&args.session).map_err(|error| error_chain(&error))?;
                if !(1..=limit).contains(&args.length) {
                    return Err(format!(
                        "invalid_argument: length must be in 1..={limit} for this session (its max_read_length); read \
                         larger ranges in pieces"
                    ));
                }
                output(registry.read_memory_at(
                    &args.session,
                    args.address.0,
                    args.length,
                    args.thread.as_deref(),
                    args.epoch,
                    cancel,
                ))
            },
        },
        DebugTool {
            name: "debug_modules",
            description: "Loaded modules and memory regions as the stub reports them: svr4 link-map entries (name, \
                l_addr load bias, l_ld, lm, and a GNU build ID when the module's ELF header is mapped at its load \
                bias) or Windows-style library lists (segment/section addresses), the exec file, qOffsets, and \
                memory-map regions (start, length, ram/rom/flash, flash block size). Modules are paged (offset/limit, \
                byte-fitted); at most 256 regions are listed. Modules are not matched to files or a project here, \
                and stubs without these lists report none, with limitations saying so. Optional epoch is checked \
                (stale_epoch); refused with target_running while the target runs.",
            input_schema: schema::<ModulesArgs>(),
            effect: Effect::None,
            handler: |registry, input, _cancel| {
                let args: ModulesArgs = arguments(input)?;
                output(registry.modules_at(&args.session, args.offset, args.limit, args.epoch))
            },
        },
        DebugTool {
            name: "debug_snapshot",
            description: "Write a stopped target's state to a new rampage-snapshot-v1 file that every runtime and \
                analysis tool can open: the requested memory ranges (1..=256, non-overlapping, each <= 16 MiB, <= 64 \
                MiB in all; permissions default rw-, thumb defaults true for executable ranges on M-profile ARM), \
                every thread's registers of at most 64 bits (at most 64 threads), svr4 modules, and the \
                architecture and data byte order. FILE WRITE: output must be a new absolute path in an existing \
                same-user 0700 directory; it is published atomically with mode 0600 and never overwrites. Refuses \
                targets whose data byte order is unknown (such as AArch64 and RISC-V) or whose architecture rampage \
                cannot represent, any range that is not fully readable, and captures whose registers, modules or \
                paths exceed the snapshot format's limits (checked before memory is read). Reads are not atomic; \
                the stop reply and threads are re-read and compared before writing. Optional epoch is checked \
                (stale_epoch); refused with target_running while the target runs; cancelling stops between memory \
                reads and writes nothing.",
            input_schema: schema::<SnapshotArgs>(),
            effect: Effect::FileWrite,
            handler: |registry, input, cancel| {
                let args: SnapshotArgs = arguments(input)?;
                output(registry.snapshot_at(&args.session, &args.output, &args.ranges, args.epoch, cancel))
            },
        },
        DebugTool {
            name: "debug_disconnect",
            description: "Detach from the target and close the session, returning its final state. A running target \
                is interrupted first and waited for up to 3 s; then every inserted breakpoint and watchpoint is \
                removed (best effort: breakpoints_removed and removal_failures report it) and D (or D;pid per \
                process in multiprocess mode) is sent. A target that never stops is abandoned: the connection is \
                closed without detaching and the state is lost. Detaching lets the target run: a stopped or QEMU -S \
                guest resumes. It never kills it. If the stub refuses D (E nn), the session stays open and attached \
                (detached: false, closed: false) and disconnecting can be retried.",
            input_schema: schema::<SessionArgs>(),
            effect: Effect::Execution,
            handler: |registry, input, _cancel| {
                let args: SessionArgs = arguments(input)?;
                output(registry.disconnect(&args.session))
            },
        },
        DebugTool {
            name: "debug_continue",
            description: "Resume every thread of a stopped target (vCont;c, or c when the stub has no vCont) at the \
                caller's epoch (refused with stale_epoch, giving the current epoch and state, if it moved on) and \
                wait up to timeout_ms (default 5000, max 60000) for the stop. Returns a typed stop event (reason: \
                breakpoint, watchpoint, interrupted, signal, exited or terminated; signal, thread, pc, matched \
                breakpoint IDs with their hit counts incremented, watch address, the new epoch, console output \
                received while running, warnings) or state running when nothing stopped it in time; then use \
                debug_wait, debug_interrupt or debug_disconnect. A thread stopped at an inserted breakpoint first \
                steps past it (z, one step, Z back; the step is its own stop and epoch, and a step that stops for \
                another reason answers instead of resuming). Resumes WITHOUT delivering any pending signal: \
                continuing after a fault usually faults again at the same pc. All-stop only. No writes, no signal delivery, no kill, \
                no symbolic or static-address breakpoints. Cancelling the call ends the wait (cancelled: true), not \
                the run.",
            input_schema: schema::<ContinueArgs>(),
            effect: Effect::Execution,
            handler: |registry, input, cancel| {
                let args: ContinueArgs = arguments(input)?;
                output(registry.resume(&args.session, args.epoch, args.timeout_ms, cancel))
            },
        },
        DebugTool {
            name: "debug_wait",
            description: "Wait up to timeout_ms (default 5000, max 60000) for a running target to stop, returning the \
                same shape as debug_continue: a typed stop event with the new epoch, or state running. A target that \
                is not running answers at once with its last stop event. Sends nothing to the stub; cancelling the \
                call ends the wait (cancelled: true), not the run.",
            input_schema: schema::<WaitArgs>(),
            effect: Effect::None,
            handler: |registry, input, cancel| {
                let args: WaitArgs = arguments(input)?;
                output(registry.wait(&args.session, args.timeout_ms, cancel))
            },
        },
        DebugTool {
            name: "debug_interrupt",
            description: "Interrupt a running target with the out-of-band 0x03 byte (sent again on every call, after \
                taking any stop reply already on its way) and wait up to 3 s for its stop, returning the same shape \
                as debug_continue (reason interrupted for SIGINT, with a new epoch), or state running if the stub did \
                not stop it in time. Refused with not_running when the target is not running. All \
                threads stop together (all-stop only). No signal is delivered and nothing is written.",
            input_schema: schema::<SessionArgs>(),
            effect: Effect::Execution,
            handler: |registry, input, cancel| {
                let args: SessionArgs = arguments(input)?;
                output(registry.interrupt(&args.session, cancel))
            },
        },
        DebugTool {
            name: "debug_step",
            description: "Single-step one thread (the stop's thread by default) count instructions (1..=1000, \
                default 1) at the caller's epoch (stale_epoch otherwise), with vCont;s:<thread> or Hc<thread> then \
                s. Stops early on any stop that is not that step's completion (breakpoint, watchpoint, another \
                signal, another thread, exit). Returns requested and completed steps, the pc after each completed \
                step, the final stop event and epoch (each step is a stop and a new epoch). Steps run through the \
                session loop: debug_status, debug_interrupt (ends the steps) and debug_disconnect are served \
                meanwhile. A step that does not finish within the request timeout leaves the target running. Steps machine instructions only: no \
                step-over or step-out, no signal delivery, no writes. All-stop: other threads stay stopped.",
            input_schema: schema::<StepArgs>(),
            effect: Effect::Execution,
            handler: |registry, input, cancel| {
                let args: StepArgs = arguments(input)?;
                output(registry.step(&args.session, args.epoch, args.thread.as_deref(), args.count, cancel))
            },
        },
        DebugTool {
            name: "debug_breakpoints",
            description: "Breakpoints and watchpoints the stub inserts, by runtime address only (static or symbolic \
                placement is a later phase). action set (epoch, kind software|hardware|write|read|access, address, \
                size for breakpoints or length for watchpoints) inserts Z0..Z4 and returns the entry with its ID; \
                an empty stub reply is unsupported and an E reply is target_error, and rampage never plants a \
                software breakpoint by writing memory. action clear (epoch, id) removes it (z0..z4). action list \
                pages the table (at most 64 entries) with kind, address, size, hit count and whether the stub holds \
                it. Breakpoint size defaults by architecture: x86 1, AArch64 4, RISC-V 4 (2 for compressed), \
                Cortex-M 2, A-profile ARM 2 or 4 from CPSR.T; an odd ARM address means Thumb. Hits are counted when a \
                stop matches: watch address within a watchpoint, swbreak/hwbreak or a SIGTRAP pc after a continue at \
                a breakpoint. Detaching removes every entry. Set and clear are refused while the target runs.",
            input_schema: schema::<BreakpointsArgs>(),
            effect: Effect::Execution,
            handler: |registry, input, _cancel| {
                let args: BreakpointsArgs = arguments(input)?;
                let epoch =
                    || args.epoch.ok_or_else(|| "invalid_argument: set and clear need the caller's epoch".to_owned());
                let unused = |names: &[(&str, bool)]| -> Result<(), String> {
                    match names.iter().find(|(_, given)| *given) {
                        Some((name, _)) => Err(format!("invalid_argument: `{name}` does not apply to this action")),
                        None => Ok(()),
                    }
                };
                match args.action {
                    BreakpointAction::Set => {
                        unused(&[
                            ("id", args.id.is_some()),
                            ("offset", args.offset.is_some()),
                            ("limit", args.limit.is_some()),
                        ])?;
                        let kind = args.kind.ok_or("invalid_argument: set needs kind")?;
                        let address = args.address.ok_or("invalid_argument: set needs address")?;
                        output(registry.set_breakpoint(
                            &args.session,
                            epoch()?,
                            kind,
                            address.0,
                            args.size,
                            args.length,
                        ))
                    }
                    BreakpointAction::Clear => {
                        unused(&[
                            ("kind", args.kind.is_some()),
                            ("address", args.address.is_some()),
                            ("size", args.size.is_some()),
                            ("length", args.length.is_some()),
                            ("offset", args.offset.is_some()),
                            ("limit", args.limit.is_some()),
                        ])?;
                        let id = args.id.ok_or("invalid_argument: clear needs id")?;
                        output(registry.clear_breakpoint(&args.session, epoch()?, id))
                    }
                    BreakpointAction::List => {
                        unused(&[
                            ("epoch", args.epoch.is_some()),
                            ("kind", args.kind.is_some()),
                            ("address", args.address.is_some()),
                            ("size", args.size.is_some()),
                            ("length", args.length.is_some()),
                            ("id", args.id.is_some()),
                        ])?;
                        output(registry.breakpoints(&args.session, args.offset, args.limit))
                    }
                }
            },
        },
    ]
}
