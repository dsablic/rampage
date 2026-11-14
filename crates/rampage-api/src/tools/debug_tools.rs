//! The `debug` group: sessions with operator-started GDB remote stubs, inspection and all-stop execution control.
//! These tools need the per-connection [`DebugRegistry`], so they are a kind of their own, served only by an MCP
//! server started with debug endpoints.

use rampage_debug::Cancel;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

use super::{Effect, MAX_RESULT_CHARS, arguments, error_chain, schema};
use crate::{BreakTarget, DebugBreakKind, DebugRange, DebugRegistry, EvidenceRange, FileOffset, Session};

/// A tool that works on the debug sessions of one MCP connection.
pub struct DebugTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub effect: Effect,
    handler: fn(&DebugRegistry, &Session, Value, &Cancel) -> Result<Value, String>,
}

impl DebugTool {
    pub fn call(&self, registry: &DebugRegistry, input: Value) -> Result<Value, String> {
        self.call_cancellable(registry, input, &Cancel::default())
    }

    /// Calls the tool, opening bound projects in the registry's own project session; setting `cancel` ends a wait
    /// early (the target is not touched) and stops a long read or snapshot between chunks.
    pub fn call_cancellable(&self, registry: &DebugRegistry, input: Value, cancel: &Cancel) -> Result<Value, String> {
        self.call_in(registry, &registry.projects, input, cancel)
    }

    /// [`DebugTool::call_cancellable`], opening the projects `debug_bind` binds in `projects` (the server's
    /// session), so they share its project cache with the project tools.
    pub fn call_in(
        &self,
        registry: &DebugRegistry,
        projects: &Session,
        input: Value,
        cancel: &Cancel,
    ) -> Result<Value, String> {
        if input.to_string().len() > 65_536 {
            return Err("invalid_argument: debug tool arguments exceed 65536 bytes".into());
        }
        (self.handler)(registry, projects, input, cancel)
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
    /// A binary to bind after connecting, as debug_bind does: the main executable or the firmware.
    path: Option<String>,
    /// With path: as debug_bind's module.
    module: Option<String>,
    /// With path: as debug_bind's slide.
    slide: Option<FileOffset>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct BindArgs {
    session: String,
    /// The binary to bind (the original image, not a snapshot); opened like the project tools open it.
    path: String,
    /// Only a runtime module with this path or file name (as debug_modules lists it); for a target without a
    /// module list, the label the binding gets. Binding the same module again replaces it.
    module: Option<String>,
    /// runtime = static + slide (hex string or integer). Needed only when no module matches; still verified
    /// against target memory and reported.
    slide: Option<FileOffset>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EvidenceArgs {
    session: String,
    /// The stop epoch the caller expects; refused with stale_epoch when the session has moved on.
    epoch: Option<u64>,
    /// 1..=8 registers to record; by default the pc, stack pointer, return-address register and first arguments.
    names: Option<Vec<String>>,
    /// At most 4 runtime memory ranges of 1..=64 bytes to record.
    memory: Option<Vec<EvidenceRange>>,
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
    /// Also report, for each value that points into a bound project, the static address and the function,
    /// symbol or string there (points_to).
    annotate: Option<bool>,
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
    /// Write exactly one range's bytes as a flat binary instead (a firmware dump: open it as a Raw project with
    /// base_address = the range's address).
    raw: Option<bool>,
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
    /// The thread to step, as debug_status lists it; the stop's thread (else the first listed) when omitted. Not
    /// with over or out, which step the stopped thread.
    thread: Option<String>,
    /// Instructions to step, 1..=1000 (default 1); with over, a call and its return count as one. Not with out.
    count: Option<u32>,
    /// Step over calls: a call runs to the instruction after it (a temporary breakpoint there), anything else
    /// steps one instruction.
    over: Option<bool>,
    /// Step out: from a function's first instruction in a bound project, run to its return address.
    out: Option<bool>,
    /// over and out: how long each run to a temporary breakpoint waits, 0..=60000 ms (default 5000).
    timeout_ms: Option<u64>,
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
    /// set: the runtime address (hex string or integer). On ARM an odd address means Thumb code. Give exactly one
    /// of address, static_address and function.
    address: Option<FileOffset>,
    /// set: an address in a bound project (as project tools show it), mapped through the binding's slide.
    static_address: Option<FileOffset>,
    /// set: a function of a bound project by name: the user's names first, then symbols. A name with several
    /// addresses is refused with the candidates.
    function: Option<String>,
    /// set with static_address or function: the bound project's path; may be omitted when one project is bound
    /// (function then searches every bound project).
    path: Option<String>,
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

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DisconnectArgs {
    session: String,
    /// Kill the target instead of detaching: remove breakpoints, then vKill;pid per process in multiprocess mode,
    /// else k. Only when the operator started rampage with --debug-kill.
    kill: Option<bool>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WriteMemoryArgs {
    session: String,
    /// The stop epoch the caller last saw; refused with stale_epoch otherwise.
    epoch: u64,
    /// Runtime address (hex string or integer).
    address: FileOffset,
    /// The bytes to write, 1..=4096, as hex digits without 0x ("deadbeef").
    bytes: String,
    /// The bytes the caller expects there now, as hex of the same length; when the target holds anything else the
    /// write is refused (expect_mismatch) and nothing is written.
    expect: Option<String>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WriteRegisterArgs {
    session: String,
    /// The stop epoch the caller last saw; refused with stale_epoch otherwise.
    epoch: u64,
    /// A thread ID as debug_status lists it; the stop's thread (else the first listed) when omitted.
    thread: Option<String>,
    /// The register's name in the target description, as debug_registers lists it.
    name: String,
    /// A hex string is the register's bytes as the stub transfers them (target-endian, exactly its size, no 0x),
    /// the form debug_registers reports as bytes; an integer is the value, accepted only when the session's
    /// endianness is known.
    value: crate::DebugRegisterValue,
}

const DISCONNECT_DESCRIPTION: &str = "Detach from the target and close the session, returning its final state. A \
    running target is interrupted first and waited for up to 3 s; then every inserted breakpoint and watchpoint is \
    removed (best effort: breakpoints_removed and removal_failures report it) and D (or D;pid per process in \
    multiprocess mode) is sent. A target that never stops is abandoned: the connection is closed without detaching \
    and the state is lost. Detaching lets the target run: a stopped or QEMU -S guest resumes. It never kills it. If \
    the stub refuses D (E nn), the session stays open and attached (detached: false, closed: false), without its \
    breakpoints (already removed and counted), and disconnecting can be retried.";

const DISCONNECT_KILL_DESCRIPTION: &str = "Detach from the target and close the session, returning its final \
    state; with kill: true (the operator allowed it with --debug-kill), kill the target instead. A running target is \
    interrupted first and waited for up to 3 s; then every inserted breakpoint and watchpoint is removed (best effort: \
    breakpoints_removed and removal_failures report it). Detaching then sends D (or D;pid per process in multiprocess \
    mode) and lets the target run: a stopped or QEMU -S guest resumes. Killing sends vKill;pid per process in \
    multiprocess mode, else k, and reports kill {killed, already_ended, packets, confirmed, reply, error} with the \
    final state: killed (the stub answered OK or X), exited (W), or lost when the stub closed the connection or did not answer within 3 s (GDB \
    takes that as a kill, rampage reports only what it saw; QEMU in system mode exits the emulator). A target that \
    never stops is abandoned: the connection is closed without detaching or killing and the state is lost. If the \
    stub refuses D or the kill (E nn), or does not support the kill, the session stays open and attached (closed: \
    false), without its breakpoints (already removed and counted), and disconnecting can be retried. Nothing is \
    killed unless kill: true is passed.";

/// Every debug tool a server without write or kill consent serves.
pub fn debug_tools() -> Vec<DebugTool> {
    debug_tools_with(crate::DebugConsent::default())
}

/// Every debug tool a server with `consent` serves: the write tools only with writes, and debug_disconnect's kill
/// option only with kill. The registry and its sessions check the same consent again whatever the list says.
pub fn debug_tools_with(consent: crate::DebugConsent) -> Vec<DebugTool> {
    let mut tools = read_and_execution_tools();
    if let Some(disconnect) = tools.iter_mut().find(|tool| tool.name == "debug_disconnect") {
        if consent.kill {
            disconnect.description = DISCONNECT_KILL_DESCRIPTION;
        } else if let Some(properties) = disconnect.input_schema["properties"].as_object_mut() {
            properties.remove("kill");
        }
    }
    if consent.writes {
        tools.extend(write_tools());
    }
    tools
}

/// The write tools, served only with the operator's --debug-writes.
fn write_tools() -> Vec<DebugTool> {
    vec![
        DebugTool {
            name: "debug_write_memory",
            description: "Write 1..=4096 bytes (hex) at a runtime address of a stopped target, at the caller's epoch \
                (stale_epoch otherwise; target_running while it runs). Only served because the operator started \
                rampage with --debug-writes. Reads the bytes there first: with expect (hex, same length) a target \
                holding anything else is refused with expect_mismatch and nothing is written. Refused, writing \
                nothing, when a software breakpoint (Z0, including a step's temporary one) overlaps the range, since \
                the stub keeps and restores the bytes under it. Writes with X when the stub takes it, else M, one \
                packet per chunk of the stub's packet size, stopping at the first refusal (never retried), then reads \
                the range back. Returns {before, after, chunks (each packet's address, length, packet, written, \
                error), complete, verified}: verified is false when the read-back differs, as when flash or ROM \
                accepts and drops a write. The epoch does not change; a later debug_snapshot records the written \
                bytes. Destructive and not idempotent. No flash programming. No automatic writes: rampage writes \
                only when this tool is called.",
            input_schema: schema::<WriteMemoryArgs>(),
            effect: Effect::TargetWrite,
            handler: |registry, _projects, input, _cancel| {
                let args: WriteMemoryArgs = arguments(input)?;
                let bytes = crate::debug_writes::parse_hex_bytes("bytes", &args.bytes).map_err(|e| error_chain(&e))?;
                if !(1..=rampage_debug::MAX_WRITE).contains(&bytes.len()) {
                    return Err(format!("invalid_argument: bytes must be 1..={} bytes", rampage_debug::MAX_WRITE));
                }
                let expect = args
                    .expect
                    .map(|expect| crate::debug_writes::parse_hex_bytes("expect", &expect))
                    .transpose()
                    .map_err(|error| error_chain(&error))?;
                if expect.as_ref().is_some_and(|expect| expect.len() != bytes.len()) {
                    return Err("invalid_argument: expect must be as long as bytes".into());
                }
                output(registry.write_memory(&args.session, args.epoch, args.address.0, &bytes, expect.as_deref()))
            },
        },
        DebugTool {
            name: "debug_write_register",
            description: "Write one register of a stopped thread (the stop's thread by default), at the caller's \
                epoch (stale_epoch otherwise; target_running while it runs). Only served because the operator \
                started rampage with --debug-writes. value is either hex bytes in the order the stub transfers them \
                (target-endian, exactly the register's size, as debug_registers reports bytes) or an integer, which \
                is accepted only when the session's endianness is known and must fit the register's bitsize. Uses P \
                when the stub supports it, else reads every register with g and writes them back with G with only \
                this one changed (refused when g marks registers unavailable or leaves this one out). Returns \
                {before, after, before_value, after_value, packet, verified}; verified is false when the register \
                reads back differently. Writing pc does not resume, and the epoch does not change. Destructive and \
                not idempotent. No automatic writes: rampage writes only when this tool is called.",
            input_schema: schema::<WriteRegisterArgs>(),
            effect: Effect::TargetWrite,
            handler: |registry, _projects, input, _cancel| {
                let args: WriteRegisterArgs = arguments(input)?;
                output(registry.write_register(
                    &args.session,
                    args.epoch,
                    args.thread.as_deref(),
                    &args.name,
                    &args.value,
                ))
            },
        },
    ]
}

/// The tools every debug server serves.
fn read_and_execution_tools() -> Vec<DebugTool> {
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
                With path (and optionally module and slide), it then binds that binary as debug_bind does and \
                reports binding, or binding_error with the session still open. Connecting does not resume the \
                target; execution control is debug_continue, debug_step, debug_interrupt and debug_breakpoints. \
                Never writes or kills.",
            input_schema: schema::<ConnectArgs>(),
            effect: Effect::None,
            handler: |registry, projects, input, _cancel| {
                let args: ConnectArgs = arguments(input)?;
                if args.path.is_none() && (args.module.is_some() || args.slide.is_some()) {
                    return Err("invalid_argument: module and slide apply only with path".into());
                }
                let connection = registry.connect(args.endpoint.as_deref()).map_err(|error| error_chain(&error))?;
                let session = connection.session.clone();
                let mut value = output(Ok::<_, crate::ApiError>(connection))?;
                if let Some(path) = args.path {
                    let bound = registry.bind(
                        &session,
                        projects,
                        std::path::Path::new(&path),
                        args.module.as_deref(),
                        args.slide.map(|slide| slide.0),
                    );
                    match bound {
                        Ok(bound) => {
                            value["binding"] = serde_json::to_value(bound.binding).map_err(|e| e.to_string())?
                        }
                        Err(error) => value["binding_error"] = Value::String(error_chain(&error)),
                    }
                }
                Ok(value)
            },
        },
        DebugTool {
            name: "debug_bind",
            description: "Bind a binary (opened like the project tools open it, sharing their cache) to one runtime \
                module of a debug session, so breakpoints can be placed by static address or function name, stops \
                and register values are located in the project, and step over/out work. Modules are matched, in \
                order of evidence, by GNU build ID or Mach-O UUID (read from target memory), by path then file name, \
                then by their mapped header bytes; a target that lists no modules (bare-metal firmware) matches \
                when the image's code is mapped byte for byte at qOffsets or 0. The evidence that matched is \
                reported; a mere name match must also verify. The slide (runtime = static + slide: svr4 l_addr for \
                ELF; for library lists the address minus the header's or first section's link address, whichever \
                verifies) is verified by comparing windows at the entry point, the start, middle and end of each code \
                segment and up to 16 function entries with target memory: any difference refuses. The project's \
                analysis runs at bind time, so later stops name functions without waiting. Without a \
                match, pass slide to bind anyway; its verification is reported as a limitation. module restricts \
                the match to a module of that path or file name. At most 8 bindings per session; binding the same \
                module again replaces it; debug_status lists them. Reads only.",
            input_schema: schema::<BindArgs>(),
            effect: Effect::None,
            handler: |registry, projects, input, _cancel| {
                let args: BindArgs = arguments(input)?;
                output(registry.bind(
                    &args.session,
                    projects,
                    std::path::Path::new(&args.path),
                    args.module.as_deref(),
                    args.slide.map(|slide| slide.0),
                ))
            },
        },
        DebugTool {
            name: "debug_evidence",
            description: "A bounded, typed record of a stopped target to cite in record_finding: endpoint, session, \
                epoch, thread, the pc and its location in a bound project, up to 8 registers (default: pc, stack \
                pointer, return-address register and the first argument registers) and up to 4 memory ranges of at \
                most 64 bytes. ledger_evidence is a ready evidence item ({tool: debug_evidence, detail}, at most 300 \
                bytes, clipped with ...) to pass in record_finding's evidence list; the full object is not stored in \
                the ledger. Optional epoch is checked (stale_epoch). Reads only.",
            input_schema: schema::<EvidenceArgs>(),
            effect: Effect::None,
            handler: |registry, _projects, input, _cancel| {
                let args: EvidenceArgs = arguments(input)?;
                output(registry.evidence(
                    &args.session,
                    args.epoch,
                    args.names.as_deref(),
                    args.memory.as_deref().unwrap_or_default(),
                ))
            },
        },
        DebugTool {
            name: "debug_status",
            description: "A debug session's state (stopped, running, exited, detached or lost with its reason), stop \
                epoch, typed stop reply, the last stop event rampage observed (reason, pc, matched breakpoint IDs, \
                watch address), milliseconds since the last resume while running, bounded console output and a page \
                of threads (offset/limit, byte-fitted). While stopped it re-reads the threads (which also \
                shows the connection is alive) and reports the session's own stop: the stub's stop reply (?) is \
                asked only when connecting, because QEMU removes every breakpoint and watchpoint when asked it. While \
                running it reports without touching the stub. Does not resume, wait or interrupt.",
            input_schema: schema::<StatusArgs>(),
            effect: Effect::None,
            handler: |registry, _projects, input, _cancel| {
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
                runs. Paged with offset/limit within 60000 JSON bytes. With annotate: true, each value that points \
                into a bound project's mapped segments gets points_to: runtime and static address, module, the \
                function and offset (code), the name there (symbol) or a string preview of at most 80 characters \
                (from the file); other values stay unannotated. No writes, no expression evaluation.",
            input_schema: schema::<RegistersArgs>(),
            effect: Effect::None,
            handler: |registry, _projects, input, _cancel| {
                let args: RegistersArgs = arguments(input)?;
                output(registry.registers_annotated(
                    &args.session,
                    args.thread.as_deref(),
                    args.names.as_deref(),
                    args.offset,
                    args.limit,
                    args.epoch,
                    args.annotate.unwrap_or(false),
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
            handler: |registry, _projects, input, cancel| {
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
                byte-fitted); at most 256 regions are listed. Modules are matched to a project by debug_bind, not \
                here, and stubs without these lists report none, with limitations saying so. Optional epoch is checked \
                (stale_epoch); refused with target_running while the target runs.",
            input_schema: schema::<ModulesArgs>(),
            effect: Effect::None,
            handler: |registry, _projects, input, _cancel| {
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
                the epoch and threads are checked again before writing. Optional epoch is checked \
                (stale_epoch); refused with target_running while the target runs; cancelling stops between memory \
                reads and writes nothing.",
            input_schema: schema::<SnapshotArgs>(),
            effect: Effect::FileWrite,
            handler: |registry, _projects, input, cancel| {
                let args: SnapshotArgs = arguments(input)?;
                if args.raw == Some(true) {
                    return output(registry.dump_at(&args.session, &args.output, &args.ranges, args.epoch, cancel));
                }
                output(registry.snapshot_at(&args.session, &args.output, &args.ranges, args.epoch, cancel))
            },
        },
        DebugTool {
            name: "debug_disconnect",
            description: DISCONNECT_DESCRIPTION,
            input_schema: schema::<DisconnectArgs>(),
            effect: Effect::Execution,
            handler: |registry, _projects, input, _cancel| {
                let args: DisconnectArgs = arguments(input)?;
                output(registry.disconnect_with(&args.session, args.kill.unwrap_or(false)))
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
                continuing after a fault usually faults again at the same pc. A stop also gets locations: the pc, \
                each matched breakpoint and the watch address in the bound projects (static address, module, \
                function and offset, show_address arguments), or null with the reason. All-stop only. No writes, no \
                signal delivery, no kill. Cancelling the call ends the wait (cancelled: true), not the run.",
            input_schema: schema::<ContinueArgs>(),
            effect: Effect::Execution,
            handler: |registry, _projects, input, cancel| {
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
            handler: |registry, _projects, input, cancel| {
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
            handler: |registry, _projects, input, cancel| {
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
                meanwhile. A step that does not finish within the request timeout leaves the target running. \
                over: true decodes the instruction at the pc with rampage's decoder (from target memory, else the \
                bound file; bytes_source says which); a call (x86 call, ARM/Thumb bl/blx, AArch64 bl/blr, RISC-V \
                jal/jalr linking ra or t0) runs to the instruction after it through a temporary hardware (else \
                software) breakpoint, waiting up to timeout_ms, and anything else single-steps; count applies. out: \
                true runs from a function's first instruction in a bound project to the ABI's return address (lr, \
                x30, ra, x86 [rsp]/[esp]); anywhere else it is refused. Arrival counts only for the same thread \
                with the frame's stack pointer (at least the call's for over, above the entry's on x86 and at least \
                it elsewhere for out); a recursive inner frame or another thread reaching the address stops there as \
                inner_frame or other_thread and nothing more runs. A temporary breakpoint is removed at the \
                next stop whatever it is (its hit, another breakpoint, a fault; after a timeout or cancel, the stop \
                debug_wait or debug_interrupt brings) and by disconnecting; a table breakpoint at the same address \
                stands in for it and stays. Breakpoints at the pc are stepped past, not hit again. Results report \
                each step's outcome (stepped, returned, stopped_elsewhere, inner_frame, other_thread, running, \
                cancelled) and the final stop's \
                locations. No signal delivery, no writes, never patches instructions. All-stop: other threads stay \
                stopped.",
            input_schema: schema::<StepArgs>(),
            effect: Effect::Execution,
            handler: |registry, _projects, input, cancel| {
                let args: StepArgs = arguments(input)?;
                let (over, out) = (args.over.unwrap_or(false), args.out.unwrap_or(false));
                if over && out {
                    return Err("invalid_argument: give over or out, not both".into());
                }
                if (over || out) && args.thread.is_some() {
                    return Err("invalid_argument: over and out step the stopped thread; thread does not apply".into());
                }
                if !(over || out) && args.timeout_ms.is_some() {
                    return Err("invalid_argument: timeout_ms applies only with over or out".into());
                }
                if over {
                    output(registry.step_over(&args.session, args.epoch, args.count, args.timeout_ms, cancel))
                } else if out {
                    if args.count.is_some_and(|count| count != 1) {
                        return Err("invalid_argument: out steps out of one function; count does not apply".into());
                    }
                    output(registry.step_out(&args.session, args.epoch, args.timeout_ms, cancel))
                } else {
                    output(registry.step(&args.session, args.epoch, args.thread.as_deref(), args.count, cancel))
                }
            },
        },
        DebugTool {
            name: "debug_breakpoints",
            description: "Breakpoints and watchpoints the stub inserts. action set (epoch, kind \
                software|hardware|write|read|access, size for breakpoints or length for watchpoints, and exactly one \
                of: address, a runtime address; static_address, an address in a bound project (path, or the only \
                binding); function, a code address or function start in a bound project by name, the user's names \
                first, then symbols, refused with candidates when it names several addresses) inserts Z0..Z4 and returns the entry with its ID and, \
                when placed statically, its placement (static address, path, module, function and offset); an \
                empty stub reply is unsupported and an E reply is target_error, and rampage never plants a software \
                breakpoint by writing memory. action clear (epoch, id) removes it (z0..z4). action list pages the \
                table (at most 64 entries, plus temporary ones of a step over or out) with kind, address, size, hit \
                count, whether the stub holds it and its placement. Breakpoint size defaults by architecture: x86 1, \
                AArch64 4, RISC-V 4 (2 for compressed), Cortex-M 2; A-profile ARM placed by static_address or \
                function follows the project's mapping of that code (2 Thumb, 4 ARM), and by address an odd address \
                means Thumb, else CPSR.T decides. Hits are counted when a stop matches: watch \
                address within a watchpoint, swbreak/hwbreak or a SIGTRAP pc after a continue at a breakpoint. \
                Detaching removes every entry. Set and clear are refused while the target runs.",
            input_schema: schema::<BreakpointsArgs>(),
            effect: Effect::Execution,
            handler: |registry, _projects, input, _cancel| {
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
                        let target = match (args.address, args.static_address, args.function) {
                            (Some(address), None, None) => {
                                unused(&[("path", args.path.is_some())])?;
                                BreakTarget::Runtime(address.0)
                            }
                            (None, Some(address), None) => BreakTarget::Static { address: address.0, path: args.path },
                            (None, None, Some(name)) => BreakTarget::Function { name, path: args.path },
                            _ => {
                                return Err("invalid_argument: set needs exactly one of address, static_address and \
                                            function"
                                    .into());
                            }
                        };
                        output(registry.set_breakpoint_at(
                            &args.session,
                            epoch()?,
                            kind,
                            target,
                            args.size,
                            args.length,
                        ))
                    }
                    BreakpointAction::Clear => {
                        unused(&[
                            ("kind", args.kind.is_some()),
                            ("address", args.address.is_some()),
                            ("static_address", args.static_address.is_some()),
                            ("function", args.function.is_some()),
                            ("path", args.path.is_some()),
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
                            ("static_address", args.static_address.is_some()),
                            ("function", args.function.is_some()),
                            ("path", args.path.is_some()),
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
