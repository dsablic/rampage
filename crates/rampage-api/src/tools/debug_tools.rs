//! The `debug` group: read-only sessions with operator-started GDB remote stubs. These tools need the per-connection
//! [`DebugRegistry`], so they are a kind of their own, served only by an MCP server started with debug endpoints.

use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

use super::{Effect, MAX_RESULT_CHARS, arguments, error_chain, schema};
use crate::{DebugRange, DebugRegistry, FileOffset};

/// A tool that works on the debug sessions of one MCP connection.
pub struct DebugTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub effect: Effect,
    handler: fn(&DebugRegistry, Value) -> Result<Value, String>,
}

impl DebugTool {
    pub fn call(&self, registry: &DebugRegistry, input: Value) -> Result<Value, String> {
        if input.to_string().len() > 65_536 {
            return Err("invalid_argument: debug tool arguments exceed 65536 bytes".into());
        }
        (self.handler)(registry, input)
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
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ModulesArgs {
    session: String,
    /// Modules to skip, for paging.
    offset: Option<usize>,
    /// Modules per page, 1..=1000 (default 64), additionally bounded to 60000 JSON bytes.
    limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SnapshotArgs {
    session: String,
    /// Absolute path of the new snapshot file, in an existing same-user 0700 directory; an existing path is refused.
    output: std::path::PathBuf,
    /// 1..=256 non-overlapping ranges to capture, each at most 16 MiB and 64 MiB in all.
    ranges: Vec<DebugRange>,
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
                Read-only: this phase never resumes, steps, sets breakpoints, writes or kills; it may not observe \
                a target that is running.",
            input_schema: schema::<ConnectArgs>(),
            effect: Effect::None,
            handler: |registry, input| {
                let args: ConnectArgs = arguments(input)?;
                output(registry.connect(args.endpoint.as_deref()))
            },
        },
        DebugTool {
            name: "debug_status",
            description: "A debug session's state (stopped, exited, detached or lost with its reason), stop epoch, \
                typed stop reply, bounded console output and a page of threads (offset/limit, byte-fitted). While \
                stopped it re-asks the stub for the stop reply (?) and threads; a different stop reply is a new \
                epoch. Does not resume or wait for the target.",
            input_schema: schema::<StatusArgs>(),
            effect: Effect::None,
            handler: |registry, input| {
                let args: StatusArgs = arguments(input)?;
                output(registry.status(&args.session, args.offset, args.limit))
            },
        },
        DebugTool {
            name: "debug_registers",
            description: "Registers of a stopped thread (the stub's current one by default; select with thread), \
                all or by name: name, regnum, bitsize, type and group from the target description, bytes exactly \
                as the stub sent them, and value decoded in the session's byte order (null when the byte order is \
                unknown or the stub marks the register unavailable). Reports the stop epoch it read at. Paged with \
                offset/limit within 60000 JSON bytes. No writes, no expression evaluation.",
            input_schema: schema::<RegistersArgs>(),
            effect: Effect::None,
            handler: |registry, input| {
                let args: RegistersArgs = arguments(input)?;
                output(registry.registers(
                    &args.session,
                    args.thread.as_deref(),
                    args.names.as_deref(),
                    args.offset,
                    args.limit,
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
                filled in. Reports the stop epoch it read at; reads are not atomic. No writes; MMIO reads go to the \
                device as the stub performs them.",
            input_schema: schema::<ReadMemoryArgs>(),
            effect: Effect::None,
            handler: |registry, input| {
                let args: ReadMemoryArgs = arguments(input)?;
                let limit = registry.tool_read_limit(&args.session).map_err(|error| error_chain(&error))?;
                if !(1..=limit).contains(&args.length) {
                    return Err(format!(
                        "invalid_argument: length must be in 1..={limit} for this session (its max_read_length); read \
                         larger ranges in pieces"
                    ));
                }
                output(registry.read_memory(&args.session, args.address.0, args.length, args.thread.as_deref()))
            },
        },
        DebugTool {
            name: "debug_modules",
            description: "Loaded modules and memory regions as the stub reports them: svr4 link-map entries (name, \
                l_addr load bias, l_ld, lm, and a GNU build ID when the module's ELF header is mapped at its load \
                bias) or Windows-style library lists (segment/section addresses), the exec file, qOffsets, and \
                memory-map regions (start, length, ram/rom/flash, flash block size). Modules are paged (offset/limit, \
                byte-fitted); at most 256 regions are listed. Modules are not matched to files or a project here, \
                and stubs without these lists report none, with limitations saying so.",
            input_schema: schema::<ModulesArgs>(),
            effect: Effect::None,
            handler: |registry, input| {
                let args: ModulesArgs = arguments(input)?;
                output(registry.modules(&args.session, args.offset, args.limit))
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
                the stop reply and threads are re-read and compared before writing.",
            input_schema: schema::<SnapshotArgs>(),
            effect: Effect::FileWrite,
            handler: |registry, input| {
                let args: SnapshotArgs = arguments(input)?;
                output(registry.snapshot(&args.session, &args.output, &args.ranges))
            },
        },
        DebugTool {
            name: "debug_disconnect",
            description: "Detach from the target (D, or D;pid per process in multiprocess mode) and close the \
                session, returning its final state. Detaching lets the target run: a stopped or QEMU -S guest \
                resumes. It never kills it. If the stub refuses (E nn), the session stays open and attached \
                (detached: false, closed: false) and disconnecting can be retried.",
            input_schema: schema::<SessionArgs>(),
            effect: Effect::None,
            handler: |registry, input| {
                let args: SessionArgs = arguments(input)?;
                output(registry.disconnect(&args.session))
            },
        },
    ]
}
