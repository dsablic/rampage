# Debug sessions with GDB remote stubs

Rampage's MCP server can connect to a GDB Remote Serial Protocol stub that an operator has already started:
`gdbserver` on Linux or Android, QEMU's `-s`/`-gdb` stub, OpenOCD, probe-rs and similar. An agent can then read
the stopped target's registers, memory, threads, loaded modules and memory map, capture it to a snapshot file
that every runtime and analysis tool opens, and control its execution: continue, wait, interrupt, single-step, and
set breakpoints and watchpoints. With a project bound to the target, it can also place breakpoints by function name
or static address, see stops and register values in the project's terms, and step over calls or out of functions.

These are steps 9.1 (inspection), 9.2 (execution control), 9.3 (static correlation) and 9.4 (target writes and
kill) of the [debugger design](plans/2026-10-29-debugger-control.md). Rampage never launches or attaches to a
process, delivers a signal or enters non-stop mode, and the protocol client keeps every such packet off the wire.
It writes registers or memory, or kills a target, only when a tool asks for it and the operator started it with
`--debug-writes` or `--debug-kill`; see [Writes and kill](#writes-and-kill).

## Setup

Start the stub yourself, then start the MCP server with the endpoint allowed.

A Linux program under gdbserver:

```sh
gdbserver :2345 ./prog
rampage mcp --debug-endpoint 127.0.0.1:2345
```

Firmware in QEMU system mode, halted at reset:

```sh
qemu-system-arm -M lm3s6965evb -kernel fw.elf -nographic -s -S
rampage mcp --debug-endpoint 127.0.0.1:1234
```

QEMU's `-s` listens on TCP port 1234.

An endpoint is either `host:port` or `unix:` followed by an absolute socket path. Repeat `--debug-endpoint` to
allow several endpoints, or set `RAMPAGE_DEBUG_ENDPOINTS` to a comma-separated list. Endpoints from the flag and
from the variable are combined.

## Consent

Three operator settings decide what agents may do. All are off by default.

| Flag | Variable | Allows |
|---|---|---|
| `--debug-endpoint ENDPOINT` (repeatable) | `RAMPAGE_DEBUG_ENDPOINTS` (comma-separated) | Connecting to that stub, inspecting it and controlling its execution (continue, step, interrupt, breakpoints) |
| `--debug-writes` | `RAMPAGE_DEBUG_WRITES=1` | The write tools, `debug_write_memory` and `debug_write_register` |
| `--debug-kill` | `RAMPAGE_DEBUG_KILL=1` | `debug_disconnect` with `kill: true` |

`--debug-writes` and `--debug-kill` (or their variables) without any endpoint stop the server at startup with an
error, since they would allow nothing. A variable set to anything but `1`, `0` or empty is also a startup error.

Listing an endpoint is the operator's consent for agents to inspect that stub and to control its execution; there
is no separate flag for execution control. The MCP client's own per-tool prompts still apply on top, and the tools'
MCP annotations mark execution control and writes as changing the target. The rules:

- Without an allowed endpoint the server has no `debug` group. `enable_tools` does not list it, its tools are
  absent from `tools/list`, and calls to them fail as unknown tools.
- An agent can connect only to an allowed endpoint. Its `endpoint` argument must match a listed endpoint exactly,
  as text: `localhost:2345` does not match `127.0.0.1:2345`. The argument may be omitted when exactly one endpoint
  is allowed. Agents cannot supply an address of their own.
- A non-loopback address works only because the operator listed it. `debug_connect` reports `local_endpoint`.
- Without `--debug-writes` the write tools do not exist: they are not in `tools/list` or in `enable_tools`, and
  calls to them fail as unknown tools. Without `--debug-kill`, `debug_disconnect`'s schema has no `kill` argument,
  and `kill: true` is refused with `not_allowed`, naming the flag, before anything is sent.
- Each layer checks on its own. The tool list follows the flags; the registry refuses a write or kill its consent
  does not allow (`not_allowed`); every session is configured with the same consent and refuses such requests
  itself; and the protocol client sends write packets (`M`, `X`, `P`, `G`) only for a write request and kill
  packets (`k`, `vKill`) only for a kill request.
- Even with the flags, rampage writes only when a write tool is called and kills only on `kill: true`. Nothing
  writes on its own: breakpoints are the stub's (`Z0`..`Z4`), never planted by writing memory.
- A Unix socket in a shared directory such as `/tmp` can be removed and replaced by another local user, who then
  receives the connection. Put stub sockets in a private directory (mode `0700`).
- The desktop assistant and `rampage-agent` are not offered the debug tools.

When the server starts with the endpoint allowed, the `debug` group is still disabled until `enable_tools`
enables it, or until the server is started with `--all-tools`, `RAMPAGE_MCP_TOOLS=all` or `RAMPAGE_MCP_TOOLS=debug`.

## Sessions

`debug_connect` returns a session ID such as `s1`. A session is a thread that owns the connection and serves one
request at a time.

- Each MCP connection may hold at most four sessions. A slot is reserved before connecting, so concurrent
  connects never exceed four.
- `debug_disconnect`, or the end of the MCP connection, removes every inserted breakpoint and watchpoint (best
  effort; failures are reported) and sends `D` (detach). A running target is interrupted first and waited for up
  to 3 s (1 s when the connection ends); if it never stops, rampage closes the socket without detaching and the
  session is `lost`. **Detaching lets the target run**: a program under gdbserver continues, and a QEMU guest
  started frozen with `-S` starts executing. Rampage kills a target only on `debug_disconnect` with `kill: true`
  (see [Kill](#kill)). When the connection ends, every session starts detaching at once and the server waits at
  most 2.5 s in all.
- If the stub refuses `D` (`E nn`), `debug_disconnect` reports `detached: false` and `closed: false`; the session
  stays open and attached, and disconnecting can be retried. Its breakpoints and watchpoints are already removed
  by then (`breakpoints_removed` counts them). In multiprocess mode `detach_error` names the processes already
  detached, and a retry detaches only the processes still attached.
- A handshake that fails while the stream is still in step (a malformed stop reply, say) sends `D` before
  closing, because some stubs (`gdbserver --once`) kill their program when a debugger simply disconnects.
- A session is `stopped`, `running`, `exited`, `killed`, `detached` or `lost`. A lost session carries the reason, such as a
  timeout, a dropped connection or a malformed reply. A timed-out request loses the session, because the reply
  stream can no longer be trusted to match requests.
- Each stop gets a stop epoch; see [Running, stopped and epochs](#running-stopped-and-epochs). Every read reports
  the epoch it read at.
- A read without `thread` selects the stop reply's thread (else the first listed thread), never whatever an
  earlier request selected, and reports the thread it used.

Reads are separate requests, so a set of them is not atomic. Anything else that can change the target, such as
another debugger on the stub, DMA or other cores, can change memory between reads.

## Tools

| Tool | Arguments | Result |
|---|---|---|
| `debug_connect` | `endpoint?`, `path?`, `module?`, `slide?` | Session ID, architecture, `endianness` and its evidence, pointer size, the stub's `qSupported` features, packet size, state, typed stop reply, epoch, a page of threads, whether modules and a memory map are available, limitations; with `path`, the `binding` or `binding_error` |
| `debug_bind` | `session`, `path`, `module?`, `slide?` | The binding: module, path, arch, slide, evidence, verification, limitations; whether it replaced one |
| `debug_status` | `session`, `offset?`, `limit?` | State (with `reason` when lost), epoch, stop reply, bounded console output, the bindings, a byte-fitted page of threads |
| `debug_registers` | `session`, `thread?`, `names?`, `offset?`, `limit?`, `annotate?` | Per register: name, regnum, bitsize, type, group, `bytes` as sent and `value` decoded; with `annotate`, `points_to` |
| `debug_read_memory` | `session`, `address`, `length` (1..=`max_read_length`), `thread?` | Hex runs of the bytes read, the thread used, plus every chunk's address, requested and read counts, and error |
| `debug_modules` | `session`, `offset?`, `limit?` | Modules and memory-map regions, the exec file and `qOffsets` |
| `debug_snapshot` | `session`, `output`, `ranges` | A new `rampage-snapshot-v1` file |
| `debug_continue` | `session`, `epoch`, `timeout_ms?` (default 5000, at most 60000) | A [stop event](#stop-events), its [locations](#stop-locations) and the new epoch, or `state: "running"` |
| `debug_wait` | `session`, `timeout_ms?` | The same shape as `debug_continue` |
| `debug_interrupt` | `session` | The same shape, after waiting up to 3 s for the stop |
| `debug_step` | `session`, `epoch`, `thread?`, `count?` (1..=1000, default 1), `over?`, `out?`, `timeout_ms?` | Requested and completed steps, the pc after each completed step (over and out: each step's outcome), the final stop event, its locations and epoch |
| `debug_breakpoints` | `session`, `action` (`set`, `clear`, `list`), and per action: `epoch`, `kind`, one of `address`, `static_address` or `function` (with `path?`), `size` or `length`, `id`, `offset`, `limit` | The entry set or cleared, or a byte-fitted page of the table |
| `debug_evidence` | `session`, `epoch?`, `names?`, `memory?` | Endpoint, epoch, thread, the pc and its location, up to 8 registers and 4 memory ranges, and a `ledger_evidence` item for `record_finding` |
| `debug_disconnect` | `session`, `kill?` (only with `--debug-kill`) | The final state, `detached`, `closed`, any detach error, `breakpoints_removed` and `removal_failures`; with `kill: true`, `kill` instead of detaching |
| `debug_write_memory` (only with `--debug-writes`) | `session`, `epoch`, `address`, `bytes` (hex, 1..=4096 bytes), `expect?` (hex, same length) | `before`, `after`, every packet's outcome in `chunks`, `complete`, `verified`, the unchanged epoch |
| `debug_write_register` (only with `--debug-writes`) | `session`, `epoch`, `thread?`, `name`, `value` (hex bytes, target-endian, or an integer) | `before`, `after` (bytes), `before_value`, `after_value`, `packet` (`P` or `G`), `verified` |

`debug_registers`, `debug_read_memory`, `debug_modules` and `debug_snapshot` also take an optional `epoch`, refused
with `stale_epoch` when the session is at another one.

## Execution control

### Running, stopped and epochs

Rampage drives the stub in all-stop mode: every thread resumes together and stops together.

- `debug_continue` resumes every thread with `vCont;c`, or `c` when the stub's `vCont?` reply does not offer `c`.
  It never delivers a signal: a target stopped by a fault usually faults again at the same pc when continued.
- A thread stopped at an inserted breakpoint would hit it again at once (QEMU and OpenOCD report the same
  breakpoint forever). So when the stopped thread's pc holds an inserted software or hardware breakpoint,
  `debug_continue` first steps past it: it removes the breakpoint (`z`), single-steps that thread, puts the
  breakpoint back (`Z`) at the step's stop, and only then resumes. The step is a stop and an epoch of its own. If
  the step stops for another reason (a fault, a watchpoint, an exit), that stop is the continue's answer and
  nothing is resumed. A breakpoint the stub will not take back is reported in `warnings` and listed as not
  inserted. If the step itself does not finish in time, the continue returns `running` and the breakpoint goes
  back at the next stop.
- Without `vCont`, a step selects its thread with `Hc<thread>`, and some stubs (gdbserver) then resume only that
  thread on a plain `c`. Before such a `c`, rampage sends `Hc-1` (all threads); a stub that refuses it is not
  continued and the call fails with `unsupported`.
- After a resume the session is `running`. Its thread keeps reading the stub between requests: console output
  (`O` packets, kept up to 4 KiB per run), notifications (ignored) and finally the stop reply.
- While the target runs, only `debug_status`, `debug_wait`, `debug_interrupt` and `debug_disconnect` are served.
  Every other tool fails with `target_running`, and `debug_status` reports `running_for_ms` without touching the
  stub.
- `debug_continue` and `debug_wait` wait up to `timeout_ms`. If no stop arrives in time they return
  `state: "running"`, and the target keeps running. A stop that arrives later is recorded and shown by
  `debug_status` (`last_stop`) and `debug_wait`. A wait on a target that is not running returns its last stop at
  once.
- `debug_interrupt` first takes a stop reply already on its way (a few milliseconds), so a target that has just
  stopped is not interrupted again. Otherwise it sends the out-of-band `0x03` byte, on every call, and waits up to
  3 s. A stub that does not stop leaves the session `running`. On a stopped target it fails with `not_running`.
  Only a SIGINT (or signal 0) stop after an interrupt is reported as `interrupted`; a fault that arrives instead
  stays a `signal`.
- `debug_status` reports `waiting`: how many continue, wait or interrupt calls are waiting for the stop.
- Each stop rampage observes (after a continue, each step and an interrupt) increments the epoch. Execution tools
  take the caller's `epoch` and fail with `stale_epoch`, which names the current epoch and state, when they differ.
  Reads take it optionally. An agent therefore never steps or sets breakpoints on a picture of the target that is
  out of date.
- Rampage asks the stub for its stop reply (`?`) only once, when connecting. QEMU takes `?` for a new debugger
  connecting and removes every breakpoint and watchpoint it holds, so asking again would silently drop the
  session's. While stopped, `debug_status` reports the session's own record of the stop and re-reads only the
  threads, which also shows the connection is alive. In all-stop mode a stopped target does not stop again until
  rampage resumes it; a stop caused by something else on the stub (another debugger) is not detected.
- A resume the stub refuses (an `E nn` or empty reply instead of a stop) leaves the target stopped at the same
  epoch and fails with `target_error` or `unsupported`.
- An exit (`W`) or termination (`X`) ends the process: the session is `exited`, and its breakpoints are marked
  not inserted.

### Stepping

`debug_step` steps one thread: the given `thread`, else the stop's thread, else the first listed. It sends
`vCont;s:<thread>` when `vCont?` offers `s`, else `Hc<thread>` then `s`. Other threads stay stopped.

- Steps run one resume at a time through the session's main loop, so `debug_status`, `debug_wait`,
  `debug_interrupt` and `debug_disconnect` are served between and during them; the session is `running` meanwhile.
  An interrupt ends the request after the current step, and a disconnect ends it at once.
- A step completes when the same thread stops with SIGTRAP and no breakpoint or watchpoint reason. Each completed
  step is counted and its pc is recorded.
- Any other stop ends the request early and is not counted: a watchpoint or reported breakpoint, another signal,
  another thread, or an exit. The final stop event says which.
- A step that does not finish within the 10 s request timeout leaves the target running; use `debug_wait` or
  `debug_interrupt`. No step of a request starts more than 60 s after it began (`truncated` says so), so a request
  takes at most 60 s plus one step's 10 s.
- Each step is a stop, so stepping `count` instructions moves the epoch by up to `count`.
- A plain step does not take breakpoints at the pc out first; QEMU executes the instruction anyway, other stubs
  may report the breakpoint again. Stepping over (below) does take them out.
- `over` and `out` are described under [stepping over and out](#stepping-over-and-out).

### Breakpoints and watchpoints

`debug_breakpoints` with `action: "set"` inserts:

| `kind` | Packet | Meaning |
|---|---|---|
| `software` | `Z0` | A breakpoint the stub plants in its own way |
| `hardware` | `Z1` | A hardware breakpoint |
| `write` | `Z2` | A write watchpoint |
| `read` | `Z3` | A read watchpoint |
| `access` | `Z4` | A read-or-write watchpoint |

- `address` is a runtime address. With a [bound project](#binding-a-project), `static_address` (an address as the
  project tools show it) or `function` (a name) places it instead; see [placing breakpoints](#placing-breakpoints).
- An empty reply means the stub does not support that kind (`unsupported`); an `E nn` reply means it refused this
  one (`target_error`). Rampage never emulates a software breakpoint by writing an instruction into memory. On a
  stub without `Z0`, try `hardware`.
- A session holds at most 64 entries. Setting the same kind, address and size twice is refused.
- Watchpoints take `length`, 1..=4096 bytes; the stub may support fewer.
- Breakpoints take `size`, the instruction size the stub receives as the `Z` kind. The default comes from the
  architecture:

| Architecture | Default `size` | Accepted |
|---|---|---|
| x86, x86-64 | 1 | 1 |
| AArch64 | 4 | 4 |
| RISC-V 32/64 | 4 | 2 (a compressed instruction), 4 |
| ARM M-profile (Cortex-M) | 2 (Thumb) | 2, 3 (32-bit Thumb-2) |
| ARM A/R-profile | 2 in Thumb state, 4 in ARM state, from CPSR.T of the stopped thread | 2, 3, 4 |
| Other | none: `size` is required | 1, 2, 3, 4, 8 |

  On ARM an odd address names Thumb code: rampage clears bit 0 and uses size 2 unless told otherwise. A-profile
  ARM with an unreadable or undecodable CPSR needs an explicit `size`.
- `action: "clear"` sends the matching `z` packet and drops the entry; a refused removal keeps it. Entries of an
  exited process are dropped without a packet.
- `action: "list"` pages the table: ID, kind, address, size, hit count, whether the stub holds the entry, its
  `placement` when it was placed statically, and `temporary: true` for a step's temporary breakpoint not yet removed.

### Stop events

A stop event reports:

- `reason`: `breakpoint`, `watchpoint`, `step`, `temporary_breakpoint` (a step over or out arrived, and no table
  breakpoint explains the stop), `interrupted`, `signal`, `exited` or `terminated`.
- `signal`, `exit_status`, `thread`, and the stop reply as parsed.
- `pc`: the stopped thread's pc, from the stop reply's expedited registers, else read with `p` (or `g`), decoded in
  the session's byte order. It is null when the byte order is unknown (AArch64, RISC-V); `pc_bytes` always has the
  bytes as sent.
- `breakpoints`: the IDs of the table entries the stop matched. Each match increments the entry's hit count.
- `watch`: the access and address of a watchpoint hit.
- `reasons`: at most 16 of the stop reply's reasons. Its expedited registers are not repeated (a stub may send
  1,024 fields of 4 KiB); read them with `debug_registers`.
- `epoch`: the epoch this stop started, `console`: output received while the target ran, and `warnings`.
- `temporary`: the temporary breakpoints this stop removed (or failed to remove), each with `hit` and `removed`.

`debug_status` and `debug_connect` give the stop reply with at most 32 short expedited registers and 16 reasons,
and `debug_status` leaves `console` out of `last_stop`, since its own `console` already holds it. Every result
stays within the 60,000-byte budget whatever the stub sends.

Stops are matched to the table like this:

- A `watch`, `rwatch` or `awatch` hit matches watchpoints whose range holds the reported address and whose access
  fits (`awatch` can match any of them).
- `swbreak` or `hwbreak` matches software or hardware breakpoints at the pc.
- Without either, a SIGTRAP after a continue matches every breakpoint at the pc. QEMU reports breakpoint hits this
  way. With an unknown byte order the pc's bytes are compared in both orders.
- A SIGTRAP after a step does not match by pc, because a completed step and a breakpoint at the next instruction
  look the same.

### Cancellation

The MCP server passes a cancellation flag to every debug tool. It is set when the client sends
`notifications/cancelled` for the call, or when the connection closes. The flag cancels the wait, not the target:

- `debug_continue`, `debug_wait` and `debug_interrupt` return at once with `state: "running"` and
  `cancelled: true`. The stop, when it comes, is recorded as usual.
- `debug_step` stops taking steps; a step in flight is left running.
- `debug_read_memory` and `debug_snapshot` stop between chunks and fail with `cancelled`. A cancelled snapshot
  writes nothing.

Every wait is bounded whether or not the client cancels.

### Threads and registers

Thread IDs use the protocol's spelling: `1f`, or `p<pid>.<tid>` when the stub is in multiprocess mode. Pass them as
`debug_status` lists them. Registers come from the stub's target description (`target.xml` and its includes). If
the stub has no target description, rampage uses GDB's built-in layout for x86-64, AArch64, ARM or RISC-V 32/64,
but only when the `g` reply has exactly that layout's size, and says so in `limitations`. Registers missing from
the `g` reply are read one at a time with `p`.

### Endianness

`value` is decoded only when evidence from the stopped target establishes the data byte order:

- x86 and x86-64 are little-endian only.
- On Cortex-M, the System Control Space is little-endian whatever the data order, so AIRCR reads back
  VECTKEYSTAT 0xFA05 in its upper bytes and its ENDIANNESS bit (15) gives the data order. A read that does not show
  0xFA05 leaves the order unknown.
- On ARM A and R profiles, CPSR.E and the mode bits are consistent with only one byte order.

AArch64 and RISC-V report `unknown`, because their registers do not expose the data endianness, as described in
[runtime data order](runtime-data-order.md). Their `value` is null and `bytes` are exactly as the stub sent them.
Architecture defaults are never used in place of evidence.

### Memory

Reads are split into chunks that fit the stub's packet size. Rampage uses binary `x` reads when the stub
advertises `binary-upload+`, and hex `m` reads otherwise.

- A short reply or an error reply is reported on its chunk. Nothing is filled in.
- The API accepts up to 64 KiB per read. The MCP tool accepts up to the session's `max_read_length`, which
  `debug_connect` reports: the most bytes whose hex and per-chunk reports fit the 60,000-byte result budget. It
  shrinks with the packet size: about 28 KiB with large packets, 26 KiB at the 2 KiB default and 3.6 KiB at a
  64-byte packet size.
- A read that would run past the top of the address space is refused.
- Memory-mapped registers are read the way the stub reads them, and a read can have device side effects.

### Modules and memory maps

Each list is read only when the stub advertises it:

- `qXfer:libraries-svr4:read`: link-map entries with name, `l_addr` load bias, `l_ld` and `lm`.
- `qXfer:libraries:read`: Windows-style entries with segment or section addresses.
- `qXfer:exec-file:read` and `qXfer:memory-map:read`: the program path, and ram, rom and flash regions with
  flash block sizes.

`qOffsets` is always asked for, and an empty reply is accepted. A module's GNU build ID is reported when its ELF
header is mapped at its load bias, which holds for shared objects and PIE executables. `debug_modules` does not
match modules to files; `debug_bind` does.

### Snapshots

`debug_snapshot` captures between 1 and 256 non-overlapping ranges, each at most 16 MiB and 64 MiB in all. The
snapshot also records every thread's registers of up to 64 bits (at most 64 threads), svr4 modules, and the
architecture and data byte order. The file uses the format in [runtime snapshots](runtime-snapshots.md).

- `permissions` defaults to `rw-`, which asserts neither immutability nor code. Pass `r-x` for code.
- `thumb` defaults to true for executable ranges on M-profile ARM, which runs only Thumb code.
- `output` must be a new absolute path in an existing same-user `0700` directory. The file is published
  atomically with mode `0600` and never overwrites an existing file.
- A range that is not fully readable is refused. A snapshot never records partial regions.
- Registers and modules are gathered and checked against the snapshot format's limits before any memory is read:
  at most 4,096 register entries and 4,096 modules, module identities of at most 128 bytes, and at most 1 MiB of
  JSON for everything except memory.
- The stop reply and the thread list are re-read after the capture; if either changed, nothing is written.
- Register `thread_id` is the thread ID; with several processes it is `pid << 32 | tid`, so their threads stay
  apart.
- A module's identity is `gnu-build-id:<hex>` (the bare hex when the prefix would exceed 128 bytes), else
  `gdb-link-map:<lm>`.
- Snapshots are refused when the data byte order is unknown, or when the architecture has no rampage equivalent.
- Modules record `image_base` 0 and `runtime_base` equal to the svr4 `l_addr`. This keeps the load bias (the
  slide), not header addresses.
- No entry point or seeds are recorded.

## Static correlation

### Binding a project

`debug_bind { session, path, module?, slide? }` binds a binary to one runtime module of a session. The binary opens
the way the project tools open it, in the MCP server's project cache, so a binding and a `decompile` of the same
path share one project and its names. It must be the original image (not a snapshot) and of the target's
architecture (`arch_mismatch` otherwise); for a universal Mach-O the target's architecture picks the slice.
`debug_connect` with `path` connects and then binds; a binding that fails leaves the session open and reports
`binding_error`.

Modules from `debug_modules` are matched in order of evidence, and the evidence that matched is reported:

| Evidence | How |
|---|---|
| `build_id` | The ELF file's GNU build ID equals the module's, as the stub's module list reports it or as rampage reads it from the ELF headers and notes mapped at the module's load bias |
| `uuid` | The Mach-O file's `LC_UUID` equals the one read from the module's mapped header |
| `path`, `basename` | The module's reported path (or, for the main program with no name, the exec file) equals the project's path, or only their file names are equal |
| `header_bytes` | The module's mapped header bytes (up to 256) equal the file's first bytes |
| `mapped_bytes` | The stub lists no modules (bare-metal firmware): every verification window (below) is readable and equal at the slide (`qOffsets` `Text`, else 0, or the caller's), at least 16 bytes in all |
| `explicit_slide` | Nothing matched and the caller gave `slide` |

`module` restricts the match to a module with that path or file name; for a target without a module list it is the
binding's label, and it must name exactly one module (`ambiguous_module` otherwise). Several modules matching
equally well are refused (`ambiguous_module`) unless `module` picks one. A target whose architecture has no rampage
equivalent cannot be checked against the project and binds only with an explicit `slide`.
Without a match the bind is refused (`no_module_match`) unless the caller gives `slide`: rampage never binds
silently on a weak match.

**Slide.** `runtime = static + slide`, wrapping at the pointer width. For svr4 modules (Linux, Android) the slide is
the link map's `l_addr`. For library lists that give segment or section addresses (Windows-style, Mach-O), it is that
address minus the file's header address, or minus its first section's address: every stage (identity, name,
header bytes) verifies each candidate and keeps the first that matches. A caller's `slide` overrides the computed
one, and the difference is reported.

**Verification.** Rampage compares windows of up to 32 bytes of the file with target memory at the slide: the entry
point, the start, middle and end of every executable segment's file bytes (at most 8 segments) and up to 16
function entries spread over the image. It reports `matched` (at least one window read and none differs; unreadable
windows are counted in `detail`), `mismatched` (any window differs), `unreadable` (none could be read) or
`no_file_bytes`. Comparing many places catches a rebuilt image that shares its first bytes (a vector table, a
header) with the one running, though an edit outside every window still goes unnoticed:

- `mismatched` refuses the bind (`slide_mismatch`) unless `slide` was given; then it binds with the failure in
  `limitations`.
- `unreadable` or `no_file_bytes` binds with a limitation when the evidence identifies the image (build ID, UUID,
  header or mapped bytes) or the slide is explicit, and refuses (`slide_unverified`) when only a name matched.

Target memory can differ from the file for good reasons (relocations, self-modifying code, a stub's own breakpoint
instructions), so a verified slide shows that the compared window matches, not that the whole image does.

A session binds at most 8 projects, one per module; binding the same module again replaces it. `debug_status` lists
the bindings, and they end with the session (a bind that finishes after a disconnect is refused). Binding runs the
project's whole-program analysis, so the execution tools that follow only use its cached result and never wait for
it; a failed analysis is a limitation, and locations then have a null `function` with `function_note`. Like the
project tools, bindings reread the annotation log before resolving names or locating addresses, so names other
clients saved since are seen.

### Placing breakpoints

`debug_breakpoints` with `action: "set"` takes exactly one of:

- `address`: a runtime address, as before;
- `static_address`: an address in a bound project, with `path` naming the project (it may be omitted when one is
  bound). It must fall in a mapped segment;
- `function`: a name in a bound project: a user name first, then the loader's symbol, export, stub and import
  names, then `sub_<hex>`. It must name code or a known function start; a data symbol or an import slot is refused
  (`not_code`). A name at several addresses (two static functions in different files, say) is refused
  with `ambiguous_name` and at most 16 `name@address` candidates; place it by `static_address` instead. Without
  `path`, every bound project is searched, and a name found in several is refused.

The entry records its `placement`: the static address, path, module, function and offset in the function (null when
the address lies below the function's start, in a cold part). On A-profile ARM, a breakpoint's kind follows the
project's mapping of the code it is placed in (2 for Thumb, 4 for ARM), not the state the target is stopped in;
watchpoints take the exact data address.

### Stop locations

A stop event from `debug_continue`, `debug_wait`, `debug_interrupt` or `debug_step` comes with `locations`:

- `pc`, each matched breakpoint and the watch address, each as `{ runtime_address, location, reason }`;
- `location` is `{ runtime_address, static_address, module, path, function, function_address, offset_in_function,
  show_address }` when the address falls in a bound project's mapped segments. `function` is what project tools
  call the function containing it (from the project's analysis; null outside every function found), and
  `show_address` holds the arguments for the `show_address` tool;
- otherwise `location` is null and `reason` says why: nothing is bound, the address is outside every bound module,
  or the pc could not be read.

When the session's byte order is unknown (AArch64, RISC-V), the pc's two decodings are tried and the one inside a
bound module is used, as `pc_evidence` says; if neither or both are, the pc is not located. `debug_status`'s
`last_stop` is not located.

### Register annotations

`debug_registers` with `annotate: true` adds `points_to` to each register whose value (at most 64 bits, not 0, and no
wider than the target's addresses) falls in a bound project's mapped segments: the location as above, a `kind` (`code` inside a function, `string`, `symbol`
or `data`), the name at exactly that address, and for non-code a string preview of at most 80 printable ASCII
characters read from the file. Values elsewhere stay unannotated. Small integers in an image linked at a low
address (firmware at 0) are annotated too: annotation says where a value would point, not that it is a pointer.
With an unknown byte order, values are read in the order that puts the pc inside a bound module, as `limitations`
says, and not at all when the pc does not settle it.

### Stepping over and out

`debug_step` with `over: true` steps the stopped thread `count` times (1..=1000; a call and its return count as one):

1. It reads the pc and the instruction bytes at it from target memory (15 bytes on x86, 4 elsewhere), and decodes
   them with rampage's decoder: the bound project's when the pc is in one, else the session architecture's raw
   decoder. ARM state is Thumb on M-profile, else CPSR.T, else the project's Thumb ranges. When target memory is
   unreadable or does not decode (a stub's own breakpoint instruction, say), the file's bytes are used;
   `bytes_source` says which.
2. A call runs to the instruction after it: rampage places a temporary breakpoint at `pc + length` (hardware,
   falling back to software; never by writing memory), continues, and waits up to `timeout_ms` (default 5000).
   Calls are x86 `call`, ARM/Thumb `bl`/`blx`, AArch64 `bl`/`blr` and RISC-V `jal`/`jalr` linking `ra` (or `t0`, the
   ABI's alternate link register), conditional ones included. Breakpoints at the pc are stepped past first, as
   `debug_continue` does.
3. Anything else is one instruction step, with breakpoints at the pc taken out for the step and put back at its
   stop.

`debug_step` with `out: true` runs from a function's first instruction to its return address.
On A-profile ARM the temporary breakpoint's kind follows the destination's state: Thumb for a call made in Thumb
state or an odd `lr`, ARM (size 4) otherwise. The rule: **the pc
must be the first instruction of a function in a bound project** (the start of a function the project's analysis
found, or of a function symbol), where the return address is still where the ABI puts it on entry: ARM/Thumb `lr`
(refused when it is an M-profile `EXC_RETURN` value, since exception handlers return by exception return), AArch64
`x30`, RISC-V `ra`, x86-64 `[rsp]` and x86 `[esp]` (read from target memory). Anywhere else the return address may
have been saved and overwritten, so `out` is refused (`step_out_refused`) with the function and offset. `out` takes
no `count`; neither `over` nor `out` takes `thread`.

Temporary breakpoints:

- A temporary breakpoint is removed at the next stop, whatever the stop is: its own hit (`reason:
  "temporary_breakpoint"`), a user breakpoint or watchpoint, a fault, an interrupt or an exit. The stop event's
  `temporary` list says whether it was hit and removed.
- If the run does not stop within `timeout_ms`, or the call is cancelled, the target keeps running with the
  temporary breakpoint inserted; the result is `running` with a warning, and the stop that `debug_wait` or
  `debug_interrupt` later brings removes it. Disconnecting removes it too.
- If the continue fails before anything runs, the temporary breakpoint is removed at once.
- A breakpoint of the table already at the return address stands in for the temporary one: none is inserted, the
  stop is that breakpoint's hit (counted), and it stays. A temporary breakpoint therefore never removes a user's.
- At most 4 temporary breakpoints wait for removal at a time (a stub that refuses to remove them leaves them in the
  table, marked temporary, and they are tried again at every stop).

Each step's result gives its pc, length, flow, `bytes_source`, return address, the temporary or user breakpoint
used, and its `outcome`: `stepped`, `returned`, `stopped_elsewhere` (another stop came first), `running` or
`cancelled`. The request stops at the first step that is not `stepped` or `returned`. The last 32 steps are listed
(`steps_omitted` counts the rest), no step starts after 60 s, and the final stop comes with its locations.

Arrival at the return address is checked against the frame and thread. Rampage records the thread and the stack
pointer when it places the temporary breakpoint, and at the hit requires the same thread and a stack pointer at least
the call's (over) or the entry's (out; above it by the popped return address on x86). A recursive inner frame
reaching the same address has a lower stack pointer and is reported as `inner_frame`; another thread as
`other_thread`. Either way the request stops there (it does not run on looking for the right frame) and says so in
`warnings`; the temporary breakpoint is already gone. When the stack pointer cannot be read the hit is accepted with
a warning that the frame was not checked.

### Evidence for findings

`debug_evidence { session, epoch?, names?, memory? }` returns a bounded record of the stopped target: endpoint,
session, epoch, thread, the pc and its location, up to 8 registers (by default the pc, stack pointer,
return-address register and the first argument registers) and up to 4 memory ranges of at most 64 bytes.
`ledger_evidence` is an evidence item `record_finding` takes as is: `{ tool: "debug_evidence", detail }`, where
`detail` is a compact text form of the record within the ledger's 300 bytes: the location, then the memory, then
the registers; items that do not fit are left out whole, counted in the detail and named in `limitations`. The
ledger stores only
that item; the structured record is in the tool result, not in the ledger, because ledger evidence is a reference to
a tool call and its outcome rather than a data store.

## Writes and kill

Step 9.4. Everything here needs the operator's flag (see [Consent](#consent)), and nothing here happens unless a
tool is called for it. Writes and kill are destructive and not idempotent; their MCP annotations say so.

### Memory

`debug_write_memory` writes 1 to 4096 bytes at a runtime address of a stopped target:

1. The epoch is checked (`stale_epoch`), and a running target is refused (`target_running`).
2. If a software breakpoint (`Z0`) covers any byte of the range, the write is refused and nothing is sent. The stub
   keeps the bytes it replaced and puts them back when the breakpoint is removed, so writing under it would be
   undone or would corrupt what it saved. Temporary breakpoints of a step over or out count too. Hardware
   breakpoints and watchpoints keep no bytes and do not stand in the way.
3. The bytes there are read first. If they cannot all be read, nothing is written. If `expect` is given and the
   target holds anything else, the write is refused with `expect_mismatch` (the message gives what is there), and
   nothing is written. This is a compare-and-set guard against acting on a stale view; it is not atomic with the
   write.
4. The bytes are written one packet per chunk of the stub's packet size: `X` (binary) while the stub takes it,
   else `M` (hex). A stub that answers `X` with an empty reply does not support it and wrote nothing; the session
   then uses `M` for that chunk and every later write. Writing stops at the first chunk the stub does not accept,
   and nothing is retried. `chunks` lists every packet sent with its address, length, packet and outcome, so a
   partial write says exactly which chunks were written. A connection lost mid-write ends the session, and the
   error names the chunks written before it.
5. The range is read back. `verified` is true only when every chunk was accepted and the read-back equals the
   bytes written. Stubs often accept a write to flash or ROM and drop it, and a device register may read back
   differently; `verified: false` is how that shows.

A write does not change the epoch: the target has not stopped again. The session caches no memory, so later
reads, step over's instruction decoding and `debug_snapshot` see the written bytes; a snapshot taken after a write
records them. The only registers it keeps are those the stub sent with the stop reply (gdbserver sends the pc);
see [Registers](#registers) for how a register write drops them. Bound projects are not re-verified: when a write falls in a bound module, the result
says that the project's file no longer matches the target there.

### Registers

`debug_write_register` writes one register of a stopped thread (the stop's thread by default). `value` is either
a hex string of the register's bytes in the order the stub transfers them, exactly its size and without `0x` (the
form `debug_registers` reports as `bytes`), or an integer. An integer is accepted only when the session's
endianness is known, as for `value` in reads, and must fit the register's bitsize; otherwise it is refused and
the hex form is needed.

The session uses `P` when the stub supports it. Otherwise it reads every register with `g`, changes only this
one, and writes them all back with `G`; that is refused when the `g` reply marks registers unavailable (`xx`) or
does not include this one, because `G` would write values nobody read. The registers are then read back:
`verified` is false when the register reads back differently, as when hardware ignores or masks the write.

Writing the pc does not resume. The epoch does not change. A successful register write drops the registers the
stub sent with the stop reply (`debug_status` then shows the stop without them), so whatever needs the pc next,
such as a continue stepping past a breakpoint at the pc, reads it again with `p` and sees the written value. The
last stop event keeps the pc it was observed with, as a record of that stop; read registers with
`debug_registers`.

### Kill

`debug_disconnect` with `kill: true` kills the target instead of detaching. A running target is interrupted and
waited for as for a detach, and every breakpoint and watchpoint is removed. Then `vKill;<pid>` is sent per
process in multiprocess mode, else `k`. The result's `kill` object gives `killed` (every packet confirmed), the
`packets` sent, the ones the stub `confirmed`, its last `reply`, `already_ended` and any `error`, and the final
state:

- `killed` when the stub answers `OK` or `X nn`, `exited` when it answers `W nn`;
- `lost` when the stub closes the connection or does not answer within 3 s. GDB takes either as a successful
  kill, but rampage did not see the target end, so it does not claim it;
- the session stays open and attached (`closed: false`) when the stub refuses (`E nn`) or does not support the
  kill; disconnecting can be retried, with or without `kill`. The breakpoints are already gone by then
  (`breakpoints_removed` counts them, and the error says so), and in multiprocess mode the processes in
  `confirmed` are already killed;
- a target that had already exited is reported with `already_ended: true`, `killed: false` and no packets sent.

A refused detach (`D` answered `E nn`) is reported the same way: the session stays open and attached,
`breakpoints_removed` counts the breakpoints already removed, and `detach_error` names any processes already
detached.

QEMU in system mode exits the emulator when killed through its stub (it answers `vKill;1` with `OK`, then exits).

### What writes do not do

- No flash programming (`vFlash*`) and no monitor commands; a stub that drops flash writes gives `verified: false`.
- No automatic writes: no breakpoint planted by writing memory, no retries, no restoring of bytes.
- No writes while the target runs, and no atomicity across the read, the write and the read-back.

## Limits

| Limit | Value |
|---|---|
| Sessions per MCP connection | 4 |
| Packet size | the stub's `PacketSize`, capped at 1 MiB (2 KiB when not advertised) |
| Decoded reply size | 1 MiB |
| Connecting, name resolution and every address included | 5 s |
| Connecting and the handshake together | 15 s |
| Detaching while closing | 2 s per session, all at once, 2.5 s in all |
| Each request | 10 s |
| Retransmissions after a NAK, and damaged replies tolerated | 3 |
| Target description | 32 documents, 4 levels of includes, 1 MiB |
| Threads | 4,096; `qThreadExtraInfo` for the first 64 |
| Console output kept | 4 KiB per session, and 4 KiB per run in stop events |
| Console-output and notification packets per request | 256 |
| Waiting for a stop (`debug_continue`, `debug_wait`) | 5 s by default, 60 s at most |
| Waiting after an interrupt | 3 s |
| Breakpoints and watchpoints per session | 64, plus at most 4 temporary ones |
| Bound projects per session | 8 |
| Candidates listed for an ambiguous name | 16 |
| Over-steps listed in a result | the last 32 |
| `debug_evidence` | 8 registers, 4 memory ranges of at most 64 bytes, 300-byte ledger detail |
| Watchpoint length | 4096 bytes |
| Steps per request | 1,000, and 60 s in all |
| One memory write | 4096 bytes |
| Waiting for the reply to a kill | 3 s |

## What 9.1 to 9.4 do not do

- No launch or attach. Register and memory writes and kill only with the operator's flags and a tool call.
- No signal delivery on resume: never `C`, `S` or `vCont;C`/`vCont;S`. A pending signal is discarded.
- No non-stop mode and no per-thread resume: every thread runs and stops together.
- No software-breakpoint emulation by writing memory; a stub without `Z0` reports it unsupported.
- No conditions or ignore counts on breakpoints.
- No source-level stepping and no frame unwinding: step out works only from a function's first instruction.
- No relocation of runtime bytes to file bytes beyond the slide, and no binding of snapshots.
- No LLDB `debugserver` extensions (9.5) and no Windows debugging (9.6).
- No expression evaluation and no monitor commands (`qRcmd`).
- Runtime bytes stay local. They are never published anywhere except the snapshot file you name.

## Acceptance

The protocol and the tools are tested against a scripted fake stub, over TCP and Unix sockets. It replays
transcripts of QEMU's Cortex-M3 stub and of gdbserver on AArch64 Linux, and also sends slow, malformed, oversized
and NAKed replies, stop replies in pieces and between console output, ignores interrupts, refuses `Z0`, and drops
the connection mid-command. Read-only scripts fail a test on any execution-control packet; execution scripts accept
only the packets listed above and fail on writes, kill, launch, attach, signal delivery and non-stop mode. Scripts
accept well-formed writes only when marked for writes (applying memory writes to their memory, with ranges that
drop or refuse writes), and `k`/`vKill` only when marked for kill; the fake stub checks this with its own parser,
written apart from the client's.

Each session request declares the packet classes it may send: `Read` (queries, register and memory reads, thread
selection for reads), `Execution` (`vCont?`, `vCont;c`, `vCont;s:<thread>`, `c`, `s`, `Hc<thread>`,
`Z0`..`Z4`/`z0`..`z4`), `Detach` (`D`, `D;<pid>`), `Write` (`M`, `X`, `P`, `G`, well-formed: data exactly as long as
the length says) and `Kill` (`k`, `vKill;<pid>`). Inspection requests may send only `Read` packets; the write
requests `Read` and `Write`; a kill `Read`, `Execution` (to stop the target and remove breakpoints) and `Kill`, never
`Detach`; detaching never `Write` or `Kill`. The client refuses anything outside the request's classes before it
reaches the wire, and refuses every other packet always.

The write tests cover: the tools absent without the flag and `kill: true` refused without it; the session's own
refusal; stale epochs and a running target; an `expect` mismatch leaving memory untouched; `X` with a fall back to
`M`; a refused chunk ending the write with exactly the written chunks reported; a dropped flash write giving
`verified: false`; `P` with a fall back to `g`/`G`; refusal under a software breakpoint, temporary ones included;
kill's refusal, confirmation and unconfirmed (closed connection) outcomes; and the read and execution tools sending
no write or kill packet with both flags on.

The live acceptance runs QEMU on an owned firmware (`tests/fixtures/firmware`, rebuilt with
`build-firmware.sh`). The firmware calls a named function, `tick`, in a loop, and `tick` increments a RAM word,
`counter`; the tests find both in the ELF's symbol table. Through the API, the tests read and snapshot the halted
target, then break on `tick` with a hardware breakpoint, continue twice with it still set (stepping past it, so
`counter` advances by one per hit), step three instructions, catch the write to `counter`
with a watchpoint, see a short continue report `running`, interrupt it, have a stale epoch refused, and disconnect,
which removes the breakpoint and detaches.

The static correlation tests bind an owned x86-64 PIE with a GNU build ID (`tests/fixtures/debug-correlation`,
rebuilt with its `build.sh`), mapped into the fake target at a load bias: binding by build ID, by path and by file
name, refusal without a match and binding with an explicit slide, a slide that does not verify, breakpoints by
function name and static address, an ambiguous name, stop locations, register annotations, stepping over a call
and a non-call, the temporary breakpoint's removal after a timeout, a cancel and another stop, user breakpoints at
the pc and at the return address, stepping out, and evidence accepted by the findings ledger. Live, `debug_connect`
with the firmware's path binds it at slide 0 verified by its mapped code; a breakpoint by `function: "tick"` stops
in `tick`, annotated registers point into `tick` and `reset_handler`, step out lands after the `bl tick`, and step
over runs that call site without stopping inside `tick` (`counter` advances by one).

QEMU removes every breakpoint and watchpoint when asked `?`. The fake stub's QEMU transcript does the same and
fails a test on any `?` asked over an inserted one, and a live test sets a software breakpoint and then a write
watchpoint, calls `debug_status` and `debug_snapshot` before each continue, and still stops at `tick` and at the
store to `counter`.

With both flags on, the live write test stops at `tick`, writes `counter` with `expect` set to what it holds, and
continues: `tick` reads the written value and adds one. It writes `r12` as an integer and reads it back, writes
four bytes of flash past the image and checks the reported `verified` against an independent read, continues once
more to show the breakpoint survived, then disconnects with `kill: true` and waits for QEMU to exit. With QEMU 11
on `lm3s6965evb`, `X` is unsupported (rampage falls back to `M`), `P` is supported, the flash write is applied
(`verified: true`: QEMU's debug path writes ROM), and `vKill;1` is answered `OK` before QEMU exits with status 0.

```sh
RAMPAGE_QEMU_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(debug_qemu::)'
```

The test harness plays the operator and starts QEMU. Rampage itself only connects.
