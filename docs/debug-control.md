# Debug sessions with GDB remote stubs

rampage's MCP server can connect to a GDB Remote Serial Protocol stub that an operator has already started:
`gdbserver` on Linux or Android, QEMU's `-s`/`-gdb` stub, OpenOCD, probe-rs, Apple's `debugserver` on macOS (see
[macOS and debugserver](#macos-and-debugserver)), MinGW-w64 `gdbserver.exe` or `lldb-server` on Windows (see
[Windows](#windows-gdbserver-and-lldb-server)) and similar. An agent can then read
the stopped target's registers, memory, threads, loaded modules and memory map, capture it to a snapshot file
that every runtime and analysis tool opens, and control its execution: continue, wait, interrupt, single-step, and
set breakpoints and watchpoints. With a project bound to the target, it can also place breakpoints by function name
or static address, see stops and register values in the project's terms, and step over calls or out of functions.

GDB remote stubs are live-verified against QEMU (Cortex-M3). The macOS `debugserver` and Windows paths are
*experimental*: they are tested against protocol transcripts but [not live-verified](#what-is-not-live-verified).
The design is in the [debugger design](plans/2026-10-29-debugger-control.md). rampage never launches or attaches to a
process, delivers a signal or enters non-stop mode, and the protocol client keeps every such packet off the wire.
It writes registers or memory, or kills a target, only when a tool asks for it and the operator started it with
`--debug-writes` or `--debug-kill`; see [Writes and kill](#writes-and-kill).

## Setup

Start the stub yourself, then start the MCP server with the endpoint allowed. The examples use
`rampage server serve`; the compatibility spelling `rampage mcp` takes the same options.

A Linux program under gdbserver:

```sh
gdbserver :2345 ./prog
rampage server serve --debug-endpoint 127.0.0.1:2345
```

Firmware in QEMU system mode, halted at reset:

```sh
qemu-system-arm -M lm3s6965evb -kernel fw.elf -nographic -s -S
rampage server serve --debug-endpoint 127.0.0.1:1234
```

QEMU's `-s` listens on TCP port 1234.

A macOS program under Apple's debugserver (launched, or attached by pid):

```sh
debugserver 127.0.0.1:2345 ./prog
debugserver 127.0.0.1:2345 --attach=<pid>
rampage server serve --debug-endpoint 127.0.0.1:2345
```

A Windows program under gdbserver or lldb-server, on a Windows host (see [Windows](#windows-gdbserver-and-lldb-server)):

```text
gdbserver.exe 0.0.0.0:2345 prog.exe
lldb-server.exe gdbserver 0.0.0.0:2345 -- prog.exe
rampage server serve --debug-endpoint winhost:2345
```

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
  started frozen with `-S` starts executing. rampage kills a target only on `debug_disconnect` with `kill: true`
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
  earlier request selected, and reports the thread it used. After an interrupt on Windows, whose stop is in a thread
  the system created, it selects the first other listed thread (see [Execution on Windows](#execution-on-windows)).

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

rampage drives the stub in all-stop mode: every thread resumes together and stops together.

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
  Only a SIGINT (or signal 0) stop after an interrupt is reported as `interrupted` (on debugserver, which stops the
  process with SIGSTOP, a SIGSTOP); a fault that arrives instead stays a `signal`.
- `debug_status` reports `waiting`: how many continue, wait or interrupt calls are waiting for the stop.
- Each stop rampage observes (after a continue, each step and an interrupt) increments the epoch. Execution tools
  take the caller's `epoch` and fail with `stale_epoch`, which names the current epoch and state, when they differ.
  Reads take it optionally. An agent therefore never steps or sets breakpoints on a picture of the target that is
  out of date.
- rampage asks the stub for its stop reply (`?`) only once, when connecting. QEMU takes `?` for a new debugger
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
  one (`target_error`). rampage never emulates a software breakpoint by writing an instruction into memory. On a
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
- `exception`: debugserver's Mach exception, when the stop reply carries one (see
  [Mach exceptions](#mach-exceptions)), or a Windows exception (see [Windows exceptions](#exceptions)).
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
- An LLDB stub (debugserver) that states a byte order, `endian:little` or `endian:big` in its `qProcessInfo`
  (else `qHostInfo`) reply, is taken at its word. debugserver states the byte order it was built for, which is the
  one of the processes it can debug on that machine (arm64 and x86-64 Macs are little-endian only); it does not
  read it from the process. This applies only when the architecture leaves the order unknown, and the evidence
  names the reply.

Otherwise AArch64 and RISC-V report `unknown`, because their registers do not expose the data endianness, as
described in [runtime data order](runtime-data-order.md). Their `value` is null and `bytes` are exactly as the stub
sent them. Architecture defaults are never used in place of evidence.

### Memory

Reads are split into chunks that fit the stub's packet size. rampage uses binary `x` reads when the stub
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
- `qXfer:libraries:read`: Windows-style entries with segment or section addresses. On a Windows target each
  entry's PE headers are read and the main executable is added when the list leaves it out; see
  [Windows modules](#modules-and-the-main-executable).
- `qXfer:exec-file:read` and `qXfer:memory-map:read`: the program path, and ram, rom and flash regions with
  flash block sizes.
- From an LLDB stub (debugserver), which advertises neither: `jGetLoadedDynamicLibrariesInfos` for the dyld image
  list, and `qMemoryRegionInfo` for regions; see [macOS and debugserver](#macos-and-debugserver).

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
| `uuid` | The Mach-O file's `LC_UUID` equals the one dyld reports for the module (debugserver), or the one read from the module's mapped header |
| `codeview` | The PE file's CodeView record (PDB GUID and age) equals the one in the module's mapped debug directory (Windows) |
| `path`, `basename` | The module's reported path (or, for the main program with no name, the exec file) equals the project's path, or only their file names are equal; on Windows, case-insensitively and ignoring `\\?\` and the slash direction |
| `header_bytes` | The module's mapped header bytes (up to 256) equal the file's first bytes; a PE image's `OptionalHeader.ImageBase` is left out, since the loader writes the runtime base there |
| `mapped_bytes` | The stub lists no modules (bare-metal firmware): every verification window (below) is readable and equal at the slide (`qOffsets` `Text`, else 0, or the caller's), at least 16 bytes in all |
| `explicit_slide` | Nothing matched and the caller gave `slide` |

`module` restricts the match to a module with that path or file name; for a target without a module list it is the
binding's label, and it must name exactly one module (`ambiguous_module` otherwise). Several modules matching
equally well are refused (`ambiguous_module`) unless `module` picks one. A target whose architecture has no rampage
equivalent cannot be checked against the project and binds only with an explicit `slide`.
Without a match the bind is refused (`no_module_match`) unless the caller gives `slide`: rampage never binds
silently on a weak match.

**Slide.** `runtime = static + slide`, wrapping at the pointer width. For svr4 modules (Linux, Android) the slide is
the link map's `l_addr`. For dyld images (debugserver) it is the header's runtime address minus the `__TEXT`
address; a dyld shared-cache library binds only from its extracted image (see
[macOS and debugserver](#modules-the-shared-cache-and-regions)). For library lists that give segment or section addresses (Windows-style, Mach-O), it is that
address minus the file's header address, or minus its first section's address: every stage (identity, name,
header bytes) verifies each candidate and keeps the first that matches. A caller's `slide` overrides the computed
one, and the difference is reported.

**Verification.** rampage compares windows of up to 32 bytes of the file with target memory at the slide: the entry
point, the start, middle and end of every executable segment's file bytes (at most 8 segments) and up to 16
function entries spread over the image. It reports `matched` (at least one window read and none differs; unreadable
windows are counted in `detail`), `mismatched` (any window differs), `unreadable` (none could be read),
`unverified` (a PE image whose compared windows held too few bytes the loader leaves alone; see
[Binding a PE image](#binding-a-pe-image)) or `no_file_bytes`. Comparing many places catches a rebuilt image that
shares its first bytes (a vector table, a
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

Arrival at the return address is checked against the frame and thread. rampage records the thread and the stack
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

Everything here needs the operator's flag (see [Consent](#consent)), and nothing here happens unless a
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

## macOS and debugserver

*Experimental: not live-verified.* Apple's `debugserver` speaks the GDB remote protocol with LLDB's extensions. rampage launches and
attaches nothing: the operator starts debugserver on a program or a pid (see [Setup](#setup)) and lists its endpoint.

### Prerequisites

- debugserver ships with the Command Line Tools
  (`/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Versions/A/Resources/debugserver`)
  and Xcode (`Xcode.app/Contents/SharedFrameworks/LLDB.framework/Versions/A/Resources/debugserver`).
- macOS lets a debugger control a process only when the Mac allows developer tools: run
  `sudo DevToolsSecurity -enable` once (or enable developer mode). Otherwise debugserver waits for an authorization
  prompt in the GUI instead of listening, and rampage's connect times out.
- The program must allow it: a binary signed with the hardened runtime needs the
  `com.apple.security.get-task-allow` entitlement (an ad-hoc signature with it is enough for your own builds; see
  `tests/fixtures/debug-macho/build.sh`), and system binaries protected by System Integrity Protection cannot be
  debugged.
- A program debugserver launches stops at its first instruction, before dyld has run: dyld may list no images or
  only some, so a bind there can fail with `no_module_match`. Bind again after the first continue, or attach
  (`--attach=<pid>`) to a program that is already running.

### What rampage asks an LLDB stub

A stub whose `qSupported` reply advertises `qEcho+` or `native-signals+` speaks LLDB's dialect, and only such a
stub is asked the queries below; gdbserver, QEMU and OpenOCD never see them. Each is a `Read`-class packet, refused
by the client in any other form, and each only adds information: a stub that answers one with an empty reply or an
error is used without it.

| Packet | Use |
|---|---|
| `qHostInfo`, `qProcessInfo` | CPU type (the architecture: debugserver's target description names none), pid, `ostype`/`vendor`, a stated byte order (see [Endianness](#endianness)), address bits for pointer authentication, whether watchpoints stop before the access. Shown by `debug_connect` as `lldb` and `address_mask` |
| `qRegisterInfo<n>` | Registers, from 0 up to the first error, when the stub serves no target description (older debugserver) |
| `jThreadsInfo` | Thread names, dispatch queues and per-thread stop reasons and exceptions, in each thread's `name`, `queue`, `reason` and `exception` |
| `jGetLoadedDynamicLibrariesInfos:{"fetch_all_solibs":true,"report_load_commands":false}` | The header address of every loaded image |
| `jGetLoadedDynamicLibrariesInfos:{"solib_addresses":[...]}` | Full information (path, UUID, header, segments) for those images, 64 at a time, so no reply outgrows a packet however many images a program loads; LLDB lists images the same way |
| `qMemoryRegionInfo:<address>` | Mapped regions with permissions, walking the address space from 0 |

The connection keeps acknowledgements. debugserver advertises no `QStartNoAckMode`, and although it accepts it, in
no-ack mode it ends every packet with the checksum `#00`, which rampage's framer would take for a damaged packet.

### Reading debugserver's registers

rampage never sends debugserver `g` or `G`. debugserver since LLVM 21 has neither; older ones send their raw
register context, which has padding (4 bytes after `cpsr` on arm64) that the register offsets they state leave
out, so a `g` reply would be read 4 bytes off from the vector registers on. Registers are read with `p`, and the
stop reply's expedited registers (debugserver sends the general registers with every stop) stand in for the stopped
thread's; the values read are kept until the target runs again or a register is written, so reading the registers
twice at one stop costs one round of `p`. `debug_write_register` uses `P` only; a debugserver that refuses `P` is
not written with `G`.

debugserver's `target.xml` (and `qRegisterInfo`) states each register's `offset`, with no gaps, and declares views
of other registers (`w0` of `x0`, `s0` of `v0`) with `value_regnums` (`container-regs`). rampage leaves views out
(read their container). A register wider than 4096 bits (an SME `ZA` array) is left out without moving the others.
Registers keep debugserver's names, so arm64 x29 and x30 are `fp` and `lr`; the alternative name (`alt_name`) and
the role (`generic`: `pc`, `sp`, `fp`, `ra`, `flags`) are in the layout, and step out and `debug_evidence` look for
`lr` where there is no `x30`.

### Modules, the shared cache and regions

Each image dyld describes is a module with `source: "dyld"` and a `dyld` object: `load_address` (the Mach-O
header's runtime address), `uuid` (`LC_UUID`, upper case with dashes), `filetype` (2 for the executable, which is
`main`), `text_vmaddr`, `segments` (link-time addresses) and `in_shared_cache`. An image whose header debugserver
cannot read is left out, and `limitations` counts it.

- **Binding.** A Mach-O image binds by its UUID as dyld reports it; the slide is `load_address` minus the file's
  `__TEXT` address (equally, minus dyld's `text_vmaddr`), verified against target memory as usual.
- **The dyld shared cache.** On macOS 11 and later, system libraries live in the dyld shared cache, and no file
  exists at their paths. dyld marks them with `MH_DYLIB_IN_CACHE` in the header flags, and rampage reports them as
  modules with `in_shared_cache: true`. Binding to one is refused (`shared_cache_image`) unless the caller gives
  the image extracted from the cache (`dyld_shared_cache_util -extract`, `ipsw dyld extract` and similar) and its
  UUID matches: a path, a file name, header bytes or a caller's `slide` are not enough, because nothing on disk is
  known to be the code that runs. An extracted image keeps its cache addresses, so it binds at the cache's slide.
- **Regions.** Without a memory map, `debug_modules` lists the mapped regions `qMemoryRegionInfo` reports, with
  `type: "mapped"`, `permissions` and `name` when the stub gives one; unmapped gaps are left out. debugserver lists
  every dirty page of a region, so a busy region's reply may be as long as a packet; the pages are skipped. When the
  walk stops before the end of the address space (a failed query, or 512 queries), `regions_partial` is true.
  Binding's slide verification counts a window outside every readable region as unreadable without reading it,
  unless the list is partial, when such a window is read.
- **Snapshots** record a dyld module with its UUID as identity, `image_base` its `__TEXT` address and
  `runtime_base` its header address.

### Pointer authentication

arm64e processes sign return addresses and frame pointers: the bits above the virtual address width hold a pointer
authentication code. debugserver itself takes the code off `lr`, `fp`, `sp` and `pc` when it reads them (with `p`
and in stop replies), so rampage sees unsigned values from it; the stripping below is a defence against stubs that
do not. On arm64 targets, rampage keeps the address bits the stub states (`qProcessInfo` before `qHostInfo`,
`low_mem_addressing_bits` before `addressing_bits`), else 47 bits on an Apple target (macOS and iOS user addresses
fit in 47 bits; debugserver on Apple silicon Macs reports `addressing_bits:47`); elsewhere without stated bits
nothing is stripped, since the width is unknown. `debug_connect` reports the mask and its source as
`address_mask`.

- Step out places its temporary breakpoint at x30 without the code, and says so in `warnings`.
- Register annotation locates a value of `lr`, `x30`, `fp`, `x29` or `pc` that lies in no bound module as it is,
  but does once the code is taken off; `points_to` then gives `signed_value`, the value as read. Other registers
  are never stripped, so a plain integer is not taken for a code pointer.
- A low address (bit 55 clear) has the bits above the width cleared; a high one has them set.

### Mach exceptions

debugserver reports stops as Mach exceptions: `metype` (the exception type), `mecount` and `medata` (its code
words), all hex, with the signal debugserver maps it to (`T91` for `EXC_BAD_ACCESS`, `T05` for `EXC_BREAKPOINT`).
rampage types them in the stop reply's reasons and in the stop event's `exception`:

| Type | `name` | Typed fields |
|---|---|---|
| 1 | `EXC_BAD_ACCESS` | `fault_address` (the second code word), `code_name`: `KERN_INVALID_ADDRESS`, `KERN_PROTECTION_FAILURE` or `EXC_ARM_DA_ALIGN` |
| 2 | `EXC_BAD_INSTRUCTION` | the codes |
| 5 | `EXC_SOFTWARE` | `code_name: "EXC_SOFT_SIGNAL"` and `signal` when it carries a Unix signal |
| 6 | `EXC_BREAKPOINT` | the codes |

Other types (3 `EXC_ARITHMETIC` to 13 `EXC_CORPSE_NOTIFY`) are named, with their codes. The stop's `reason` follows
the usual rules: a breakpoint hit is a SIGTRAP whose pc is a breakpoint's, a step a SIGTRAP after a step, and a
fault a `signal`.

- **Watchpoints.** debugserver reports a hit as `reason:watchpoint` with no exception and signal 0. `watch_addr` is
  the start of the watchpoint nearest the access, which the stop event's `watch.address` gives and which matches the
  table; `me_watch_addr` is the address accessed, given as `watch.accessed`. Older versions report a hit as
  `EXC_BREAKPOINT` with code `EXC_ARM_DA_DEBUG` (0x102) and the accessed address as the second code word. Neither
  says whether it was a read or a write, so the hit is an `access`, which matches watchpoints of any kind there.
- **Watchpoints stop before the access.** On ARM, debugserver says `watchpoint_exceptions_received:before`: the
  thread stops at the accessing instruction, which has not run. The next continue (or step over) therefore takes
  the watchpoints that stop hit out, single-steps the thread and puts them back, as it does for a breakpoint at the
  pc, so the same access does not stop the target again. A stub that says `before` gets the same; without the key,
  an Apple ARM stub is taken to.
- **Interrupts.** debugserver answers the interrupt byte by stopping the process with SIGSTOP, so on an Apple stub
  a SIGSTOP (17) stop after rampage's interrupt is reported as `interrupted`.
- `description` (hex text) is decoded into the reasons. Long informational fields (`jstopinfo`,
  `detailed-binaries-info`) are listed by name only.

### Execution

debugserver supports `vCont` (`vCont;c;C;s;S`), so continues and steps use `vCont;c` and `vCont;s:<thread>`.

- Software breakpoints on arm64 must take kind 4: debugserver writes as many bytes of its `brk #0` as the kind says,
  so another kind would plant a broken instruction. rampage's AArch64 default and only accepted size is 4.
- debugserver's hardware breakpoints take kind 2 or 4.
- Watchpoints: debugserver widens what it is asked to watch to what the hardware can (DNBArchImplARM64): a range of
  up to 8 bytes within one aligned doubleword, else a power-of-two-sized aligned range as a mask, or the request
  split across two watchpoint registers. A hit can therefore come from an access next to the requested range; the
  stop's `watch.accessed` says where. Ranges it cannot cover are refused (`E09`, reported as `target_error`).
  Prefer 1, 2, 4 or 8 bytes, aligned.
- These follow debugserver's source and are not live-verified; the live acceptance (see [Acceptance](#acceptance))
  checks them on a real target.

## Windows (gdbserver and lldb-server)

*Experimental: not live-verified.* This is the RSP-stub route of the
[Windows design](plans/2026-11-05-debugger-windows.md). Two stubs serve
Windows user-mode processes over the same protocol: GDB's `gdbserver` built for Windows (MinGW-w64, as MSYS2 and
other MinGW distributions build it) and LLVM's `lldb-server`. rampage launches and attaches nothing: the
operator starts the stub on the Windows host and lists its endpoint. Everything below follows the stubs' sources
(GDB's `gdbserver/win32-low.cc`, `gdbserver/win32-i386-low.cc`, `gdbserver/server.cc`, `gdb/nat/windows-nat.c`;
LLVM's `NativeProcessWindows.cpp`, `NativeThreadWindows.cpp`, `GDBRemoteCommunicationServerLLGS.cpp`), as read on
their main branches. None of it has run against a real stub on a Windows host.

### Setup on the Windows host

Copy the program over and start one of these, on a port the machine running rampage can reach:

```text
gdbserver.exe 0.0.0.0:2345 prog.exe              launch, stopped at the loader breakpoint
gdbserver.exe --attach 0.0.0.0:2345 <pid>        attach to a running process
lldb-server.exe gdbserver 0.0.0.0:2345 -- prog.exe
lldb-server.exe gdbserver 0.0.0.0:2345 --attach <pid>
```

Then `rampage server serve --debug-endpoint winhost:2345`. The endpoint is not on loopback, so only the operator's listing
allows it (see [Consent](#consent)); the stub accepts anyone who reaches the port, so keep it on a trusted network
or tunnel it (`ssh -L 2345:localhost:2345 winhost` and `--debug-endpoint 127.0.0.1:2345`). gdbserver's
`--once` ends it after one connection. A process gdbserver launched runs in a new process group, which matters for
interrupts (below).

### What rampage recognizes

`debug_connect` reports `windows` with the stub and what showed it:

- gdbserver's target description names the OS ABI `Windows` (`win32-i386-low.cc`, `i386_arch_setup`, through
  `gdbsupport/tdesc.cc`'s `<osabi>`): `i386:x86-64` for a 64-bit process, `i386` for a 32-bit (WoW64) one, with
  the core and SSE registers (no AVX). gdbserver names the OS ABI from GDB 16 on ("gdbserver: pass osabi to GDB in
  more target descriptions"). For an older gdbserver (the MinGW builds of GDB 12 to 15 are common), a GDB stub on x86
  that lists `qXfer:libraries:read` but not the svr4 list is taken for gdbserver on Windows when the stopped thread's
  TIB answers `qGetTIBAddr`, or else an `MZ` header lies 0x1000 below its first library's segment address. Any
  gdbserver on Windows that has `qGetTIBAddr` (GDB 7.1 and later) is recognized this way; the evidence says which
  test matched.
- lldb-server answers `qHostInfo` and `qProcessInfo` (it advertises `qEcho+` and `native-signals+`, so it is asked
  LLDB's queries) with a Windows triple (`x86_64-pc-windows-msvc`, hex-encoded) and `ostype:windows`. Its target
  description has a single unnamed `<feature>` with LLDB register names (`rflags`) and stated offsets.
- lldb-server sends `PacketSize` in decimal (`PacketSize=131072`); RSP clients, LLDB's too, read it as hex, so
  rampage does as well and caps it at 1 MiB as usual. A 32-bit process's description names the architecture
  `i686` (lldb-server passes the triple's architecture through), which rampage reads as x86.
- Thread IDs are Windows thread IDs in hex (`1a2c`): neither stub enables multiprocess mode on Windows.

### Modules and the main executable

| | gdbserver | lldb-server |
|---|---|---|
| Entries | `<library name="C:\..."><segment address="..."/>` | `<library name="C:\..."><section address="..."/>` |
| The address | the image base plus 0x1000, a constant (`win32-low.cc`, `handle_load_dll`: "The symbols in a dll are offset by 0x1000"), not the first section's RVA | the image base (`NativeProcessWindows.cpp`, `GetLoadedLibraries`) |
| The executable | left out: modules are enumerated from index 1, and index 0 is the executable (`windows-nat.c`, `add_dll`) | listed first |
| Exec file | `qXfer:exec-file:read` (the Windows path) | not offered |
| Paths | as `GetModuleFileNameEx` spells them; `ntdll.dll` completed with the system directory; 32-bit DLLs of a WoW64 process under `SysWOW64` | the loader's spelling, `\\?\` taken off, with the on-disk case when only case differs |

gdbserver prints library names into the list without XML-escaping them (`server.cc`, `handle_qxfer_libraries`), so a
path with `&` would break the document; rampage reads a `&` that does not start an entity as the character.

For each listed module rampage reads the PE headers at the base the address gives (the stub's own reading first:
the segment minus 0x1000, or the section as is; then the other) and keeps the base where an `MZ` and `PE` header
parse. `debug_modules` entries gain `pe`: the runtime `base`, `base_from` (`segment_minus_0x1000`, `section`,
`peb`, ...), `machine`, `dll`, `aslr`, `size_of_image`, `timestamp` and the `codeview` record (GUID, age and PDB path)
read from the mapped debug directory. At most 64 modules are read.

Under lldb-server, the listed image that is not a DLL is the main executable (`main: true`). Under gdbserver, which
never lists the executable (an `.exe` it lists was loaded as a library, and is not the program), rampage finds it
as GDB does (`gdb/windows-tdep.c`, `create_inferior_hook`): `qGetTIBAddr:<thread>` gives a thread's TIB, whose
process environment block pointer (TEB+0x60, or +0x30 in a 32-bit process) leads to `ImageBaseAddress` (PEB+0x10,
or +0x8). The entry is listed first with `source: "peb"` and the exec file's path. A stub that answers neither
leaves a limitation, and the executable then binds only with an explicit `slide`.

### Binding a PE image

Evidence comes in this order, as for other formats: the CodeView record, then the path or file name, then the
header bytes.

- **CodeView.** The RSDS record's PDB GUID and age identify a build, like a build ID: the file's (from its debug
  directory) must equal the module's (read from its mapped debug directory). Linkers that write a PDB write one
  (MSVC's `/DEBUG`, LLD with `-g`); MinGW's GNU ld only with `--build-id` or a PDB-writing option. A file without
  one gets a limitation and binds by name or header bytes.
- **Names.** Windows compares file names case-insensitively, and stubs report `C:\...` paths, so a module's path
  equals the project's after both are lowercased, `/` read as `\` and `\\?\` (or `\??\`, `\\?\UNC\`) taken off; the
  file name alone matches the same way. `module` is compared the same way. Case folding covers ASCII letters only
  (Windows folds Unicode too), and Cygwin's `/cygdrive/c/...` spellings are not translated; such names fall back to
  the CodeView record or header bytes.
- **Header bytes.** The first 256 bytes of the file against the mapped headers, `OptionalHeader.ImageBase` left out:
  the loader writes the runtime base there when it moves the image.

**Slide.** `runtime = static + slide`, where the slide is the module's runtime base minus the file's
`OptionalHeader.ImageBase`. An ASLR image (`DYNAMIC_BASE`) usually moves, and its slide is not 0; an image without
ASLR normally loads at its preferred base, slide 0. The runtime base is the one rampage read the headers at; for a
module whose headers it could not read, the candidates are the address minus 0x1000 (gdbserver), the address minus
the file's first section RVA, and the address read as the header, and each is verified.

**Relocations.** When the loader moves an image it applies the base relocations of its `.reloc` section: every
absolute address in the image (vtables, jump tables, `movabs` immediates, initialized pointers) is rewritten.
Mapped bytes then differ from the file at exactly those spans, so a byte-for-byte comparison of a moved image would
fail. Slide verification reads the file's base relocation blocks (`IMAGE_REL_BASED_DIR64` 8 bytes, `HIGHLOW` 4,
`HIGH`/`LOW`/`HIGHADJ` 2, and 8 for types it does not know) and leaves those bytes out of every window when the slide
is not 0. The import address table and the import directory (data directories 12 and 1) are left out at every
slide, since the loader writes the IAT even at the preferred base, and linkers can merge them into an executable
section (`/MERGE:.rdata=.text`, Delphi). So that leaving bytes out cannot make the check vacuous:

- a window with fewer than 8 bytes left to compare is skipped rather than matched;
- when any byte was left out, the matched windows must compare at least 16 bytes in all;
- otherwise the outcome is `unverified`, with the counts in `detail` (windows compared, skipped and unreadable, and
  bytes left out). Like `unreadable`, it binds with a limitation when the evidence identifies the image and is
  refused (`slide_unverified`) when only a name matched.

The relocation reader is bounded: at most 1,048,576 entries, and at most 256 of types it does not know (each
assumed to patch 8 bytes); a table past either, or one that cannot be read, leaves a limitation instead.

`function:` breakpoints, stop locations and register annotations then work as for ELF and Mach-O images; names come
from the image's exports and symbols (a PE file rarely has a COFF symbol table), or from a PDB imported into the
project (`import_pdb_names`). Step over decodes x86-64 calls with rampage's decoder, which Windows code does not
change. Step out's x86-64 rule holds for the Microsoft x64 calling convention too: at a function's first
instruction the return address is at `[rsp]` whatever the convention (the 32-byte home space the caller reserves
lies above it). `debug_evidence` reads `rcx`, `rdx`, `r8` and `r9` (the convention's first arguments) by default
on Windows x64.

### Exceptions

Windows reports faults and traps as exceptions; the stubs pass them on in two forms, and rampage types both in the
stop event's `exception` (and the stop reply's reasons) with `"system": "windows"`, `code` (the `NTSTATUS`),
`name`, `address` (where it happened), `source` (`siginfo` or `description`), and for access violations `access`
(`read`, `write`, or `execute` for a DEP violation) and `fault_address`.

**gdbserver** reports a signal (`gdb/nat/windows-nat.c`, `handle_exception`):

| Exception | Signal |
|---|---|
| `EXCEPTION_ACCESS_VIOLATION`, `STATUS_STACK_OVERFLOW` | SIGSEGV (11) |
| `EXCEPTION_FLT_*`, `EXCEPTION_INT_DIVIDE_BY_ZERO`, `EXCEPTION_INT_OVERFLOW`, `EXCEPTION_ARRAY_BOUNDS_EXCEEDED` | SIGFPE (8) |
| `EXCEPTION_ILLEGAL_INSTRUCTION`, `EXCEPTION_PRIV_INSTRUCTION`, `EXCEPTION_NONCONTINUABLE_EXCEPTION` | SIGILL (4) |
| `EXCEPTION_BREAKPOINT`, `STATUS_WX86_BREAKPOINT`, `EXCEPTION_SINGLE_STEP`, `STATUS_WX86_SINGLE_STEP` | SIGTRAP (5) |
| `DBG_CONTROL_C`, `DBG_CONTROL_BREAK` | SIGINT (2) |
| any other, at its second chance | 143 (GDB's unknown signal); at its first chance it is passed to the program without a stop |

It reports the exception itself only as `qXfer:siginfo:read`: the thread's `EXCEPTION_RECORD` (152 bytes, or the
80-byte `EXCEPTION_RECORD32` of a 32-bit process; `windows_thread_info::xfer_siginfo`). rampage reads it after every
stop with a signal, except the SIGTRAP of a single step, selecting the stopped thread first; a refusal leaves the
stop without an `exception`.

**lldb-server** stops for exceptions other than breakpoints and single steps only at their second chance, when the
program did not handle them (`HandleGenericException`: first-chance exceptions go to the program), with signal 5
(SIGTRAP), `reason:exception` and a `description` like `Exception 0xc0000005 encountered at address 0x7ff6...:
Access violation writing location 0x00000010` (`ExceptionRecord.cpp`, `Dump`), which rampage parses.

Classification:

- **Breakpoints.** A table breakpoint is a `breakpoint` stop: gdbserver says `swbreak` (it advertises it), and
  lldb-server says `reason:breakpoint`, which matches by pc. An int3 that is not rampage's (a compiled-in
  `__debugbreak`) is a `breakpoint` stop with no table entry, not a `signal`: gdbserver says `swbreak`, and
  lldb-server's `EXCEPTION_BREAKPOINT` description is read as a breakpoint.
- **The pc after an int3.** The CPU leaves the pc after the int3. gdbserver moves it back onto the int3 for every
  int3 stop, its own breakpoints or not (`win32-low.cc`, `maybe_adjust_pc`), and the reported pc is the int3's.
  lldb-server moves it back only for its own breakpoints; for any other int3 the pc is after it. So under gdbserver
  a continue from a foreign int3 executes it again and stops at once; the stop event's `warnings` say so. Writing
  the pc past it (`debug_write_register`, with `--debug-writes`) is the way out.
- **Steps.** A single step (`EXCEPTION_SINGLE_STEP`; lldb-server's `reason:trace`) is a `step`. A hardware
  breakpoint hit is also `EXCEPTION_SINGLE_STEP` and matches its table entry by pc after a continue.
- **Faults** are `signal` stops carrying the exception. rampage resumes without a signal, so gdbserver continues the
  exception as handled: a faulting instruction runs again and faults again, and the program's own exception handlers
  do not see it.
- **DLL loads.** After startup gdbserver stops for each DLL load or unload with signal 0 and `library`
  (`target.cc`, `mywait`), which is a `signal` stop with signal 0; continue again. A DLL-load stop that arrives
  after rampage's interrupt is not the interrupt's answer: it is reported as a `signal` stop, and the interrupt stays
  pending, so the stop after the next continue in a new thread is `interrupted`. lldb-server stops for DLL loads
  only for clients that advertise `qXfer:libraries:read+` in `qSupported`, which rampage does not.

### Execution on Windows

- **`vCont`.** gdbserver answers `vCont?` with `vCont;c;C;t;s;S` (`server.cc`; single steps through the trap flag),
  lldb-server with `vCont;c;C;s;S;t`. rampage uses `vCont;c` and `vCont;s:<thread>`.
- **Breakpoints.** Software breakpoints are kind 1 (`int3`) on x86 and x86-64. gdbserver inserts `Z0` by writing the
  int3 itself, `Z1` hardware breakpoints and `Z2` (write) and `Z4` (access) watchpoints in the debug registers
  (`win32-i386-low.cc`, `i386_supports_z_point_type`); it has no read watchpoints, so `Z3` is answered as
  unsupported. lldb-server takes `Z0`, `Z2`, `Z3` and `Z4`, turning a read watchpoint into a read/write one
  (`NativeRegisterContextWindows_x86_64.cpp`, `SetHardwareWatchpoint`), but refuses hardware breakpoints
  (`NativeThreadWindows.cpp`, "unimplemented."), so step over and out fall back to a temporary software breakpoint
  there.
- **Watchpoints.** x86 has four debug registers, each watching 1, 2, 4 or 8 aligned bytes; gdbserver splits a
  longer or unaligned range over several (`gdb/nat/x86-dregs.c`) and refuses one that does not fit. Hits stop after
  the access. gdbserver reports every hit as `watch:<address>`, whatever the kind; lldb-server as
  `reason:watchpoint` with the description `<watchpoint address> <index> <address hit>`, which rampage reads as the
  watchpoint and `watch.accessed`.
- **Interrupts.** gdbserver first sends a console Ctrl-Break to the process group (`win32-low.cc`,
  `request_interrupt`), which works for a process it launched (it starts them in a new group); Windows delivers it as
  `DBG_CONTROL_BREAK` (SIGINT) in a thread it creates for the console handler. Otherwise (an attached process in
  another console) it calls `DebugBreakProcess`, which creates a thread that executes an int3 in
  `DbgBreakPoint`: a SIGTRAP with `swbreak`, its pc moved back onto that int3, so continuing stops there again (see
  above). lldb-server always uses `DebugBreakProcess` and reports its own injection as SIGSTOP (17, the signal
  numbering LLDB's host uses on Windows) with the description `interrupt`, its pc after the int3.
  - Ctrl-Break reaches console programs only. For a GUI program gdbserver launched, `GenerateConsoleCtrlEvent` can
    succeed with nobody to receive it, and gdbserver then does not fall back to `DebugBreakProcess`, so the
    interrupt may never arrive: `debug_interrupt` waits 3 s and the target keeps running. For GUI programs, start
    gdbserver with `--attach` (the Ctrl-Break to a process that is not a group leader fails, and the fallback runs)
    or use lldb-server.
  - rampage reports such a stop as `interrupted` when it arrives after its interrupt in a thread it had not listed:
    SIGINT, lldb-server's SIGSTOP, or an unmatched SIGTRAP. The event's `thread` is that new thread, and `warnings`
    say so.
  - Until the target runs again, reads and steps without `thread` (`debug_registers`, `debug_read_memory`,
    `debug_step`, `debug_evidence`, step over and out) use the first other listed thread, usually the main thread,
    since the break-in thread only runs the debugger's break-in and ends when resumed.
  - Under gdbserver, `DebugBreakProcess`'s break-in thread would hit its int3 again on every continue (gdbserver
    moved its pc back onto it). gdbserver resumes only the threads a `vCont` names (`win32-low.cc`,
    `win32_process_target::resume`), so rampage parks that thread: continues send `vCont;c:<thread>;...` naming
    every other listed thread, and the break-in thread stays suspended. It exists only to trap, so the program does
    not miss it. Steps name their own thread as always. A disconnect detaches with it still suspended; the system
    then resumes it, and `DbgUiRemoteBreakin`'s exception handler absorbs the int3. rampage sends that per-thread
    form only to gdbserver on Windows; the client refuses it on any other session. If the other threads cannot be
    named in one packet, or there are none, the continue is refused and says so; writing the break-in thread's pc
    past the int3 (`--debug-writes`) or disconnecting are then the ways out.
- **`?`.** rampage sends `?` only while connecting. gdbserver answers with the last event and makes its thread the
  current one, with no other effect (`server.cc`, `handle_status`); a launched process reports its loader breakpoint
  (SIGTRAP, pc after it, not moved back: `maybe_adjust_pc` waits for the initial stop to pass).

### WoW64, 32-bit x86 and arm64

- **WoW64 under 64-bit gdbserver** is supported: gdbserver describes the process as `i386` (32-bit registers),
  lists the 32-bit DLLs from `SysWOW64`, reports a 32-bit TIB (the 64-bit one plus 0x2000, `child_add_thread`) and an
  `EXCEPTION_RECORD32`. rampage binds 32-bit PE images (`PE32`, `HIGHLOW` relocations), finds the executable through
  the 32-bit PEB (TEB+0x30, PEB+0x8), and steps out by `[esp]`. A 32-bit gdbserver on a 32-bit process looks the
  same. gdbserver skips the 64-bit loader breakpoint of a WoW64 process and reports an int3 in 64-bit code, such as
  `DebugBreakProcess`'s break-in, as SIGINT with the record's code changed to `DBG_CONTROL_C` (`handle_exception`):
  after rampage's interrupt that is `interrupted`, otherwise a `signal` stop.
- **WoW64 under lldb-server** (`NativeRegisterContextWindows_WoW64.cpp`) should bind the same way but is not
  covered by the fake stub's transcripts.
- **arm64 Windows.** Both stubs have arm64 code: gdbserver's `win32-aarch64-low.cc` (new in GDB, `brk #0xf000`,
  `Z1`, `Z2`, `Z4`) and lldb-server's `NativeRegisterContextWindows_arm64.cpp`. rampage's AArch64 support applies
  (kind 4 breakpoints; the byte order only when lldb-server states `endian:little`), but nothing arm64-Windows-specific
  is implemented or tested.

### Snapshots of Windows targets

A module with `pe` is recorded with the identity `pe-codeview:<GUID><age>` (else `pe-image:<base>`) and
`runtime_base` its runtime base. A bound module's `image_base` is its file's preferred base, so `runtime_base -
image_base` is the slide, as for dyld images; an unbound one's is 0, so its addresses read as RVAs (the mapped
header's `ImageBase` holds the runtime base once the loader moved the image, so target memory does not give the
preferred one).

### What is not live-verified

The Windows path has not run on a Windows host. The fake stub's transcripts (`rampage_debug::fake::windows`) are written from
the sources named above, not recorded, and these details come from the sources without having been observed:

- gdbserver's `<osabi>Windows</osabi>` and the `i386:x86-64` description; lldb-server's triple and `ostype`;
- the module list forms and addresses, the executable's absence under gdbserver, and the TIB and PEB offsets;
- the `EXCEPTION_RECORD` layout behind `qXfer:siginfo:read`, and lldb-server's description text;
- the int3 pc adjustment, the interrupt's new thread and its signal under each stub, the `Z` support;
- that the loader writes the runtime base into a moved image's `ImageBase` (rampage leaves the field out either
  way).

The [live acceptance](plans/2026-10-29-debugger-control.md#windows-stubs) describes how these are checked against a real stub on a
Windows host.

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
| `qHostInfo` and `qProcessInfo` replies | 4 KiB, 64 fields |
| `qMemoryRegionInfo` replies | the decoded reply size (dirty-page lists are skipped), 64 fields |
| `qRegisterInfo` queries | 1,024 registers |
| `jThreadsInfo` | asked only with at most 64 threads; names and queues of 128 characters |
| `jGetLoadedDynamicLibrariesInfos` | 4,096 images; full information 64 images per request, 32 segments each |
| `qMemoryRegionInfo` queries per module listing | 512 |
| Windows modules whose PE headers are read | 64 |

## What the debug tools do not do

- No launch or attach. Register and memory writes and kill only with the operator's flags and a tool call.
- No signal delivery on resume: never `C`, `S` or `vCont;C`/`vCont;S`. A pending signal is discarded.
- No non-stop mode and no per-thread resume: every thread runs and stops together.
- No software-breakpoint emulation by writing memory; a stub without `Z0` reports it unsupported.
- No conditions or ignore counts on breakpoints.
- No source-level stepping and no frame unwinding: step out works only from a function's first instruction.
- No relocation of runtime bytes to file bytes beyond the slide, and no binding of snapshots.
- No Windows debugging through DbgEng, no kernel targets and no minidumps; Windows user-mode processes only through
  an RSP stub, not live-verified. LLDB's extensions are used only to add information (see
  [macOS and debugserver](#macos-and-debugserver)); nothing requires them.
- No expression evaluation and no monitor commands (`qRcmd`).
- Runtime bytes stay local. They are never published anywhere except the snapshot file you name.

## Acceptance

The fake-stub tests, the live QEMU, debugserver and Windows acceptance runs and the commands that start them are
recorded in the debugger design's [acceptance record](plans/2026-10-29-debugger-control.md#acceptance-record).
