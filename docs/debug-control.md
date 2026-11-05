# Debug sessions with GDB remote stubs

Rampage's MCP server can connect to a GDB Remote Serial Protocol stub that an operator has already started:
`gdbserver` on Linux or Android, QEMU's `-s`/`-gdb` stub, OpenOCD, probe-rs and similar. An agent can then read
the stopped target's registers, memory, threads, loaded modules and memory map, capture it to a snapshot file
that every runtime and analysis tool opens, and control its execution: continue, wait, interrupt, single-step, and
set breakpoints and watchpoints.

These are steps 9.1 (inspection) and 9.2 (execution control) of the
[debugger design](plans/2026-10-29-debugger-control.md). Rampage never launches or attaches to a process, and it
never writes registers or memory, delivers a signal, enters non-stop mode or kills a target. The protocol client
keeps every such packet off the wire.

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

Listing an endpoint is the operator's consent for agents to inspect that stub and to control its execution
(continue, step, interrupt, breakpoints); there is no separate flag for execution control. The MCP client's own
per-tool prompts still apply on top, and the tools' MCP annotations mark execution control as changing the
target. The rules:

- Without an allowed endpoint the server has no `debug` group. `enable_tools` does not list it, its tools are
  absent from `tools/list`, and calls to them fail as unknown tools.
- An agent can connect only to an allowed endpoint. Its `endpoint` argument must match a listed endpoint exactly,
  as text: `localhost:2345` does not match `127.0.0.1:2345`. The argument may be omitted when exactly one endpoint
  is allowed. Agents cannot supply an address of their own.
- A non-loopback address works only because the operator listed it. `debug_connect` reports `local_endpoint`.
- There are no `--debug-writes` or `--debug-kill` flags yet; writes and kill arrive in step 9.4.
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
  started frozen with `-S` starts executing. Rampage never kills a target. When the connection ends, every session
  starts detaching at once and the server waits at most 2.5 s in all.
- If the stub refuses `D` (`E nn`), `debug_disconnect` reports `detached: false` and `closed: false`; the session
  stays open and attached, and disconnecting can be retried. In multiprocess mode a retry detaches only the
  processes still attached.
- A handshake that fails while the stream is still in step (a malformed stop reply, say) sends `D` before
  closing, because some stubs (`gdbserver --once`) kill their program when a debugger simply disconnects.
- A session is `stopped`, `running`, `exited`, `detached` or `lost`. A lost session carries the reason, such as a
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
| `debug_connect` | `endpoint?` | Session ID, architecture, `endianness` and its evidence, pointer size, the stub's `qSupported` features, packet size, state, typed stop reply, epoch, a page of threads, whether modules and a memory map are available, limitations |
| `debug_status` | `session`, `offset?`, `limit?` | State (with `reason` when lost), epoch, stop reply, bounded console output, a byte-fitted page of threads |
| `debug_registers` | `session`, `thread?`, `names?`, `offset?`, `limit?` | Per register: name, regnum, bitsize, type, group, `bytes` as sent and `value` decoded |
| `debug_read_memory` | `session`, `address`, `length` (1..=`max_read_length`), `thread?` | Hex runs of the bytes read, the thread used, plus every chunk's address, requested and read counts, and error |
| `debug_modules` | `session`, `offset?`, `limit?` | Modules and memory-map regions, the exec file and `qOffsets` |
| `debug_snapshot` | `session`, `output`, `ranges` | A new `rampage-snapshot-v1` file |
| `debug_continue` | `session`, `epoch`, `timeout_ms?` (default 5000, at most 60000) | A [stop event](#stop-events) and the new epoch, or `state: "running"` |
| `debug_wait` | `session`, `timeout_ms?` | The same shape as `debug_continue` |
| `debug_interrupt` | `session` | The same shape, after waiting up to 3 s for the stop |
| `debug_step` | `session`, `epoch`, `thread?`, `count?` (1..=1000, default 1) | Requested and completed steps, the pc after each completed step, the final stop event and epoch |
| `debug_breakpoints` | `session`, `action` (`set`, `clear`, `list`), and per action: `epoch`, `kind`, `address`, `size` or `length`, `id`, `offset`, `limit` | The entry set or cleared, or a byte-fitted page of the table |
| `debug_disconnect` | `session` | The final state, `detached`, `closed`, any detach error, `breakpoints_removed` and `removal_failures` |

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
- While stopped, `debug_status` re-asks the stub for its stop reply (`?`). A reply that differs from the previous
  `?` reply is a stop rampage did not cause (another debugger, say) and a new epoch. The first `?` after a stop
  rampage observed only sets the baseline, because stubs answer `?` in their own words: QEMU always says SIGTRAP,
  even after a watchpoint or an interrupt.
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
- Stepping is by machine instruction only. Stepping over or out of a call needs rampage's decoders and is step 9.3.

### Breakpoints and watchpoints

`debug_breakpoints` with `action: "set"` inserts:

| `kind` | Packet | Meaning |
|---|---|---|
| `software` | `Z0` | A breakpoint the stub plants in its own way |
| `hardware` | `Z1` | A hardware breakpoint |
| `write` | `Z2` | A write watchpoint |
| `read` | `Z3` | A read watchpoint |
| `access` | `Z4` | A read-or-write watchpoint |

- Addresses are runtime addresses. Placing a breakpoint by static address or function name in a bound project is
  step 9.3.
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
- `action: "list"` pages the table: ID, kind, address, size, hit count and whether the stub holds the entry.

### Stop events

A stop event reports:

- `reason`: `breakpoint`, `watchpoint`, `step`, `interrupted`, `signal`, `exited` or `terminated`.
- `signal`, `exit_status`, `thread`, and the stop reply as parsed.
- `pc`: the stopped thread's pc, from the stop reply's expedited registers, else read with `p` (or `g`), decoded in
  the session's byte order. It is null when the byte order is unknown (AArch64, RISC-V); `pc_bytes` always has the
  bytes as sent.
- `breakpoints`: the IDs of the table entries the stop matched. Each match increments the entry's hit count.
- `watch`: the access and address of a watchpoint hit.
- `reasons`: at most 16 of the stop reply's reasons. Its expedited registers are not repeated (a stub may send
  1,024 fields of 4 KiB); read them with `debug_registers`.
- `epoch`: the epoch this stop started, `console`: output received while the target ran, and `warnings`.

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
header is mapped at its load bias, which holds for shared objects and PIE executables. Modules are not matched
to files on disk or to a project; that is step 9.3.

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
| Breakpoints and watchpoints per session | 64 |
| Watchpoint length | 4096 bytes |
| Steps per request | 1,000, and 60 s in all |

## What 9.1 and 9.2 do not do

- No launch or attach, no register or memory writes, no kill (writes and kill are step 9.4).
- No signal delivery on resume: never `C`, `S` or `vCont;C`/`vCont;S`. A pending signal is discarded.
- No non-stop mode and no per-thread resume: every thread runs and stops together.
- No software-breakpoint emulation by writing memory; a stub without `Z0` reports it unsupported.
- No conditions or ignore counts on breakpoints, no step over or step out.
- No static correlation: no slides, symbols, breakpoints by static address or function name, or binding to a
  project (9.3).
- No LLDB `debugserver` extensions (9.5) and no Windows debugging (9.6).
- No expression evaluation and no monitor commands (`qRcmd`).
- Runtime bytes stay local. They are never published anywhere except the snapshot file you name.

## Acceptance

The protocol and the tools are tested against a scripted fake stub, over TCP and Unix sockets. It replays
transcripts of QEMU's Cortex-M3 stub and of gdbserver on AArch64 Linux, and also sends slow, malformed, oversized
and NAKed replies, stop replies in pieces and between console output, ignores interrupts, refuses `Z0`, and drops
the connection mid-command. Read-only scripts fail a test on any execution-control packet; execution scripts accept
only the packets listed above and fail on writes, kill, launch, attach, signal delivery and non-stop mode.

Each session request declares the packet classes it may send: `Read` (queries, register and memory reads, thread
selection for reads), `Execution` (`vCont?`, `vCont;c`, `vCont;s:<thread>`, `c`, `s`, `Hc<thread>`,
`Z0`..`Z4`/`z0`..`z4`) and `Detach` (`D`, `D;<pid>`). Inspection requests may send only `Read` packets. The client
refuses anything outside the request's classes before it reaches the wire, and refuses every other packet always.

The live acceptance runs QEMU on an owned firmware (`tests/fixtures/firmware`, rebuilt with
`build-firmware.sh`). The firmware calls a named function, `tick`, in a loop, and `tick` increments a RAM word,
`counter`; the tests find both in the ELF's symbol table. Through the API, the tests read and snapshot the halted
target, then break on `tick` with a hardware breakpoint, continue twice with it still set (stepping past it, so
`counter` advances by one per hit), step three instructions, catch the write to `counter`
with a watchpoint, see a short continue report `running`, interrupt it, have a stale epoch refused, and disconnect,
which removes the breakpoint and detaches.

```sh
RAMPAGE_QEMU_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(debug_qemu::)'
```

The test harness plays the operator and starts QEMU. Rampage itself only connects.
