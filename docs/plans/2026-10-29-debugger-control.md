# Debugger execution control (Phase 9) — design for review

Status: **approved 2026-10-29** with the decisions under "Approval decisions" below. 9.1–9.5 are done (9.5's live macOS
`debugserver` acceptance passed 2026-11-11); 9.6a (Windows through RSP stubs) is implemented, with live acceptance pending. See
[Phased delivery](#phased-delivery) and the user-facing [debug control guide](../debug-control.md). The parity
roadmap requires an approved design before any launch, attach, resume, step, breakpoint or target-write code lands
(`docs/plans/2026-10-16-ida-ghidra-parity-roadmap.md`, Phase 9; `todo.md` "execution-control debugger integration
requires separate design/review").

## Why now

Debugging is the largest category where agent-facing competitors are ahead. REA drives GDB/MI, a Rizin debugger, an
LLDB tracer and Frida, but returns console text, loses state with its ephemeral databases and has repeated
wedge/crash bugs in those wrappers (GDB MI lines over 16 MiB wedge sessions; out-of-range values kill the server).
rampage today has only a read-only, stopped-session LLDB bridge (`query_debugger`, `docs/lldb-query.md`) and snapshot
tools that work on captured files. Execution control lets an agent confirm static hypotheses at runtime: hit a
function, read its arguments, watch a buffer being decrypted, and feed the result back into the static project.

## Decisions proposed

1. **GDB Remote Serial Protocol (RSP) client first, written natively in Rust.** One client covers gdbserver (Linux,
   Android), QEMU user and system mode, OpenOCD / probe-rs / J-Link GDB servers (embedded firmware), many emulators,
   and Apple `debugserver` (RSP with LLDB extensions). No GDB, LLDB or Python process in the loop; responses are
   parsed into typed structs rather than console text.
2. **rampage never launches or attaches to processes.** The operator starts the stub (`gdbserver :2345 ./prog`,
   `qemu-system-arm -s -S …`, `openocd …`) and allows its endpoint. This keeps the existing rule "no automatic launch,
   attach or plugin execution" (`todo.md`) and avoids running untrusted code on rampage's behalf.
3. **Operator consent is configuration, not a tool call.** MCP has no consent mechanism of its own, and tool groups
   are discovery control, not authorization (`docs/mcp.md`). So:
   - Debug tools exist only when the server is started with `--debug-endpoint <host:port|unix-path>` (repeatable)
     or `RAMPAGE_DEBUG_ENDPOINTS`. An agent can connect only to a listed endpoint; it cannot supply one.
   - Endpoints default to loopback/Unix sockets; a non-loopback address must be listed explicitly.
   - Execution control (resume, step, breakpoints) is allowed by the endpoint listing. Target writes (memory,
     registers) additionally need `--debug-writes`. Killing the inferior needs `--debug-kill`.
   - The client's own per-tool permission prompts still apply on top.
4. **Sessions live in the MCP server process**, one registry per MCP connection. The decompiler worker is one request
   per process and cannot hold a connection; `Session`/`Project` hold no runtime state. A session is a thread that owns
   the socket and serves typed commands from the tool handlers over a channel, one command in flight.
5. **New crate `rampage-debug`** for the protocol client, target description parsing and session thread, with no
   dependency on the analysis stack. `rampage-api` adds the tool registry entries and static/runtime correlation.

## Session model

```
MCP tool call ──► RampageServer ──► DebugRegistry (per connection)
                                        │  session id → DebugSession
                                        ▼
                               session thread ── RSP over TCP / Unix socket ──► gdbserver / QEMU / OpenOCD
```

- **State machine:** `Connected(stopped)` ⇄ `Running` → `Exited | Detached | Lost`. Every stopped state carries a stop
  epoch (incremented on each stop). Reads return the epoch; writes and steps require the caller's epoch to match, so an
  agent never acts on registers from an earlier stop. This mirrors the LLDB bridge's stop tokens.
- **Running is not blocking:** `debug_continue` waits up to a bounded timeout (default 5 s, max 60 s) and returns either
  a stop event or `running`. `debug_wait` waits again; `debug_interrupt` sends `\x03`.
- **Lifetime:** sessions end when the MCP connection closes. Default disconnect action is detach (`D`), never kill
  unless `--debug-kill` and an explicit `kill: true`.
- **Limits:** at most 4 sessions per connection; packet size from `qSupported` capped at 1 MiB; memory reads ≤ 64 KiB
  per call (same as `query_debugger`); per-command timeouts; cancellation through the existing `AtomicBool` pattern.

## Protocol coverage

- Framing, checksums, `+`/`-` acks and `QStartNoAckMode`, binary escaping, run-length decoding, `O` console output.
- `qSupported`, `qXfer:features:read:target.xml` (with includes) for registers and architecture; fallback layouts for
  stubs without target descriptions (x86-64, AArch64, ARM, RISC-V 32/64).
- `?`, `T`/`S`/`W`/`X` stop replies including `watch`, `library`, `swbreak`/`hwbreak` and thread fields.
- Threads: `qfThreadInfo`/`qsThreadInfo`, `Hg`/`Hc`, `qThreadExtraInfo`, `vCont?` and `vCont`.
- Registers and memory: `g`/`p`, `m`/`x` (binary when supported), and with `--debug-writes`, `P`/`G` and `M`/`X`.
- Breakpoints: `Z0`/`z0` software, `Z1` hardware, `Z2`/`Z3`/`Z4` write/read/access watchpoints.
- Modules: `qXfer:libraries-svr4:read`, `qXfer:libraries:read` (Windows-style stubs), `qXfer:exec-file:read`,
  `qOffsets`, `qXfer:memory-map:read` (flash/RAM regions on embedded targets).
- LLDB extensions where the stub offers them (`qHostInfo`, `qProcessInfo`, `jThreadsInfo`, `qMemoryRegionInfo`), used
  only to add information, never required.

The packet parser is fuzzed and has property tests; every response is validated (lengths, hex, register sizes from
the target description) before it reaches a typed result.

## MCP tools (new `debug` group, absent unless an endpoint is configured)

| Tool | Purpose |
|---|---|
| `debug_connect` | Connect to an allowed endpoint; optionally bind a project path. Returns session id, architecture, features, threads, stop reason, modules, epoch. |
| `debug_bind` | Bind a project to one of the session's runtime modules after connecting (added in 9.3). |
| `debug_status` | Current state, epoch, stop reason, threads. |
| `debug_registers` | Typed registers for a thread (all or named), with the target description's names and sizes. |
| `debug_read_memory` | Bounded memory read; hex plus optional decode through `inspect_data`-style typing. |
| `debug_continue` / `debug_wait` / `debug_interrupt` | Resume every thread (all-stop; per-thread resume was not implemented) with a bounded wait; wait again; interrupt. |
| `debug_step` | Single-step instructions (count ≤ 1000), or `over: true` to step over a call using rampage's own decoder to place a temporary breakpoint after the call. |
| `debug_breakpoints` | Set/clear/list software and hardware breakpoints and watchpoints, by runtime address, static address or function name in the bound project. Rampage counts hits; conditions and ignore counts are not implemented (see the deviations). |
| `debug_modules` | Loaded modules, each matched (by path, build id/UUID, or hash of mapped bytes) to the bound project with its slide. |
| `debug_evidence` | A bounded record of the stop with a ready `record_finding` evidence item (added in 9.3). |
| `debug_snapshot` | Capture the stopped state to a `rampage-snapshot-v1` file (regions, registers, modules) so every existing runtime tool works on it. |
| `debug_write_memory` / `debug_write_register` | Only with `--debug-writes`; epoch-checked; returns before/after bytes. |
| `debug_disconnect` | Detach (default) or kill (only with `--debug-kill`). |

### Static ↔ runtime correlation (the differentiator)

When a project is bound, rampage computes each module's slide and translates in both directions: breakpoints by
function name or static address; stop locations reported as runtime address, static address, function name and
`show_address` hint; registers that point into the image are annotated with the symbol or string they reference. An
agent can go from `decompile` to "break here, show me the arguments" without address arithmetic. Findings can be
recorded in the project's findings ledger with the debug session as evidence.

## Phased delivery

| Step | Scope | Risk |
|---|---|---|
| 9.1 | **Done 2026-10-29** (`bbc68e9`; live QEMU Cortex-M3 acceptance passes). `rampage-debug` crate: framing, parser fuzzing, scripted fake stub for tests; read-only tools (`connect`, `status`, `registers`, `read_memory`, `modules`, `snapshot`, `disconnect` with detach). No execution. | Low: equivalent to today's read-only LLDB bridge over a different transport. |
| 9.2 | **Done 2026-11-04** (`019c5b3`; live QEMU Cortex-M3 acceptance passes). Execution control: continue/wait/interrupt, step, breakpoints and watchpoints; stop epochs enforced. | Medium. |
| 9.3 | **Done 2026-11-05** (`b111cea`; live QEMU Cortex-M3 acceptance passes). Static correlation: binding, slides, symbolic breakpoints, step-over via rampage decoders, stop-location enrichment. | Medium. |
| 9.4 | **Done 2026-11-05** (`4b2190d`; live QEMU RAM, register and flash writes and kill pass). Writes behind `--debug-writes`; kill behind `--debug-kill`. | Higher; reviewed separately. |
| 9.5 | **Implemented 2026-11-05** (`6a184b3`); live debugserver acceptance passed 2026-11-11. macOS `debugserver` acceptance (RSP plus LLDB extensions); evaluate driving LLDB's SB API through the existing bridge for crash/core files. | Platform-dependent. |
| 9.6 | **9.6a implemented 2026-11-05** (`c3f9669`); live acceptance pending (no Windows host). Windows: separate short design (dbgeng vs. a GDB stub such as a Windows gdbserver); Option A (RSP stub) approved 2026-11-05: [`2026-11-05-debugger-windows.md`](2026-11-05-debugger-windows.md). 9.6a covers user-mode processes through `gdbserver.exe` and `lldb-server`; Option B (DbgEng) is deferred. | Platform-dependent. |

Each step follows the same cadence: implementation, independent review, fixes, full suite, then MCP-level acceptance.

## LLDB's SB API for crash and core files (9.5 evaluation)

The design asks whether to drive LLDB's SB API through the existing bridge for crash and core files. Written
evaluation only; nothing is implemented.

- **What `query_debugger` does today.** `tools/lldb_bridge.py` runs inside an operator's LLDB session that is
  already stopped. It answers six enumerated read-only operations (`describe_session`, `list_modules`,
  `list_threads`, `read_registers`, `read_memory`, `resolve_module_address`) with stop tokens and byte budgets,
  in session or over an operator-served private Unix socket. It never creates targets, attaches, resumes or
  evaluates expressions. Because it reads whatever `SBProcess` the session has, it already works on a core file the
  operator loaded with `target create --core`: LLDB's ELF, Mach-O and minidump core plug-ins present a stopped
  process. What is missing is only a way to turn such a session into a `rampage-snapshot-v1` file, which the
  snapshot guide's LLDB export workflow does by hand for x86-64 and ARM32.
- **Reading cores through rampage-debug's snapshot path instead.** `debug_snapshot` captures from a live stub, so
  it would need a core-file "stub": parsers for ELF cores (`PT_LOAD` segments, `NT_PRSTATUS` per thread,
  `NT_FILE` for mapped files, `NT_GNU_BUILD_ID` through the mapped images), Mach-O cores (`LC_SEGMENT_64`,
  `LC_THREAD` flavors per architecture, the `main bin spec` and `load binary` notes that newer LLDB writes) and
  minidumps; a register mapping per architecture into the snapshot's register list; and module identity from the
  notes. That is a new loader-sized component (rampage-loaders already parses ELF and Mach-O files, not their core
  variants), with every core flavor a format to keep up with, but no LLDB in the loop and no Python.
- **Through LLDB.** A new bridge operation such as `export_snapshot` would use `SBProcess.GetMemoryRegions`,
  `ReadMemory`, `SBFrame` registers and `SBModule` UUIDs to write the snapshot. It inherits LLDB's core support for
  free (including Mach-O cores with the shared cache), but keeps rampage dependent on the operator's LLDB and its
  Python, and runs inside LLDB's process with the bridge's existing limits on interrupting SDK calls.
- **Recommendation.** Do neither for 9.5. First, document the existing path: load the core in LLDB, serve the
  bridge, and use `query_debugger` plus the snapshot guide's export. Next, when a core-file need is concrete, add
  an enumerated read-only `export_snapshot` bridge operation (bounded regions, the token checks, a new snapshot file
  only), because it reuses LLDB's core plug-ins rather than reimplementing them. Native core parsing in
  rampage-loaders is worth it only for ELF cores, if headless batch triage without LLDB becomes a requirement.

## Acceptance

- **Unit and protocol:** fuzzed packet parser; a scripted fake stub replaying recorded transcripts (including malformed,
  oversized and slow responses, disconnects mid-command).
- **Live, owned fixtures only:**
  - QEMU system mode (`brew install qemu`) running a tiny owned bare-metal ARM Cortex-M or RISC-V firmware: covers
    the firmware investigation track, hardware breakpoints and memory maps, runs on macOS.
  - Linux `gdbserver` with owned x86-64 and AArch64 ELF fixtures in CI.
  - macOS `debugserver` with an owned arm64 fixture (9.5).
- **Agent-level:** a parity-scorecard task where an agent, through MCP only, breaks on a named function in an owned
  fixture, reads its arguments, steps out and records the observed return value as a finding.

## Acceptance record

Moved from [debug control](../debug-control.md). What each step's tests and live runs cover.

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

### debugserver

The fake stub's debugserver transcript (`transcripts::debugserver_arm64`) is built from debugserver's source
(`lldb/tools/debugserver/source/RNBRemote.cpp`) and LLDB's `lldbgdbremote.md`, not recorded: the machine it was
written on could not run debugserver. It covers `qHostInfo` and `qProcessInfo`, a target description with gapless
offsets and views, `qRegisterInfo`-only discovery, `g` answered as unsupported (registers come from `p` and the stop
reply), `jThreadsInfo`, the image list (addresses, then a batch) with the main executable, dyld and a shared-cache
library, `qMemoryRegionInfo` with a busy region whose dirty-page list runs past 4 KiB, and stop replies with Mach
exceptions and a watchpoint stop without one. The fake stub checks every LLDB query against its own parser and
fails a test on any other form or any other `j` packet. The tests check the handshake (the architecture from the
CPU type, the stated byte order, the address mask), both register discovery paths, that no `g` or `G` is sent and
registers are read once per stop, that GDB stubs are asked none of the queries, breakpoints of kind 4, `vCont`
steps, a watchpoint hit as `reason:watchpoint` (its accessed address too) and a continue that steps past it with
the watchpoint taken out and put back, an interrupt answered with SIGSTOP, and `EXC_BAD_ACCESS` with its fault
address. Through the tools, they bind the owned arm64 fixture (`tests/fixtures/debug-macho`, rebuilt with its
`build.sh`: a C program calling `tick` in a loop, `tick` adding to the global `counter`, ad-hoc signed with
`get-task-allow`) by UUID at a slide, refuse a shared-cache library by path, by name with a slide and by a file of
another UUID, bind an extracted image of the cached UUID, step out with a signed x30 and annotate it (defensively:
debugserver strips those itself) while leaving an integer register with the same bits unannotated, and report a
Mach exception in a stop event.

The live acceptance needs debugserver and `sudo DevToolsSecurity -enable` (or developer mode). The harness plays the
operator: it starts the fixture, then `debugserver 127.0.0.1:<port> --attach=<pid>`. It connects with the fixture's
path (binding by UUID), breaks on `_tick` by name, continues to it, steps out to `_main`, catches the write to
`counter` with a watchpoint on two continues in a row with the watchpoint still set, interrupts a running continue,
snapshots the program's `__TEXT` and detaches, then kills debugserver and the program whatever the outcome. Without `RAMPAGE_DEBUGSERVER_LIVE=1` it skips with a message; `RAMPAGE_DEBUGSERVER` names a
debugserver binary other than the Command Line Tools' or Xcode's. It has not yet run against a real debugserver.

```sh
RAMPAGE_DEBUGSERVER_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(debug_debugserver_live::)'
```

### Windows stubs

The fake stub's Windows transcripts (`rampage_debug::fake::windows`) follow gdbserver's and lldb-server's sources;
they were not recorded (see [what is not live-verified](../debug-control.md#what-is-not-live-verified)). gdbserver x64 serves its
generated description with the `Windows` OS ABI, DLLs at their base plus 0x1000 without the executable, the exec
file, `qGetTIBAddr` with the TIB and PEB in memory, `EXCEPTION_RECORD`s through `qXfer:siginfo:read`, refuses `Z3`,
and grows a thread when interrupted; its WoW64 variant serves the `i386` description, 32-bit DLLs, a 32-bit TIB and
`EXCEPTION_RECORD32`. lldb-server x64 serves LLDB's features with a decimal `PacketSize`, `qHostInfo` and
`qProcessInfo` with a Windows triple, an unnamed feature with offsets and a view, every image at its base,
`qMemoryRegionInfo`, stop replies with `reason` and a hex `description`, and refuses `Z1`. The fake maps PE images
the way the loader does (`map_pe`: sections at their RVAs, base relocations applied, the runtime base written into
`ImageBase`).

The tests check, in `rampage-debug`: Windows detection; both module forms with the PE headers and CodeView records
read at the right base; the executable from the PEB (gdbserver) or the list (lldb-server); breakpoints, single steps
and access violations with their exception records; that a step's SIGTRAP asks for no record; `Z3` and `Z1`
refusals; lldb-server's watchpoint description and exception descriptions (a compiled-in int3 as a breakpoint);
interrupts in a new thread under both stubs, with reads and steps passing over it and gdbserver's break-in thread
parked (the next continue names every other thread); a DLL-load stop racing an interrupt; gdbserver before 16,
recognized without an OS ABI, with a loaded `.exe` in its list not taken for the program; library names with a bare
`&`; and a WoW64 process. Through the tools, with the owned fixtures in `tests/fixtures/debug-windows` (rebuilt
with its `build.sh`: a C program without a C runtime, `start` calling the exported `tick` in a loop, `tick` adding to
`counter` through a `movabs` pointer that a base relocation patches; zig's MinGW target links it with LLD, which
writes the RSDS record; x64 and x86 builds of 4-5 KiB): binding by CodeView at an ASLR slide with the relocated bytes
left out (the mapped bytes differ from the file at the relocation), refusing an image whose unrelocated code differs,
case-insensitive `\\?\` paths, a breakpoint by function name with its stop located in `tick`, step out to `start`
by `[rsp]`, a Windows exception and an interrupt through `debug_continue` and `debug_interrupt` with registers and
evidence read from the main thread (and the x64 argument registers), a WoW64 process binding the x86 fixture and
stepping out by `[esp]`, an ASLR image at its preferred base binding at slide 0 with nothing left out, an image whose
code is all relocated reported `unverified` rather than matched, and a snapshot recording a bound module's
preferred base.

The live acceptance needs a Windows host the machine running the tests can reach. On the Windows host, copy
`tests/fixtures/debug-windows/pe-loop-x64.exe` (or `pe-loop-x86.exe`) over and start one of:

```text
gdbserver.exe --once 0.0.0.0:2345 pe-loop-x64.exe
lldb-server.exe gdbserver 0.0.0.0:2345 -- pe-loop-x64.exe
```

Then, on the machine running the tests:

```sh
RAMPAGE_WINDOWS_LIVE=1 RAMPAGE_WINDOWS_ENDPOINT=winhost:2345 \
    cargo nextest run -p rampage-api --run-ignored only -E 'test(debug_windows_live::)'
```

`RAMPAGE_WINDOWS_FIXTURE=pe-loop-x86.exe` runs it against the 32-bit fixture. The test launches nothing: it connects
with the endpoint allowed, binds the fixture by its CodeView record, breaks on `tick` by name, steps out to `start`,
catches the write to `counter` with a watchpoint, interrupts a running continue, snapshots `.text` and detaches.
Without both variables it skips with a message. It has not yet run against a real stub.

## What this deliberately does not do

- No process launch or attach by rampage; no plugin or host launch.
- No expression evaluation in the stub. Breakpoint conditions were planned rampage-side and typed, and are not
  implemented (see the deviations).
- No remote endpoints unless the operator lists them; no publishing of runtime bytes (they stay local, as today).
- No automatic writes, ever; no kill without both the flag and an explicit argument.
- Debug tools are not offered to the in-app UI assistant until the UI has its own consent flow.

## Approval decisions (2026-10-29)

1. **Consent:** operator configuration as described (`--debug-endpoint`, `--debug-writes`, `--debug-kill`) plus the
   client's own permission prompts. No additional per-session confirmation.
2. **No separate execution-control flag:** listing an endpoint allows read-only inspection and execution control.
3. **First live acceptance target:** QEMU system mode running a tiny owned bare-metal firmware. Linux gdbserver and
   macOS `debugserver` follow.
4. **Home:** a new `rampage-debug` crate for the protocol client, target descriptions and session thread, with no
   dependency on the analysis stack. `rampage-api` adds the tools and static/runtime correlation.

## Deviations recorded during implementation

- **9.1, cancellation:** the `AtomicBool` cancellation in "Limits" is not implemented. MCP tool calls in rampage
  have no cancellation path to plumb it to, so a `debug_snapshot` of up to 64 MiB runs until it completes, fails,
  or a request (10 s each, per 64 KiB read) times out. It is bounded but not cancellable. Revisit with 9.2's
  `debug_continue`/`debug_wait`, which need a cancellable wait anyway.
- **9.2, cancellation (closes the 9.1 deviation):** rmcp 3.5's `RequestContext::ct` is cancelled on
  `notifications/cancelled` for the request, and (through its parent token) when the service shuts down after the
  connection closes. The MCP server turns it into a cancel flag that reaches the debug tools through
  `spawn_blocking`. `debug_continue`, `debug_wait` and `debug_interrupt` then return at once with
  `{ state: "running", cancelled: true }`; the session thread drops the waiter and keeps the target as it is.
  `debug_step` stops between steps. `debug_read_memory` and `debug_snapshot` stop between chunks, and a cancelled
  snapshot writes nothing. Waits stay bounded either way.
- **9.2, breakpoint table:** entries the stub refuses are not added; the table's `inserted` flag records whether
  the stub still holds an entry (false after the process exits). Breakpoint conditions and hit counts evaluated by
  rampage beyond counting are left for 9.3.
- **9.2, matching by pc:** QEMU reports breakpoint hits as a bare SIGTRAP without `swbreak`/`hwbreak`, so a SIGTRAP
  after a continue matches breakpoints at the pc; after a step it does not, since the two look the same.
- **9.2, stepping past breakpoints:** a stub stopped at an inserted breakpoint reports it again on every continue,
  so `debug_continue` removes the breakpoints at the pc, single-steps the thread and re-inserts them first. Without
  `vCont`, an `Hc<thread>` step is undone with `Hc-1` before a plain `c` (added to the execution class); a stub
  refusing it is not continued.
- **9.3, step out:** only from a function's first instruction in a bound project, where the ABI's return address
  (lr, x30, ra, `[rsp]`/`[esp]`) is reliable; elsewhere it is refused rather than guessed. Frame unwinding would
  lift this and is not in 9.3.
- **9.3, frames:** a step over or out checks the thread and stack pointer at the return address and stops,
  reported as `inner_frame` or `other_thread`, when a recursive frame or another thread got there first, rather
  than running on until the right frame arrives.
- **9.3, temporary breakpoints:** all-stop stubs cannot take a breakpoint out while the target runs, so a step
  over or out that times out or is cancelled leaves its temporary breakpoint inserted until the next stop (which
  removes it whatever it is) or the disconnect. A table breakpoint at the same address stands in for it.
- **9.3, plain steps:** `debug_step` without `over` still does not take breakpoints at the pc out (QEMU steps
  anyway); `over` does, for calls and single steps alike.
- **9.3, findings:** ledger evidence is a `{tool, detail}` reference of at most 300 bytes, so `debug_evidence`
  returns the structured record in its result and a compact text item for `record_finding`; the ledger format is
  unchanged.
- **9.3, agent-level scorecard task:** not added. The parity runner (`crates/rampage-eval/src/parity_agent.rs`)
  serves an in-memory `RampageServer` without a debug registry, allows only listed read-only tools plus opt-in edit
  classes, requires every call's `path` to be the fixture (debug tools take a `session`), and has no harness-owned
  emulator lifecycle; its answers must be deterministic, and the firmware's `tick` returns nothing. Adding it needs
  a QEMU-owning task kind, an execution-effect permission class for the debug tools and `record_finding`, and a
  firmware function with arguments and a return value. The live acceptance runs the same sequence through the tool
  layer instead (break on a named function, read registers, step out, record a finding with `debug_evidence`).
- **9.3, breakpoint conditions:** not added. The 9.2 deviation left conditions and hit counts beyond counting to
  9.3, and 9.3 did not implement them. Breakpoints have hit counts but no conditions or ignore counts; agents check
  values themselves after a stop.
- **9.3, stop locations:** `debug_status`'s `last_stop` is not located; the results of continue, wait, interrupt
  and step are.
- **9.5, transcripts:** debugserver could not run on the machine 9.5 was written on (developer tools security
  off; sudo not used), so the fake stub's debugserver transcript is built from debugserver's source and LLDB's
  protocol documentation, not recorded, and the live acceptance (`RAMPAGE_DEBUGSERVER_LIVE=1`) is written but has
  not run. Field formats that the sources leave open were taken conservatively: `qProcessInfo` numbers are hex and
  `qHostInfo` numbers decimal, addressing bits decimal in both; `j` replies are parsed binary-unescaped, falling
  back to the reply as sent.
- **9.5, which stubs are asked LLDB queries:** only stubs advertising `qEcho+` or `native-signals+`, so gdbserver,
  QEMU and OpenOCD see no new packets. Acknowledgements stay on: debugserver advertises no `QStartNoAckMode`, and
  in no-ack mode it sends the checksum `#00`, which rampage's framer rejects.
- **9.5, `jThreadExtendedInfo`:** not used. `jThreadsInfo` gives names, queues and stop reasons; it is asked only
  with at most 64 threads, since its reply carries every thread's registers and stack memory.
- **9.5, shared cache:** a module flagged `MH_DYLIB_IN_CACHE` binds only by UUID (an extracted image); a name,
  header bytes or an explicit slide are refused with `shared_cache_image`.
- **9.5, PAC:** stripped only on arm64 sessions whose stub states addressing bits or is an Apple one (47-bit
  default); Linux AArch64 pointer authentication (`pauth_cmask` registers) is not read.
- **9.5, interrupts:** debugserver stops an interrupted process with SIGSTOP, which counts as `interrupted` on an
  Apple stub only.
- **9.5, review against LLVM main:** an independent review of the protocol assumptions against debugserver's
  source led to these changes. `g` and `G` are never sent to an Apple stub (newer debugserver dropped them; older
  ones send a padded register context their gapless offsets do not describe); registers come from `p` and the stop
  reply's expedited registers, cached per stop, and register writes use `P` only. The image list is fetched as LLDB
  does, addresses first and then 64 images per request, so no reply outgrows a packet. Region replies may be as long
  as a packet (dirty-page lists), and a region walk that stops short marks the list partial. Watchpoint hits on a
  stub that reports them before the access (`watchpoint_exceptions_received:before`) are stepped past on the next
  continue. The stop event's watch hit gives debugserver's accessed address (`me_watch_addr`) beside the
  watchpoint's start. PAC stripping in annotations is limited to lr, fp and pc. The live test attaches to a
  program it started rather than having debugserver launch it.
