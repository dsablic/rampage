# Debugger execution control (Phase 9) — design for review

Status: **approved 2026-10-29** with the decisions under "Approval decisions" below. Nothing here is implemented yet. The parity roadmap requires an approved design
before any launch, attach, resume, step, breakpoint or target-write code lands (`docs/plans/2026-10-16-ida-ghidra-
parity-roadmap.md`, Phase 9; `todo.md` "execution-control debugger integration requires separate design/review").

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
| `debug_status` | Current state, epoch, stop reason, threads. |
| `debug_registers` | Typed registers for a thread (all or named), with the target description's names and sizes. |
| `debug_read_memory` | Bounded memory read; hex plus optional decode through `inspect_data`-style typing. |
| `debug_continue` / `debug_wait` / `debug_interrupt` | Resume (all or one thread) with a bounded wait; wait again; interrupt. |
| `debug_step` | Single-step instructions (count ≤ 1000), or `over: true` to step over a call using rampage's own decoder to place a temporary breakpoint after the call. |
| `debug_breakpoints` | Set/clear/list software and hardware breakpoints and watchpoints, by runtime address, static address or function name in the bound project. Conditions and hit counts are evaluated by rampage, not by the stub. |
| `debug_modules` | Loaded modules, each matched (by path, build id/UUID, or hash of mapped bytes) to the bound project with its slide. |
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
| 9.1 | **Done 2026-10-29** (`55f9f22`; live QEMU Cortex-M3 acceptance passes). `rampage-debug` crate: framing, parser fuzzing, scripted fake stub for tests; read-only tools (`connect`, `status`, `registers`, `read_memory`, `modules`, `snapshot`, `disconnect` with detach). No execution. | Low: equivalent to today's read-only LLDB bridge over a different transport. |
| 9.2 | **Done 2026-11-04** (`019c5b3`; live QEMU Cortex-M3 acceptance passes). Execution control: continue/wait/interrupt, step, breakpoints and watchpoints; stop epochs enforced. | Medium. |
| 9.3 | **Done 2026-11-05** (`b111cea`; live QEMU Cortex-M3 acceptance passes). Static correlation: binding, slides, symbolic breakpoints, step-over via rampage decoders, stop-location enrichment. | Medium. |
| 9.4 | **Done 2026-11-05** (`4b2190d`; live QEMU RAM, register and flash writes and kill pass). Writes behind `--debug-writes`; kill behind `--debug-kill`. | Higher; reviewed separately. |
| 9.5 | **Implemented 2026-11-05** (`6a184b3`); live debugserver acceptance pending (needs DevToolsSecurity enabled). macOS `debugserver` acceptance (RSP plus LLDB extensions); evaluate driving LLDB's SB API through the existing bridge for crash/core files. | Platform-dependent. |
| 9.6 | Windows: separate short design (dbgeng vs. a GDB stub such as a Windows gdbserver). Proposal for review: `docs/plans/2026-11-05-debugger-windows.md`. | — |

Each step follows the wave cadence: implementation, fresh-context review, fixes, full suite, then MCP-level acceptance.

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

## What this deliberately does not do

- No process launch or attach by rampage; no plugin or host launch.
- No expression evaluation in the stub; conditions are rampage-side and typed.
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
- **9.5, review against LLVM main:** a fresh-context review of the protocol assumptions against debugserver's
  source led to these changes. `g` and `G` are never sent to an Apple stub (newer debugserver dropped them; older
  ones send a padded register context their gapless offsets do not describe); registers come from `p` and the stop
  reply's expedited registers, cached per stop, and register writes use `P` only. The image list is fetched as LLDB
  does, addresses first and then 64 images per request, so no reply outgrows a packet. Region replies may be as long
  as a packet (dirty-page lists), and a region walk that stops short marks the list partial. Watchpoint hits on a
  stub that reports them before the access (`watchpoint_exceptions_received:before`) are stepped past on the next
  continue. The stop event's watch hit gives debugserver's accessed address (`me_watch_addr`) beside the
  watchpoint's start. PAC stripping in annotations is limited to lr, fp and pc. The live test attaches to a
  program it started rather than having debugserver launch it.
