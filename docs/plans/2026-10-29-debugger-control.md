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
| 9.1 | `rampage-debug` crate: framing, parser fuzzing, scripted fake stub for tests; read-only tools (`connect`, `status`, `registers`, `read_memory`, `modules`, `snapshot`, `disconnect` with detach). No execution. | Low: equivalent to today's read-only LLDB bridge over a different transport. |
| 9.2 | Execution control: continue/wait/interrupt, step, breakpoints and watchpoints; stop epochs enforced. | Medium. |
| 9.3 | Static correlation: binding, slides, symbolic breakpoints, step-over via rampage decoders, stop-location enrichment. | Medium. |
| 9.4 | Writes behind `--debug-writes`; kill behind `--debug-kill`. | Higher; reviewed separately. |
| 9.5 | macOS `debugserver` acceptance (RSP plus LLDB extensions); evaluate driving LLDB's SB API through the existing bridge for crash/core files. | Platform-dependent. |
| 9.6 | Windows: separate short design (dbgeng vs. a GDB stub such as a Windows gdbserver). Not started before 9.1–9.4 land. | — |

Each step follows the wave cadence: implementation, fresh-context review, fixes, full suite, then MCP-level acceptance.

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
