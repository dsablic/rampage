# Read-only debug sessions with GDB remote stubs

Rampage's MCP server can connect to a GDB Remote Serial Protocol stub that an operator has already started:
`gdbserver` on Linux or Android, QEMU's `-s`/`-gdb` stub, OpenOCD, probe-rs and similar. An agent can then read
the stopped target's registers, memory, threads, loaded modules and memory map, and capture it to a snapshot file
that every runtime and analysis tool opens.

This is step 9.1 of the [debugger design](plans/2026-10-29-debugger-control.md). It is inspection only. Rampage
never launches or attaches to a process, and it never resumes, steps, sets breakpoints, writes registers or
memory, or kills a target. The protocol client keeps every such packet off the wire.

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

Listing an endpoint is the operator's consent for agents to inspect that stub; the MCP client's own per-tool
prompts still apply on top. The rules:

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
- `debug_disconnect`, or the end of the MCP connection, sends `D` (detach). **Detaching lets the target run**: a
  program under gdbserver continues, and a QEMU guest started frozen with `-S` starts executing. Rampage never
  kills a target. When the connection ends, every session starts detaching at once and the server waits at most
  2.5 s in all.
- If the stub refuses `D` (`E nn`), `debug_disconnect` reports `detached: false` and `closed: false`; the session
  stays open and attached, and disconnecting can be retried. In multiprocess mode a retry detaches only the
  processes still attached.
- A handshake that fails while the stream is still in step (a malformed stop reply, say) sends `D` before
  closing, because some stubs (`gdbserver --once`) kill their program when a debugger simply disconnects.
- A session is `stopped`, `exited`, `detached` or `lost`. A lost session carries the reason, such as a timeout,
  a dropped connection or a malformed reply. A timed-out request loses the session, because the reply stream can
  no longer be trusted to match requests.
- Each stop the session observes gets a stop epoch. `debug_status` re-asks the stub for its stop reply (`?`) and
  threads; a stop reply different from the last one is a new stop and increments the epoch. In 9.1 rampage never
  runs the target, so the epoch changes only if something else does. Every read reports the epoch it read at.
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
| `debug_disconnect` | `session` | The final state, `detached`, `closed` and any detach error |

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
| Console output kept | 4 KiB |
| Console-output and notification packets per request | 256 |

## What 9.1 does not do

- No launch, attach, resume, step, interrupt, breakpoints, watchpoints, register or memory writes, or kill. Those
  are steps 9.2 and 9.4.
- No static correlation: no slides, symbols or binding to a project (9.3).
- No LLDB `debugserver` extensions (9.5) and no Windows debugging (9.6).
- No expression evaluation and no monitor commands (`qRcmd`).
- No cancellation: a long snapshot runs until it completes, fails or hits a request timeout (see the design's
  approval notes).
- Runtime bytes stay local. They are never published anywhere except the snapshot file you name.

## Acceptance

The protocol and the tools are tested against a scripted fake stub, over TCP and Unix sockets. It replays
transcripts of QEMU's Cortex-M3 stub and of gdbserver on AArch64 Linux, and also sends slow, malformed, oversized
and NAKed replies and drops the connection mid-command. The fake stub fails a test on any execution-control
packet.

The live acceptance runs QEMU on an owned firmware (`tests/fixtures/firmware`, rebuilt with
`build-firmware.sh`):

```sh
RAMPAGE_QEMU_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(debug_qemu::)'
```

The test harness plays the operator and starts QEMU. Rampage itself only connects.
