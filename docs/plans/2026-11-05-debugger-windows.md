# Debugger on Windows targets (Phase 9.6): short design for review

Status: **Option A approved 2026-11-05** (RSP stub route first; Option B deferred behind its own design); **9.6a
implemented 2026-11-05** (`c3f9669`), live acceptance pending. No Windows
VM was offered, so 9.6a ships with fake-stub coverage plus an opt-in live test against an operator-provided endpoint,
and the docs mark it "not live-verified" until that test runs. The parent design
(`docs/plans/2026-10-29-debugger-control.md`) requires a separate short design for Windows before any code. 9.1–9.4 are
done, and 9.5 (macOS `debugserver`) is implemented (`6a184b3`) with live acceptance pending.

## Constraints carried over

- **No launching or attaching.** rampage never launches or attaches to processes. The operator starts the debug
  server and lists its endpoint.
- **Consent flags.** `--debug-endpoint`, `--debug-writes` and `--debug-kill` keep their meaning.
- **Same tools.** The tool surface stays the same (`debug_*`), with typed, bounded results and stop epochs.
- **Owned fixtures.** Live acceptance uses owned fixtures only.

## Options

| | A. RSP stub on Windows | B. DbgEng client to an operator-started debug server |
|---|---|---|
| What runs on the target host | `gdbserver.exe` (MinGW-w64/MSYS2 build) or `lldb-server gdbserver` | `cdb`/`windbg -server tcp:port=N` attached by the operator, or `dbgsrv` |
| rampage code | None new in the protocol layer: `rampage-debug` already speaks RSP. Small additions: Windows module lists (`qXfer:libraries:read`), PE binding (the `debug_correlation` PE path), and Windows exception stop mapping | A new backend behind a session trait: DbgEng COM (`DebugConnect`) on a Windows host only. rampage would no longer run on macOS/Linux for these targets |
| Fidelity | Basic user-mode debugging: threads, registers, memory, breakpoints, watchpoints. Exception detail depends on the stub | Full: first- and second-chance exceptions, PDB-aware symbols, minidumps, and kernel targets through KDNET |
| Consent model | Unchanged | Mostly unchanged. The operator's debugger owns the attach; rampage connects as a client. Its command channel must be restricted to a typed allowlist, like the RSP packet classes, never free-form debugger commands |
| Risk | Low. Stub maturity on Windows is the unknown (see below) | Medium to high: COM bindings, Windows-only CI, and a command surface that is harder to allowlist |

### Facts to verify before choosing (not verifiable without a Windows host)

- **lldb-server on Windows.** Its Windows support landed upstream through LLVM review D56233, "Make lldb-server
  work on Windows". Its maturity in current LLVM releases (x64 and arm64), especially exceptions and watchpoints,
  needs a hands-on check on a Windows VM.
- **MinGW-w64 `gdbserver.exe`** (MSYS2 package). It is widely used for user-mode targets. Check its `qXfer:libraries`
  output and its handling of Windows exceptions in `T` replies.
- **WinDbg's own RSP use goes the other way, as a client.** It connects to Linux gdbserver (`gdb:server=…,port=…`),
  and EXDI connects to QEMU, OpenOCD or UEFI stubs for kernel debugging. Neither gives rampage a Windows-side stub to
  connect to.

## Recommendation

1. **9.6a, Option A first.** It reuses all of `rampage-debug`, keeps rampage cross-platform, and fits the existing
   consent and packet-class model unchanged. Work items:
   - Windows `qXfer:libraries` module lists, and PE binding and slides;
   - Windows exception codes in stop events;
   - a live acceptance on a Windows x64 VM with an owned PE fixture, built with zig, which already targets PE here.
   Acceptance needs a Windows VM, which the maintainer would provide; until then, fake-stub transcripts from the
   LLVM and GDB sources.
2. **9.6b, Option B later, only if needed.** Go to Option B only if users need PDB-rich, exception-heavy or kernel
   debugging that RSP stubs can't give. Write a separate design first: it adds a Windows-only backend and a second
   command allowlist.
3. **Crash dumps (minidumps) are not live debugging.** They belong with the snapshot and loader work (a minidump
   loader feeding `rampage-snapshot-v1`), not here.

## Decisions requested

- Is Option A as 9.6a acceptable, with Option B deferred behind its own design?
- Can a Windows x64 VM (or CI runner) be provided for live acceptance? Without one, 9.6a ships with fake-stub
  coverage only, and the docs mark it "not live-verified".

## Implementation notes (9.6a)

9.6a is implemented on the RSP-stub route; 9.6 is not done until the live acceptance runs on a Windows host. What
was decided while building it, from the stubs' sources (GDB's `gdbserver/win32-low.cc`, `win32-i386-low.cc`,
`server.cc`, `gdb/nat/windows-nat.c`, `gdb/windows-tdep.c`; LLVM's `NativeProcessWindows.cpp`,
`NativeThreadWindows.cpp`, `GDBRemoteCommunicationServerLLGS.cpp`), and recorded in `docs/debug-control.md`:

- **No Windows VM.** Fake-stub transcripts for gdbserver x64, gdbserver with a WoW64 process and lldb-server x64
  are built from those sources (`rampage_debug::fake::windows`). The opt-in live test (`RAMPAGE_WINDOWS_LIVE=1`,
  `RAMPAGE_WINDOWS_ENDPOINT`) connects to an operator-started stub and launches nothing.
- **Detection.** gdbserver's target description names the `Windows` OS ABI; lldb-server states a Windows triple and
  `ostype:windows`. `debug_connect` reports `windows` with the stub and the evidence.
- **Modules.** gdbserver's `<segment address>` is the image base plus a constant 0x1000 (not the first section's
  RVA), and its list leaves out the executable, which rampage finds as GDB does, through `qGetTIBAddr` and the PEB.
  lldb-server's `<section address>` is the image base, and its list includes the executable. Rampage reads each
  module's PE headers and CodeView record from target memory.
- **Binding.** CodeView (PDB GUID and age) is identity evidence. Windows paths compare case-insensitively without
  `\\?\`. PE header comparison leaves out `ImageBase`. The slide is the runtime base minus the preferred base, and
  slide verification leaves out the spans the file's base relocations patch when the image moved.
- **Exceptions.** gdbserver's signals plus its `EXCEPTION_RECORD` from `qXfer:siginfo:read` (asked after every
  signal stop but a step's SIGTRAP), and lldb-server's second-chance `reason:exception` descriptions. Both become the
  stop event's `exception` with `"system": "windows"`. A foreign int3 is a breakpoint stop; under gdbserver its pc is
  moved back onto the int3, so a continue stops there again, which the stop's warnings say.
- **Interrupts.** Both stubs' interrupts stop in a thread Windows creates (gdbserver: Ctrl-Break as SIGINT, else
  `DebugBreakProcess` as SIGTRAP with `swbreak`; lldb-server: SIGSTOP). Rampage reports `interrupted` and uses
  another thread for reads and steps without `thread` until the target runs again.
- **Packet classes.** `qGetTIBAddr:<thread>` and `qXfer:siginfo:read` join the `Read` class. Nothing else changed in
  the packet classes or the consent model.
- **Found on the way.** lldb-server's target description has an unnamed `<feature>`, which rampage refused; it is
  now accepted, which matters for lldb-server on any platform. lldb-server writes `PacketSize` in decimal, which is
  read as hex, as LLDB reads it.
- **WoW64** under gdbserver is supported and tested with an x86 fixture; lldb-server's WoW64 is untested. **arm64
  Windows** was not built: both stubs have arm64 code, and rampage's AArch64 handling would apply.
- **Review fixes.** An independent review against the sources led to these changes:
  - gdbserver names the `Windows` OS ABI only from GDB 16 on. Older ones are recognized as an x86 GDB stub listing
    Windows-style libraries without svr4, confirmed by `qGetTIBAddr` or an `MZ` header 0x1000 below a library's
    segment address.
  - `DebugBreakProcess`'s break-in thread under gdbserver is parked. Continues name every other thread
    (`vCont;c:<thread>;...`, an Execution-class form the client allows only on Windows gdbserver sessions), since
    gdbserver resumes only the threads a `vCont` names and would otherwise run the break-in thread into its int3
    again.
  - Slide verification needs 8 compared bytes per window that had bytes left out, and 16 in all. Without them it
    reports `unverified` with counts. The IAT and import directory are always left out. Relocation types the reader
    does not know are capped at 256 entries.
  - A DLL-load stop racing an interrupt leaves the interrupt pending.
  - Under gdbserver the executable always comes from the PEB.
  - Library names with a bare `&` are read leniently (gdbserver does not escape them).
  - `i686` descriptions are x86.
  - Snapshots record a bound PE module's preferred base.
- **Conservative choices.** A failed siginfo read leaves the stop without an exception rather than failing it. A
  module whose PE headers cannot be read keeps its stub address and is verified under several base readings.
  Unknown relocation types are assumed to patch 8 bytes.
