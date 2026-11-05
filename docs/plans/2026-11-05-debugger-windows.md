# Debugger on Windows targets (Phase 9.6): short design for review

Status: **proposal, not approved.** Nothing here is implemented. The parent design
(`docs/plans/2026-10-29-debugger-control.md`) requires a separate short design for Windows before any code. 9.1–9.4 are
done, and 9.5 (macOS `debugserver`) is in progress.

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

### Facts to verify before choosing (I couldn't verify these from here)

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
