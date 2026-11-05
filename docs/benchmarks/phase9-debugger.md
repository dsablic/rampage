# Phase 9 debugger acceptance

Part of the [accuracy benchmarks](../benchmarks.md).

## Phase 9 debugger acceptance (2026-10-29 to 2026-11-05)

Phase 9 has no scorecard row: the agent-level debugger task was not added (see the design's deviations). Its
acceptance is the [acceptance record](../plans/2026-10-29-debugger-control.md#acceptance-record) in the debugger
design.

| Step | Fake-stub tests | Live run |
| --- | --- | --- |
| 9.1–9.4 (GDB stubs, execution, correlation, writes and kill) | QEMU Cortex-M3 and gdbserver AArch64 transcripts | Passes on QEMU with the owned firmware |
| 9.5 (macOS `debugserver`) | A transcript built from debugserver's source, not recorded | Not run: needs DevToolsSecurity enabled |
| 9.6a (Windows through `gdbserver.exe` and `lldb-server`) | Transcripts built from the stubs' sources, not recorded | Not run: needs a Windows host |

There is no live Linux gdbserver run. The commands for each live run are in the acceptance record.
