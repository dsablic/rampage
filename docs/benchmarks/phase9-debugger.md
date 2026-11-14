# Phase 9 debugger acceptance

Part of the [accuracy benchmarks](../benchmarks.md).

## Phase 9 debugger acceptance

Phase 9 has no scorecard row because there is no agent-level debugger task (see the design's deviations). Its
acceptance is the [acceptance record](../plans/2026-10-29-debugger-control.md#acceptance-record) in the debugger
design.

| Step | Fake-stub tests | Live run |
| --- | --- | --- |
| 9.1–9.4 (GDB stubs, execution, correlation, writes and kill) | QEMU Cortex-M3 and gdbserver AArch64 transcripts | Passes on QEMU with the owned firmware |
| 9.5 (macOS `debugserver`) | A transcript built from debugserver's source, not recorded | Passed 2026-11-11 (`debug_debugserver_live`, arm64 macOS): break, step out, watch, interrupt and snapshot |
| Cortex-M flash dump (`debug_snapshot` `raw: true`) | QEMU Cortex-M3 transcript | Passes on QEMU (`lm3s6965evb`, 2026-11-14): the 256 KiB dump equals the loaded image and opens as a Cortex-M Raw project |
| 9.6a (Windows through `gdbserver.exe` and `lldb-server`) | Transcripts built from the stubs' sources, not recorded | Not run: needs a Windows host |

There is no live Linux gdbserver run. The commands for each live run are in the acceptance record.
