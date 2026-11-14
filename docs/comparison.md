# rampage compared with Ghidra, IDA and REA

This page compares rampage with three tools an agent might use for reverse engineering: Ghidra, IDA Pro, and
REA, an MCP server over headless Ghidra. It is about agent-driven work. For an analyst at a GUI, Ghidra and IDA are
far more complete than rampage.

Where rampage has measured the comparison, the numbers come from its published benchmarks. Elsewhere this page
states plain facts about features, licences and architecture; it does not claim rampage is better at things
nobody has measured.

## Architecture at a glance

| | rampage | Ghidra | IDA Pro | REA |
| --- | --- | --- | --- | --- |
| Licence | Apache-2.0 | Apache-2.0 | Commercial | MIT |
| Written in | Rust, with Ghidra's C++ decompiler embedded | Java, with a C++ decompiler | C/C++ | TypeScript on Node, driving headless Ghidra (and optionally Rizin, Hopper or IDA) |
| Primary interface | MCP server; CLI and desktop UI share its API | GUI; headless analyzer; Java and Python scripting | GUI; IDAPython and C++ SDK | MCP server |
| Decompiler | Ghidra's, in a supervised worker process when `rampage-worker` is installed, otherwise in-process | Ghidra's | Hex-Rays (licensed per architecture) | Ghidra's (through Ghidra) |
| Analysis state | Analysed on first use; function discovery reused from a per-user store on later opens (experimental); annotations in a JSON Lines log beside the binary | Project database | `.idb`/`.i64` database | Ghidra project, per REA session |
| Heuristics | Data: signature JSON, data packs, YARA, capa, constants | Analyzers in Java; FunctionID databases | FLIRT signatures, type libraries, plugins | Those of the backing tool |
| Scripting API | None by design; features land as MCP tools | Yes | Yes | Through the backing tool |

## Measured: agent head-to-head with REA

rampage has been measured against REA with one model (`claude-sonnet-5-5` through Claude Code), each server on
its own, on tasks with machine-checked answers. These are the only measured comparisons with another tool.
Ghidra and IDA have not been measured directly; REA's results reflect Ghidra as REA exposes it, not what an analyst
can do in Ghidra.

| | rampage | REA (Ghidra 12.2) |
| --- | --: | --: |
| Suite v2, 15 harder tasks × 3, correct (strict) | 44/45 | 38/43 |
| Suite v2, core tasks only (C++, typing, investigation) | 29/30 | 25/28 |
| Suite v2, server tool calls per run, median | 3 | 6 |
| Suite v2, wall time per run outside the scale tasks, median | 12.5 s | 27.0 s |
| Suite v2, open and analyse a 49.2 MB stripped Go binary (one run, outside the agent) | 12.9 s | 2,355 s |
| Suite v1, 17 analysis tasks × 3, correct | 50/51 | 49/51 |
| Suite v1, tools listed at session start | 40 | 235 |

Read these with their caveats, which the reports state in full:

- One model and one client. A second model or client has not been run.
- The tasks were written by the rampage project. Suite v2's categories lean towards what rampage was built
  around (RTTI evidence, pclntab names, build diffing); the core-only row is the fairer view.
- REA ran without Rizin installed, so part of its catalog could not run, and its Hopper and IDA providers were
  not used.
- REA's suite v2 denominator is 43 because two of its runs fell back to another model and are excluded.
- REA's import time varied almost 3× with host load; the 2,355 s figure is one measurement.
- 15 tasks × 3 runs is small: 2/3 against 3/3 on one task is within run-to-run variance.

- On [suite v3](benchmarks/agent-h2h-v3-2026-11-14.md) (21 tasks × 3, the 1.0.0 feature set) rampage scored 57/63
  and REA 61/63. Both were 51/51 outside the semantics tasks; there, every miss was the model evaluating a loop by
  hand from equivalent pseudocode, since neither server can run the function.

Sources: [suite v3 report](benchmarks/agent-h2h-v3-2026-11-14.md), [suite v2 report](benchmarks/agent-h2h-v2-2026-11-05.md) and
[suite v1 report](benchmarks/agent-h2h-2026-11-05.md). rampage's static analysis is also compared with Ghidra's
on fixtures built by the rampage project (function starts, CFG edges, call edges, decompilation health) in
[accuracy benchmarks](benchmarks.md); there Ghidra is a reference, not ground truth.

## What differs for an agent

These are design facts, not measured advantages.

- **Startup.** rampage analyses a binary on first use; there is no project import step, and release builds reuse
  a binary's stored function discovery when it is opened again.
  REA waits for Ghidra's import and auto-analysis.
- **Output shaped for context.** Every rampage tool has a size cap, pages large results with explicit cursors
  and totals, and declares a result size Claude Code will display whole. Tools are grouped, so a session lists
  about 40 tools at first and enables the rest on demand.
- **One install.** rampage is two native executables (`rampage` and `rampage-worker`) with Ghidra's processor
  specifications bundled. Ghidra and REA need a JVM and a Ghidra install; REA also needs Node.
- **Shared annotations.** Names, types, comments and findings go into a log beside the binary that the MCP
  server, CLI and desktop UI all replay, with undo and redo.
- **Heuristics as data.** Library signatures and detection rules are data packs that can be added, exported as
  `.rpack` archives and checked, without rebuilding rampage. The experimental [flywheel](flywheel.md) lets an
  agent propose signature rows gated on held-out truth.

## What rampage does not do

Compared with Ghidra and IDA, rampage does not have:

- a scripting API (IDAPython, Ghidra scripts); new capabilities are added as MCP tools instead;
- a mature interactive GUI: its desktop UI is experimental and has no type or struct editor;
- DEX/APK or JVM class files, or relocation of object files and static archives;
- Swift metadata, C++ class-layout recovery beyond RTTI and vtable evidence, or exception-table recovery beyond
  MSVC `__CxxFrameHandler3` tables (experimental);
- full version tracking: [annotation transfer](build-diffing.md) moves names, comments, signatures, types and
  globals between builds, but not local variables, data types or patches, and has no interactive review UI;
- a full project database: the experimental [analysis store](mcp.md#persistent-analysis-store) keeps only
  function discovery, and analysis does not run incrementally after edits;
- decompilation for most of its Sleigh processor profiles (only MSP430 and AVR8 have reviewed C models; the
  experimental Cortex-M profile decompiles with the ARM v8 Thumb model);
- a Windows host build;
- process launch or attach: debugging connects only to a stub the operator started; macOS `debugserver` has
  passed one live acceptance run and Windows targets are not yet live-verified, so both stay experimental;
- the breadth of processor modules, file loaders, plugins and community tooling that both Ghidra and IDA have
  built up over many years.

Compared with REA, rampage does not drive Rizin, Frida, Hopper or IDA. Its execution-control debugger speaks only
the GDB remote protocol; LLDB is reached only through a read-only bridge to a stopped session.

See [the roadmap](plans/2026-10-16-ida-ghidra-parity-roadmap.md) for which of these are planned.
