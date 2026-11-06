# Known limits

What rampage 1.0 does not do, or does only partly. The [comparison with Ghidra, IDA and REA](comparison.md) sets
these against other tools, and the [stability policy](stability.md) says which areas are *experimental*.

## Hosts

| Host | Status |
| --- | --- |
| macOS on Apple silicon | Tested; the primary development host. |
| macOS on Intel | Untested. It should build from source, but no one has run the test suite on it. |
| Linux x64 (Ubuntu 24.04) | Supported: CI builds and tests the whole workspace; the desktop UI is untested there. |
| Windows | Not supported as a host in 1.0; planned for 1.x. |

Prebuilt archives cover macOS on Apple silicon and Linux x64 only; other hosts build from source, see
[getting started](getting-started.md#what-you-need) for the prerequisites.

## Decompilation and safety

- **The worker is optional, and without it decompilation runs in-process.** rampage decompiles in a supervised
  `rampage-worker` process when it finds one: `RAMPAGE_WORKER`, or `rampage-worker` beside `rampage`. When it
  finds none, `decompile` runs Ghidra's native decompiler inside the `rampage` process itself, without the
  worker's time, memory and output limits. The MCP server warns on stderr at startup when it has no worker, and
  every `decompile` result names where it ran in its `decompiler` field (`supervised` or `in-process`). Start the
  server with `--require-worker` (or use the CLI's `decompile --isolated`) to refuse to decompile without the
  worker instead.
- **Worker supervision is not an OS sandbox.** It bounds time, memory and output. Analyse hostile files in a VM or
  container if you need isolation.
- **Decompiled C is not proof** that the recovered program is correct. Results report their recovery issues.
- Only MSP430 and AVR8 decompile among the Raw processor profiles; the others disassemble only.

## Analysis

- On very large images (the 50 MB Go binary of the benchmark), `search` for the functions referencing a string
  stops on its work budget before finding them. A text search for the string followed by `xrefs` to its
  address works.
- Byte searches with wildcards charge their pattern length for every candidate start, so they cover less of a
  large image than exact searches do.
- `disassemble` prints ARM and Thumb immediates in decimal (`movt r1, #1934`); only `inspect_raw_code` adds the
  hex value.
- There is no Raw Project profile for ARM or Thumb (Cortex-M) firmware. `inspect_raw_code` reads it, without
  functions, cross-references or decompilation.
- Go string literals referenced only through static `{ptr, len}` headers in data, not by code, have no
  `go_literal` bounds.
- `function_graph` refuses a view too large for one result; `function_summary` pages its blocks instead.
- Not built yet: DEX/JVM, Intel HEX/SREC and multi-region firmware maps, object-file relocation, Swift metadata,
  C++ layout recovery beyond RTTI evidence, and incremental analysis or a persistent database for very large
  binaries (analysis runs again in each session).

## Library identification

- Bundled signatures recognise the library builds they were made from, not every version of a library.
- The bundled corpus's recall on matched library versions is below the 80% the project aims for; see the
  [signature corpus](signature-corpus.md).

## Annotations

- The annotation log has no compaction. A log that reaches its size limits can only be read; see
  [MCP edits](mcp.md#edits-and-session-state).

## Debugging

- rampage never launches or attaches to a process: it connects only to a GDB remote stub the operator started.
- Apple `debugserver` and Windows targets through `gdbserver.exe` or `lldb-server` are *experimental*: tested
  against protocol transcripts, not yet against live targets.

## Data disclosure

rampage itself uploads nothing, but an AI client sends tool results (strings, disassembly, decompiled code) to
its model provider. Make sure you may disclose that material; see
[data disclosure](mcp.md#authorization-and-data-disclosure).

## Benchmarks

The [head-to-head benchmarks](benchmarks.md) use one model and one client, on tasks written by the rampage
project. They are not general accuracy guarantees.
