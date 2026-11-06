# Changelog

All notable changes to rampage are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org);
see the [stability policy](docs/stability.md) for what the version promises.

## 1.0.0 (unreleased)

The first public release. It summarises what rampage does rather than listing every change since the project
started; the [roadmap](docs/plans/2026-10-16-ida-ghidra-parity-roadmap.md) and git history have the detail.

### MCP server

- `rampage server serve` (also `rampage mcp`) serves the Model Context Protocol over stdio. It needs no API key.
- Tools are grouped: `core` is listed at startup, and `enable_tools` lists and enables `detection`, `types`,
  `runtime`, `diagnostics`, `dotnet`, `carve` and `formats`. `--all-tools` lists every group from the start.
- Every tool has a result size cap, pages large results with explicit offsets and totals, reports omissions, and
  refuses unknown arguments with a one-line error naming its arguments.

### Analysis and decompilation

- ELF, PE and Mach-O loading, including universal binaries and explicitly selected embedded images.
- Recursive-descent function discovery, control-flow graphs, cross-references, strings, imports and exports, and
  non-returning call detection.
- Stripped Go function names from the pclntab; C++ class names and base classes from RTTI and vtables, including
  Mach-O chained fixups; Objective-C classes, methods and properties.
- C decompilation through the embedded Ghidra decompiler, with processor specifications bundled, run in a
  supervised `rampage-worker` process with time, memory and output limits.
- Guided reports: `triage_report`, `find_main`, `network_surface`, `persistence_surface`, `string_decoding`,
  `find_crypto` and `diff_builds`.

### Typing and annotations

- Names, comments, signatures, types and globals in an append-only annotation log beside the binary, shared by
  the MCP server, CLI and desktop UI, with undo, redo and atomic batches.
- Local variable and parameter renames and retypes by storage, a project type library, data and operand typing,
  stack-frame inspection, type propagation across direct calls, and checked DWARF and PDB type import.
- An investigation ledger (`record_finding`, `list_findings`) for findings, unknowns and open questions, with
  evidence and confidence.

### Search and patching

- Byte, text, regex, immediate, instruction and reference search with function context and resumable budgets.
- An assembler for an x86, x86-64 and AArch64 subset, checked byte patches kept in the annotation log, and export
  of the patched image to a new file.

### Formats and processors

- x86 and x86-64; AArch64, A32 and Thumb decoded from Arm's machine-readable specification; MIPS, PowerPC,
  RISC-V, SPARC, s390x and m68k through Capstone.
- Sixteen further processor families open as Raw Projects through Ghidra's Sleigh; MSP430 and AVR8 also
  decompile.
- Raw code windows for headerless images, explicit LZSS decoding of file ranges, and embedded-file carving.
- .NET metadata and CIL disassembly; Go build info and cargo-auditable dependency data; PE resources and load
  config; PyInstaller archives; WebAssembly module summaries; ZIP directory inventory.

### Library identification and detection

- Function signatures with bundled databases for x86-64, AArch64, i386 and A32/Thumb, plus user PAT files and
  explicitly configured Ghidra FunctionID databases; fuzzy candidates that never rename on their own.
- Packer, compiler and toolchain detection, YARA through yara-x, a file-scope subset of capa rules, capability
  tags and a crypto-constant database.
- Data packs extend all of these with data only, and move between machines as checked `.rpack` archives
  (`rampage pack export`, `import` and `diff`).

### Debugging

- The `debug` group connects to a GDB remote stub the operator started and allowed with `--debug-endpoint`:
  registers, memory, modules, snapshots, all-stop execution control, breakpoints and watchpoints, and binding to
  a static project for breakpoints by name and located stops. Live-verified against QEMU (Cortex-M3).
- Memory and register writes need `--debug-writes`, and kill needs `--debug-kill`. rampage never launches or
  attaches to a process.
- A read-only bridge to a stopped LLDB session, and runtime snapshot analysis.

### File formats and compatibility

- The annotation log's identity lines carry `"format": 1`; a reader refuses a log that declares a newer format
  instead of misreading it. Logs 0.1.x wrote are format 1 and keep opening.
- `.rpack` archives declare `min_rampage_version` instead of a rampage version range, and readers accept every
  archive of a format version they support. Archives 0.1.x exported keep importing; 0.1.x builds refuse new
  archives as having an unknown field.
- `rampage-pack.toml` and constants files take an optional `format_version` (absent means 1). Fields a reader
  does not know are ignored with a warning, a content kind it does not know is reported as unsupported, and a
  newer major is refused.
- Snapshot tests in `tests/contract/` pin the MCP tool schemas and result fields and the CLI commands, flags and
  `--json` fields; see [how the stable surface is checked](docs/stability.md#how-the-stable-surface-is-checked).

### Experimental

These ship in 1.0.0 but are outside the stability promise:

- The desktop UI.
- Apple `debugserver` and Windows targets through `gdbserver.exe` or `lldb-server`: implemented with protocol
  tests, not yet live-verified.
- Raw processor profiles other than MSP430 and AVR8.
- The heuristic flywheel: the `improve` group served with `--corpus`, `report_observation`, and the `rampage-eval`
  flywheel and bundle commands.
- `rampage-eval`, the evaluation and benchmark harness.
- The WebAssembly triage-component plugin host.

### Known limits

- Hosts: macOS on Apple silicon is tested. Linux x64 builds and tests in CI; Windows is not supported as a host.
- Decompiled C is not proof of correct recovery; worker supervision is not an OS sandbox.
- Bundled signatures recognise the library builds they were made from, not every version of a library.
- Not built yet: DEX/JVM, Intel HEX/SREC and multi-region firmware maps, object-file relocation, Swift metadata,
  C++ layout recovery beyond RTTI evidence, and incremental analysis for very large binaries.
- The annotation log has no compaction; a log at its size limits can only be read.
- In the suite v2 benchmark, searches on a 49.2 MB Go binary stopped on their work budget before finding a
  string's referencing function; see the [report's ranked gaps](docs/benchmarks/agent-h2h-v2-2026-11-05.md#ranked-rampage-gaps)
  and [todo.md](todo.md) for what is fixed and what is open.
