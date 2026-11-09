# Changelog

All notable changes to rampage are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org);
see the [stability policy](docs/stability.md) for what the version promises.

## Unreleased

### Added

- `file_layout` (MCP, `core`) and `binary layout` map any regular file, or a range of up to 64 MiB, without a
  loader: 0xff/0x00/repeated-byte fill and occupied regions with per-region SHA-256 and entropy, per-block
  entropy with high and low spans, printable-string clusters, the range's SHA-256, and labelled heuristic hints
  such as Cortex-M vector-table candidates. Capped lists report totals and a continuation range. See
  [file layout](docs/file-layout.md).

### Firmware

- Experimental Raw Project profile `ARM:LE:32:Cortex` for headerless Cortex-M (ARMv6-M/ARMv7-M Thumb) images, with
  aliases such as `cortex-m4`, `thumb` and `armv7m`. It uses the native ARM decoder in Thumb mode, so listing,
  cross-references, search and decompilation (ARM v8 Thumb with its reviewed C model) work as for ARM ELF. Input
  may be up to 4 MiB for this profile; Sleigh profiles keep 128 KiB.
- `"vector_table": true` (or an address) in the `raw` selector reads the Cortex-M vector table: Reset becomes the
  entry and the other Thumb handlers seeds, and `binary_info` reports every word with its verdict under
  `raw.vector_table`, with a labelled, never applied base-address suggestion when the handlers fall outside the
  asserted mapping. One call with path, profile and base address now opens a firmware image.
- The Cortex-M profile decodes the M-profile instruction set: `MRS`/`MSR` special registers (`msp`, `psp`,
  `primask`, `basepri`, `basepri_max`, `faultmask`, `control`, ...), which used to stop discovery as invalid
  instructions, and no A32 state or A-profile-only instructions (BLX to A32, Advanced SIMD, SETEND, ERET, ...).
  Odd-aligned string literals are not taken for Thumb function pointers. `inspect_raw_code` stays A-profile.
- The session's Raw project cache is also bounded by 64 MiB of input bytes.
- Raw interpretation identities move to `rampage-raw-interpretation-v3`, which binds the vector-table request.

## 1.0.0 (unreleased)

The first stable release. The stable surface in the [stability policy](docs/stability.md) is the one rc.1 froze;
no contract snapshot changed through either release candidate, and from here a change to it needs a new major
version. The code is rc.2's.

### Stability

- Contract snapshots now pin the result fields of every stable MCP group (`mcp-results-<group>.json`), not just
  `core` and `debug`. A tool that a group adds without a fixture exercising it fails the test, and
  `query_debugger`'s result envelope is pinned against a scripted bridge.

## 1.0.0-rc.2 (2026-11-09)

The second release candidate. The stable surface is unchanged from rc.1: no contract snapshot changed. This
candidate improves library identification only, which the [stability policy](docs/stability.md) counts as an
analysis improvement, not an API change.

### Library identification

- The bundled signature databases gain rows learned on the flywheel corpus (zlib, lz4, cJSON, zstd and Lua builds
  across compilers and optimisation levels), with operand fields wildcarded so one row covers more builds. On
  held-out library versions, for example, Lua 5.4.6 goes from 70 to 772 named functions and zstd 1.5.5 from 172
  to 348.
- A bundled call graph names unnamed callees of already named functions by their position in known call
  sequences, and only when the callee's own calls also fit. These names report the source
  `rampage-builtin call graph` and never replace a database match or an existing name.
- Precision is traded slightly for recall: on the ledgered final split the new rows gained about 37,000 correct
  names against 100 wrong ones. Names for libc and compiler-runtime functions can be an alias of the binary's own
  symbol (`lseek` for `__lseek`).
- Identification takes slightly longer on large binaries (about 0.16 s on the largest corpus binary).

### Experimental

- The flywheel corpus has a ledgered final split, a false-positive allowance earned by large gains, and an
  operator-only view of development cases. `rampage-eval bundle` gains `--arm`, `--arm-library`,
  `--arm-exclude`, `--call-graph` and `--final-reason`.

## 1.0.0-rc.1 (2026-11-06)

The first public release, as a release candidate for 1.0.0: the stable surface in the
[stability policy](docs/stability.md) is frozen unless the candidate turns up a problem, and 1.0.0 follows once it
runs without unplanned contract-snapshot changes. It summarises what rampage does; the
[roadmap](docs/plans/2026-10-16-ida-ghidra-parity-roadmap.md) and git history have the detail.

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
  supervised `rampage-worker` process with time, memory and output limits when the worker is installed. Without
  it, decompilation runs in-process: the MCP server warns at startup, each `decompile` result names its
  `decompiler` (`supervised` or `in-process`), and `rampage server serve --require-worker` refuses to decompile
  without the worker.
- Guided reports: `triage_report`, `find_main`, `network_surface`, `persistence_surface`, `string_decoding` and
  `diff_builds` in `core`, and `find_crypto` in the `detection` group.

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

### Hosts and installation

- Supported hosts are macOS on Apple silicon, Linux x64 and Linux ARM64 (Ubuntu 24.04). Each release has prebuilt
  archives for `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, and
  `tools/install.sh --archive` verifies an archive's checksum before installing it.

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

### Known gaps

[Known limits](docs/known-limits.md) lists them in full. In short:

- Hosts: macOS on Apple silicon is tested; Intel macOS is untested. Linux x64 and Linux ARM64 build and test in
  CI, and this is their first release. Windows is not supported as a host.
- Without `rampage-worker` installed, decompilation runs in-process. Decompiled C is not proof of correct
  recovery, and worker supervision is not an OS sandbox.
- Bundled signatures recognise the library builds they were made from, not every version of a library.
- On a 50 MB image, `search` for the functions referencing a string stops on its work budget; a text search
  followed by `xrefs` works.
- Not built yet: DEX/JVM, Intel HEX/SREC and multi-region firmware maps, object-file relocation, Swift metadata,
  C++ layout recovery beyond RTTI evidence, and incremental analysis for very large binaries.
- The annotation log has no compaction; a log at its size limits can only be read.
