# rampage-decompiler

Embeds Ghidra's decompiler as an in-process library and exposes it to rampage through a small, safe Rust API.
A `Decompiler` is opened once over a program's executable segments and decompiles functions to C on demand.

## Vendored source

`vendor/ghidra/` holds the decompiler's C++ sources, taken from the Ghidra 12.1.4 release
(tag `Ghidra_12.1.4_build`), path `Ghidra/Features/Decompiler/src/decompile/cpp`. They are the decompiler
library set (the Makefile's `LIBDECOMP` sources) without the BFD loader, the Ghidra-process bridge and the
SLEIGH compiler. `src/shim.cc` is rampage's own C ABI over that library.

Vendored integration changes: `loadimage.hh` adds instruction-lookahead, instruction-range
validation and partial-string-read hooks; `sleigh.cc` validates decoded lengths; `stringmanage.cc` consumes only
available string bytes; `sleigh.hh` and `sleigh.cc` expose translation-cache invalidation without re-registering
context variables; `funcdata.hh` synchronizes display names; `grammar.cc` and `type.cc` bound array layouts;
`prettyprint.hh` and `printlanguage.hh` allow an address-aware token emitter. Default loader hooks preserve
upstream behavior; `modelrules.hh` and `modelrules.cc` add optional aligned stack-slot assignment for Darwin.
Other vendored sources are unchanged.

Ghidra is Copyright the National Security Agency, licensed under the Apache License 2.0; `vendor/ghidra/LICENSE`
is that license. rampage's own code is under the workspace's MIT/Apache-2.0 terms, but this crate links the
vendored Apache-2.0 sources.

## Memory mappings

`MemoryRegion` maps backed bytes and an explicitly declared zero-fill tail with read/write/execute permissions.
Zero-fill does not allocate its virtual size. Truncated file bytes and sparse capture gaps are unavailable,
not zero-filled. SLEIGH may look ahead beyond a mapping, but every byte of the resulting instruction must be
executable and mapped. Data reads require a complete readable range; strings require a mapped terminator.
`Segment`/`open` remain a convenience for raw readable executable buffers without zero-fill tails.

## Instruction context

Each handle owns its SLEIGH translator so opening another image cannot replace its loader or context. ARM mode
points can be installed with `set_code_modes`; the project layer merges loader ranges with instruction modes
learned by discovery. Every decompilation sets the entry mode explicitly, including ARM rather than Thumb,
and invalidates translation caches. Mixed-mode requests do not depend on which function was requested first.
Equal-valued context points remain barriers between independently decoded code. Context boundaries can be odd
when padding ends a Thumb range; exclusive ends beyond the target address space are not installed as points.
Failed specification initialization keeps translator ownership with Ghidra until initialization succeeds.
Mode points are validated before mutation and passed to the C ABI in batches of at most 4,096, without a
whole-program point-count cutoff. The million-point scale gate runs with
`cargo test -p rampage-decompiler --test context -- --include-ignored`.

## Compiler specifications and prototypes

The project layer selects Windows specifications for PE, Apple specifications for little-endian ARM64 Mach-O,
macOS specifications for big-endian PowerPC Mach-O, and existing defaults otherwise. `DecompilerOptions` exposes
platform/compiler overrides; `Project::set_decompiler_options(None)` restores format-based selection. The CLI accepts
`decompile --compiler windows` (or another compiler ID advertised by the selected processor language).
Unknown IDs are errors, not silent fallback to the first compiler in a language definition. Results report the
exact selected `language_id`.

Bundled C data organizations explicitly use ILP32 for MIPS32 and PowerPC32 (including Darwin) and LP64 for
SPARC64 and Darwin PowerPC64; these six compiler specifications carry local corrections marked in their XML.
Selected C specifications with incompatible pointer/`int`/`long` widths are rejected, including external installs
that still contain the original missing/incorrect widths.

Pointer, `int` and `long` widths come from the selected compiler specification. `Decompiler::c_prototype`
uses those widths for `size_t`, `ssize_t`, `long` and `unsigned long`, and applies `__cdecl` to x86 Windows CRT
functions rather than the specification's default `__stdcall`. The `clangwindows` alias gets identical runtime
handling. Automatic declarations omit library-dependent
`off_t`, `time_t`, `clock_t` and `pthread_t`; a compiler spec alone does not establish those typedefs. The legacy
free `c_prototype` helper remains LP64-only and is not used by the project integration.

These defaults do not establish full ABI parity. Darwin ARM64 selects `apple`, with byte-packed fixed stack
arguments, consecutive integer register allocation, reserved x18 preservation and explicit unnamed-argument
eight-byte stack slots. General variadic call recovery and exact narrow caller-extension modeling remain open.
Compiler overrides such as Go or Swift disable automatic C runtime declarations rather than assigning C
signatures to functions using another calling convention.
ARM BE8 selects mixed-endian SLEIGH using loader instruction/data order; compiler-only overrides preserve it.

## Processor specifications

The compiled SLEIGH specifications (`.sla`) and their processor/compiler specs for every supported architecture
are vendored under `specs/` (about 4.5 MB, from the same Ghidra 12.1.4 release) and embedded in the executable.
`sleigh_home` uses `GHIDRA_INSTALL_DIR` when set; otherwise it materializes the embedded files in
`~/.cache/rampage/specs-<content-id>`, verifying bytes and repairing changed files under a cross-process lock.
Relocated executables need neither a build tree nor an external Ghidra installation. A writable HOME cache is
required without an override. s390x has no Ghidra specification and is unsupported.

## Symbols and user types

Runtime prototypes bind by target address, separately from displayed names. Import slots have independent
external function bindings; their contents are not fabricated into resolved pointers. Duplicate low-level slot
registration fails explicitly. Project name changes, undo/redo and refreshed external edits rebuild the cached
engine; anonymous functions named after a runtime function do not gain that runtime signature.

`set_signature` persists one address-bound declaration; `set_types` persists typedef/struct/union/enum declarations.
`set_global` persists named object declarations on fully mapped, non-executable data ranges. Storage classes and
qualifiers are rejected rather than silently discarded; function-pointer objects remain data. These annotations
are available through API/MCP and participate in shared-log locking, validation and undo/redo. Type removal
is rejected while a signature depends on it. Declarations use sized types, contain no comments/preprocessor
directives, and have decimal array bounds in 1..65536 without leading zeros. Array layouts are at most one MiB;
array parameters require explicit pointers. `debug-types` previews bounded embedded-DWARF scalar/pointer
function signatures; `--apply` merges them without replacing analyst signatures. Aggregate layouts and external
debug files are explicitly skipped with diagnostics. `class_evidence` reports bounded named Itanium vtable/RTTI
candidates and validated code slots without inferring object layouts or applying class types. Automatic C++
class-layout recovery is not provided.

## Structured output and limits

Results include semantic tokens and an engine-derived `structure`: typed signature/parameter storage, local
symbols, basic blocks and successor indices, call source/targets and jump-table destinations/partial status.
Storage offsets are qualified by address-space kind and must not be treated as program virtual addresses.
Storage use ranges select Ghidra definition/use points, not value liveness; entry inputs commonly select entry-1.
Single-piece joins may represent floating-point precision extension, not a bytewise copy into the logical type.
The UI pseudocode panel loads in the background and coalesces navigation while a request runs. Semantic tokens
carry byte spans in the rendered C, enabling inline navigation; flow-only records remain spanless. Jump tables
include recovered raw case-value bit patterns, with null for absent labels. Engine output is evidence, not a
guarantee of recovered source types or original source structure.

Text output is bounded to four MiB and tokens to 262,144; the engine also retains its instruction-flow bound.
`rampage decompile --isolated` uses a supervised sibling `rampage-worker`; `RAMPAGE_WORKER` explicitly selects
the executable for sessions (including UI/MCP). `Project::set_decompiler_worker` enables it programmatically.
Sessions select a sibling worker automatically when installed beside the application; `tools/install.sh`
installs the worker and CLI together, optionally with the UI. Direct `Project` construction remains explicitly
opt-in; `Session::open` also selects a sibling worker when present.
The protocol bounds input/output, drains pipes concurrently, cancels/times out and reaps failed children without
native fallback. Defaults are 30 seconds and one GiB memory. Linux uses hard AS/DATA limits; macOS samples RSS
and can overshoot between samples. Supervision is supported on 64-bit Linux/macOS and is not an OS sandbox.
All native C ABI operations contain C++ exceptions; unexpected partial native failures poison the handle and
retain unsafe state until process exit rather than risking cleanup through corrupt ownership. In-process mode
must still be limited to trusted inputs: exception containment does not prevent native memory-safety bugs.
Broader supervisor platform support remains separate work.
