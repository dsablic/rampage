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
context variables; `funcdata.hh` synchronizes display names and `funcdata.cc` resets per-analysis recovery flags;
`grammar.cc` and `type.cc` bound array layouts;
`prettyprint.hh` and `printlanguage.hh` allow an address-aware token emitter. Default loader hooks preserve
upstream behavior; `modelrules.hh` and `modelrules.cc` add optional aligned stack-slot assignment for Darwin.
`fspec.hh`, `fspec.cc` and `marshal.cc` add an opt-in bounded integer input-extension window.
Other vendored sources are unchanged.

Ghidra is Copyright the National Security Agency, licensed under the Apache License 2.0; `vendor/ghidra/LICENSE`
is that license. rampage's own code uses the workspace's Apache-2.0 license. The root `NOTICE` retains attribution
for vendored components; this crate links the vendored Apache-2.0 sources.

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
macOS specifications for big-endian PowerPC Mach-O, and existing defaults otherwise. A little-endian x86-64 or
ARM64 image whose Go pclntab is go1.18 or later selects `golang`, Go's register ABI; a go1.16 table (go1.16 or
go1.17) and older Go keep the platform default, since go1.16 and earlier pass arguments on the stack.
Go functions on both architectures also get derived prototypes, so values pass between calls: inputs come
from each function's ArgInfo traceback layout, and result counts from the result registers callers read after a
call (including registers passed straight to another call or returned again). A result no caller reads is not
found. Functions that take or return floats, or whose inputs do not fit in registers, keep inferred prototypes;
user signatures replace derived ones. Every derived value is an 8-byte or smaller `xunknown` word, and a
multi-word result is a `go_results_N` struct with fields `r0` to `rN-1`.
Generated result declarations precede analyst types and signatures. A token-equivalent analyst copy is installed
once, including when an earlier analyst declaration depends on it. Arbitrary redefinitions and aliases of these
generated anonymous result types are not supported by this replay guarantee.
`DecompilerOptions` exposes platform/compiler overrides; `Project::set_decompiler_options(None)` restores
format-based selection. The CLI accepts `rampage function decompile IMAGE --at FUNCTION --compiler windows`
(or another advertised compiler ID). Unknown IDs are errors, not silent fallback to the first compiler in a
language definition. Results report the exact selected `language_id`.

Bundled C data organizations explicitly use ILP32 for MIPS32 and PowerPC32 (including Darwin) and LP64 for
SPARC64 and Darwin PowerPC64; these six compiler specifications carry local corrections marked in their XML.
The ARM64 Go specification also carries one: its prototypes pop no stack on return, as `bl` pushes nothing.
Selected C specifications with incompatible pointer/`int`/`long` widths are rejected, including external installs
that still contain the original missing/incorrect widths.

Pointer, `int` and `long` widths come from the selected compiler specification. `Decompiler::c_prototype`
uses those widths for `size_t`, `ssize_t`, `long` and `unsigned long`, and applies `__cdecl` to x86 Windows CRT
functions rather than the specification's default `__stdcall`. The `clangwindows` alias gets identical runtime
handling. Selected POSIX I/O/time declarations also substitute `off_t`, `time_t`, `mode_t` and `pid_t` widths:
Darwin uses 64-bit `off_t` and 16-bit `mode_t`; otherwise they use `long` and 32 bits respectively. `time_t` uses
`long` width and `pid_t` uses 32 bits. These are explicit prototype policies, not universal libc typedef inference:
32-bit Linux unsuffixed I/O uses 32-bit offsets, and 32-bit Darwin uses 32-bit time. Time64/large-file variants
and other library-specific ABI choices need separate evidence. `clock_t` and `pthread_t` are not guessed.
The legacy free `c_prototype` helper remains LP64-only and is not used by the project integration.

These defaults do not establish full ABI parity. Darwin ARM64 selects `apple`, with byte-packed fixed stack
arguments, consecutive integer register allocation, reserved x18 preservation and explicit unnamed-argument
eight-byte stack slots. Bundled Apple rules extend signed/unsigned fixed register inputs smaller than 32 bits
according to their declared integer type only through bit 31; upper register bits remain unknown. External
specifications must supply the corresponding `extension_size` rule. This does not infer missing source types,
change return rules or establish general variadic-call recovery. Other models retain their existing extension rules.
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
Discovery's listed and inferred noreturn callees are marked by address in both native and worker engines,
including registered import slots. Calls marked `listed` or `inferred` in function graphs have no fall-through;
native SSA treats them as terminal. Conditional calls retain fall-through, resumable traps are not terminal
evidence, and mutual tail-call inference requires a path to an evidenced noreturn call or non-resumable trap.
An unevidenced tail-call cycle remains unknown, not a newly inferred noreturn function.

`set_signature` persists one address-bound declaration; `set_types` persists typedef/struct/union/enum declarations.
`set_global` persists named object declarations on fully mapped, non-executable data ranges. Storage classes and
qualifiers are rejected rather than silently discarded; function-pointer objects remain data. These annotations
are available through API/MCP and participate in shared-log locking, validation and undo/redo. Type removal
is rejected while a signature depends on it. Declarations use sized types, contain no comments/preprocessor
directives, and have decimal array bounds in 1..65536 without leading zeros. Array layouts are at most one MiB;
array parameters require explicit pointers. `rampage type import-debug IMAGE` previews bounded embedded-DWARF
scalar/pointer function signatures; `--apply` merges them without replacing analyst signatures. Aggregate layouts
and external debug files are explicitly skipped with diagnostics. `class_evidence` reports bounded named Itanium
vtable/RTTI candidates and validated code slots without inferring object layouts or applying class types.
Automatic C++ class-layout recovery is not provided.

### Plain-struct layout verification

`Decompiler::inspect_plain_struct(name)` reads a previously parsed, complete flat struct from the selected native
type factory. `assert_plain_struct_layout(expected)` compares its complete layout with an independently supplied
`layout::PlainStructLayout`: struct name/size/alignment, compiler organization, ordered field names/offsets/sizes,
and semantic scalar or scalar-pointer leaf descriptors. Matching display names alone is insufficient.

The bridge accepts only `x86:LE:64:default:gcc`, with measured LP64 widths and primitive alignments, including when
specifications come from an external installation. Limits are 128 fields, 128 bytes per name, 32 KiB cumulative
name/type text, one MiB aggregate size and alignment at most eight bytes. Incomplete types, unions, nested or
recursive aggregates, arrays, bitfields, enums, callbacks, pointer chains and unsupported leaves are refused.
Ordinary mismatches do not modify registered types or prior decompilation results. Inspection exceptions are
contained; failure while storing an error diagnostic poisons the handle and clears results. No padding is
synthesized. Refusal applies to retained native type facts, not syntax already normalized by the C parser.

Inspection measures Ghidra's parsed layout, not a producer's debug layout. Assertions are read-only and ephemeral:
callers must repeat them for every engine/session/compiler-specification rebuild, before dependent prototypes.
This supplies no persistent assertions, debug provenance, DWARF/PDB layout import or general aggregate ABI recovery.
The ordered worker `assert_plain_struct_layout` operation performs the same check, including validation-only requests.
`PlainStructLayout::from_wire(bytes)` preflights raw JSON before Serde can buffer tagged values. A layout/assertion
is limited to 384 KiB encoded data, 64 KiB decoded text including keys/tags, 2,048 nodes and depth 12. Wire strings
and keys are at most 128 decoded bytes, tags 32 bytes, arrays 128 entries and objects 32 keys. These are wire caps
in addition to the semantic limits above. Arbitrary third-party Serde deserializers do not supply this allocation
boundary; use `from_wire` for isolated untrusted JSON.
Layout records require object representation and enum tags require strings; positional Serde alternatives are refused.

The project layer's separate [checked DWARF layout import](../../docs/debug-layout-import.md) persists bounded
assertion-backed declarations and prototypes. Unlike ordinary manual inspection, this path requires the exact
embedded specification manifest and a compatible process-cached context. `verify_bundled_specifications` and
`require_verified_bundled_native_context` expose the respective fresh-worker and native-context checks;
`verify_bundled_plain_struct_counterpart` measures native facts without filling unknown producer evidence.

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

Recovery diagnostics export the engine's warning database, current-pass bad-data/unimplemented flags and counts
of unresolved calls, indirect jumps and partial jump tables. `recovery_status` distinguishes `incomplete`,
`warnings`, `no_reported_issues` and `unavailable`; producing C is not proof of usable recovery, and absence of
reported issues is not proof of correctness. Older result producers without diagnostics remain `unavailable`.
The CLI and pseudocode panel surface issues; corpus reports keep output success and recovery-status counts
separate. Header warnings have no instruction address; body warnings carry their engine instruction address.

Text output is bounded to four MiB and tokens to 262,144; the engine also retains its instruction-flow bound.
`rampage function decompile IMAGE --at FUNCTION --isolated` uses a supervised sibling `rampage-worker`;
`RAMPAGE_WORKER` explicitly selects the executable for sessions (including UI/MCP).
`Project::set_decompiler_worker` enables it programmatically.
Sessions select a sibling worker automatically when installed beside the application; `tools/install.sh`
installs the worker and CLI together, optionally with the UI. Direct `Project` construction remains explicitly
opt-in; `Session::open` also selects a sibling worker when present.
Worker protocol version 5 carries ordered symbol/type/prototype/global/mode, `no_return`, local-variable and
layout-assertion operations; mismatched request or response versions are rejected. Install the CLI and worker
together rather than mixing builds.
The protocol bounds input/output, drains pipes concurrently, cancels/times out and reaps failed children without
native fallback. Hard wire limits are 128 MiB requests, 16 MiB stdout and 64 KiB stderr. Defaults are 30 seconds
and one GiB memory. Linux uses hard AS/DATA limits; macOS samples RSS and can overshoot between samples.
Supervision is supported on 64-bit Linux/macOS and is not an OS sandbox.
All native C ABI operations contain C++ exceptions; unexpected partial native failures poison the handle and
retain unsafe state until process exit rather than risking cleanup through corrupt ownership. In-process mode
must still be limited to trusted inputs: exception containment does not prevent native memory-safety bugs.
Broader supervisor platform support remains separate work.
