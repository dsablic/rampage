# rampage-decompiler

Embeds Ghidra's decompiler as an in-process library and exposes it to rampage through a small, safe Rust API.
A `Decompiler` is opened once over a program's executable segments and decompiles functions to C on demand.

## Vendored source

`vendor/ghidra/` holds the decompiler's C++ sources, taken from the Ghidra 12.1.4 release
(tag `Ghidra_12.1.4_build`), path `Ghidra/Features/Decompiler/src/decompile/cpp`. They are the decompiler
library set (the Makefile's `LIBDECOMP` sources) without the BFD loader, the Ghidra-process bridge and the
SLEIGH compiler. `src/shim.cc` is rampage's own C ABI over that library.

Four vendored files have small integration changes: `loadimage.hh` adds instruction-lookahead, instruction-range
validation and partial-string-read hooks; `sleigh.cc` validates decoded lengths; `stringmanage.cc` consumes only
available string bytes; `sleigh.hh` and `sleigh.cc` expose translation-cache invalidation without re-registering
context variables. Default loader hooks preserve upstream behavior. All other vendored sources are unchanged.

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

The project layer selects Windows specifications for PE, macOS PowerPC specifications for big-endian PowerPC
Mach-O, and the existing default specifications otherwise. `DecompilerOptions` exposes platform/compiler
overrides; `Project::set_decompiler_options(None)` restores format-based selection. The CLI accepts
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

These defaults do not establish full ABI parity. In particular, the bundled ARM64 default is AAPCS64, not a
Darwin-specific C ABI specification; Apple ARM64 variadic/stack rules and ARM BE8 require further integration
work. Compiler overrides such as Go or Swift disable automatic C runtime declarations rather than assigning
C signatures to functions using another calling convention.

## Processor specifications

The compiled SLEIGH specifications (`.sla`) and their processor/compiler specs for every supported architecture
are vendored under `specs/` (about 4.5 MB, from the same Ghidra 12.1.4 release), so a source build decompiles with
no external Ghidra install. `sleigh_home` resolves them in order: `GHIDRA_INSTALL_DIR` if set, then the vendored
`specs/` (the path is baked at build time), then a Homebrew install (`brew --prefix ghidra`). A relocated binary
built elsewhere falls back to an install or the environment override. s390x has no Ghidra specification and is
unsupported.
