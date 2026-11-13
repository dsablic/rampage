# Feature overview

rampage provides static binary analysis through an MCP server, a CLI and a desktop UI that share one API, and
opt-in live debugging of operator-started stubs through MCP. Findings are evidence for an investigation, not proof
of behavior, recovered original source or parity with another reverse engineering tool.

This page is an overview: each area below says what rampage does and its main limits, and links to the reference
with the detail. Tool names are in the [MCP reference](mcp.md) and commands in the [CLI reference](cli-reference.md).
Areas marked *experimental* are outside the [stability policy](stability.md).

| Area | What it covers | Section |
| --- | --- | --- |
| Formats and decoding | ELF, PE, Mach-O, raw windows, snapshots; x86, Arm, Capstone and Sleigh decoders | [Formats and instruction decoding](#formats-and-instruction-decoding) |
| Analysis | Function discovery, names, CFGs, cross-references, Go and C++ metadata | [Function discovery, names and references](#function-discovery-names-and-references) |
| Decompilation and typing | Embedded Ghidra decompiler, local variables, type library, data and operand types, propagation, DWARF/PDB import | [Decompilation and persistent types](#decompilation-and-persistent-types) |
| Triage and detection | Hashes, entropy, hardening, packer/compiler detection, YARA, capa, capabilities, crypto constants | [Triage and detection](#triage-and-detection) |
| Agent ergonomics | Compact views and atomic annotation batches | [Tool views and annotation batching](#tool-views-and-annotation-batching) |
| Findings ledger | Findings, unknowns and questions with evidence, kept in the annotation log | [Investigation ledger](#investigation-ledger) |
| Build matching | One-to-one function matching with another build and annotation transfer | [Annotation transfer](#annotation-transfer) |
| Patching | Assembler subset, checked patches, export to a new file | [Checked patches and assembly](#checked-patches-and-assembly) |
| Search | Bytes, text, regex, immediates, instructions, references | [Search](#search) |
| Library identification | Bundled signatures, PAT and FunctionID inputs, fuzzy candidates | [Library identification](#library-identification) |
| Guided reports | Triage, main, network, persistence, string decoding, build diffing, crypto | [Guided reports and batch analysis](#guided-reports-and-batch-analysis) |
| File formats | ZIP inventory, Go and Rust build info, PyInstaller, WebAssembly, PE resources, .NET | [Archive metadata](#archive-metadata) and [File formats](#file-formats) |
| Debugging | GDB remote stubs; `debugserver` and Windows stubs are *experimental* | [Debugging](#debugging) |
| Heuristic flywheel | Agent-proposed signatures gated on held-out truth (*experimental*) | [Heuristic flywheel](#heuristic-flywheel) |
| Desktop UI | Listings, graphs, decompilation and shared annotations (*experimental*) | [Desktop UI](#desktop-ui) |
| Measurements | Evaluation harness, benchmarks, crates | [Measurements and development](#measurements-and-development) |

## Formats and instruction decoding

- [File layout](file-layout.md) maps any file or range of up to 64 MiB in one call: padding and occupied
  regions with hashes, block entropy, string clusters and labelled hints, including header-checked
  compressed-component candidates. Limits: statistics and heuristic
  candidates only; no format or architecture detection, and a compressed-component candidate names no codec.
- Bounded [raw-code windows](raw-code.md) accept explicit ranges and asserted architecture/mode/order/base
  through MCP without a native executable header. Limits: little-endian x86/x64/ARM/AArch64, linear decoding
  only; no code detection, function discovery or execution.
- [Native data inspection](data-inspection.md) links bounded stored words to metadata candidates, while
  [explicit decoding](decoding.md) provides LZSS (classic 4K and every explicit variant) and LZ4-block providers,
  transient previews and a bounded probe that ranks parameter sets for an unknown variant. Limits: pointer
  links are suppressed on loader warnings; decoding is not extraction, authentication or a load mapping.
- ELF, PE and Mach-O, including universal Mach-O binaries and explicitly selected embedded executable images.
- x86 and x86-64 use [iced-x86](https://github.com/icedland/iced).
- AArch64 and 32-bit ARM decode natively from Arm's
  [machine-readable architecture specification][arm-spec]. AArch64 includes SVE and SME; AArch32 includes A32,
  Thumb, VFP and Advanced SIMD.
- MIPS, PowerPC, RISC-V, SPARC, z/Architecture and m68k use
  [Capstone](https://www.capstone-engine.org), with supported little- and big-endian variants. MIPS and SPARC
  delay slots remain in their branch's block. Native, specification-derived decoders are the preferred direction
  where machine-readable specifications exist.
- Runtime snapshots and bundle directories use the same query surfaces. Snapshots contain validated sparse
  memory, virtual addresses, explicit seeds and provenance; missing memory is unavailable, not fabricated zeros.
  See [runtime snapshots](runtime-snapshots.md) for capture, persistence and format limits.
- Read-only stopped-session [LLDB queries](lldb-query.md) are available through an explicitly operator-started
  local Unix socket, CLI/MCP requests and a local desktop query window. They do not attach, control execution,
  evaluate expressions or write target memory; observations remain non-atomic and separate from snapshot identity.
- [Debug sessions](debug-control.md) (MCP `debug` group, only with an operator-allowed endpoint): inspection,
  snapshots, all-stop execution control and project correlation over GDB remote stubs, Apple's `debugserver` and
  Windows RSP stubs (the last two not yet live-verified); writes and kill only behind operator flags.

Decoder accuracy against `llvm-mc` and real arm64 code is recorded in the
[benchmarks](benchmarks.md#earlier-measurements).

## Function discovery, names and references

Recursive-descent discovery builds functions, control-flow graphs and cross-references. Names come from symbols
and exports, then import stubs and thunks (`puts`, or `puts@plt` on ELF). A bare import name resolves to its stub;
import slots such as GOT entries, Mach-O symbol pointers and the PE import address table are `__imp_<name>`.
Disassembly comments branches and data references with the name or string they target. Stripped Go function
names are recovered from the embedded pclntab, including binaries built with `-ldflags "-s -w"`. Decompiling
x86-64 and ARM64 Go (go1.18+) uses Go's register ABI with per-function argument and result prototypes derived
from that table and from how callers use results; see the
[decompiler reference](../crates/rampage-decompiler/README.md).

ARM ELF32 [EHABI unwind metadata](arm-unwind-starts.md) supplies checked discovery candidates from compact
EXIDX/extab records. Limits: metadata is not boundary proof; no unwinding, interior-range expansion or ARM32
exact-entry architecture expansion is implied. Unsupported descriptors and malformed prefixes retain warnings.

On AArch64, ADRP+ADD and ADRP+LDR pairs provide data references. Known ADR/ADRP/ADD/MOV/LDR values can resolve
BR/BLR targets through readable, non-writable pointers. This does not resolve authenticated pointers or prove
that a runtime branch executes. Writable captured slots are observation evidence, not proven call edges.

Calls to documented non-returning functions (`exit`, `abort`, `__stack_chk_fail`, `ExitProcess`, C++ throw
helpers, Rust and Go panics) terminate a block without fall-through. Discovery can also infer non-returning
functions when every path ends in a qualifying call or trap. `function_graph` and the hidden `export-cfg`
command mark these calls `listed` or `inferred`; the decompiler receives the same callee information.

`function_summary` reports the decoded graph, paginated references and partial typed AArch64 IR, not recovered
source. Bounded register/memory SSA exposes predecessor-indexed phi nodes and 32-bit result truncation.
Unsupported instruction semantics are explicit barriers, not inferred no-ops. Partial ARM64 SSA pseudocode
also retains explicit unknowns. See the [ARM64 development track](arm64-development.md) for validation and limits.

## Decompilation and persistent types

Embedded Ghidra (Apache-2.0) produces C for the decoded architectures except s390x. The integration includes
target-sized runtime prototypes, ARM/Thumb context, BE8 and a Darwin ARM64 compiler model. Results include C,
address-linked semantic tokens, signatures, storage mappings, CFG edges and recovered calls/jump tables.
Processor specifications are embedded: relocated executables need no external Ghidra installation.
`GHIDRA_INSTALL_DIR` overrides the embedded specifications; otherwise they use a writable HOME cache.
Bundled Darwin ARM64 rules model declared narrow integer register inputs with signed/unsigned extension to 32 bits,
without assuming values for the upper 32 bits. General variadic-call recovery remains separate.

Decompilation runs in a supervised `rampage-worker` process when one is installed beside `rampage` (or named by
`RAMPAGE_WORKER`). **Without a worker, it runs in-process**, inside the server or CLI, without the worker's time,
memory and output limits. The MCP server warns on stderr at startup when it finds no worker, and each `decompile`
result names where it ran in `decompiler` (`supervised` or `in-process`). `rampage server serve --require-worker`
and the CLI's `decompile --isolated` refuse to decompile without the worker; batch decompilations and workflow
previews always require it. Direct library projects can opt in through `set_decompiler_worker`. Supervision is
not an OS sandbox: limit in-process decompilation to trusted inputs, and analyse hostile files in a VM or
container. Producing C or reporting no engine warnings
does not prove correct recovery. See the [decompiler reference](../crates/rampage-decompiler/README.md) for
compiler models, resource bounds, diagnostics and supported supervisor platforms, and the
[integration corpus](decompiler-corpus.md) for bounded recovery checks.

Address-bound signatures, calling conventions, type declarations and typed globals share the annotation log
and dependency-checked undo/redo. Embedded DWARF scalar/pointer signatures can be previewed and imported
without replacing analyst signatures. Named Itanium and MSVC vtables provide bounded class evidence, including
the C++ class name, not inferred object layouts. For stripped binaries, Itanium and MSVC RTTI scanning recovers
class names and base-class edges, following Mach-O chained rebases and accepting chained binds to the C++
runtime's typeinfo vtables, as arm64 images linked with the default chained fixups store them (see
[debug signature import](debug-signatures.md)). In x86 and x64 PE images, MSVC vftables are found through the RTTI
complete object locator before slot 0 and reported with their class, subobject offset and slot targets; every slot
also seeds a function start, so virtual methods reached through no direct call are discovered. MCP serves this
evidence as `class_evidence`, and demangled names with Objective-C classes, superclasses, methods and properties as
`language_metadata`; both are core tools, listed without enabling a group. See
[MSVC C++ metadata](file-formats.md#msvc-c-metadata).

Types-group [`edit_variable`](local-variables.md) persists local/parameter names and types by native storage
identity and returns refreshed C in one call, with undo/replay. Limits: single whole register/stack mappings
and same-size retypes; unsupported storage is explicit, with no automatic cross-call propagation.

The [project type library](type-library.md) provides named declaration/header import, paged inventory, native
size/alignment/packing/field inspection and dependency-checked deletion. Existing address-bound `set_types`
annotations remain compatible. Limits: bounded type-only C, minimal explicit ABI profiles, no full preprocessor/SDK.

[Data and operand typing](data-types.md) binds native layouts, struct arrays and explicit string encodings to
data ranges, renders typed fields alongside raw backing status, and labels selected immediate enums and struct
memory offsets in disassembly. Raw instructions and file bytes remain unchanged. Limits: bounded data windows,
supported x86/x64/AArch64 operands, no automatic object-type inference or pointer traversal.

[`function_frame`](function-frame.md) exposes current native local/parameter names, types and complete storage
with actual address-space widths, plus available AArch64 stack-access/register candidates. Limits: bounded
paging and recovery evidence, separate coordinate origins, no guessed full-frame size or ABI preservation claim.

[Type propagation](type-propagation.md) derives explicit-source candidates across supported direct calls and
persists them separately from analyst types. Native inference uses unlocked hints; conflicts and unsupported
mappings remain visible. Limits: bounded scalar/pointer contexts, no forced analyst replacement or general
alias proof.

[Checked debug-type import](debug-types.md) reads bounded DWARF graphs and explicitly selected, identity-matched
PDB types into the project library, with native counterpart checks and atomic signature/proof persistence.
Limits: supported nested aggregates/arrays and scalar/pointer signatures; unknown alignments stay unknown,
unsupported bitfields/qualifiers are not projected into complete source types, and C tag names alone do not
resolve ambiguous CodeView forward identities.
The decompiler library can inspect/assert complete flat-struct layouts for x86-64 GCC before using dependent
prototypes. This read-only bridge compares native field offsets, sizes, alignment and leaf types against independent
facts; it does not import debug layouts or persist assertions across engine rebuilds. Nested aggregates and inferred
class layouts remain unsupported by this bridge.
The separate [checked DWARF layout import](debug-layout-import.md) can persist verified flat-struct pointer declarations
and dependent signatures as one non-overwriting batch, replaying assertions on reopen in native and worker engines.
Its scope is small x86-64 ELF C metadata with explicit struct alignment and verified bundled specifications;
it does not widen the scalar-only CLI/MCP importer or infer stripped-binary class layouts. Explicit reviewed
CLI/MCP and UI actions bind approval to the complete preview fingerprint before atomic application. A bounded C++
extension projects producer-described base-free, non-polymorphic records and exact mutable `this` methods; it does
not infer vptr storage, inheritance or virtual-call targets.
An explicit [PDB name import API](pdb-symbols.md) matches PE/PDB GUID and age, then previews or applies names to
already-discovered unnamed entries without replacing existing labels. PDB types/layouts and undiscovered starts
are not imported; no PDB sidecar is opened automatically.

## Triage and detection

Triage reports MD5/SHA-1/SHA-256, section entropy and a file-wide entropy profile, overlays, and PE imphash
using pefile's algorithm without its ordinal-name tables. Format details include:

- PE build time, mitigations, Rich header and signing.
- ELF interpreter, needed libraries, NX/RELRO/PIE and build ID.
- Mach-O dylibs, platform, UUID, signing and encryption.

Hints identify likely packing and missing hardening. Permissive default databases are bundled; additional
databases are supplied at runtime. Detection databases name likely packers, compilers,
protectors, installers, linkers and runtimes; user PeID `userdb.txt` files are accepted, with warnings for
malformed entries that are skipped. YARA runs through embedded yara-x, while Mandiant capa rules use imports,
exports and strings only: file-scope features, not instruction/function-level capa analysis. Built-in
[capability rules](capabilities.md) use corroborated evidence. Every hit is a triage signal, not proof.

The corresponding MCP tools are `detect_tools`, `yara_scan`, `capa_detect` and `capabilities`. A spec-derived
constant database finds AES, DES, Blowfish, SHA/MD5, ChaCha, CRC, Deflate, Base64 and curve-parameter tables.
[Data packs](data-packs.md) extend these heuristic databases with data only.

## Tool views and annotation batching

Six structural/code/data tools share `view: full|summary|code`; metadata tools reject code view explicitly.
Reduced views retain required identity, diagnostics, source/coordinate and recovery evidence with omission
receipts; oversized output refuses rather than producing cut JSON. The atomic `batch` tool composes checked
annotation operations in one existing undo/history step. See [tool views and batches](tool-views.md).

## Investigation ledger

`record_finding` and `list_findings` keep what an agent established, what it still does not know and its open
questions, each with the tool calls that support it, a confidence and an open/resolved/rejected status. Entries
live in the annotation log, so they survive the session, replay on reopen, undo and redo like comments, and are
shared with other processes under the log's lock; ids are stable and not reused within the log. Entries made on
another build of the binary are kept and flagged. Its size limits, which keep it from crowding out other edits,
are in [MCP edits](mcp.md#edits-and-session-state).

## Annotation transfer

`transfer_annotations` matches functions one-to-one with an analyzed earlier build (exact bytes, symbols, masked
hashes, unique strings, call-graph propagation and neighbourhood, each with a confidence; ambiguity is reported,
not guessed), reports changed, added and removed functions, and previews or applies the source's names, comments,
signatures, types and globals as an undoable batch with a provenance ledger entry. See
[build matching and annotation transfer](build-diffing.md).

## Checked patches and assembly

Static ELF64 x86-64/AArch64 patches use the annotation log, original identity/preimage checks,
reviewed revisions and immutable effective projects. Listing, analysis and decompilation consume the same
effective bytes. Export publishes only a new file; source files and debugger/capture memory remain unchanged.
Unsupported profiles and incompatible image-sealed metadata reject rather than weakening evidence gates.

The pure assembler supports a documented x86/x64/AArch64 subset and returns verified bytes without applying
them. See [patching/export contracts](patching.md) and [assembly grammar and limits](assembly.md).

## Search

The Core `search` tool and `binary search` CLI query mapped bytes, ASCII/Unicode UTF-16 text and regex,
structured immediates, mnemonic/operand globs, and retained references or referencing functions. Results
preserve function context, native evidence and address ordering; incomplete scans report lower-bound totals
and explicit budgets rather than complete negative answers. Exact text is matched in linear time against the
budget, so a default search covers a 50 MB image, and a stopped byte/text scan says where to resume and which
ranges it left unscanned. See [search reference](search.md).

Search is static and read-only. Native preparation/scanning is bounded and cancellable after the
non-interruptible analysis/cache initialization. Unmapped overlays, virtual gaps and zero-fill are not
invented byte content. Instruction evidence uses production decoding, retained modes and bounded semantic
lookahead, not arbitrary byte sweeps.

## Library identification

Native signatures hash function bytes with position-dependent encodings masked out: relative
branch/call targets, x86 RIP-relative displacements and PC-relative encodings of fixed-width instruction sets.
Supported signature architectures are x86, x86-64, AArch64, A32/Thumb, MIPS/MIPS64 and PowerPC/PowerPC64.

Identification applies the reviewed default corpus for x86-64, AArch64, i386 and A32/Thumb without setup. Build an
overlay database from a binary with named functions using `function build-signatures` (legacy `signatures`).
A database hashes each function over both its symbol size and discovered extent. A function cut short at an
unresolved jump table can match when discovery stops at the same place in the target.

MCP identification pages complete match/warning/candidate rows within 60000 JSON bytes, keeping whole-result match/apply
totals. Its default window is 100 rows; offsets never select which names apply. Oversized receipts refuse before
renaming, without truncating JSON strings.

Colliding masked bodies, such as `fprintf`/`sscanf`, are distinguished by named callees once those are known.
Databases retain these keys in optional `calls`/`ambiguous_calls` fields; bodies below the confidence gate do
not use them, so a thunk is not named after the function it forwards to. A database matches only the library
build it was generated from, not every version of that library. Regenerate or extend the bundled set with
`tools/gen-signatures.sh`; see [rampage-signatures](../crates/rampage-signatures).

Bundled databases use deterministic gzip and lazy per-architecture decoding; pack listing does not decode them.
The [offline corpus pipeline](signature-corpus.md) builds public-library profiles with ownership-filtered truth,
frozen tool/input receipts and collision-preserving export. Reviewed precision-safe exports are promoted explicitly;
raw recall/precision failures, unsupported profiles and unrun coverage remain visible. The default corpus does not
identify arbitrary library versions; its recall is in the [signature corpus](signature-corpus.md) reference.

[User-supplied PAT inputs](signature-imports.md) match validated byte patterns, CRC windows and tails without
converting them to native hashes. Genuine schema-6 FID databases use the separate explicitly configured trusted
Ghidra/JVM import/query API. It is static host analysis, not target execution or a sandbox for untrusted tools.

After the signature databases, a bundled call graph names the callees of functions they named, where the caller
calls them in the same position as training builds of the same library do, the callee's own calls fit training too,
and one of them is already named (source `rampage-builtin call graph` in results). Names the binary already has
(symbols, exports, the analyst's) seed it and are never handed out again. It covers the flywheel corpus's libraries (zlib, LZ4, cJSON,
zstd and Lua).

[Secondary fuzzy matching](fuzzy-signatures.md) compares CFG, constants and calls. API/CLI/MCP results expose
scores, provenance and confidence gates as separate suggestions; even eligible proposals do not automatically
rename functions. Exact signatures and existing analyst names retain priority.

## Guided reports and batch analysis

`triage_report`, `find_main`, `network_surface`, `persistence_surface`, `string_decoding` and `diff_builds` (in
`core`) and `find_crypto` (in the `detection` group) compose primitives into bounded reports. Each finding
retains evidence, source tool and confidence; reports state limitations and end with concrete next tool calls.
These are MCP tools or CLI workflows.

`binary analyze` (legacy `analyze`) composes workflows and explicitly selected supervised decompilations across
supported architecture slices into one bounded report, retaining task failures and recovery diagnostics. It
does not execute suggested next steps or annotation edits. See [CLI batch analysis](cli-analysis.md).

## Archive metadata

Standalone ZIP32 directory inventory is available through API, `binary archive-inventory` and the
`archive_inventory` file tool. Member references retain directory ordinals, including duplicate names; flags,
sizes, CRCs and local-header offsets remain unverified payload declarations. Metadata reads are bounded and
revalidated but not atomic, and tail search may overlap member data. No member offset is followed, and no extraction,
decompression, automatic member opening or execution occurs. See [archive inventory](archive-inventory.md).

## File formats

These read embedded metadata and containers without executing, extracting or decompiling anything. The
[file formats reference](file-formats.md) has their bounds and output.

- **Toolchain build info** (`build_info`, `binary build-info`): Go build info as `go version -m` prints it, and the
  Rust dependency lists that cargo-auditable embeds. Both are self-reported by the build, not verified against
  code. See [toolchain build info](file-formats.md#toolchain-build-info).
- **PyInstaller archives and WebAssembly modules** (`pyinstaller_archive`, `wasm_module`): the CArchive cookie,
  Python version and table of contents, and a core WebAssembly module's sections, imports, exports and functions.
  See [PyInstaller and WebAssembly](file-formats.md#pyinstaller-archives-and-webassembly-modules).
- **PE resources and load config** (`pe_resources`, `pe_load_config`): resource leaves with decoded version
  resources and manifests, and the load config's security cookie, SafeSEH, CFG and CET settings checked against
  the header's mitigations. See [PE resources and load config](file-formats.md#pe-resources-and-load-config).
- **MSVC C++ exception handling** (`exception_handlers`, experimental; validated on clang-cl
  `__CxxFrameHandler3` output, while cl.exe x64 `__CxxFrameHandler4` tables are counted, not decoded): per function, try blocks with typed catch handlers and
  their funclets, destructor cleanups by state and SEH scopes, from `__CxxFrameHandler3` FuncInfo (x64 and x86)
  and `__C_specific_handler` scope tables, plus the catchable types of each `_ThrowInfo`. Funclets seed function
  starts. See [MSVC C++ metadata](file-formats.md#msvc-c-metadata).
- **Managed assemblies** (`dotnet_metadata`, `dotnet_il`): ECMA-335 metadata (types, P/Invokes, custom
  attributes, resources) and ILDasm-style CIL for one method. CIL is reported as managed code, never as native
  instructions. See [managed assemblies](file-formats.md#managed-assemblies).

## Debugging

The MCP `debug` group exists only on a server started with an allowed `--debug-endpoint`. It connects to a GDB
remote stub the operator started (gdbserver, QEMU, OpenOCD and similar), reads registers, memory, modules and
memory maps, writes snapshots, controls execution in all-stop mode with breakpoints and watchpoints, and binds the
session to a static project so breakpoints take function names and stops are reported in the project's terms.
Memory and register writes need `--debug-writes`, and kill needs `--debug-kill`. rampage never launches or
attaches to a process. Live acceptance has run against QEMU (Cortex-M3). Apple's `debugserver` and Windows targets
through `gdbserver.exe` or `lldb-server` are *experimental*: implemented and tested against protocol transcripts,
not yet live-verified. See [debug sessions](debug-control.md). The read-only [LLDB query bridge](lldb-query.md)
and [runtime snapshots](runtime-snapshots.md) are separate.

## Heuristic flywheel

*Experimental.* A server started with `--corpus` serves only the `improve` group, through which an agent proposes
library-signature rows from a training split; candidates must pass a fast gate and a held-out gate before
promotion, and promoted rows leave as `.rpack` data packs. Limits: libid is the only family, and against the
deterministic signature generator the agent has promoted no row. See [the flywheel](flywheel.md).

## Desktop UI

*Experimental.* An egui client over the same API: docked functions, strings, imports and exports, a disassembly
listing with clickable references, hex, graph, cross-references, triage, Ghidra pseudocode, shared annotations,
project workspaces and an optional assistant that sends questions and tool results to Anthropic's API. See the
[desktop UI reference](desktop-ui.md).

## Measurements and development

The `rampage-eval` harness scores library identification on stripped reference copies and on different programs
linking the same library, and function discovery against symbol starts, with no-wrong-name gates and committed
recall floors. The [benchmarks](benchmarks.md) hold the head-to-head agent runs, the static comparisons with
Ghidra and measurements of decoders, recall and discovery speed, each with its method and limits.

| Crate | Purpose |
| --- | --- |
| `rampage-loaders` | Memory-mapped PE/ELF/Mach-O loading and address-based reads |
| `rampage-arch` | Instruction decoding with control-flow classification |
| `rampage-analysis` | Strings, recursive-descent discovery and cross-references |
| `rampage-api` | Session/query layer shared by clients |
| `rampage-debug` | GDB remote protocol client, target descriptions and session thread for the `debug` tools |
| `rampage-mcp`, `rampage-cli`, `rampage-ui` | MCP server, CLI and desktop clients |
| `rampage-decompiler`, `rampage-worker` | Embedded native engine/specifications and supervised worker |
| `rampage-decode` | Bounded decoder providers for explicitly requested file ranges |
| `rampage-signatures` | FLIRT/Function ID-style library-function signatures |
| `rampage-detect`, `rampage-capabilities`, `rampage-constants`, `rampage-yara` | Toolchain/packer detection, capability tags, crypto-constant scanning, YARA rules |
| `rampage-agent` | Desktop assistant conversation over rampage tools |
| `rampage-eval` | Strip-and-compare evaluation of heuristics and the parity scorecard |
| `rampage-plugin`, `rampage-plugin-contract`, `rampage-plugin-worker`, `rampage-componentize` | Experimental component plugins: runtime, schema, worker and build helper |

`tools/armgen` regenerates decoder tables from an AARCHMRS release, one instruction set at a time:

```sh
cargo run --release -p armgen -- <AARCHMRS-directory> A64 crates/rampage-arch/src/a64/spec.rs
```

Test fixtures live in `tests/fixtures`; `tests/fixtures/build.sh` rebuilds them using zig and Apple clang.
`tools/install.sh [ROOT] [--ui] [--plugins]` builds the CLI/native worker, with optional UI and matching plugin worker;
see [source installation](plugins.md#source-installation) for retention, staging and partial-publication behavior.
See [extension points](plugins.md): builtin registries remain internal; the explicit experimental triage-component
host is separate, with no stable public plugin API or automatic discovery.

[arm-spec]: https://developer.arm.com/Architectures/A-Profile%20Architecture
