# Feature reference

rampage provides static binary analysis through a CLI, MCP server and desktop UI. Findings are evidence for an
investigation, not proof of behavior, recovered original source or parity with another reverse engineering tool.
See the [CLI reference](cli-reference.md) for commands and [MCP reference](mcp.md) for tool names.

## Formats and instruction decoding

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

The previously reported decoder comparisons sampled words across every encoding: A32 matched `llvm-mc` on
97.95%, 16-bit Thumb on 100%, and 32-bit Thumb on 97.49%. AArch64 matched every instruction sampled from
Chrome's arm64 code and 99.85% of sampled words across encodings. These are sampled output comparisons, not
proof of exhaustive instruction coverage or semantic correctness.

## Function discovery, names and references

Recursive-descent discovery builds functions, control-flow graphs and cross-references. Names come from symbols
and exports, then import stubs and thunks (`puts`, or `puts@plt` on ELF). A bare import name resolves to its stub;
import slots such as GOT entries, Mach-O symbol pointers and the PE import address table are `__imp_<name>`.
Disassembly comments branches and data references with the name or string they target. Stripped Go function
names are recovered from the embedded pclntab, including binaries built with `-ldflags "-s -w"`. Decompiling
x86-64 Go (go1.18+) uses Go's register ABI with per-function argument and result prototypes derived from that
table and from how callers use results; see the [decompiler reference](../crates/rampage-decompiler/README.md).

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

Sessions select a supervised sibling `rampage-worker` when installed. `--isolated` explicitly requires worker
execution; batch decompilations and workflow previews also require supervision.
`RAMPAGE_WORKER` selects an explicit worker executable.
Direct library projects can opt in through `set_decompiler_worker`. Supervision is not an OS sandbox, and
in-process native decompilation must be limited to trusted inputs. Producing C or reporting no engine warnings
does not prove correct recovery. See the [decompiler reference](../crates/rampage-decompiler/README.md) for
compiler models, resource bounds, diagnostics and supported supervisor platforms, and the
[integration corpus](decompiler-corpus.md) for bounded recovery checks.

Address-bound signatures, calling conventions, type declarations and typed globals share the annotation log
and dependency-checked undo/redo. Embedded DWARF scalar/pointer signatures can be previewed and imported
without replacing analyst signatures. Named Itanium and MSVC vtables provide bounded class evidence, including
the C++ class name, not inferred object layouts. For stripped binaries, Itanium and MSVC RTTI scanning recovers
class names and base-class edges. See [debug signature import](debug-signatures.md).
The decompiler library can inspect/assert complete flat-struct layouts for x86-64 GCC before using dependent
prototypes. This read-only bridge compares native field offsets, sizes, alignment and leaf types against independent
facts; it does not import debug layouts or persist assertions across engine rebuilds. Nested aggregates and inferred
class layouts remain unsupported by this bridge.
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

## Library identification

FLIRT/Function-ID-style signatures hash function bytes with position-dependent encodings masked out: relative
branch/call targets, x86 RIP-relative displacements and PC-relative encodings of fixed-width instruction sets.
Supported signature architectures are x86, x86-64, AArch64, A32/Thumb, MIPS/MIPS64 and PowerPC/PowerPC64.

Identification applies the bundled musl libc starter database for x86-64 and AArch64 without setup. Build an
overlay database from a binary with named functions using `function build-signatures` (legacy `signatures`).
A database hashes each function over both its symbol size and discovered extent. A function cut short at an
unresolved jump table can match when discovery stops at the same place in the target.

Colliding masked bodies, such as `fprintf`/`sscanf`, are distinguished by named callees once those are known.
Databases retain these keys in optional `calls`/`ambiguous_calls` fields; bodies below the confidence gate do
not use them, so a thunk is not named after the function it forwards to. A database matches only the library
build it was generated from, not every version of that library. Regenerate or extend the bundled set with
`tools/gen-signatures.sh`; see [rampage-signatures](../crates/rampage-signatures).

## Guided reports and batch analysis

`triage_report`, `find_main`, `network_surface`, `find_crypto`, `persistence_surface`, `string_decoding` and
`diff_builds` compose primitives into bounded reports. Each finding retains evidence, source tool and confidence;
reports state limitations and end with concrete next tool calls. These are MCP tools or CLI workflows.

`binary analyze` (legacy `analyze`) composes workflows and explicitly selected supervised decompilations across
supported architecture slices into one bounded report, retaining task failures and recovery diagnostics. It
does not execute suggested next steps or annotation edits. See [CLI batch analysis](cli-analysis.md).

## Archive metadata

Standalone ZIP32 directory inventory is available through API, `binary archive-inventory` and the
`archive_inventory` file tool. Member references retain directory ordinals, including duplicate names; flags,
sizes, CRCs and local-header offsets remain unverified payload declarations. Metadata reads are bounded and
revalidated but not atomic, and tail search may overlap member data. No member offset is followed, and no extraction,
decompression, automatic member opening or execution occurs. See [archive inventory](archive-inventory.md).

## Managed assemblies

ECMA-335 metadata includes assembly identity, references, entry point and one paged list:

- `types`: fields, method/property signatures, event types and metadata accessor tokens, plus IL body sizes.
- `pinvokes`: the DLL export bound by each P/Invoke method.
- `attributes`: targets and fixed/named primitive, string, type, single-dimensional array and verified
  local-enum arguments, including boxed values and supported vectors inside `object[]`. Unsupported values report
  errors. An attribute target can be filtered by parent token.
- `resources`: ManifestResource tokens/names/flags, raw offsets and metadata-only implementation links.

One method's CIL can be disassembled ILDasm-style with tokens resolved to names/signatures, `ldstr` literals,
branch/switch labels, locals and exception clauses. Paging counts instructions; an IL label selects the
instruction containing that offset. Metadata and body decoding are bounded against hostile inputs. CIL is
reported as managed code, never treated as native instructions. See
[managed CLI commands](cli-reference.md#managed-code) or MCP tools `dotnet_metadata` and `dotnet_il`.

Events retain tokens, names, flags, bounded type rendering and same-owner add/remove/fire/other method bindings.
EventPtr ordering is preserved; malformed types remain unreadable and invalid ownership is diagnosed. Accessor
bindings are metadata, not proof of accessor behavior. Events do not imply resource or general attribute decoding.

Verified local enum literals can carry optional `enum_constant` field metadata with an underlying integral type
and exact decimal `value` string, including 64-bit extrema. Different named fields may retain equal values as
aliases; duplicate Constant rows for one field invalidate that field's evidence. This requires a verified local
enum owner, matching value-type field signature, appropriate literal flags, and exact Constant type/width/padding.
It works without custom attributes and does not replace numeric attribute values with symbolic names or synthesize
`Flags` combinations.

Enum constants have separate bounds of 100,000 Constant rows, 100,000 owner/field work rows, 10,000 retained
constants and 4 MiB of work/text, with bounded diagnostics. Incomplete or over-limit Constant tables yield no
constant evidence because an unread suffix could contain duplicate parents. External assemblies are not loaded.

Boxed custom-attribute values retain serialized types in their existing rendered strings, such as `box(int32, 42)`
and `box(int32[], null)`; named arguments keep their declared `object`/`object[]` type. Boxed strings, types and
verified local enums share the existing depth/node/text/image-work budgets, including failed type/name lookups.
Direct jagged constructor types, unknown/external or assembly-qualified enum resolution, bare `0xFF` object tags
and repeated object tags are unsupported. A failure in named arguments retains only fully charged valid fixed values.

Serialized local enum names use exact canonical reflection spelling: literal `+`, comma, backslash, brackets,
`*` and `&` are escaped with backslashes, while structural nesting uses an unescaped `+`. For example,
`Demo.Mo\+de` names a literal `Mo+de`, not a nested type. Dots, slashes, whitespace, case and Unicode are preserved;
there is no case folding, Unicode normalization, alternate spelling or general type-expression parser.

Only unique local definitions with verified integral widths resolve. Assembly-qualified names remain unsupported,
even when the assembly name appears to match the local image. Invalid/conflicting nesting, cycles, unreadable names
or incomplete identity evidence disable the whole serialized-name index rather than proving partial uniqueness.
Direct numeric enum decoding and constant evidence remain independent when their own evidence and budgets suffice.
Initial nesting scans cap readable rows at 100,000 and reserve eight shared-work units per attempt before reads or
insertion; escape expansion and failed name lookup also consume the existing decoding budgets. Within-limit ordinary
ILAsm nested-type display is unchanged.

Resource inventory distinguishes embedded-directory locations, external File/AssemblyRef links, unsupported
ExportedType links and malformed/dangling references. An embedded `readable_location` reports only a checked,
mapped location within a directory that fits one backed section span, not a validated length prefix or payload extent.
No payload, external resource, assembly or named file is opened or interpreted.

Resource inventory attempts at most 100,000 rows with a separate 4 MiB name-work budget; failed lookups and repeated
linked names consume that budget. Names have a 1,024-byte cap, UTF-8-safe truncation markers and explicit flags.
`resource_counts` separates declared/readable/retained/returned rows and reports inventory/name truncation independently
of filtering and pagination. `declared_known` distinguishes an observed zero from an unread declaration count;
`declared: 0` is only a placeholder when that flag is false. A recovered declaration can survive a later header
failure, but such a header still yields no decoded rows. `contains` matches resource or linked File/AssemblyRef names.

## Measurements and development

The `rampage-eval` harness scores library identification on stripped reference copies and different programs
linking the same library, and function discovery against symbol starts. It reports precision, recall and
architecture-specific disagreements, with no-wrong-name gates and committed recall floors. Previously reported
cross-program library-ID recall was 0.92 (x86-64) and 0.82 (AArch64), at precision 1.00. These results describe
the evaluated samples, not expected accuracy on arbitrary inputs; see the [benchmark reference](benchmarks.md)
for methods and comparison limits. Fixture passes do not establish IDA/Ghidra parity or semantic equivalence.

Previously reported discovery on a stripped Chrome framework on an M1 Max found 176,480 functions and
14.5 million instructions in the x86_64 slice in about 1.2 s, and 186,252 functions and 13.8 million instructions
in the arm64 slice in about 1.4 s. Repeated MCP queries reuse session analysis; previously reported cached queries
took milliseconds. Timings depend on the binary, machine, build and query, and are not latency guarantees.

| Crate | Purpose |
| --- | --- |
| `rampage-loaders` | Memory-mapped PE/ELF/Mach-O loading and address-based reads |
| `rampage-arch` | Instruction decoding with control-flow classification |
| `rampage-analysis` | Strings, recursive-descent discovery and cross-references |
| `rampage-api` | Session/query layer shared by clients |
| `rampage-mcp`, `rampage-cli`, `rampage-ui` | MCP server, CLI and desktop clients |
| `rampage-decompiler`, `rampage-worker` | Embedded native engine/specifications and supervised worker |

`tools/armgen` regenerates decoder tables from an AARCHMRS release, one instruction set at a time:

```sh
cargo run --release -p armgen -- <AARCHMRS-directory> A64 crates/rampage-arch/src/a64/spec.rs
```

Test fixtures live in `tests/fixtures`; `tests/fixtures/build.sh` rebuilds them using zig and Apple clang.
`tools/install.sh [ROOT] [--ui]` builds and installs the CLI and worker together, optionally with the UI.
See [extension points](plugins.md): registries are internal, not a stable public plugin API or dynamic loader.
The [LLDB query bridge](lldb-query.md) provides bounded read-only queries in an existing authorized stopped
session through explicit CLI/MCP requests and a local UI window; it is not an attach/resume controller.

[arm-spec]: https://developer.arm.com/Architectures/A-Profile%20Architecture
