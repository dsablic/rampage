# rampage

A high-performance, open source reverse engineering toolkit written in Rust. The goal is a general-purpose
IDA Pro alternative where AI agents are first-class clients: a scriptable CLI and an MCP server come first,
and a GUI arrives later as one more client of the same API.

Status: early, but with real teeth. The one-shot CLI, recursive-descent function discovery with
cross-references, the MCP server, an AArch64 decoder generated from Arm's specification, saved annotations,
triage and a first desktop UI are in. Functions decompile to C through an embedded build of Ghidra's
decompiler. See [the design](docs/plans/2026-10-10-rampage-design.md) for the roadmap.

## Supported today

- Formats: ELF, PE, Mach-O (including universal binaries)
- Architectures: x86 and x86-64 (via [iced-x86](https://github.com/icedland/iced)), AArch64 and 32-bit ARM (A32 and
  Thumb, with VFP and Advanced SIMD) decode natively; MIPS, PowerPC, RISC-V, SPARC, z/Architecture and m68k decode
  through [Capstone](https://www.capstone-engine.org) for now, in either byte order, with MIPS and SPARC delay slots
  kept in their branch's block. Native decoders replace Capstone where a machine-readable specification exists.
- 32-bit ARM is generated from the same specification as AArch64; on words sampled across every encoding its output
  matches `llvm-mc` on 97.95% (A32), 100% (16-bit Thumb) and 97.49% (32-bit Thumb).
- AArch64 includes SVE and SME, decoded from tables generated out of Arm's open-source
  [machine-readable architecture specification](https://developer.arm.com/Architectures/A-Profile%20Architecture).
  Its output matches `llvm-mc` on every instruction sampled from Chrome's arm64 code and on 99.85% of words
  across all encodings. On AArch64, function
  discovery resolves ADRP+ADD and ADRP+LDR pairs into data references.
- Calls that never return end their block with no fall-through: to functions documented never to return (`exit`,
  `abort`, `__stack_chk_fail`, `ExitProcess`, C++ throw helpers, Rust and Go panics), and to functions discovery
  infers never return because every path through them ends in such a call or a trap. `function_graph` and
  `export-cfg` mark each such call `listed` or `inferred`, and the decompiler is told the same callees.
- Triage: MD5/SHA-1/SHA-256, entropy per section and as a profile across the file, PE imphash (pefile's
  algorithm, without its ordinal-name tables), overlays, and format details: PE build time, mitigations, Rich
  header and signing; ELF interpreter, needed libraries, NX/RELRO/PIE and build ID; Mach-O dylibs, platform,
  UUID, signing and encryption. Hints point out likely packing and missing hardening.
- Names: symbols and exports, then import stubs and thunks named after their import (`puts`, or `puts@plt` on
  ELF; a bare import name finds its stub), and import slots (GOT entries, Mach-O symbol pointers, the PE import
  address table) as `__imp_<name>`. Disassembly comments
  each branch or data reference with the name or string it points to.
- Decompilation: embedded Ghidra (Apache-2.0) supports every decoded architecture except s390x, with target-sized
  runtime prototypes, ARM/Thumb context, BE8 and a Darwin ARM64 compiler model. Results include rendered C,
  address-linked tokens, signatures, storage mappings, CFG edges and recovered calls/jump tables. Specifications
  are embedded, so relocated executables need no external installation (override with `GHIDRA_INSTALL_DIR`).
  Sessions select a supervised sibling worker when installed; `--isolated` requires worker execution explicitly.
  Direct library projects can opt in through `set_decompiler_worker`. See
   [crates/rampage-decompiler](crates/rampage-decompiler).
- Persistent types: address-bound signatures, calling conventions, type declarations and typed globals share the
  annotation log and dependency-checked undo/redo. Embedded DWARF scalar/pointer signatures can be previewed and
  imported without replacing analyst signatures. Named Itanium and MSVC vtables provide bounded class evidence
  (with the C++ class name), not inferred object layouts; for stripped binaries, Itanium and MSVC RTTI data is
  scanned to recover class names and base-class edges. See [debug signature import](docs/debug-signatures.md).
- Library identification: a FLIRT/Function-ID-style signature of each function, hashed with position-dependent
  bytes masked out (relative branch and call targets, x86 RIP-relative displacements, and the PC-relative
  encodings of the fixed-width sets), so the same library function matches across binaries linked at different
  addresses. `rampage identify` applies a bundled starter database (musl libc, for x86-64 and AArch64) out of the
  box, so stripped static library code is named without any setup; build your own from a binary whose functions
  are named (`rampage signatures`) to overlay on top. A database also hashes each function over the extent
  discovery finds for it in the reference, so a function discovery cuts short (at a jump table it cannot follow)
  still matches where discovery stops at the same place in the target. Functions whose masked bodies collide
  (`fprintf`/`sscanf`) are told apart by the names of the functions they call, once those are named; databases keep
  these callee keys in optional `calls`/`ambiguous_calls` fields, and never use them for bodies too small to pass
  the confidence gate (a thunk is not named after what it forwards to). x86, x86-64, AArch64, 32-bit ARM (A32
  and Thumb), MIPS/MIPS64 and PowerPC/PowerPC64; see [crates/rampage-signatures](crates/rampage-signatures). A
  database matches only the library build it was made from; regenerate or extend the bundled set with
  `tools/gen-signatures.sh`.
- Go binaries: stripped Go function names are recovered from the embedded pclntab at load, so they appear in the
  function list, metadata and disassembly even after `-ldflags "-s -w"`.
- Heuristic databases: one detection layer where each database is data, with permissive defaults bundled and the
  rest supplied at runtime. `rampage detect` names the producing packer, compiler, protector, installer, linker or
  runtime from an authored signature database (and accepts your own PeID `userdb.txt`, warning about the entries it
  skips as malformed); `rampage yara` runs your YARA rules through the embedded yara-x engine; `rampage capa`
  evaluates a Mandiant capa-rules directory against imports, exports and strings (file-scope features only);
  `rampage capabilities` applies the built-in corroborated rules. Every hit carries its evidence and is a triage
  signal, not proof. Also exposed as the `detect_tools`, `yara_scan` and `capa_detect` tools. A
  spec-derived constant database (AES, DES, Blowfish, SHA/MD5, ChaCha, CRC, Deflate, Base64, curve parameters)
  locates algorithm tables in the image.
- Guided investigation workflows: `triage_report`, `find_main`, `network_surface`, `find_crypto`,
  `persistence_surface`, `string_decoding` and `diff_builds` compose the primitives into one bounded report.
  Each finding carries its evidence, source tool and confidence; each report ends with concrete next tool calls
  and states its limitations. MCP tools, or `rampage report`.
- Measured accuracy: `rampage-eval` scores library identification (on a stripped copy of the reference and on a
  different program linking the same library) and function discovery (against symbol starts): precision, recall
  and a disagreement set per architecture slice, gated on no wrong names and committed recall floors -- the
  harness behind the heuristic flywheel (`docs/plans/`). Current cross-program library-ID recall: 0.92 (x86-64),
  0.82 (AArch64) at precision 1.00.
- .NET assemblies: `rampage dotnet` (and the `dotnet_metadata` tool) reads ECMA-335 metadata -- assembly
  identity, references, entry point, and one paged list chosen with `--list` / `list`: `types` (fields and
  methods with ILAsm-style signatures such as `int32 Combine<T1>(T1)` and IL body sizes), `pinvokes` (the DLL
  export each P/Invoke method binds to) or `attributes` (custom attributes with their targets and
  primitive/string/type arguments, filterable by `--parent-token`). `rampage dotnet --il <token|Type::Name>`
  (and the `dotnet_il` tool) disassembles one method's CIL, ILDasm style: tokens resolved to names and
  signatures, `ldstr` literals, branch and switch labels, locals and exception clauses; `--offset` / `offset`
  pages by instruction index, `--at IL_0042` / `at` starts at the instruction holding that IL offset. Decoding
  is bounded against hostile metadata and bodies. CIL is reported, never treated as native code.

## Usage

```
cargo build --release

rampage report triage-report <file>          # guided overview with evidence and next steps
rampage report find-main|network-surface|find-crypto <file>
rampage report persistence-surface|string-decoding <file>  # autostart indicators; candidate decoding loops
rampage report diff-builds <file> --other <file> [--other-image-offset 0x... [--other-image-length N]]
rampage carve   <file> [--max-candidates N]  # embedded executables/archives by validated header; extracts nothing
rampage dotnet  <file> [--list types|pinvokes|attributes] [--contains TEXT]  # .NET metadata, one list per page
rampage dotnet  <file> --il <token|Type::Name> [--at IL_0042 | --offset N]  # one method's CIL, a page at a time
rampage triage  <file>                       # hashes, entropy, format details, overlay, packing hints
rampage detect  <file> [--peid <userdb.txt>]  # producing packer/compiler/...; warns on skipped PeID entries
rampage yara    <file> [--rules <file|dir>]   # user-supplied and data-pack YARA rules (embedded yara-x)
rampage capa    <file> [--rules <dir>]        # user and data-pack Mandiant capa rules (file-scope subset)
rampage packs list | check <dir>             # data packs in effect, or validate one pack
rampage capabilities <file>                   # built-in corroborated behavior indicators
rampage audit   <file>                       # bounded decode coverage and unreliable-code evidence
rampage metadata <file>                      # demangled symbols, named RTTI/vtables, ObjC selectors
rampage inventory <directory>                # binaries in bundles/extracted packages; no execution
rampage decompile <file> --at <addr|symbol>   # decompile a function to C (embedded Ghidra decompiler)
rampage decompile <file> --at main --isolated # require supervised native execution
rampage debug-types <file> [--apply]          # preview/import bounded embedded DWARF signatures
rampage summarize <file> --at <addr|symbol>   # CFG/reference summary, not decompiled source
rampage pseudocode <file> --at <addr|symbol>  # partial ARM64 SSA pseudocode with explicit unknowns
rampage compare <file> --reference <json>     # image-matched, versioned function-start comparisons
rampage jump-table <file> --at <addr> --count N # explicit immutable ARM64 table validation
rampage correlate <snapshot> --original <file> --module <uuid> --at <addr> # runtime/image correlation
rampage compare-runtime <snapshot> --original <file> --module <uuid> --range <addr>:<size>
rampage observe-pointer <snapshot> --at <slot> # raw captured value, not a proven call edge
rampage compare-pointers <before> --other <after> --at <slot> --other-at <slot>
rampage observe-indirect-branch <snapshot> --start <addr> --at <branch> # bounded ARM64 slot-load link
rampage info    <file>                       # format, arch, entry, segments, sections
rampage imports <file> [--contains TEXT]     # imported functions, libraries and import slots
rampage exports <file> [--contains TEXT]
rampage disasm  <file> [--at <addr|symbol>] [--count N]
rampage strings <file> [--min-len N]         # ASCII and UTF-16LE
rampage funcs   <file> [--name TEXT]         # recursive-descent function discovery
rampage xrefs   <file> --to|--from <addr|name>
rampage rename  <file> <addr|name> <new name|--clear>
rampage comment <file> <addr|name> <text|--clear>
rampage annotate-batch <file> <entries.json> # [{at, name?, comment?}] as one undo step, all or nothing
rampage check-names <file> <name>...         # valid identifier? address-shaped? already used?
rampage annotations <file>                   # names, comments, signatures, types and globals
rampage mcp [--all-tools]                    # MCP server on stdin/stdout (core tools + enable_tools)

# global flags
--json                 machine-readable output for every command
--arch x86_64|aarch64|arm|...  pick a slice from a universal Mach-O
--image-offset 0x...   open the ELF/PE/Mach-O embedded at this file offset (e.g. a carve candidate) in place; for
                       a universal Mach-O, its fat header's offset with --arch. Rejected by commands that open
                       no image or two (carve, inventory, packs, mcp, correlate, compare-*); report diff-builds
                       takes it for <file> and --other-image-offset/--other-image-length for --other
--image-length N       with --image-offset, the image's length: bytes past its header extent become its overlay
--pack <dir>           layer a data pack over the bundled heuristic databases (repeatable; see Data packs)
```

`--rules` is optional for `yara` and `capa` when a data pack holds rules of that kind. YARA `include` statements
are refused in every rule set (yours, packs' and agents'): each rule file must stand alone.

Addresses accept `0x` hex, decimal, symbol and export names, or `sub_<hex>`. In JSON output every address is
a `"0x…"` string, because JSON numbers lose precision above 2^53 in common consumers.

Names, comments and typed annotations are saved beside ordinary binaries in `<file>.rampage`
(`<file>.<arch>.rampage` for a slice of a universal binary; `<file>@0x<offset>[+0x<length>].rampage-image` for an
image opened with `--image-offset`, or `image_offset` over MCP): an append-only JSON Lines log of edits, each
recording the value it replaced, so undo is just another edit and the file is a full history. A batch is written
under a header line and replayed only once all of its edits are present. Several clients can share it: the UI
picks up names an agent saves through MCP within a second. The UI opens whole files and universal-binary slices,
not embedded images, so an embedded image's annotations are shared by the CLI and MCP only.
Edits follow a line naming the SHA-256 of the image they were made on; when the binary beside the log is rebuilt or
replaced, its annotations still apply by address, with a warning (in the binary's warnings and `list_annotations`)
that some were made on another image. Logs written before identity lines carry a note until the next edit. Replace a
binary by renaming a new file over it rather than truncating it in place: it is memory-mapped while open.
Snapshot annotations use a capture-identity log instead, sharing edits only across equal analysis identities
in the same directory by default. Legacy unscoped snapshot logs are not automatically loaded or migrated;
see [runtime snapshots](docs/runtime-snapshots.md) for persistence and explicit cross-directory reuse.

## Data packs

A data pack is a directory that extends the heuristic databases with data only: nothing is downloaded or run.
Load packs with `--pack <dir>` (repeatable) or `RAMPAGE_PACKS` (a platform path list, loaded after the flags); a
directory given twice loads once. `rampage packs list` shows the packs in effect, in precedence order, with each
content's status; `rampage packs check <dir>` validates one pack and fails when anything in it does not load. Over
MCP, `list_packs` (detection group) does the same, and detection results carry the pack problems bearing on them
in `warnings`. Packs load on first use, so commands that consult no database never read them.

Each pack holds a `rampage-pack.toml`; unknown fields are rejected:

```toml
name = "acme-sdk"                 # letters, digits, -, _ and .; not rampage-builtin or default
version = "1.2.0"
license = "CC-BY-4.0"             # an SPDX expression
source = "https://example.com/acme-sdk"   # provenance
description = "Signatures and rules for the Acme SDK"

[[contents]]
kind = "signatures"               # a database from `rampage signatures` / build_signatures (JSON)
path = "sigs/x86_64.json"
arch = "x86_64"                   # optional, signatures only; must match the database

[[contents]]
kind = "yara"                     # a .yar/.yara file or a directory of them
path = "yara"
```

Kinds: `signatures` (library identification), `peid` (a PeID `userdb.txt` overlaid for tool detection), `yara`
(compiled in a namespace named after the pack), `capa` (a capa rule file or directory tree) and `constants`
(accepted, but reported as unsupported: the crypto-constant database takes no user data yet). For identification
the first database to name a function wins: a user database (`--db`), then packs in the order given, then the
bundled `rampage-builtin` one; each match names its `source`. PeID, YARA and capa contents all run beside the
bundled and user-supplied ones. Every path must stay inside the pack (symbolic links included), each file is read
once with a size cap and within per-pack and overall budgets, at most 64 packs load, and a content that fails is
reported without keeping the others from loading.

## Desktop UI

```
cargo run --release -p rampage-ui -- <file> [--arch aarch64]
```

An egui app over the same API: docked functions, strings, imports and exports lists, a disassembly listing with
clickable references (or a hex view for data), a control-flow graph view, cross-references, triage, and a navigation
band across the image. Keys: Space listing/graph, G go to, Esc or Alt+Left back, Alt+Right forward, N rename, `;`
comment, Ctrl/Cmd+Z undo, Shift+Ctrl/Cmd+Z redo. Drop a file on the window to open it. Analysis runs in the
background; on Chrome's framework (190,000 functions, 930,000 strings) frames take a few milliseconds. `cargo test
-p rampage-ui` renders the UI offscreen into `crates/rampage-ui/tests/snapshots`.
The Pseudocode tab loads decompilation in the background and navigates inline address-linked tokens.

The Assistant tab talks to Claude about the open binary: the model reads functions, graphs, strings and
cross-references through rampage's tools, renames and comments what it works out, and points the listing at what it
discusses. Set `ANTHROPIC_API_KEY` (and optionally `RAMPAGE_MODEL`) to use it; questions and the code the model reads
are sent to Anthropic's API.

## Using it from an AI agent

`rampage mcp` serves the [Model Context Protocol](https://modelcontextprotocol.io) over stdio. Its tools come in
groups so the list an agent reads stays short:

- `core`: `triage`, `binary_info`, `list_functions`, `disassemble`, `decompile`, `function_graph`,
  `function_summary`, `xrefs`, `list_strings`, `list_imports`, `list_exports`, `rename`, `set_comment`,
  `annotate_batch` (bulk naming), `check_names` (pre-flight), `undo`, `redo`, `discard_undo`, `list_annotations`,
  and the workflows `triage_report`, `find_main`, `network_surface`, `persistence_surface`, `string_decoding`,
  `diff_builds`
- `detection`: `detect_tools`, `identify_functions`, `build_signatures`, `capabilities`, `yara_scan`,
  `capa_detect`, `find_crypto`, `list_packs`
- `types`: `set_signature`, `set_types`, `set_global`, `import_debug_signatures`, `class_evidence`,
  `language_metadata`
- `runtime`: `observe_pointer`, `compare_pointer_observations`, `compare_runtime_bytes`, `observe_indirect_branch`
- `diagnostics`: `analysis_diagnostics`, `inspect_jump_table`
- `dotnet`: `dotnet_metadata`, `dotnet_il`
- `carve`: `carve`

By default the server lists `core` and an `enable_tools` meta-tool: called without arguments it lists every group
with a one-line description and its tools; `{"groups": ["detection"]}` (or `["all"]`) enables groups and sends
`notifications/tools/list_changed`. Calling a tool of a group that is not enabled fails with the group to enable
and runs nothing. For clients that do not refresh their tool list, `rampage mcp --all-tools` lists every group
from the start, and `RAMPAGE_MCP_TOOLS=all` or `RAMPAGE_MCP_TOOLS=detection,types` chooses groups by environment
(`core` is always served). The UI's assistant offers every tool that works on the open binary (all but `carve`
and `list_packs`). Workflow reports name each suggested tool's `group`, so an agent knows which to enable.

`undo` and `redo` revert or reapply one step, which may be a whole batch. When another client's edit blocks undoing a
step, `discard_undo` drops it from the session's undo history, leaving its edits in effect and the log unchanged, so
earlier steps can be undone; it refuses a step undo could still revert unless given `force: true`. `carve` takes any
file path rather than a binary: it pages candidates with `offset`/`limit` and reports `more` instead of a total,
scanning only as far as the candidate after the page. Agents' annotations land in the same log the UI and CLI use, and
the UI shows them as they arrive. Analysis runs once per binary and is cached for the session. `observe_pointer` exposes
captured slot evidence without modifying discovery.
To add it to Claude Code:

```
claude mcp add rampage -- /path/to/rampage mcp
claude mcp add rampage -- /path/to/rampage mcp --all-tools   # every group, for clients without list_changed
```

## Performance

On the Chrome framework (stripped), on an M1 Max, `funcs` discovers 176,480 functions and 14.5 million
instructions in the x86_64 slice in about 1.2 s, and 186,252 functions and 13.8 million instructions in the
arm64 slice in about 1.4 s. Repeated MCP queries are answered from the cached analysis in milliseconds.

## Layout

| Crate | Purpose |
|---|---|
| `rampage-loaders` | Memory-mapped PE/ELF/Mach-O loading and address-based reads |
| `rampage-arch` | Instruction decoding with control-flow classification |
| `rampage-analysis` | String scanning, recursive-descent function discovery, cross-references |
| `rampage-api` | Session and query layer shared by every client |
| `rampage-mcp` | MCP server |
| `rampage-cli` | The `rampage` binary |
| `rampage-ui` | The desktop UI |
| `rampage-decompiler` | Embedded native engine, specifications and supervised protocol |
| `rampage-worker` | Isolated native decompiler process |

`tools/armgen` regenerates the decoder tables from an AARCHMRS release, one instruction set at a time:
`cargo run --release -p armgen -- <AARCHMRS directory> A64 crates/rampage-arch/src/a64/spec.rs`.

Test fixtures live in `tests/fixtures`; `tests/fixtures/build.sh` rebuilds them (needs zig and Apple clang).
`tools/install.sh [ROOT] [--ui]` builds the worker and CLI before installing them together.
The [corpus runner](docs/decompiler-corpus.md) measures selected recovered facts and resource diagnostics;
passing fixture assertions is not IDA/Ghidra parity or semantic equivalence.

Runtime images use a validated sparse JSON snapshot with virtual addresses, explicit seeds and provenance.
The same CLI, UI and MCP tools open snapshots and bundle directories. See
[runtime snapshots](docs/runtime-snapshots.md) for the read-only LLDB exporter and format limits.
On AArch64, known ADR/ADRP/ADD/MOV/LDR values can resolve BR/BLR targets through readable, non-writable pointers.
This does not resolve authenticated pointers or replace a debugger/decompiler. `function_summary` exposes
the decoded graph, paginated references and partial typed AArch64 IR to tools, explicitly as a structural
summary rather than recovered source. Bounded register/memory SSA exposes predecessor-indexed phi nodes and
32-bit result truncation. Unsupported instruction semantics are explicit barriers, not inferred no-ops.
The [ARM64 development track](docs/arm64-development.md) records native semantics validation and remaining gates.

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The decompiler embeds Ghidra (Apache-2.0), and the
AArch64/AArch32 decoder tables are generated from Arm's machine-readable architecture specification, which Arm
licenses under the BSD 3-clause license (see `crates/rampage-arch/src/a64/LICENSE-ARM`).
