# CLI reference

The primary CLI uses noun/verb routes. Existing flat spellings remain accepted as hidden compatibility
commands; routing does not change analysis behavior, output, annotations or MCP tool names. Use
`rampage --help`, `rampage <noun> --help` or `rampage <noun> <verb> --help` for the parser's full option list.

In the catalog, routes and compatibility spellings follow `rampage`. `FILE` is the image to open, `DIR` a
directory, and `ADDRESS` an address or supported name. Brackets describe optional arguments, not literal input.

## Binary queries and scans

| Primary route and operands | Compatibility spelling | Result |
| --- | --- | --- |
| `binary inspect FILE` | `info FILE` | Format, architecture, entry, segments and sections |
| `binary triage FILE` | `triage FILE` | Hashes, entropy, format details, overlay and hints |
| `binary analyze FILE` | `analyze FILE` | Bounded multi-slice workflow/decompilation report |
| `binary detect FILE [--peid userdb.txt]` | `detect` | Producing toolchain/packer evidence |
| `binary capabilities FILE` | `capabilities` | Corroborated behavior indicators, not proof |
| `binary audit FILE [--include-discovery]` | `audit` | Bounded decode coverage and unreliable-code evidence |
| `binary carve FILE [--max-candidates N]` | `carve` | Validated embedded headers; no extraction/decompression |
| `binary inventory DIR` | `inventory` | Binaries in bundles/extracted packages; no execution |
| `binary list-imports FILE [--contains TEXT]` | `imports` | Imports, libraries and import slots |
| `binary list-exports FILE [--contains TEXT]` | `exports` | Exported symbols |
| `binary scan-yara FILE [--rules FILE_OR_DIR]` | `yara` | Embedded yara-x rule scan |
| `binary scan-capa FILE [--rules DIR]` | `capa` | Mandiant capa file-scope feature subset |

Compatibility entries showing only a command name take the same operands and flags as the primary route.
`--rules` is optional when a [data pack](data-packs.md) supplies that kind of rule. YARA `include` statements
are refused in every rule set, including user files, packs and agent-supplied rules; each file must stand alone.
`carve` accepts 1–4096 candidates. Header-estimated extents do not establish that a whole container is valid.

See [CLI batch analysis](cli-analysis.md) for `analyze` task selection, limits, worker requirements and exit
behavior. Its flat examples remain compatible:

```sh
rampage binary analyze module.dylib --all-architectures --workflow triage-report \
  --function exported_entry --json
```

## Functions, strings and language metadata

| Primary route and operands | Compatibility spelling | Result |
| --- | --- | --- |
| `function list FILE [--name TEXT] [--symbols-only]` | `funcs` | Recursive-descent functions, or symbols only |
| `function disassemble FILE [--at ADDRESS] [--count N]` | `disasm` | Instructions; defaults to the entry point |
| `function decompile FILE --at ADDRESS [--isolated]` | `decompile` | Embedded Ghidra C and recovery diagnostics |
| `function summarize FILE --at ADDRESS` | `summarize` | Structural CFG/reference summary, not recovered source |
| `function pseudocode FILE --at ADDRESS [--structured]` | `pseudocode` | Partial ARM64 SSA with explicit unknowns |
| `function xrefs FILE --to ADDRESS` or `--from ADDRESS` | `xrefs` | Code/data references; exactly one direction |
| `function identify FILE [--db DB] [--apply]` | `identify` | Library signature matches; optionally save names |
| `function build-signatures FILE [--output DB]` | `signatures` | JSON database from named functions |
| `function compare FILE --reference JSON` | `compare` | Versioned, image-matched function-start comparison |
| `function inspect-table FILE --at ADDRESS --count N` | `jump-table` | Explicit immutable ARM64 table validation |
| `string list FILE [--min-len N] [--contains TEXT]` | `strings` | ASCII and UTF-16LE strings; minimum defaults to 4 |
| `language inspect FILE` | `metadata` | Demangled symbols, named RTTI/vtables and ObjC metadata |

Noun labels do not narrow the queries: disassembly is not function-bounded, and xrefs can name data or an
instruction. `compare` compares function starts, not decompiled semantics. The hidden `export-cfg FILE`
benchmark action remains accepted; see [benchmarks](benchmarks.md) rather than treating it as an interactive query.

`decompile --compiler ID` overrides the format-selected Ghidra compiler ID. Sessions select a sibling worker
when present; `--isolated` requires supervision explicitly. See the
[decompiler reference](../crates/rampage-decompiler/README.md) for engine limits and recovery status.
`identify --no-bundled` requires a user database or a matching pack database. `build-signatures` defaults to
stdout; identification defaults to the bundled starter database. See
[library identification](features.md#library-identification).
`inspect-table --relative-base ADDRESS` selects signed-relative32 rather than absolute64 entries.

## Managed code

| Primary route | Compatibility spelling |
| --- | --- |
| `managed inspect FILE [--list types\|pinvokes\|attributes]` | `dotnet FILE` with metadata options |
| `managed disassemble FILE --il METHOD` | `dotnet FILE --il METHOD` |

Metadata pages default to `types`. `--contains TEXT` filters names/targets; `--parent-token TOKEN` filters
attribute targets with `--list attributes`. `--offset N` skips list entries and `--limit N` selects the page
size (default 100). Types include fields, method/property signatures, accessor tokens and IL body sizes;
P/Invokes include DLL/export bindings. Supported attribute values and bounded decoding limits are described in
[managed assemblies](features.md#managed-assemblies). Accessor tokens are metadata bindings, not inferred behavior.

`METHOD` accepts a MethodDef token such as `0x0600000d` or `Namespace.Type::Name`; ambiguous overloaded names
report their tokens/signatures. IL output resolves tokens, strings, branches/switches, locals and exception
clauses. In IL mode `--offset N` counts instructions; `--at IL_0042` (also `0x42` or decimal) instead starts at
the instruction containing that IL offset. CIL is never passed to native disassembly/decompilation.

`managed inspect` rejects `--il`; `managed disassemble` requires it. Explicit `--list` conflicts with `--il`,
which also conflicts with `--contains`/`--parent-token`. IL `--at` requires `--il` and conflicts with explicit
`--offset`. The compatibility `dotnet` command retains both modes with the same option validation.

## Annotations and debug types

| Primary route and operands | Compatibility spelling |
| --- | --- |
| `annotation list FILE` | `annotations` |
| `annotation rename FILE ADDRESS NAME` or `--clear` | `rename` |
| `annotation comment FILE ADDRESS TEXT` or `--clear` | `comment` |
| `annotation apply-batch FILE entries.json` | `annotate-batch` |
| `annotation check-names FILE NAME...` | `check-names` |
| `type import-debug FILE [--apply]` | `debug-types` |

Rename/comment take positional operands, not `--at`. `--clear` replaces the new name/text operand and cannot
be combined with it. A batch is a JSON array of `{at, name?, comment?}` entries, at most 1000, applied all or
nothing as one undo step. `check-names` checks identifier validity, address-shaped names and existing use.
Debug import previews bounded embedded DWARF scalar/pointer signatures unless `--apply` is explicit; it does
not replace analyst signatures. See [debug signature import](debug-signatures.md).

### Persistence and shared edits

Names, comments, signatures, types and globals use an append-only JSON Lines log. Ordinary files use
`<file>.rampage`; universal slices use `<file>.<arch>.rampage`. Embedded views use
`<file>@0x<offset>[+0x<length>].rampage-image`, separate from the outer file's annotations. CLI, MCP and UI
clients opening the same view share its edits; the UI refreshes external annotations within about a second.

Each edit records its replaced value; undo is another edit, leaving a full history. A batch is stored under
a header and replayed only once all its edits are present. Typed edits participate in dependency-checked undo/redo.
MCP and UI provide undo/redo; the CLI has no separate undo verb. See
[MCP undo behavior](mcp.md#edits-and-session-state).

An image-identity line records SHA-256. When a binary is rebuilt/replaced, old edits still apply by address but
produce identity-mismatch warnings in binary warnings and `list_annotations`. Logs predating identity lines
carry a note until the next edit. Replace an open binary by renaming a new file over it rather than truncating
in place: binaries are memory-mapped while open.

Snapshots instead use capture-identity logs, sharing edits only across equal analysis identities in the same
directory by default. Legacy unscoped snapshot logs are not automatically loaded or migrated. See
[runtime snapshots](runtime-snapshots.md) for persistence and explicit cross-directory reuse.

## Captured runtime evidence

Live read-only debugger queries use `runtime debugger query --socket PATH --request JSON` without an image
operand. They require an operator-started local endpoint in an authorized stopped LLDB session, not attachment
or execution control. See the [LLDB protocol and local transport](lldb-query.md).

| Primary route and operands | Compatibility spelling |
| --- | --- |
| `runtime pointer observe SNAPSHOT --at SLOT` | `observe-pointer` |
| `runtime pointer compare BEFORE --other AFTER --at SLOT --other-at SLOT` | `compare-pointers` |
| `runtime branch inspect SNAPSHOT --start ADDRESS --at BRANCH` | `observe-indirect-branch` |
| `runtime bytes compare SNAPSHOT --original FILE --module UUID --range ADDRESS:SIZE` | `compare-runtime` |
| `runtime module correlate SNAPSHOT --original FILE --module UUID --at ADDRESS` | `correlate` |

Runtime comparison/branch windows require explicit hexadecimal addresses. `--range` is repeatable. Pointer
observations do not change discovery or prove a call edge; comparison does not independently establish time
ordering or slot correspondence. Branch inspection links a captured ARM64 branch to a slot load in a bounded
window. Byte/module correlation uses an explicit UUID-matched original Mach-O, without annotation transfer.
See [runtime snapshots](runtime-snapshots.md) and the separate [read-only LLDB query bridge](lldb-query.md).

## Workflows, packs and serving

| Primary route | Compatibility spelling |
| --- | --- |
| `workflow run WORKFLOW FILE` | `report WORKFLOW FILE` |
| `pack list` / `pack check DIR` | `packs list` / `packs check DIR` |
| `server serve [--all-tools]` | `mcp [--all-tools]` |

Registered workflows are `triage-report`, `find-main`, `network-surface`, `find-crypto`, `persistence-surface`,
`string-decoding` and `diff-builds`. Reports retain evidence, confidence, limits and suggested next tools.
`--limit N` caps findings per section (default 25, maximum 200); `--no-decompile` skips find-main's preview.
`diff-builds` requires `--other FILE`; `--other-image-offset OFFSET` and `--other-image-length N` select an
embedded second image. These second-input options are rejected for workflows that do not compare images.
See [data packs](data-packs.md), [MCP](mcp.md) and the [internal workflow registry](plugins.md).

## Global options and addresses

- `--json`: machine-readable query output. MCP serving uses its protocol, not the CLI text/JSON renderer.
- `--arch ARCH`: selects a universal Mach-O slice, e.g. `x86_64`, `aarch64` or `arm`.
- `--image-offset OFFSET`: opens an embedded ELF/PE/Mach-O in place; hex `0x...` or decimal. For a universal
  Mach-O this is the fat header's offset; use `--arch` for its slice. Offset 0 without a length opens the file itself.
- `--image-length N`: requires `--image-offset`. It selects the embedded extent; bytes after the executable's
  header-derived extent within that selection can become its overlay. Without a length, those bytes are excluded.
- `--pack DIR`: repeatable data-pack layers; directories from `RAMPAGE_PACKS` load afterward.

JSON, architecture and image options can appear before or after command names; packs can be supplied at route
levels in precedence order. Embedded-image options are rejected by `carve`, `inventory`, pack commands,
MCP serving and runtime correlation/comparison actions that do not open a single image. `function compare`
does accept an embedded view. `diff-builds` applies the global image selection to its first input only;
use its `--other-image-*` options for the second. MCP tools take `image_offset`/`image_length` per call instead.

Native addresses accept `0x` hex, decimal, symbols/exports/import stubs or `sub_<hex>`, except explicit runtime
comparison slots/ranges and branch windows. JSON addresses are `"0x…"` strings: common consumers lose integer
precision above 2^53. Managed `--at` is an IL offset, not a native address.
