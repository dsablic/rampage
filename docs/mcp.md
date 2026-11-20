# MCP reference

`rampage server serve` (compatibility spelling `rampage mcp`) serves the
[Model Context Protocol](https://modelcontextprotocol.io) over stdin/stdout. The MCP server is rampage's main
interface: every capability is an MCP tool first, and the CLI and desktop UI share the same API. No API key is
needed for local serving; the AI client controls its own model and provider connection.

This page is organised from overview to detail:

- [Connect a client](#connect-a-client) and [server options](#server-options).
- [Tool groups](#tool-groups): the catalog of every tool, by group.
- [Flywheel (improve)](#flywheel-improve): the restricted server for the experimental flywheel.
- [Inputs, paging and decompiler tokens](#inputs-paging-and-decompiler-tokens): addresses, size caps, paging and
  per-tool notes.
- [Raw projects](#raw-projects): headerless code through Sleigh processor profiles and the Cortex-M profile.
- [Edits and session state](#edits-and-session-state): annotations, undo, batches and the findings ledger.
- [Authorization and data disclosure](#authorization-and-data-disclosure).
- [For contributors](#for-contributors): the instruction size budget and how agent benchmarks drive the server.

For a guided first session, see [getting started](getting-started.md).

## Connect a client

With the built CLI on `PATH`, add rampage to Claude Code:

```sh
claude mcp add rampage -- rampage server serve
```

This uses Claude Code's default `local` scope, which applies only in the directory where you ran it. To make
rampage available in every project, add it with user scope instead (the `--scope` option goes before the server
name):

```sh
claude mcp add --scope user rampage -- rampage server serve
```

For other clients, a JSON `mcpServers` entry:

```json
{
  "mcpServers": {
    "rampage": {
      "command": "rampage",
      "args": ["server", "serve"]
    }
  }
}
```

An absolute path to the installed CLI can replace `rampage`. For clients that do not refresh their tool list, add
`--all-tools` (`claude mcp add rampage -- rampage server serve --all-tools`).

### Agents, subagents and scripted sessions

An agent can only call rampage's tools if its session started the server. When an agent falls back to the
`rampage` CLI or to shell scripts, check these in order:

- **Registration scope.** Run `claude mcp list` in the directory where the agent runs. A `local` registration
  applies only to the directory it was added in. Register with `--scope user` for every directory, or with
  `--scope project` to write a `.mcp.json` that the repository shares (Claude Code asks once before it starts
  project servers).
- **Subagents.** Subagents use the MCP servers of the session that starts them. A custom subagent that lists
  `tools` in its definition gets only those tools, so add the `mcp__rampage__…` names it needs, or omit `tools` so
  it inherits every tool.
- **Scripted sessions.** `claude -p` loads the servers registered for its working directory. Pass
  `--mcp-config FILE` to name the server explicitly, and `--strict-mcp-config` to ignore every other server. An
  `--allowedTools` list must include `mcp__rampage__*`, and `ToolSearch` when the client defers MCP tool schemas.
  `tools/agent-bench/claude-runner.py` builds such a command.
- **Startup.** `rampage server serve` must start from the agent's environment: `rampage` on `PATH` (or an absolute
  `command`) and the worker beside it. The server writes start-up warnings to stderr; `/mcp` shows a server that
  failed to start.

Install `rampage-worker` beside `rampage` (as `tools/install.sh` does), or name it with `RAMPAGE_WORKER`.
Decompilation then runs in that supervised worker process, with time, memory and output limits. **Without a
worker, decompilation runs in-process**, inside the server itself. The server warns on stderr at startup when it
finds no worker, and every `decompile` result says where it ran in its `decompiler` field: `supervised` or
`in-process`. If you analyse hostile files, start the server with `--require-worker` so that `decompile` refuses
instead of running in-process. Supervision bounds resources; it is not an OS sandbox.

## Server options

| Option | Effect |
| --- | --- |
| `--all-tools` | List every tool group at startup instead of `core` alone. `RAMPAGE_MCP_TOOLS=all` or a list such as `detection,types` also selects startup groups. |
| `--pack DIR` | Load a [data pack](data-packs.md); repeatable. `RAMPAGE_PACKS` adds more. |
| `--debug-endpoint ENDPOINT` | Allow the `debug` tools to connect to an operator-started stub; repeatable. See [debug control](debug-control.md#consent). |
| `--debug-writes`, `--debug-kill` | Also allow target memory and register writes, and kill. |
| `--require-worker` | Decompile only in the supervised `rampage-worker`: without one, `decompile` refuses instead of running in-process. |
| `--observations DIR` | Serve `report_observation`, recording into DIR (*experimental*). |
| `--corpus DIR` and the `--flywheel-*`, `--gate`, `--require-novel-gain` options | Serve only the `improve` group over a flywheel corpus (*experimental*); see [the flywheel](flywheel.md). |

## Tool groups

By default the server lists `core` plus `enable_tools`, keeping the initial tool list short. Read-only inspectors
that answer common first questions, such as `language_metadata` and `class_evidence` for class names and
hierarchies, are in `core` so that a client deferring schemas still sees their names.

A default session lists 48 tools: the 47 in `core` plus `enable_tools`. Enabling every group lists 106. The
`debug` group adds 14 tools (16 with `--debug-writes`), `--observations` adds `report_observation`, and a
`--corpus` server lists `enable_tools` and the 4 `improve` tools only.

- `core`: `triage`, `binary_info`, `list_functions`, `disassemble`, `decompile`, `evaluate_function`,
  `check_claim`, `function_graph`,
  `assemble`, `patch_bytes`, `revert_patch`, `list_patches`, `export_patched`,
  `function_summary`, `xrefs`, `search`, `list_strings`, `list_imports`, `list_exports`, `rename`, `set_comment`,
  `annotate_batch`, `batch`, `check_names`, `undo`, `redo`, `discard_undo`, `list_annotations`, `record_finding`,
  `list_findings`, `transfer_annotations`, `triage_report`,
  `find_main`, `network_surface`, `persistence_surface`, `string_decoding`, `diff_builds`, `inspect_data`,
  `list_dir`, `decode_file_range`, `probe_compression`, `file_layout`, `inspect_raw_code`, `inspect_sleigh`,
  `language_metadata`,
  `objc_sends`, `class_evidence`; with --observations (or RAMPAGE_OBSERVATIONS), also `report_observation`.
- `detection`: `detect_tools`, `identify_functions`, `build_signatures`, `capabilities`, `yara_scan`,
  `capa_detect`, `find_crypto`, `list_packs`, `lock_mechanisms`.
- `types`: `set_signature`, `set_types`, `set_global`, `import_debug_signatures`, `import_debug_layouts`,
  `import_pdb_names`, `edit_variable`, `declare_types`, `list_types`, `get_type`, `delete_type`, `apply_data_type`,
  `read_data`, `apply_enum`, `apply_offset`, `function_frame`, `propagate_types`, `import_debug_types`,
  `import_svd`, `peripheral_access`.
- `runtime`: `observe_pointer`, `compare_pointer_observations`, `compare_runtime_bytes`, `observe_indirect_branch`,
  `query_debugger`.
- `diagnostics`: `analysis_diagnostics`, `entry_diagnostics`, `inspect_jump_table`.
- `dotnet`: `dotnet_metadata`, `dotnet_il`.
- `android`: `dex_metadata`, `dex_code` ([Android APKs and DEX](android.md)).
- `carve`: `carve`, `archive_inventory`, `fs_list`, `fs_extract`, `write_decoded_range`, `endpoint_inventory`,
  `endpoint_blocklist`, `privacy_surface`, `diff_firmware`.
- `formats`: `build_info`, `pe_resources`, `pe_load_config`, `exception_handlers`, `pyinstaller_archive`,
  `wasm_module`, `integrity_checks`, `export_image`.
- `debug`, only on a server started with a debug endpoint: `debug_connect`, `debug_bind`, `debug_status`,
  `debug_registers`, `debug_read_memory`, `debug_modules`, `debug_snapshot`, `debug_continue`, `debug_wait`,
  `debug_interrupt`, `debug_step`, `debug_breakpoints`, `debug_evidence`, `debug_disconnect`; with the
  --debug-writes flag, also `debug_write_memory` and `debug_write_register`.
- `improve`, only on a server started with --corpus, which then serves this group alone: `corpus_failures`,
  `propose_heuristic`, `evaluate_candidate`, `promote_candidate`.

Calling `enable_tools` without arguments lists each group's description, tool names/count and enabled state.
`{"groups": ["detection"]}` enables that group; `{"groups": ["all"]}` enables every group. Enabling sends
`notifications/tools/list_changed`. A call to a disabled group's tool fails with the group to enable and runs
nothing. `--all-tools` lists all groups at startup; `RAMPAGE_MCP_TOOLS=all` or a comma-separated list such as
`detection,types` also selects startup groups. `core` is always served. The `debug` group exists only on a server
started with an allowed debug endpoint, and its write tools and `kill` argument only with the operator's
`--debug-writes` and `--debug-kill`; the flags and variables are in [debug control](debug-control.md#consent).
The `improve` group exists only on a server started with `--corpus DIR`, which then serves `enable_tools` and the
improve group alone; see [the flywheel](#flywheel-improve).

Workflow reports name the `group` of suggested next tools. The [desktop assistant](desktop-ui.md) uses the same
tools without group gating, plus the interactive `show_address`, which is not an MCP tool because the server has
no listing to navigate. It does not offer the file tools (`carve`, `archive_inventory`, `fs_list`, `fs_extract`,
`write_decoded_range`, `endpoint_inventory`, `endpoint_blocklist`, `diff_firmware`, `dex_metadata`, `dex_code`,
`list_packs`, `query_debugger`, `list_dir`, `inspect_data`, `decode_file_range`, `probe_compression`, `file_layout`,
`inspect_raw_code`, `inspect_sleigh`, `pyinstaller_archive`, `wasm_module`) or the `debug` tools.

File tools that only read the files they name (`list_dir`, `carve`, `fs_list`, `file_layout`, `decode_file_range`,
`probe_compression`, `archive_inventory`, `endpoint_inventory`, `diff_firmware`, `dex_metadata`, `dex_code`,
`inspect_data`, `inspect_raw_code`, `inspect_sleigh`, `pyinstaller_archive`, `wasm_module`, `list_packs`) carry the
MCP read-only annotation (`diff_firmware` writes only to a private scratch directory it removes) and are closed-world; `query_debugger` is read-only and open-world. `fs_extract` and
`write_decoded_range` are marked as writing new files, and `endpoint_blocklist` as replacing the file it names.
The `debug` tools' annotations are described with those tools below.

## Flywheel (improve)

`rampage server serve --corpus target/flywheel/corpus/<version>` starts a server for the flywheel ([how-to](flywheel.md)),
through which an agent improves rampage's library-identification signatures on a prebuilt corpus.

**What the server exposes.** It serves `enable_tools` and the `improve` group, and nothing else: no analysis tool,
and no other group can be enabled. Every tool argument naming a file under the corpus or the flywheel directory is
refused, so a proposer cannot open a corpus binary or its symbolized twin.

**What it hides.** The corpus holds target libraries in an older version (training) and their current version
(held out), plus negative binaries. No tool returns a held-out binary, function, name or truth:
`corpus_failures` serves the training split only, and the held-out gate returns its verdict and the overall
delta only.

- `corpus_failures`: target-library training failures and false names, grouped by masked function body (same
  architecture, length and fixed bytes). Each group has occurrences, truth names, configurations, an example and
  `masked_bytes` (`..` for position-dependent bytes). Filters: `arch`, `compiler`, `opt`, `library`, `origin`,
  `outcome`, `name_contains` and `min_occurrences`. Results are paged with `offset`/`limit` and fitted to the result
  size.
- `propose_heuristic`: adds rows to a scratch candidate under `target/flywheel/scratch/libid/<id>/`, a directory
  that is an ordinary data pack.
  - Each row is a whole-function PAT pattern with a name and an optional library tag, taken from a `case` or given
    as `pattern` and `arch`, with optional extra `wildcards`.
  - Rows are schema-checked and must be at least 32 bytes.
  - Each added row comes back with a training-split preview.
- `evaluate_candidate`: evaluates the candidate merged with the promoted rows, against the current state.
  - `stage: "fast"` checks the full training split for new false positives and the negatives for any name, and
    returns the fast slice's deltas and changed cases plus the names given on negatives.
  - `stage: "heldout"` returns pass/fail and the overall delta only.
  - Results are cached by (candidate hash, corpus identity, baseline hash).
  - Held-out evaluations per corpus are capped across all servers (`max_heldout_evaluations`).
- `promote_candidate`: refused without a passing held-out result for the same candidate hash, corpus identity
  and baseline. It writes the rows with their provenance to `target/flywheel/promoted/libid/` and returns a revert
  id (`rampage-eval flywheel-revert <id>`, latest first).
- `report_observation` (core, ordinary servers with `--observations` only): records a typed, evidence-backed
  observation in the local, opt-in observation store, as a weak label. Nothing is renamed, annotated or promoted.

Errors from these tools are JSON objects: `{"error": kind, "message": text}`. `kind` is one of
`invalid_argument`, `not_found`, `refused`, `corpus` or `io`.

## Inputs, paging and decompiler tokens

Binary tools take `path`, optional `arch`, and optional `image_offset`/`image_length` to open an embedded view.
`image_offset` is not the paging `offset`. `arch` picks a universal Mach-O's slice (default x86_64, then aarch64,
then x86). `image_offset` (hex `"0x..."` or decimal) opens the ELF, PE or Mach-O image embedded there, such as a
`carve` candidate, with its annotations kept apart from the outer file's; for a universal Mach-O embedded in a larger
file give its fat header's offset with `arch` for the slice; offset 0 without `image_length` is the file itself.
`image_length` defaults to the extent the image's header tables give, which leaves out any overlay after it.
Native addresses are hexadecimal strings; most queries also accept
symbols, exports, import-stub names and `sub_<hex>`. Runtime comparison slots/ranges and branch windows require
explicit hexadecimal addresses. See [CLI global options](cli-reference.md#global-options-and-addresses).

List queries use `offset`/`limit`, generally defaulting to 100 entries and capped at 1000. `list_functions`
filters with `name_contains`; strings/imports/exports filter with `contains`. Disassembly counts are capped at
1000. Large ordinary binary-tool results can be truncated after 60,000 UTF-8 bytes with an added text marker;
workflow reports shrink to remain valid JSON and retain limitations. Page or narrow a query rather than
assuming a large response is complete. Every tool declares `_meta["anthropic/maxResultSizeChars"]` = 61,024 (the
60,000-byte cap plus room for the marker), so Claude Code shows such a page whole instead of a 50,000-character preview.

Project and file tools refuse an argument their schema does not list, and a missing required one, before
running anything, over MCP and in the agent and desktop assistant alike. The one-line error names the tool's
arguments, marks the required ones, and suggests the likely intended name for a habitual one (`address` for
`at`, `length` for `count` or `size`, `query` for `mode` or `contains`), so a client calling before it has
loaded a schema can correct the call at once; at most 8 unknown names are listed, the rest counted. Debug tools
refuse unknown arguments through their own parsing, without the argument list. The CLI builds its own inputs.

`entry_diagnostics` can report ARM ELF32 EHABI candidates under its `function_starts` origin. These
are metadata assertions, not verified boundaries; `CantUnwind` and coalesced interiors are not expanded. See
[ARM unwind candidates](arm-unwind-starts.md).

`identify_functions` takes JSON database inputs and is read-only by default. Its default detail window is 100
rows (`limit` 1–256); `offset` continues matches first, then warnings. `matched`/`applied` are whole-result totals:
pages never select writes. Complete JSON stays within 60000 bytes; an oversized row refuses before any rename.
Builtin signatures are cached per architecture; `list_packs` reads count indexes without decoding every bundle.
Firmware (a Cortex-M Raw project, or a static Thumb ELF executable) also gets the
[embedded firmware set](signature-corpus.md#embedded-firmware-set) (newlib, libgcc, compiler-rt, FreeRTOS, STM32F4
HAL), source `rampage-builtin embedded`. A Cortex-M Raw project's `raw` selector is accepted, with applied names
memory-only like its other annotations.
The [offline corpus pipeline](signature-corpus.md) measures generated databases separately; its failed or unrun
profiles are not default recognition coverage.

`import_debug_types` reviews embedded-DWARF or explicitly selected identity-matched PDB types into the project
library, independently checking retained producer constraints against native measurements. Whole-plan review
hashes bind atomic library/proof/signature edits; pages do not select writes. Unknown producer alignment and
unsupported bitfields/qualifiers remain explicit. See [checked debug-type import](debug-types.md).

`import_svd` previews, or with `apply: true` stores, a CMSIS-SVD file's peripherals as annotations, replacing an
earlier import in one undo step. Decompiled register accesses are volatile and read `TIMER0.CR = uVar1 | 0x21;` with a
bit-field comment (`/* CR: EN|MODE=Single_MATCH */`); disassembly, xref rows and `evaluate_function` faults name
`PERIPHERAL.REGISTER`; those names resolve as addresses; `xrefs` to a peripheral's name covers all its registers;
and `evaluate_function` takes `mmio` values for polled registers. `peripheral_access` pages peripherals with
access counts, or one peripheral's registers with bit fields and accessing functions. Limits: accesses are found
only through constants a function forms itself. See [peripheral maps](peripheral-maps.md).

`integrity_checks` (group `formats`) finds checksum, CRC and digest fields and the ranges they cover in the
original image, by bounded brute force, CRC code evidence and, with `emulate` (default), the image's own routine
run on the range; each check reports stored and computed values on the patched image, evidence and confidence.
`fix: true` with the receipt's tokens writes corrected values as patch records in dependency order, by default
only for checks confirmed by emulation or referenced by code (others by `ids`).
`export_image` writes the patched image to a new file in its original container (HEX/S-record records, the binary
file, the native file with an optional PE CheckSum) or as a flat binary. Both take `raw`, as do the patch tools
except `export_patched`. Limits: one contiguous range per check; 256 MiB of hashing per search. See
[firmware patching](firmware-patching.md).

Xtensa code names a CRC routine by the polynomial literal its `l32r` loads.

MIPS code names a CRC routine by the polynomial it builds with `lui` and `ori`/`addiu`, or by a CRC-16
polynomial as an instruction's immediate (`xori $v0, $v0, 0xa001`) in a function that also shifts by one bit and
XORs, as a bitwise CRC loop does.

On a Raw project the CRC code evidence comes from the discovered functions (pointer tables and scatter-load copies
included); on Cortex-M a polynomial literal that no discovered code references is followed to the PC-relative
`ldr` that loads it (within 4 KiB, either side), and the routine around it is listed with `inferred_range`: from
the nearest `push {..., lr}` whose instructions lead to the load to the first return after the load, which may end
early when the routine returns from several places. When a session opens a Cortex-M Raw project with `pointer_tables`
unset (discovery then runs at open; an explicit `pointer_tables` keeps it lazy), it looks for such routines after
discovery and, when it finds any, reopens the same interpretation with their starts as further
seeds (at most 16), so they are functions that `lock_mechanisms`, `decompile` and `integrity_checks` see.
A routine outside every discovered function that calls such a routine with a Thumb `bl` (inside a `push {..., lr}`
routine that decodes cleanly) is seeded with it, and its own callers likewise, three rounds deep, so `xrefs` to
the CRC routine shows the code that checks with it.
`binary_info` lists them in `raw.inferred_seeds` (`address`, `reason` with the polynomial, literal slot, load
and prologue, or the `bl` a caller makes); a reopen that is refused keeps the first project. The seeded project also answers a request that
states those seeds. On a Raw project mapped over a container file, a compressed stream behind a record (within 64 bytes before
it: its compressed length, its decoded size, and a byte sum of the compressed bytes or a word holding the stream's
own file offset) is listed in `container_streams`: offsets, sizes, `checksum` (whether a record word is the byte sum or CRC-32 of the
compressed bytes; that word is then the check `check`, with its range and stored value at mapped addresses),
`decode_check` (the classic 4 KiB-ring LZSS or LZ4 block decoder reproducing the sizes) and `open_as_raw`, the
decoded image's `raw` selector with the profile and best load address. `next` then says to run
`integrity_checks` with that selector, since the checksum routines are in the decoded code. A record word that
does not verify is reported as such (the record may use another algorithm or range, or the bytes changed); it is
called changed only when a verified sibling record keeps its checksum at the same place. The search is bounded:
at most 64 candidate streams, 64 MiB of CRC-32 and 8 decodes within 6 s per project (found once and kept), and
`notes` says when a budget ran out.

`lock_mechanisms` (group `detection`, experimental) explains mechanisms that can make a device refuse a repair:
signature and MAC verification, challenge-response unlocks, binding to a unique chip ID, anti-rollback counters,
debug and readout protection, and fuse feature locks. Each mechanism names what is checked, the data and registers
consulted, the decision's function and branch, what each path does (`reset`, `exit`, `halt`, `transfer`, `writes`,
`returns`) and which is the refusal when the code shows it, with evidence and a confidence; `not_locks` lists plain
integrity checks, identity reads and crypto that decide nothing. It never suggests changes or reads out keys.
Pages with `offset`/`limit` (default 10, at most 50) and filters by `category`. Limits: register roles need
`import_svd`; decisions are traced on ARM/Thumb, AArch64 and x86-64 only. See [lock mechanisms](lock-mechanisms.md).

`propagate_types` previews direct-call type candidates; `apply=true` persists separate unlocked hints with
source fingerprints. Analyst annotations take priority, conflicts remain explicit and unsupported mappings
are not guessed. Ordinary decompilation may derive ephemeral hints without writing them; undo affects durable
hint state, not all automatic inference. See [type propagation](type-propagation.md) for bounds and replay limits.

`function_frame` pages current native variables/storage and available static stack-register evidence. Actual
native address-space widths and entry-SP tracker coordinates remain separate. Header metadata is independently
bounded with explicit omissions, and unsupported tracking is distinguished from infrastructure failures.
See [function-frame inspection](function-frame.md); this is not a complete ABI or runtime frame claim.

`apply_data_type` binds native element types/arrays or explicit encoded strings to data ranges. `read_data`
retains raw backing status alongside typed fields. `apply_enum` and `apply_offset` use decoder-native operand
indices and complete instruction bytes; disassembly retains raw text with separate symbolic annotations.
Limits: bounded data windows and supported x86/x64/AArch64 operand forms, not runtime object proof or pointer
traversal. See [data and operand typing](data-types.md).

`declare_types`, `list_types`, `get_type` and `delete_type` manage project-wide named declarations with native
target layout inspection and checked undo/replay. Inline headers and minimal bundled profiles do not read
system files or invoke a host preprocessor. Deletion is dependency checked; multi-name groups require an explicit
flag. See the [type-library reference](type-library.md) for input limits and packing behavior.

`get_type` also reads producer layouts from embedded DWARF, read-only and without importing: when the library has
no such name, or with `source: "dwarf"`, it returns the type's size, members (offset, size, type name), typedef
chain and every distinct definition across compilation units (`ambiguous` when they differ), with members paged
by `offset`/`limit` and by-value records expanded to `depth`. `member: "init.busy"` returns that member's offset
from the start of the type; `byte_offset: "0x80"` returns the innermost member covering it (array elements
included). The first DWARF lookup on an image skims each unit's top-level DIEs once into a name index; each
lookup then reads only the requested type and what its members name (at most 65,536 DIEs and 16 same-named
entries), whatever the image size. Use it where the whole-image `import_debug_types`/`import_debug_layouts`
previews stop at their budgets.

On a Go binary (go1.16 and later), `get_type` falls back to Go runtime type metadata when neither the library
nor DWARF has the name, or reads it directly with `source: "go"`. These are the descriptors Go keeps for
reflection and interfaces, so they survive `-ldflags "-s -w"`. Results carry `source: "go_runtime"` and
`caveats`. Names are runtime type strings (`restic.Snapshot`, `*restic.Node`, `[]string`) or named types qualified
by import path (`github.com/restic/restic/internal/restic.Snapshot`). A definition gives the kind, size and
alignment, struct fields (offset, size, type, `embedded`, `exported`, struct tag), interface methods with
signatures, a named type's methods (pointer-receiver methods are on the `*T` type) with entry addresses where the
linker kept them, and the key, element, length or direction of composite types. `member` (promoted fields
included), `byte_offset`, `depth` and paging behave as they do for DWARF. Only types that have descriptors are
present: those reachable from the module's typelinks, itabs or other descriptors (go1.27 and later: every emitted
descriptor). The first lookup walks the descriptors once (about 20 ms and 16,000 types on a 26 MB binary). After
that, each lookup decodes only the requested type and the types its fields name, at most 200,000 reads.
`list_types` lists the named Go types when the project library is empty, or with `source: "go"`.

`edit_variable` accepts one current display name or complete native storage object, with name/type changes or
clear flags. It atomically persists the changes and returns complete refreshed C, diagnostics and variable
descriptors within the tool budget. Limits: one whole register/stack mapping and same-size types; invalid or
oversized results do not persist. See [local variables](local-variables.md) for selectors and undo/replay.

`inspect_raw_code` reads an explicitly mapped regular-file window with required architecture, mode, instruction
and data byte orders, and base VA; it returns range hashes, source offsets and bounded linear observations.
Limits: 4096 bytes, 256 instructions, little endian only; no target following or validated code identity.
ARM, Thumb and AArch64 rows print decimal `#` immediates of 10 or more in hex too, as GNU objdump does
(`movt r1, #1934 ; 0x78e`). `disassemble` and `function_graph` rows on ARM and AArch64 images keep `text` as
the decoder renders it (operand globs match it) and carry those hex values in `immediates_hex` (`"0x78e"`); the
CLI listing prints them after the instruction as `; 0x78e`, before the comment column. A native binary tool on a file with no recognised header says how to read it as
headerless code: `inspect_raw_code` for ARM/Thumb, AArch64 and x86, or the `raw` selector for the Raw profiles.
See [raw-code windows](raw-code.md#raw-code-windows). `decode_file_range` and `inspect_data` have separate source/coordinate
contracts; see [decoding](decoding.md) and [data inspection](data-inspection.md).

`list_dir` (core) lists one directory, so an agent given only a folder can start: each entry's `name`, `kind`
(`file`, `dir`, `symlink` with its stored `link` target, or `other`; links are never followed), `size` and, for
files, a `format` sniffed from the first 1088 bytes (`elf`, `pe`, `macho`, `macho_universal`, `dex`, `wasm`,
`squashfs`, `ext`, `cpio`, `tar`, `android_sparse`, `ota_payload`, `ubi`, `ubifs`, `ar`, `zip`, `gzip`, `xz`,
`zstd`, `bzip2`, `lz4_frame`, `7z`, `ihex`, `srec`, `text` or `unknown`). Entries are sorted by name and paged by
`cursor` (`limit` 1..=500, default 100; a cursor not returned by list_dir is refused), in memory bounded by the page.
A call reads at most 1,000,000 entries: past that, `truncated` says only those read were listed and counted. A path
that is a symlink or not a directory is refused. Names that are not UTF-8 show other bytes as `\xHH`, and entries
sort by that text (a backslash-led name before letters). A file is sniffed without blocking (a FIFO swapped in is
not waited on); a FIFO, socket or device is `other` and never opened.

`file_layout` maps any regular file, or an explicit range of at most 64 MiB, in one call and without a loader:
fill (0xff, 0x00, other repeated byte) and occupied regions with per-region SHA-256 and entropy, block entropy
with high and low spans, printable-string clusters with previews, the range's SHA-256, and labelled heuristic
hints such as Cortex-M vector-table and header-checked compressed-component candidates, which are evidence, not
mappings. `probe_compression` ranks LZSS and LZ4-block parameter sets for such a payload and returns
`decode_arguments` for `decode_file_range`; see [decoding](decoding.md#probing-an-unknown-variant). Capped lists report totals and
the first omitted offset, and `continuation` gives the next call's range. See [file layout](file-layout.md).

With `contains`, `list_strings` rows carry `match_address`, where the text matches inside the string. Go string
data is not NUL-terminated, so in a Go image a run that code references at more than one address carries a
`note`, and a match its `go_literal` bounds: the last address code or a static `{ptr, len}` string header in data
references at or before the match (with `start_is_match` saying whether that is the match itself, since
otherwise it may begin an earlier literal), the first one after it (or the run's end), and how many references
the start has. When a header gives the start's length, `header_length` carries it and `end` is exact. String
references in `search` (`functions_referencing`) end a Go literal the same way. Do not count offsets into such a
run by hand. Listing strings in a Go image runs the cached whole-program analysis.

`function_summary` with `view=summary` or `view=code` adds `callees` (distinct call targets with names and call
counts, taken from all of the function's references, not only the 1,000 the native summary keeps) and refuses for
size only when a single graph block exceeds 60,000 bytes. When a large function does not fit, its graph blocks,
references and callees are returned as whole-row pages: `graph.blocks_offset`/`blocks_next_offset`,
`references.items_offset`/`items_next_offset` (in these views `items_offset` replaces the native page
`offset`) and `callees_offset`/`callees_next_offset`, continued with the
`block_offset`, `reference_offset` and `callee_offset` arguments, and a `fitted` receipt lists any optional
analysis omitted to fit. Graph edges keep indexing blocks by their position in the whole function. `view=full`
refuses when oversized.

A byte or text `search` charges one unit of match work per candidate start for exact text, so the default
budget covers a 50 MB image; byte patterns with wildcards charge their length per start. When a budget or
cancellation stops a byte/text scan, the report gives `resume_at` (search again with `range.start` there),
the first 32 `unscanned_ranges` with `unscanned_range_count` and `unscanned_bytes`, and the page a `scan_resume`
hint. A regex stopped by its text-run limit gives no `resume_at`, since resuming would meet the same run.

`decompile` returns C and address-linked semantic tokens alongside structured recovery evidence. Token byte
spans index the rendered C; flow-only records can be spanless. Storage offsets are qualified by address space,
not automatically program virtual addresses. C production and `no_reported_issues` do not establish correct
recovery. See the [decompiler reference](../crates/rampage-decompiler/README.md) for token/output bounds,
diagnostics and worker requirements; `function_summary` remains a structural alternative, not decompiled C.

`evaluate_function` (core, experimental) runs one function of the image on given arguments and returns its
result, so a question like "what does this return for (0x00F0A500, 3)?" is answered by running the code rather
than simulating it from pseudocode. A p-code interpreter over the bundled Sleigh specifications executes it
(x86, x86-64, AArch64, 32-bit ARM and Thumb, MIPS, PowerPC, RISC-V, Xtensa); nothing runs natively. `at` names the entry;
`args` are integers (numbers, or `0x` hex or decimal strings; `{value, bits}` for an explicit width, and a hex
string longer than 8 digits is 64-bit on a 32-bit target), floats (`{float, bits}`: a number, or a string that is
decimal, `inf`, `-inf`, `nan` or the `0x` hex of its bits; a double unless `bits` is 32) or
`{buffer: {hex | text, size}}` buffers passed by pointer and returned with their final bytes. Arguments go where the
binary's calling convention puts them; `convention` selects cdecl, stdcall, fastcall or thiscall on x86, sysv or
win64 on x86-64, and aapcs or aapcs_vfp on 32-bit ARM. Floats travel in XMM registers on x86-64 (System V counts
them apart from the integer registers, Win64 by position), on the stack on 32-bit x86, in s/d registers on AArch64
and under ARM hard float (`aapcs_vfp`, chosen for an ELF whose header flags the hard-float ABI), and in core
registers under ARM soft float; MIPS, PowerPC and RISC-V take no float arguments. Xtensa (`xtensa`: a2-a7,
result in a2) runs the ESP32's windowed code and the ESP8266's call0 code: a `call4/8/12` rotates the register
window into the callee and back on return, and `loop`/`loopnez`/`loopgtz` repeat their body. `return_bits` sets the integer
result width (default the register width), and twice the register width reads a register pair (EDX:EAX, r1:r0).
Without `return_bits` on a 64-bit target the result also has `low_32`, the value of a C `int` or `bool` whose
upper register bits are undefined. `return_float` 32 or 64 reads a float or double instead, from XMM0, ST0 on
32-bit x86 (rounded from the x87 extended value), s0/d0, or r0 (r1:r0) under ARM soft float: the result then has
`hex` (its bits) and `float` (the shortest decimal that reads back as the same value) in place of `unsigned` and
`signed`. `trace` N (1-32) adds `trace`: the first and last N executed instructions with what each wrote
(`REGISTER=value` after it ran, `[address]=value` for stores, a write inside a larger one left out, at most 200
characters a row), the count omitted between them, and a row for each import run as a model; the report is
otherwise unchanged. Small functions that take arguments and return a value get a `next` from `decompile` that
points here. Addresses below 0x1000 and segments without permissions (Mach-O
`__PAGEZERO`) are unmapped, except in a fixed-address image linked to run there (a Raw project or an ELF
executable with a segment in page 0, as Cortex-M firmware often is), and Apple arm64 binaries pack stack arguments at their own size. Memory starts as the file's image (zero-filled bss, copy-on-write) plus a
zeroed stack and thread block; `memory` writes bytes into it first. Calls inside the image are followed; `stop`
says why the run ended: `returned` (with `result` as hex, unsigned and signed), `step_limit`, `timeout`,
`external_call` (an import, named), `external_read`, `unmapped_read`/`unmapped_write`/`unmapped_fetch`, `user_op`
(system calls, traps and processor operations, named), `unsupported_op`, `invalid_instruction` or
`division_by_zero` or `memory_limit` (more than 64 MiB of written image pages), with `stopped_at` naming the
instruction and function. Imports of common C library functions (`memcpy`, `memmove`, `memset`, `memcmp`,
`strlen`, `strnlen`, `strcpy`, `strncpy`, `strcmp`, `strncmp`, `strchr`, `strrchr`, `strcat`, `toupper`,
`tolower`, `abs`, `malloc`, `calloc`, `realloc`, `free`, `strdup`, `strndup`, `sprintf`, `snprintf`, also under
their Mach-O underscore, `__name_chk` fortified and MSVC CRT names, and C++ `operator new`/`new[]` and
`delete`/`delete[]` under their Itanium and MSVC names) run as built-in models with the binary's calling convention
instead of stopping; `stubbed` counts them, and `stubs: false` stops at them as before. The formatting models
handle `%d %i %u %x %X %o %c %s %p %%` with flags, width, precision and length modifiers, copying bytes as they
are (a 64-bit value on a 32-bit target from two argument words, an even pair of the call's words under AAPCS and
o32; on Apple arm64 the variadic arguments are read from the stack); `%f`-style conversions and `%n` stop with
`unsupported_op`. The allocators use a bump heap of at most 16 MiB whose pages count against the 64 MiB cap;
aligned and placement `operator new` are not modelled. Argument buffers read to the end of their 4 KiB page, as
aligned vector loads do on real memory, while writes stop at the buffer's size: the padding reads as zeros, so a
hex buffer without a terminating NUL still looks NUL-terminated to `strlen` or `%s`. On 32-bit x86, fastcall and
thiscall pass float arguments on the stack, not in ECX/EDX. On x86 the SSE, SSSE3, SSE4.1/4.2 and AVX/AVX2
operations Sleigh leaves as processor operations (shuffles, packs, unpacks, blends, extensions, saturating and
high multiplies, horizontal adds, sum of absolute differences, AVX shifts and permutes, packed float arithmetic,
comparisons, rounding and conversions, `crc32`) are interpreted, as are 32-bit ARM's VFP/NEON `vcvt` conversions
with their rounding (toward zero, FPSCR's mode, or the `vcvta/n/p/m` round type; half-precision forms stop).
Float p-code is IEEE binary32/binary64 with round-to-nearest-even (the default mode; other rounding modes set at
run time are not modelled), conversions to integers saturate (the integer indefinite on x86), and x87 80-bit
values convert exactly but compute their arithmetic in binary64 (53-bit, not 64-bit, significands). Each result
also lists where every argument went and the functions called. Limits: `max_steps` (default 1,000,000, at most
20,000,000) and `timeout_ms` (default 10,000, at most 60,000); AVX-512, AES, SHA and string-compare (`pcmpistri`)
operations, x87 transcendental functions (`fsin`, `fcos`, ...) and NEON arithmetic left as processor operations
stop with `user_op`; a fused multiply-add rounds twice, as Sleigh's p-code describes it.

`check_claim` (core, experimental, raw-capable) takes `claims`, 1-32 objects each with a `kind`. It returns
`results`, one per claim in order, with:

- `index`, `id` (when given) and `kind`;
- `verdict`: `verified`, `refuted`, `unknown` or `invalid`;
- `confidence`: `exact`, `sampled`, `static` or `heuristic`, absent for unknown and invalid;
- `negated` (for `not: true`), `method` and `evidence`;
- `reason` and `needs` for an unknown;
- `elapsed_ms`.

The report adds counts per verdict, `elapsed_ms` and `timeout_ms`. The kinds are:

- `returns`: `evaluate_function` against a stated `value`, `float` or `buffers`;
- `computes`: an `algorithm` (CRC presets or `{crc: {...}}`, checksums, hashes, digests, `sha256_block`,
  transforms) or an `expression` at `bits`, run on `samples` seeded generated inputs, with argument roles in
  `args` and `setup` calls first;
- `calls`: `callee` within `depth`, or before another call;
- `references`: a `target` or `string`, with `by` or `only_by`;
- `constant`;
- `region`: recompute at `stored`, or a detected check;
- `lock`;
- `layout`.

The bounds: `timeout_ms` (default 60000, at most 300000) covers the whole call, and each evaluation also stops at
`max_steps`. The grammar, verdict rules and examples are in [checking claims](claim-checking.md).

`string_decoding` with `evaluate: true` also runs each candidate decoder on the blobs passed to it (at most 16
pairs, 200,000 steps and 500 ms per run, 5 s in all): it replays the caller's block holding the call through the
call's return (imports before the call without a model return 0, except on 32-bit PE, where the replay
stops because an import may pop its own arguments), and failing that calls the routine as (blob),
(output, blob, length) and (blob, output, length). Printable output at the result or an argument pointer that
differs from the file, from what that address held before, and from the blob (not equal to or a prefix of it)
is reported in a "Decoded by emulation" section with the arguments, stop reason and library stand-ins used;
a pair that gives no text is reported with each attempt's stop. Decoded text is emulation output, not file content.
Without `evaluate` the report is unchanged.

`dotnet_metadata` selects `types`, `pinvokes`, `attributes` or `resources`, filtering with `contains`/`parent_token` and
paging entries. `dotnet_il` selects a method token or qualified name and pages instructions with `offset`/`limit`,
or starts at an IL label with `at`. Property signatures/accessor tokens and supported attribute values are
metadata evidence. CIL is never treated as native code; see [managed assemblies](file-formats.md#managed-assemblies).
Resources preserve raw metadata and offset/reference availability, with independent inventory counts and truncation.
Embedded mapping evidence does not validate payload extents; external targets and resource payloads are not read.
`parent_token` is an attribute-target filter, not a resource-owner selector.

`pe_resources` pages PE resource leaves with `offset`/`limit`, filtered by `type` (`RT_VERSION`, `VERSION`, `16`,
`#16` or a string type name). Each leaf carries its type, name, language, data RVA, size, code page, image offset and
whether its bytes are in the file. The page holds whole rows within 60,000 JSON bytes (`resources.next_offset`,
`resources.byte_capped`); `types` counts leaves per numeric or string type, at most 256 rows (`types_total`,
`types_truncated`). The page's first RT_VERSION or RT_MANIFEST payload is always decoded, later ones until 24,000
payload bytes are spent (`decode_skipped` counts the rest); other payloads are located only. `pe_load_config` reads
the load config up to its own declared Size, listing later fields in `absent_fields`, and adds CET flags and findings
against the DllCharacteristics that triage reports. Both return null for a non-PE image. See
[PE resources and load config](file-formats.md#pe-resources-and-load-config).

`carve` accepts any file path rather than requiring a loadable binary. Pages use `offset`/`limit` and `more`,
not a total; scanning stops at the candidate after the page. It extracts/decompresses nothing. It recognises ELF,
PE, Mach-O, zip, gzip, xz, zstd, LZMA, bzip2, LZ4 frames, lzop, SquashFS, ext2/3/4, UBI, UBIFS, JFFS2, CramFS, FAT,
Android sparse and boot images, OTA payloads, cpio, tar, uImage, TRX, device trees (and FIT images), MBR and GPT
disks (at 512-byte-aligned offsets), and UEFI firmware volumes and capsules. Inside a SquashFS, UBIFS, JFFS2,
CramFS, Android sparse or OTA payload image whose validated extent fits the file, whose contents are compressed
blocks or chunks, it reports only executables whose headers validate; inside such an ext, UBI, tar, cpio or ZIP
image, whose files or volumes are stored whole, it reports every candidate whose header validates. The image's notes count what was
left out inside it; `fs_list` lists the image's files (not yet for JFFS2 or CramFS). Inside a TRX, device tree,
MBR or GPT disk, FAT volume or UEFI volume or capsule, which `fs_list` does not read, it reports every candidate,
each noting its container.
`archive_inventory` similarly needs no image or sidecar, but inventories bounded standalone ZIP32 central-directory
metadata. Its member ordinals and metadata hashes are not payload validation or extraction-safe paths; whole-record
JSON pages stay within 60,000 bytes and errors within 4,096 bytes. See [archive inventory](archive-inventory.md).
`fs_list` and `fs_extract` list and extract firmware filesystem images (SquashFS, ext2/3/4, Android sparse, Android
OTA payloads, cpio, tar, UBI volumes, UBIFS) and ZIP archives (APKs included) in any file, at an `image_offset` or nested through `inner`; `fs_extract` writes into a new
or empty `output_dir` under traversal, symlink, special-file and size limits and returns the executables it wrote.
See [firmware filesystem images](firmware-images.md).
`endpoint_inventory` lists the URLs, hosts, IPs, pins and certificates of a file or a directory tree (paged by
`cursor` under `max_files` and `timeout_ms`), classified and grouped by domain and component; `endpoint_blocklist`
writes chosen hosts to an absolute `output` file as a hosts, dnsmasq, unbound, domain or IP list. See
[endpoint inventory and blocklists](endpoint-inventory.md).
`privacy_surface` is a guided report on one binary: microphone, camera, screen and input-device capture sources
(with `evidence` `argument`, `name` or `string`), network and file sinks with the endpoints they name, ranked
capture-to-send call paths, and what reaches each capture (program start, timer, network command, user input;
`no_user_trigger`). Its `path` may also be an APK or DEX file (DEX call graph, manifest and framework triggers,
native libraries merged through JNI; the report has `input` instead of `target`) or a directory (one page of
programs and APKs with init `.rc`, systemd and init.d boot starts; `cursor`, `max_files`, `timeout_ms`). See
[privacy surface](privacy-surface.md).
`diff_firmware` (*experimental*) compares two versions of an update: `path` (older) and `other` (newer), each a
file or directory, with `image_offset`/`image_length`, `inner` and `as_raw` per side (`other_` forms for the newer
one; `other_as_raw` defaults to `as_raw` only when that has no `length`). Components (an executable, a Raw image,
decoded container streams, ESP partitions, a filesystem's changed files, embedded images) are paired and compared:
digests and container facts, files by SHA-256, and per changed code image functions with match method and
confidence, strings, versions, endpoints, lock mechanisms, integrity checks and capture sources added or removed.
`component` with `list` (`changed`, `added`, `removed`, `unchanged`, `strings`, `endpoints`, `files`;
`offset`/`limit` up to 500) pages one part, and with `function` diffs one function with addresses normalised.
`timeout_ms` (default 60000, at most 600000; soft, one image's analysis is not interrupted) and `max_images`
(default 8, at most 64) bound the work, with a fixed 2 GiB read budget;
`not_compared` lists what they left out. Results stay within 56,000 JSON bytes. See
[firmware version diffing](firmware-diffing.md).
`build_info` returns `{go, rust}`: Go build info (toolchain version, main package and module, dependency modules with
`=>` replacements, build settings, and a cross-check of the version against the pclntab layout) and cargo-auditable
`.dep-v0` packages. Each is `null` when absent, or has `status` `present` or `unreadable` with a `reason`. `offset`/
`limit` page `go.deps` and `rust.packages` independently, each page holding whole items within the 60,000-byte result
(`next_offset`, `byte_capped`). Build settings are listed up to a byte share (`settings_total`,
`settings_byte_capped`) and roots up to 16 (`roots_total`). Both records are self-reported by the toolchain, not
verified against code. See [toolchain build info](file-formats.md#toolchain-build-info).

`pyinstaller_archive` and `wasm_module` are file tools too: they take any file path and open no project. The first
returns the CArchive cookie, package, Python version and a page of TOC entries (null without cookie magic, and
`{archive: null, rejected_candidates}` when magic matches but none validates as a cookie); the second returns a core
WebAssembly module summary and, with `list`, a page of imports, exports or functions (null without the `\0asm`
magic). Both pages hold whole items within 60,000 JSON bytes and report `next_offset` and `byte_capped`. See
[PyInstaller and WebAssembly](file-formats.md#pyinstaller-archives-and-webassembly-modules).
`observe_pointer` exposes a captured slot without modifying discovery or asserting a call edge. See
[runtime snapshots](runtime-snapshots.md) for runtime evidence limits and [data packs](data-packs.md) for pack warnings.

`compare_runtime_bytes` accepts `original_image_offset` and optional dependent `original_image_length` for its
explicit original path. Integer/decimal/hex forms and null-as-absent follow ordinary image-selector parsing. They
do not select the primary snapshot, infer pointer correspondence or enable embedded snapshot-JSON loading.

`query_debugger` accepts an explicit local Unix socket and typed read-only request without opening a binary or
annotation sidecar. An LLDB operator must start the stopped-session endpoint; this tool cannot attach, resume,
evaluate expressions or write target memory. Initial session queries return a token required for subsequent
queries. Stale tokens fail without automatic refresh. Responses retain the backend's error/observation envelope
and remain non-atomic. See [LLDB queries](lldb-query.md) for request operations, endpoint policy and limits.

The `debug` tools connect to a GDB remote stub the operator started and allowed (gdbserver, QEMU, OpenOCD, Apple's
`debugserver`, or `gdbserver.exe` and `lldb-server` on Windows) and inspect and control it in all-stop mode.
`debug_connect` returns a session ID; at most four sessions are open per MCP connection, and they detach when it
ends. Reads report the stop epoch they read at, and execution tools require the caller's epoch. `debug_bind` (or
`debug_connect` with `path`) binds a project to a runtime module, which adds breakpoints by function name or static
address, located stops, annotated registers and `debug_evidence` items for `record_finding`. With the operator's
flags, `debug_write_memory`, `debug_write_register` and `debug_disconnect` with `kill: true` change the target;
nothing writes or kills on its own, and no signal is delivered. `debug_snapshot` with `raw: true` writes one range
as a flat binary, a firmware dump to open as a Raw project. [Debug control](debug-control.md) has each tool's
arguments and results, the macOS and Windows specifics, and the limits.

Debug tools carry MCP annotations: inspection tools and `debug_wait` are read-only; `debug_snapshot` only adds a
file; execution tools, `debug_disconnect` and the write tools are neither read-only nor idempotent and may be
destructive. All are open-world. Cancelling a call (`notifications/cancelled`, or the connection closing) ends a wait early with
`cancelled: true` and the target untouched, and stops a long read or snapshot between chunks.

Errors start with a code: `unknown_session`, `endpoint_not_allowed`, `session_limit`, `timeout`,
`connection_lost`, `protocol_error`, `target_error`, `unsupported`, `session_not_stopped`, `target_running`,
`not_running`, `stale_epoch`, `cancelled`, `not_allowed`, `expect_mismatch` or `invalid_argument`; binding and placement add `no_module_match`,
`slide_mismatch`, `slide_unverified`, `ambiguous_module`, `arch_mismatch`, `binding_limit`, `not_bound`,
`ambiguous_name`, `not_code`, `step_out_refused`, `undecodable` and `shared_cache_image`. See
[debug control](debug-control.md).

## Tool details

Tool descriptions say when to call a tool, what it needs and what it returns; the details below are what they leave
out. The feature guide linked for each tool is the full reference.

- `batch`: names resolve against the snapshot before the batch; duplicate targets, malformed declarations and
  receipts over the 60,000-byte budget (which reserves room for refresh and cancellation evidence) write nothing.
  A bound assistant may stop after a committed batch when it cannot attribute the transition to itself; the
  outcome is kept and the batch is not retried.
- `transfer_annotations`: methods and confidences are exact_bytes 1.0, symbol_name 0.95, masked_hash 0.9,
  unique_string 0.8, call_graph 0.75 (propagation from matched callers), call_position 0.6 (a non-calling callee
  placed by call position alone) and neighbourhood 0.6; derived matches build only on matches at least as
  confident. Statuses are transfer, already_present, conflict, below_threshold and not_transferred (with a reason).
  The first applied batch records the source SHA-256, threshold and methods in the findings ledger. See
  [build diffing](build-diffing.md).
- `assemble`: source is at most 16 KiB of literal assembly, never a file name; only the base address resolves
  names. The proposal is encoding evidence, not execution or behaviour verification. See [assembly](assembly.md).
- `search`: `include_context` defaults to true; a capture's `file_offset` is null; `budget` bounds scan work
  separately from paging. See [search](search.md).
- `decompile` with `exact_entry`: the entry is an analyst assertion; entry metadata and decoding are not proof of
  boundaries or completeness, and output carries context counts, omissions and preparation timings. There is no
  silent whole-program fallback. It takes Raw Cortex-M Thumb code as well as x86,
  x86-64 and AArch64; other ARM code is refused with a pointer to plain `decompile`, which takes any code address.
  See [exact-entry decompilation](exact-entry-ui.md).
- ARM code addresses with bit 0 set (the Thumb bit vector tables and function pointers carry): `decompile`,
  `disassemble`, `function_graph`, `function_summary`, `xrefs` `from` and, on Cortex-M, `evaluate_function` read the
  Thumb code at the even address when it is known Thumb (an M-profile image, a Thumb range, or a mode discovery
  learned there), and say so in `note` (`notes` for `xrefs`; on the first row of a `disassemble` listing). An odd
  address not known to be Thumb is used as given, with a `note` saying so.
- `xrefs` `to` that finds nothing adds `notes`: the start of the string the address lies inside, when that start is
  referenced and NUL-terminated; on M-profile images and the Thumb ranges of other little-endian ARM images, up to
  eight Thumb `bl` encodings outside every discovered function that target it (code discovery did not reach, to
  seed; at most 64 MiB are read); and that calls through pointers are not resolved.
- `lock_mechanisms` traces the functions its evidence selects (crypto constants, CRC routines, role registers,
  verify/MAC/random APIs), their callers and callees, not every function: `coverage` gives `functions_analyzed` of
  `functions_discovered`, and a limitation says so when that is under a tenth.
- `triage` and `triage_report` on a file with no recognised executable header (and no `raw` or `image_offset`)
  return a container-level result instead of an error: `parsed_as_executable: false`, the open error as `reason`,
  a `file_layout` summary with the largest occupied regions, the compressed components headers describe, `carve`'s
  first candidates, `next`: ready-to-run `probe_compression` calls with each payload's offset, length and decoded
  size (and `triage` at each embedded executable), and `then`, what to do with the probe's `open_as_raw`. If the
  layout itself fails, the open error is returned as before. Nothing is decoded.
- `record_finding`: the ledger holds at most 1024 entries and 2 MiB, and a write that would leave the shared
  annotation log less than a quarter of its budget free is refused, so names and comments keep room.
- `discard_undo`: the annotation log is not rewritten; the dropped step's edits stay.
- `class_evidence`: RTTI pages are also bounded to 16,000 JSON bytes and vftable pages to 24,000; a vftable lists
  at most 64 slot targets.
- `patch_bytes`: `original_hex` must be the original file's bytes, not an existing patch's; headers, captured or
  debugger memory and source files are never written. See [patching](patching.md).
- `inspect_data`: image addresses, selected-image offsets and outer-file offsets are distinct; retained Mach-O
  chained rebases and import identities are reported separately from raw words; partial encoded-pointer words are
  not followed and other relocations are not applied. See [data inspection](data-inspection.md).
- `inspect_sleigh`: the roster has 20 language IDs (16 reviewed processor profiles plus four x86/A64 variants);
  widths are never inferred from CPU names. Native calls and discovery are not interruptible, so deadlines are
  checked between operations. Gated flow (Hexagon packets, SuperH delay slots, user-defined operations) is
  reported rather than followed, and entry retention is not proof of body coverage. Unix regular files only. See
  [Sleigh decoding](sleigh-decoding.md).
- `inspect_raw_code`: mapping assertions and decoding are not execution or boundary proof; invalid or incomplete
  instructions stop decoding. See [raw code](raw-code.md).
- `decode_file_range`: lzss-4k is LSB-first flags with 1 meaning a literal, 12-bit references and lengths of the
  nibble plus 3, its ring starting at 4078 with an explicit fill. The decode deadline is cooperative; file I/O and
  hashing are not timed out. See [decoding](decoding.md).
- `probe_compression`: LZSS sweeps windows of 10..13 bits, minimum match 2 or 3, flag bit order and polarity, five
  16-bit reference layouts, and distance or ring offsets with ring start and fill. See [decoding](decoding.md).
- `file_layout`: high-entropy spans are at least 7.2 bits/byte and low ones at most 2.0. A vector-table candidate
  has an initial SP in SRAM and an odd reset address; a compressed-component candidate has a header word equal to
  the payload's length with a byte sum or CRC-32 of it, or a packed payload ending at a boundary. See
  [file layout](file-layout.md).
- `identify_functions`: `source` is "user database", the data pack's name, "rampage-builtin" or "rampage-builtin
  embedded". Thunks too small for the confidence gate are never named. An oversized first row or header is refused
  before any name is written. FID namespaces need the separately configured Ghidra import. Fuzzy loading,
  querying and receipt checks finish before exact names are applied; fuzzy totals never count toward
  matched/applied, and fuzzy requests cannot combine with `no_bundled`. See
  [fuzzy signatures](fuzzy-signatures.md).
- `import_debug_layouts`: review_sha256 binds every admitted layout, function, producer evidence, warning, the
  image, options, specifications and annotation eligibility, not just the page. Opaque vptr projections describe
  consumer storage, not producer types; exact method associations are checked source evidence, not object-vptr
  proof or virtual-call targets. See [debug layout import](debug-layout-import.md).
- `import_pdb_names`: user, symbol, export, entry and concurrently added labels are kept; there are no automatic
  paths or downloads. See [PDB symbols](pdb-symbols.md).
- `edit_variable`: selectors include inclusive definition/use points, not live ranges; dynamic, join, piece and
  ambiguous storage is refused; an invalid or oversized refreshed result does not persist. See
  [local variables](local-variables.md).
- `function_frame`: native stack space is not equated with entry-SP tracker offsets, and paging does not imply a
  complete frame. See [function frames](function-frame.md).
- `dotnet_metadata`: attribute values cover primitives, strings, types, single-dimensional arrays, verified local
  enums and boxed values in object[]; others report errors. Resource locations are not validated payload extents.
- `pe_resources`: the tree walk has depth, table, entry and leaf limits with loop detection, and a directory size
  overrunning its section is read from the RVA as Windows does. A page decodes its first payload always and later
  ones until it has spent 24,000 payload bytes (decode_skipped counts the rest). The manifest scan is textual, not
  an XML parse.
- `pe_load_config`: fields past the directory's Size are listed in absent_fields; SafeSEH is read only for native
  x86. Table contents beyond SafeSEH handlers, CHPE, hot-patch, enclave and volatile metadata are not decoded.
- `build_info`: Go records come from .go.buildinfo, __go_buildinfo or a 16-byte aligned scan of writable data;
  the Rust section is zlib JSON, capped at 8 MiB. Settings and roots are capped with totals. No vulnerability
  lookup and no network access.
- `exception_handlers`: x64 tables come through .pdata unwind info; x86 tables by a validated scan tied to the
  function that registers the handler thunk. cl.exe x86 places catch blocks inline.
- `pyinstaller_archive`: the cookie (magic MEI\x0c\x0b\x0a\x0b\x0e) is searched backwards through the last 8 MiB,
  stepping over an appended signature, in both the 24-byte pre-2.1 and the 88-byte layout. Nothing is extracted,
  decompressed, decrypted or decompiled.
- `wasm_module`: at most 64 sections are listed and the first 32 errors kept (repeats counted).
- `archive_inventory`: limits are a 65,557-byte tail, 8 MiB directory, 4096 records, 1 MiB of names (1024 bytes
  each) and 24 MiB of reads; exhausting a budget rejects the whole inventory. Names keep raw hex and ordinal
  identity. See [archive inventory](archive-inventory.md).
- `query_debugger`: the socket must sit in a same-user 0700 directory; paths recorded in capture metadata are never
  opened, and content hashes are not authenticity or atomicity proofs. See [LLDB queries](lldb-query.md).

## Raw projects

The workflow (choosing a base, compressed images, regions, scatter-load) is in [Raw code](raw-code.md); this
section is the reference.

Raw-capable tools (`binary_info`, `list_functions`, `disassemble`, `function_graph`, `xrefs`, `search`,
`list_strings`, `analysis_diagnostics`, `entry_diagnostics`, `capabilities`, `rename`, `set_comment`,
`annotate_batch`, `list_annotations`, `undo`, `redo`, `decompile`, `evaluate_function`, `check_claim`, `import_svd`,
`peripheral_access`, `list_patches`, `patch_bytes`, `revert_patch`, `integrity_checks`, `export_image`,
`identify_functions`, `lock_mechanisms`, `function_summary`, `find_crypto`, `triage`, `triage_report`,
`find_main`, and the file tool `inspect_data`) take an optional `raw` object in place of a native image. `find_crypto`, `triage` and
`triage_report` read every backed region (decoded ones included) at mapped addresses; `triage` adds a hint and
`triage_report` a limitation saying which file-format facts (build time, libraries, imports, hardening, overlay,
imphash) do not apply. `find_main` follows a MIPS reset vector's code (past `b reset` over the exception vectors)
to the jump into its C entry, and a
Cortex-M reset handler to the first call that never returns, or to
the copied code that starts the scheduler (see [find main](raw-code.md#find-main)). `function_summary` and `lock_mechanisms` work on the functions discovery found, pointer
tables and scatter-load copies included; when no function qualifies, `lock_mechanisms` says why none was
analysed. `list_strings` lists every backed region's strings at their mapped addresses (decoded regions
included); in a code region, where flash images keep constants among instructions, only runs a NUL ends and no
discovered instruction overlaps are listed. `inspect_data` gives `file_offset` only for bytes mapped from a
file range (none for decoded, record or unbacked bytes). `evaluate_function` runs a Raw
project's code when the interpreter supports its processor (the Cortex-M and MIPS32 profiles among them); others, such as
MSP430, are refused with the reason. Only the selected bytes are mapped (RAM and peripherals are not): `memory`
changes image bytes, `mmio` maps a page for each value it sets, and imported SVD register names work in `mmio`:

```json
{
  "path": "tests/fixtures/sleigh/msp430.bin",
  "raw": {
    "profile": "TI_MSP430:LE:16:default",
    "offset": 0,
    "length": 30,
    "base_address": "0x4400",
    "entry": "0x4400",
    "seeds": ["0x4400", "0x4410"]
  }
}
```

`profile` is a closed Raw language ID, listed in the server instructions, in any letter case, or a processor
alias such as `msp430`, `avr`, `8051`, `z80` or `cortex-m4`. An unknown name gets the closest profiles; an
A-profile ARM, AArch64 or x86 name is pointed to `inspect_raw_code` with an example, since those have no Raw
profile; `offset`/`length` select original-file bytes (1..=131072, or up to 4 MiB for `ARM:LE:32:Cortex`, the
MIPS32 profiles and Xtensa);
`base_address`, `entry` and `seeds` (at most 8192) are internal code-space byte offsets, also for word-addressed
processors, and tool addresses use the same coordinates. The mapping is an analyst assertion, not header admission.
`raw` cannot be combined with `arch`, `image_offset` or `image_length`, and other tools refuse it with "tool X does not
accept Raw projects". Tools that cannot answer on Raw code refuse explicitly (immediate search on Sleigh profiles;
decompilation for every profile except MSP430, AVR8, Cortex-M, MIPS32 and Xtensa, which have reviewed C models). Annotations are
memory-only for the server session and the exact interpretation (bytes, profile, mapping, entry, seed set): no sidecar
or log is written, changed seeds or bytes give a fresh project, and at most 32 interpretations are retained. Each tool's
`raw` schema is a compact shape
(about 0.7 KB); the field meanings and profile list appear once in the server instructions to keep the catalog small. See [explicit Sleigh decoding](sleigh-decoding.md#ordinary-raw-projects).

A MIPS32 boot ROM or bare-metal image opens with `MIPS:BE:32:default` (alias `mips`) or `MIPS:LE:32:default`
(`mipsel`), decoded natively as Cortex-M is: up to 4 MiB, further `regions`, and `decompile` and
`evaluate_function` with the o32 model. Without `entry` the entry is `base_address`, the reset vector of a boot ROM
mapped at 0xbfc00000 ([MIPS boot ROMs](raw-code.md#mips-boot-roms-and-bare-metal-mips)). MIPS64, microMIPS and
MIPS16e have no Raw profile.

ESP32 and ESP8266 firmware (`Xtensa:LE:32:default`, aliases `esp32`, `esp8266`, `xtensa`) is decoded natively too.
`"format": "esp"` maps an app image by its segment headers, from `offset` (default 0) of the file, so an app in a
flash dump opens with its partition's offset: `{"profile": "esp32", "format": "esp", "offset": "0x10000"}`.
`binary_info` reports the image under `raw.esp` (chip, ABI, segments, checksum and SHA-256 checks, `esp_app_desc`),
and on a flash dump opened without `raw` names the bootloader, the partition table and each app's selector
([ESP32 and ESP8266 firmware](raw-code.md#esp32-and-esp8266-firmware)).

A Cortex-M flash image (experimental `ARM:LE:32:Cortex` profile) opens in one call from path, profile and base
address, with `"vector_table": true` to read the vector table at `base_address` (or an address in its place):

```json
{
  "path": "tests/fixtures/firmware/raw-cortex-m.bin",
  "raw": { "profile": "cortex-m3", "offset": 0, "length": 800, "base_address": "0x8000000", "vector_table": true }
}
```

Accepted Thumb handlers become the entry (Reset, unless `entry` is given) and seeds. `binary_info` reports the
interpretation under `raw` (experimental for every profile): `profile`, `base_address`, `length`, `seed_count` and,
for Cortex-M seeding, `vector_table`. That lists every system vector and every accepted external one with `index`,
`name`, `word`, `status` (`stack_pointer`, `accepted`, `empty`, `erased` for 0xFFFFFFFF, or `refused`), the handler
`target` and a `refused_reason` (`sp_unaligned`, `reserved`, `thumb_bit_clear`, `outside_image`, `in_table`), plus
`stop_reason` (`image_end`, `max_external`, `reached_handler`, `non_handler_word`) and `stop_detail`. When handler
words fall outside the asserted mapping, `base_address_suggestion` gives `base_address` (the most aligned base that
would hold them) within `lowest_base`..`highest_base`; it is never applied, and an explicit `vector_table` address
moves with the base. The reset-time table is also judged as a whole: when Reset is not `accepted`, or the initial SP
word lies outside RAM (0x10000000..=0x40000000, or inside or at the end of a `ram` region) and fewer than two other
handlers are `accepted`, `refused_reason` says why (for example code at offset 0, whose first words are no SP and no
Thumb handler) and no handler of it becomes the entry or a seed; the words are still listed with their verdicts. A
table whose Reset and two more handlers check out is kept with an SP outside RAM (external SDRAM, a part's own RAM),
the SP word `refused` with `sp_outside_ram`. A table that VTOR stores install is not held to the SP rule.

`"pointer_tables": true` (Cortex-M only) also seeds functions from tables of Thumb code pointers,
such as handler arrays and command tables, so a raw image needs no hand-built symbol list. `false` never scans.
Left unset, the scan runs automatically when discovery from the entry, seeds, vector table, scatter-load jump and
data records finds fewer than one function per 16 KiB of code (none at all in a smaller image) or functions whose
bodies cover less than an eighth of its code-like bytes (runs of 64 or more copies of one byte excluded), and `list_functions` adds a one-line `note`. Every backed code region is
scanned (the primary one, mapped startup copies and `regions`), each table's targets in the region that holds it.
`raw.pointer_tables.automatic` gives `functions_before`, `code_bytes`, `covered_bytes`, `applied`, `reason` and
`outcome`: `applied` (the project is opened with the scan, the interpretation of `"pointer_tables": true`),
`found_none` (the scan accepted no table, so the project stays that of `false`) or `refused` (its seeds cannot be
admitted, more than 8192; `refused` says why, the sparse discovery stays and `next` suggests mapping less or giving
seeds). With discovery in proportion the project is exactly that of `false`. The project an unset request produced
also answers an explicit request for the same interpretation (`true` when applied, `false` otherwise), keeping its
annotations; its `binary_info` still shows the `automatic` record. A table is a run of at
least three word-aligned code pointers at a stride of 4, 8, 12 or 16 bytes (zero or 0xFFFFFFFF slots allowed
between them), where a code pointer is an odd word whose target lies in the image and decodes like code. Its
`evidence` is `push_lr` (one of the first four instructions pushes `lr`), `call_target` (a decodable `bl` in the image
calls it) or `reaches_exit` (its straight-line decode reaches a return or branch). A table is `accepted` when two
distinct targets have strong evidence (`push_lr` or `call_target`); otherwise it is `refused` with
`too_few_functions` (one target throughout) or `no_strong_evidence` (switch tables of case labels, constants that
point into code, tables of leaf functions only).
`binary_info` reports `raw.pointer_tables`: `words_scanned` (the vector table's words are skipped),
`pointers_without_evidence`, `isolated_pointers` (code pointers in no run of three), `accepted_tables`,
`refused_tables`, `refused_tables_not_listed` (beyond 64 listed), `seeds` (distinct accepted targets) and
`tables`, each with `address`, `stride`, `status`, `refused_reason` and `entries` (`index`, `address`, `word`,
`status` of `accepted`, `empty` or `refused`, `target`, `evidence`). Only accepted entries become seeds.

`binary_info` on a Raw project never fails over the size of `raw`: `view: "summary"` keeps the first 3 rows of
every list under `raw` (the decode receipt's, vector-table words, pointer tables and their entries, scatter-load
copies, base candidates; lists of plain values keep 8) and adds `<list>_count` with an omission receipt per cut in
`view_projection.omissions`. The default full view is returned unchanged when it fits 60,000 bytes; otherwise its
`raw` lists keep their first 16 rows the same way and `view_projection.fitted` says so. Either view then reduces
`raw` sections that still do not fit, largest first, to their scalar fields and list counts, with a receipt;
`base_check` (the better base and the bad fetch) is never reduced.

`disassemble` with `count` up to 1000 pages through the whole image as text, data included.
The session keeps at most 32 Raw interpretations and 64 MiB of their input bytes, evicting the least recently used.

### Multiple regions, Intel HEX and S-records

A Cortex-M or MIPS project (experimental) may map up to 15 further regions of the same file beside the primary code region,
so a bootloader's second stage is analysed at the address it runs from:

```json
{
  "path": "tests/fixtures/firmware/raw-cortex-m-stages-lzss.bin",
  "raw": {
    "profile": "cortex-m3", "offset": 0, "length": 1024, "base_address": "0x8000000", "vector_table": true,
    "regions": [
      { "kind": "code", "base_address": "0x20000000", "offset": "0x408", "length": 128,
        "decode": { "codec": "lzss-4k", "expected_output_size": 128 } },
      { "kind": "ram", "base_address": "0x20000800", "offset": "0x800", "length": 8 },
      { "kind": "ram", "base_address": "0x20001000", "length": "0x4000" }
    ]
  }
}
```

Each region has a `kind`: `code` (r-x; seeds may lie here, and on Cortex-M its literal pools fold as constants, but
words the code reads through an address it forms do not),
`data` (r--, constant bytes) or `ram` (rw-; its bytes, if any, are initial values the program may change, so the
decompiler never folds loads from it). `offset`/`length` select its bytes in the same file; a `ram` region without
`offset` has no bytes (zero-filled or uninitialised RAM, memory-mapped I/O) and `length` is its size. `decode`
maps the in-memory output of the decoder provider over the range instead: it takes `decode_file_range`'s `codec`,
`lzss`, `expected_output_size` (the region's size), `initial_write_offset`, `dictionary_fill` and `timeout_ms`;
nothing is written to disk. `from` instead copies `length` bytes of an earlier region, which is how startup code
moves code and initialised data from its load address to its run address (scatter-load): `"from": {"region":
"primary", "offset": "0x400"}` takes them at that byte offset of the primary region (its decoded bytes, with a
top-level `decode`); `region` is `0`, `"primary"` or `"raw.code"` for the primary region, or `n` or its name
`raw.<kind>.<n>` for `regions[n-1]`, which must come earlier and have bytes. Copies count against the byte cap,
and patches go to the source region, never to a copy. Regions never overlap (the refusal names both), all backed
regions together hold at most 4 MiB, `vector_table` reads the primary region only and `pointer_tables` every code
region. Discovery,
data references, calls and the decompiler's memory image span every region, so a call from flash through a literal
pool into the RAM stage, and back, resolves.

`binary_info` lists `raw.regions`, the primary region first (`raw.code`, then `raw.<kind>.<n>`), each with `kind`,
`base_address`, `length`, `sha256` of the mapped bytes (absent when unbacked) and `source`: `file_range`
(`offset`, `length`), `decoded` (`offset`, `length` and the provider's `receipt`: codec, parameters, source-range
SHA-256, output SHA-256, consumption and limits, without the path and preview), `slice` (`region`, `offset`,
`length`), `records` (`format`) or `unbacked`. Each region is also a segment and section with its permissions.

`"format": "ihex"` (Intel HEX) or `"srec"` (Motorola S1/S2/S3 with S7/S8/S9) reads a record file instead; omit
`offset`, `length` and `base_address`, since every address comes from the records. Each record's checksum is
verified; a missing end record, data after it, an unknown record type or overlapping records are refused, and
nothing is filled across gaps. Each contiguous run of records becomes a `code` region, the lowest one the primary
region; a `regions` entry without `offset` whose `base_address` and `length` match a later run exactly states that
run's kind (say, `ram` for initialised data); other `regions` entries may only add unbacked RAM, since
`offset` and `decode` would read the record text itself and are refused. Toolchain HEX files often leave
alignment gaps between sections, and each gap starts another run: an image with many gaps can reach the 16-region
limit and is then refused (convert it to a binary and use `regions` instead). `binary_info`
reports `raw.records`: `format`, `data_records` and `start_address` (`word` as written, `status` `accepted`,
`empty` or `refused`, `target`, `refused_reason` `outside_code`, `unaligned` or `in_vector_table`). An accepted start
address becomes the entry unless `entry` or the vector table's Reset names another address, in which case it is a
seed. Sleigh profiles take a record file with one contiguous run and no `regions`.

### Scatter-load copies

Startup code often copies code and initialised data from flash to the addresses they run at (TCM, SRAM) and zeroes
`.bss` before it jumps into the copied code, so discovery from the entry alone stops in the startup code and calls
into the copy have no bytes. A Cortex-M project with an entry (or a vector table's Reset) follows the reset code
instead: a deterministic Thumb interpreter over the mapped bytes, with no host effects, runs from the entry and
records every store with where its bytes came from, until the code jumps into memory it wrote, returns, halts or
spends 2,000,000 instructions. It handles the usual shapes alike (GCC-style loops over linker symbols, an Arm-style
region table walked with copy and zero handlers, a routine called with constant triples). A call it cannot follow
(an unmodelled instruction, a branch on a peripheral's value) is skipped with r0-r3, r12, lr and the flags unknown,
and listed in `skipped_calls`.

`binary_info` reports `raw.scatter_load`: `entry`, `steps`, `stop` (`jumped_into_copied_code`, `returned`, `halted`,
`step_budget`, `unsupported_instruction`, `unknown_branch`, `unknown_store_address`, `bad_fetch`,
`too_many_writes`, `call_depth`), `stopped_at`, `continues_at` (the jump into copied code, seeded as a function)
and `copies`: every write of at least 8 bytes by more than one store, in the order they began, with `kind` (`copy`
from mapped bytes, `zero`, or `computed` bytes such as a decompressor's output), `destination`, `length`, `source`
with its `source_region` and `source_offset`, `stores`, `store_sites`, the entry-level `call_site` and `routine`
that wrote it, `executed`, `written_after_jump` and `status`. A write is complete when the part of the follow
that made it finished: the follow is cut into segments, each entry-level call one and the entry's own code between calls
another; a segment that ends (its call returns, or the entry moves on to a call) leaves its writes complete, while
the writes of a call that is skipped, or of the segment the follow stops in after an unclean stop (anything but
`jumped_into_copied_code`, `returned` or `halted`), are `incomplete`. So a copy made by a routine that returned
still maps when a later call polls a peripheral, and a copy cut off mid-routine never does. By default each
complete copy is mapped as a region (`raw.<kind>.<n>`, source `scatter_load` with the copy's index) when it was
not overwritten, a copy's source lies wholly in one backed region, the destination is unmapped, and the 16-region
and 4 MiB caps hold. A copy maps as `code` when the copied code ran and nothing stored into it after the jump;
every other copy is data and maps as writable `ram` with its initial bytes; a zero fill maps as unbacked `ram`.
Otherwise `not_mapped_reason` says why: `not_requested`, `incomplete`, `overwritten`, `computed_bytes`,
`source_not_mapped`, `destination_mapped`, `region_limit`, `byte_limit` or `out_of_range`. `"scatter_load": false` reports the copies
without mapping them; a region you state yourself (for example with `from`) always wins, since a copy into it is
`destination_mapped`. A patch inside a mapped copy is refused with the load address to patch in its source region
instead; the copy keeps the bytes it was admitted with, so patching the source does not refresh it. Other profiles have no reset-code follow.

After the jump into copied code the follow goes on for at most 200,000 more instructions (`after_jump`: `steps`,
`stop`, `stopped_at`); stores there no longer become copies, but a copy the code stores into is marked
`written_after_jump` (data, so it maps as `ram`). Constant stores to the Vector Table Offset Register (0xE000ED08)
anywhere in the follow are listed in `vtor_stores` (the first eight; `vtor_stores_not_listed` counts the rest)
and the last one in `last_vtor_store`; the table at that value is read when a region with bytes
holds it, reported as `vector_table` (each word with its verdict, as for `vector_table`), and its accepted handlers
become seeds, so handlers that only the relocated table names are discovered. Otherwise `vector_table_refused` says
why (for example, the table lies in memory nothing copied).

When discovery from the entry and seeds finds fewer than one function per 16 KiB of a Raw project's code (none at all
in a smaller image), or functions covering less than an eighth of it, `list_functions` adds a one-line `next` naming what to try, and so does `binary_info` once
discovery has run (it never starts discovery itself): `"pointer_tables":
true` on Cortex-M when `false` turned it off, and dropping `"scatter_load": false` when the startup copies it
reported were left unmapped. With `pointer_tables` unset, the scan runs by itself instead (above). Startup code and calls through function pointers are the usual reasons discovery stops early.

Once discovery has run, a Cortex-M `binary_info` lists `raw.starting_points` (at most 8, never cut by the summary
view, computed once per project; before discovery its `next` says how to run it): `address`, `name` and `reasons`, for the reset handler, the function holding scatter-load's jump target and
the target of a trampoline there, `find_main`'s candidate with its confidence and observation, the three largest
routines of the init table the startup function walks (the longest run of at least two Thumb code pointers at an
address that function loads, or one word of a record there points at), and the CRC routines in `inferred_seeds`.

On Cortex-M, discovery also follows code pointers held in data: after it runs, the 16 words from each address the
code references (a record such as an RTOS thread definition passed by address) are read, and an odd word that
points at code outside every discovered function and not at text becomes a seed when its target opens with
`push {..., lr}`, or follows a function end (`bx lr`, `pop {..., pc}`, an unconditional branch, `nop` or zero
padding), and its straight-line decode reaches an unconditional return, branch or halt within 128 instructions with
no undecodable bytes; a word in a run of three code pointers (an array, the two words before the record included)
needs the `push {..., lr}`, which a switch's case labels and constants pointing into code lack. Up to three more
rounds run while each finds new starts, at most 4096 per round; each record and target is judged once across
rounds, and record words read plus instructions decoded share one budget of 1,000,000. `binary_info` reports
`raw.record_seeds` (`seeds`, `rounds`, `work`, `truncated`) once discovery has run. The pointer-table scan has its
own budget of 2,000,000 decoded instructions per region; when it runs out, `walk_budget_exhausted` is set and targets
judged after that have no evidence. For a request with `pointer_tables` unset, the pointer-table scan and the
inferred CRC seeds are applied in one reopen that carries the record seeds over (judged again, not found again);
a reopen that cannot be admitted keeps the first project and says why in `raw.pointer_tables.automatic.refused` or
`raw.inferred_seeds_refused`. In M-profile Thumb code,
`adr rN, #0` forms the address of the word after it (a string placed in the code), and is a data reference.

### A compressed image as the code region

`decode` on the selector itself maps a decoder provider's output as the primary code region, so a compressed
application in a vendor update file is analysed like a plain flash image: `vector_table`, `pointer_tables`, `entry`
and seeds read and address the decoded bytes. `offset`/`length` then select the encoded bytes (at most 8 MiB), and
`decode.expected_output_size` is the mapped size, under the profile's cap (4 MiB for Cortex-M, 128 KiB otherwise),
with any `regions` sharing that cap. `decode` takes the same fields as a region's; any profile accepts it.
`binary_info` reports the receipt as the primary region's `source`, as for a decoded region.

```json
{
  "path": "update.bin",
  "raw": {
    "profile": "cortex-m", "offset": "0x40", "length": 1802, "base_address": "0x8000000", "vector_table": true,
    "decode": { "codec": "lzss-4k", "expected_output_size": 2048 }
  }
}
```

`decode_file_range` (when the decode succeeds) and each reproduced `probe_compression` candidate return this selector
without `profile` and `base_address` as `open_as_raw`, with a one-line `next`: add the profile and load address and
pass it as `raw` with the same path. A decoded size above 4 MiB has no selector.

### Load-address candidates and `base_check`

A decoder knows the decoded size but not the address the image loads at, and a wrong `base_address` quietly ruins a
Cortex-M project: the vector table is refused, literal-pool pointers point nowhere, and the reset-code follow
fetches outside every region. So `decode_file_range` and the first three reproduced `probe_compression` candidates
also return `base_candidates`, and a Cortex-M Raw `binary_info` reports `raw.base_check`.

`base_candidates` ranks at most five load addresses for the bytes as Thumb code, best first. Each has `base_address`,
`alignment` (1 MiB, 64 KiB, 4 KiB or 4), `score`, `confidence` (`strong`, `plausible` or `weak`; only the first can
be more than `weak`, and only with at least one pointer hit), `methods` and `evidence`:

| Evidence | Counts |
| --- | --- |
| `function_pointers` | distinct odd words whose target, under this base, is a `push {..., lr}` prologue in the image |
| `string_pointers` | distinct words pointing at the start of a NUL-terminated run of at least four printable bytes |
| `code_pointers_inside` | distinct odd words inside the image, prologue or not |
| `literal_pointers_inside` | literal-pool and `movw`/`movt` constants of at least 0x10000 inside the image |
| `reset_constants_inside`, `reset_code_pointers` | constants the first 4 KiB of code from the entry loads that land inside, and odd ones landing on prologues (in the score and hits only when no image word already counts them, as for `movw`/`movt` pairs) |
| `vector_table` | a vector table at offset 0 (initial SP in RAM, odd handlers) fits the image from this base |
| `hints` | the container record fields that name this base |

The pointer vote pairs aligned words with prologues and string starts at bases aligned to 4 KiB (a word and a
target agree on `word - offset`), then counts hits exactly for the bases with the most votes. Only bases from
which the image lies in memory a Cortex-M executes from (the code region, SRAM, external RAM) are candidates, and in
SRAM literal constants count half. A base that is not 4 KiB aligned is found only from a vector table or a hint.
Code the startup copies to another address votes for the base of its copy too, so a candidate can be a copy's
displacement; one whose image would span 0x20000000 (code copied to SRAM, seen from flash) ranks after the others
and stays `weak`. Hints that are not candidates are listed in `rejected_base_hints` with the reason (outside
executable memory, more than eight, or ranked below the five listed). Work is bounded: 1 Mi words read, and at
most 4 Mi word-target pairings cast as votes (a pairing with a prologue weighs 2), sampled by cost over all
pairings when there are more and stopped at the cap, so about 16 MiB of votes; scans are memoized by the bytes'
SHA-256. A release build takes about 65 ms for 3.5 MiB and under 100 ms and 30 MiB of heap for any 4 MiB image in
the hostile tests. `probe_compression`'s `sweep` reports `base_candidate_scans` and `base_candidate_ms`; scans run
within its 10-second reproduction deadline, and candidates reached after it get none. Candidates are
suggestions; nothing is applied. When the first is `strong`, or `plausible` with a container record's hint
agreeing with a pointer vote of at least 3 hits, more than any other candidate's, `next` names it with the ready
`profile` and `base_address` to add to `open_as_raw`.

`raw.base_check` (Cortex-M, mapped from a byte range rather than records) judges the asserted base: `verdict`
`consistent`, `looks_wrong` or `unknown`; `evidence` for the asserted base, counted like a candidate's;
`pointer_share` (its pointer hits over the best candidate's); `reset_constants_in_regions` of `reset_constants`
(constants of the reset code inside any mapped region); `candidates`; and, when the base looks wrong,
`better_candidate` and a `next` line naming the base to reopen with, which `binary_info`'s own `next` repeats;
`note` explains a verdict that sets another base aside. It looks wrong when a `strong` or `plausible` candidate has
more than four times its pointer hits, or when the scatter-load follow stopped with `bad_fetch` at an address
outside every region that is a function start under a `strong` or `plausible` candidate with more pointer hits
(`bad_fetch.target` and `bad_fetch.candidate_base`). Copy displacements are never the better base: startup code
that copies functions to a run address makes pointers to the copies vote for `run - load offset`, so a candidate
equal to a copy's displacement in `raw.scatter_load` (destination minus the source's offset in the image) is set
aside with a `note`, and a vector table at offset 0 that fits the asserted base keeps it `consistent` whatever
another base's pointer count. A `bad_fetch` that no such candidate explains (a bootloader jumping to an application
outside its image, a region left unmapped) is reported with `candidate_base` absent and the verdict `unknown`.

## Edits and session state

Analysis runs once per binary when first needed and is cached for the session, and across processes by the
[persistent analysis store](#persistent-analysis-store). Annotations share the
[persistent logs](cli-reference.md#persistence-and-shared-edits) used by CLI and UI; the UI reflects incoming edits.
`annotate_batch` validates all entries before applying one undo step; `check_names` pre-flights candidate names.
`batch` extends the same transaction/history path with typed name/comment/signature/types/global operations
and explicit null clears; it does not expose raw patch or export operations. See
[view and batch contracts](tool-views.md) for required fields, prebatch selectors and receipt bounds.
Types/signatures/globals also persist, with dependency checks rather than inferred class layouts.
The explicit [PDB name-import tool](pdb-symbols.md#shared-tool-and-mcp) previews by default and applies eligible
names as one undoable batch only with `apply: true`. Detail pagination does not restrict the batch's writes.
`transfer_annotations` matches functions with an analyzed earlier build (`from`) and previews, or with
`apply: true` writes, its annotations here as an undoable batch with a provenance ledger entry; see
[build matching and annotation transfer](build-diffing.md).

`record_finding` keeps an investigation ledger in the same log: `kind` (`finding`, `unknown` or `question`), `text`
(at most 2000 bytes), optional `address`, `function` (stored as the containing function's start), up to 8
`evidence` references `{tool, detail}`, `confidence` (`low`/`medium`/`high`), `status` (`open` by default,
`resolved`, `rejected`) and `resolution`. Without `id` it creates an entry and returns its id, which is not
reused within the log, even after an undo; with `id` it changes only the fields given. Each call is one undo step,
and ids are allocated under the log's cross-process lock. Restoring an older copy of the log forgets the ids its
discarded tail used, so a process that opens the restored log can hand them out again.

The ledger holds at most 1,024 entries and 2 MiB of entry JSON. The log is append-only, and each update logs the
whole entry twice (new and replaced value), so updates spend the log's budget too. `record_finding` refuses, with
a message saying which limit, any write that would leave the log past three quarters of what a reader opens or a
checked edit allows: 16 MiB, 8,192 lines and 65,536 JSON separators read; 8,192 records and 8 MiB of edit text
replayed; and, in a session that reads its log checked, 8 MiB of cached annotations and undo history and 1,024
undo steps. The remaining quarter stays for names, comments and other edits, so a full ledger never makes the log
unreadable. Separately, every edit refuses a write that would leave the log past the limits its readers enforce
(see [persistence](cli-reference.md#persistence-and-shared-edits)). There is no compaction, so a log at its limits
can only be read.

`list_findings` filters by `kind`, `status`, `address`, `function` and `contains`, pages with `offset`/`limit`
(default 50, at most 100, and at most 48 KB of JSON), and reports open/resolved/rejected counts per kind over the
whole ledger. Entries recorded on another build of the binary are kept and flagged `image_changed`; giving an
entry a new `address` or `function` re-records it on this build. Entries with neither record no build and are
never flagged. Raw Projects do not offer the ledger, as their annotations are not persisted.

Builds without the ledger skip its log lines when the log holds only ordinary edits, but refuse to open a log
that also holds checked edits (patches, type hints, data or operand types, type libraries or debug layouts) and
ledger entries. Builds with the ledger skip edits of fields they do not know in both cases.

`undo`/`redo` revert/reapply one session step, including a whole batch. When another client's edit blocks undo,
`discard_undo` drops the blocked step from session history, leaving its edits in effect and the log unchanged,
so earlier steps can be undone. It refuses a step that undo could still revert unless `force: true` is explicit.
`build_signatures` writes a database to its requested output path; `identify_functions` and
`import_debug_signatures` persist changes only when `apply: true` is requested.

## Persistent analysis store

Function discovery (functions, blocks, switch tables, cross-references, noreturn facts) is most of the time it
takes to open and analyse a binary, and decompilation is most of the time a query takes: each decompiled function
costs from under a second to several seconds on a large Go binary. rampage keeps each completed discovery, and
each function it decompiles, in a per-user SQLite store, and loads them the next time any process (an MCP server, a
CLI call, the UI) asks for the same thing, so re-opening an already-analysed binary skips discovery and asking for
an already-decompiled function skips the decompiler. Results are identical to fresh ones. Annotations are not
stored there: they stay in their own log and apply over stored results exactly as over fresh ones.

| Setting | Effect |
|---|---|
| `RAMPAGE_ANALYSIS_CACHE` unset | Release builds use the default file; debug builds (tests, `cargo run`) keep the store off. |
| `RAMPAGE_ANALYSIS_CACHE=off` (or `0`, `false`, `no`, empty) | No store: every process analyses and decompiles afresh. |
| `RAMPAGE_ANALYSIS_CACHE=on` (or `1`, `true`, `yes`) | The default file, also in debug builds. |
| `RAMPAGE_ANALYSIS_CACHE=/path/file.sqlite` | That file. |
| `RAMPAGE_ANALYSIS_CACHE_MAX_MB=N` | Size bound in MiB (default 1024), for discovery and decompilations together. |

The default file is `rampage/analysis/rampage-analysis-store-v2.sqlite` under `$XDG_CACHE_HOME` when set, else
`~/.cache`, else `%LOCALAPPDATA%`. On Unix the `analysis` directory is kept private to the user (0700, also when it
already exists; the shared `rampage` directory beside the Sleigh specifications keeps its mode), and the store file
is created 0600 without following symbolic links, so SQLite's `-wal` and `-shm` files are 0600 too. For a custom
path, a missing directory is created 0700 and an existing one keeps its mode; the file is created 0600. Nothing is
written next to the analysed binary, which often sits in a read-only or shared directory; the store is keyed by
content, so a copy of a binary under another path hits too. Deleting the file is always safe. Version 2 (with
decompilations) replaced version 1; creating the default version 2 file removes a version 1 file beside it, and a
version 1 build treats a version 2 file as foreign.

`rampage server store` shows the file, its size and bound, and how many entries of each kind (`discovery`,
`decompile`) it holds; `rampage server store --clear` deletes it (`--json` for either).

`binary_info` (and `binary inspect --json`) report the store's part as `analysis_store`: `state` is `pending` (a
store is configured but analysis has not run in this process), `hit` (discovery loaded from the store), `miss`
(analysed fresh; `detail` says whether it was stored), `rejected` (an entry or the file failed validation, see
`detail`; analysed fresh), `disabled`, or `unsupported` (runtime captures are never stored). Once analysis ran with a
store, `key` is the entry key. Once a decompilation was looked up, `decompilations` counts `hits` (served from the
store), `stored` (decompiled and written) and `rejected` (an entry failed validation; `last_rejection` says why).

**Discovery key.** SHA-256 over every input discovery reads: the whole source file's SHA-256, the loaded image's
offset and length in it, format and architecture slice; for a Raw Project its decoder binding (interpretation
identity: bytes, profile, mapping, entry, seeds, vector and pointer tables, regions; plus the bundled Sleigh
manifest) and the record seeds an automatic reopen carried over, in order; the store schema, rampage version and
`ANALYSIS_VERSION`; and the running executable's path, size and modification time, so a rebuilt rampage never reads
what an earlier build stored. Data packs, annotations and decompiler options do not affect discovery and are not in
the key. A Raw Project owns the bytes it analyses, so its "source file" in the key is the analysed image itself:
every backed region's bytes in region order, decoded and scatter-loaded ones included, not the opened file. Its
interpretation identity binds how each region got its bytes: a decoded region's whole decode receipt (codec, every
LZSS parameter, initial write offset, dictionary fill, expected and actual output size, encoded offset, length and
SHA-256, output SHA-256), a slice's source, a scatter-load copy and whether `scatter_load` was followed and mapped.
Any change to those, to the base address or to the decoded bytes is another entry; only `decode.timeout_ms`, which
decides no byte, is left out. A byte-patched view (after `patch_bytes`, or once `integrity_checks` or another
patch-aware tool has checked the image) is keyed by its own bytes, apart from the original: a view is loaded from its
bytes without the recovery an ordinary open runs (stripped Go symbols), so it can analyse differently. Views over the
same bytes share an entry. A golden test records each fixture's analysis digest under `ANALYSIS_VERSION` and fails
when discovery output changes without a version bump (see [development](development.md#analysis-store-version)).

**Decompilation key.** SHA-256 over the discovery key, the function, the decompiler options (compiler, platform,
BE8), where decompilation runs (in process, or the supervised worker with its limits and its executable's path,
size and modification time), `DECOMPILE_CACHE_VERSION`, and every annotation a decompilation can read: names,
signatures, types, type libraries, debug types, globals, local names and types, type hints, data and operand types,
patches and peripherals. Comments and findings are left out because no decompilation reads them. Only successful
decompilations are stored; `decompile` with `exact_entry` takes another path and is not stored. With
`GHIDRA_INSTALL_DIR` set (external specifications, which can change without rampage knowing) decompilations are
neither read nor stored, and neither are they when the binary's file changed in place after it was opened: its
bytes are no longer the ones the key hashed, so the decompilation runs as without a store (and may refuse the
changed source). A second golden test ties the decompiled C to `DECOMPILE_CACHE_VERSION` (see
[development](development.md#analysis-store-version)).

**Edits.** An edit never re-runs discovery: annotations do not feed it. A decompilation is invalidated by its key:

| Edit | Stored decompilations |
|---|---|
| Comment, finding | All still used. |
| Rename, signature, type, global, local variable, type hint, data or operand type, peripheral map, patch | None match any more: each function is decompiled afresh when next asked for, and stored under the new key. |
| Undo or redo back to earlier annotations | The earlier key's results are used again. |

The invalidation is coarse on purpose: a rename can change any function that refers to the renamed address, and
names also select library prototypes and call fix-ups, so which functions an edit can change is not known without
re-running the decompiler. Every edit an MCP tool makes on an image that has been through patch authority builds a
new effective view over the same bytes; it reuses the stored discovery instead of rediscovering every function,
and, after a comment or finding, the stored decompilations too.

**Untrusted file.** An entry is used only when its payload's stored SHA-256 matches, the key (and, for a
decompilation, the kind) embedded in the payload equals the one looked up, and the payload decodes completely:
for discovery, counts bounded by the bytes left, tags and strings checked, no trailing bytes, sorted orders
revalidated; for a decompilation, a strict JSON shape for exactly the function asked for, with every token span
inside the code on a character boundary. A file with another schema is neither read nor written. A truncated,
corrupt or foreign file or entry is reported as `rejected` and the work is done afresh; it never fails an open or a
decompilation, nor yields a partial result. A payload longer than the bound is refused without being read. The
checksums establish consistency, not authorship: they are not a MAC, so anyone who can write the store file
(0600, the user's own) can change what a later open or decompilation returns. `server store --clear` deletes the
file only after checking that it is an SQLite database whose `meta` names a rampage store layout.

**Concurrency and size.** Several processes may open the same binary at once. The store uses SQLite's write-ahead
log; a reader reads an entry in one statement, so it sees a committed entry whole or not at all. A fresh analysis
is written after it is already in use, and a decompilation after it is computed; a write waits at most 200 ms for
another writer before it is skipped; refreshing an entry's use time never waits. Each write keeps a running total
of the payload bytes in the same transaction; when it passes the size bound, the least recently used entries of
either kind (found through an index on their use time) are evicted until it fits. An entry larger than half the
bound (or a decompilation over 32 MiB) is not stored. Discovery entries are delta-encoded varints, a few bytes per block and
cross-reference; a decompilation entry is its JSON, typically 10–150 KB.

## Authorization and data disclosure

Use MCP only for files you own or have permission to inspect, and grant an AI client access only to authorized
paths. Tool-group selection is discovery control, not a filesystem sandbox or an authorization boundary.
Annotation tools can edit shared logs; consent to those edits through the client's permission policy.

The local server does not itself upload binaries to a model service. An AI client may send questions, tool
results, strings, disassembly, decompiled code and annotations to its configured provider. Confirm authorization
to disclose that material before connecting a remote model; local analysis permission is not necessarily upload
permission. The [desktop assistant](desktop-ui.md#assistant-and-data-disclosure) specifically uses Anthropic's API.
The analysis tools read data and explicit annotations; none runs shell commands or executes the target. The opt-in
`debug` tools are the exception: they control an operator-started stub's execution, and with the operator's flags
can write target memory or kill it (see [debug control](debug-control.md#consent)). Debugger queries can expose
process bytes, registers and module paths to the MCP client. Authorization to inspect that process is not
authorization to upload its contents to a model provider.

## For contributors

Claude Code shows a model only the first 4,096 characters of the server instructions. The instructions therefore
open with the essentials (how to enable groups, one line per group naming its key tools, the first calls, the
debug consent and endpoints) and mark the start of the details; tests in `crates/rampage-mcp/src/lib.rs` keep the
essentials at least 300 characters short of the cut. Put new detail after that mark or in a tool description.

Head-to-head agent runs drive an agent CLI against `rampage server serve` (or another server) through
`tools/agent-bench/claude-runner.py`, with only that server's tools allowed; see the
[parity scorecard](parity-scorecard.md#head-to-head-agent-runs). The parity scorecard records static metrics and
task definitions separately from live MCP and model results; contract checks and scripted transport tests are not
measurements of AI task success.
