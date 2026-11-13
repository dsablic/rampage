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

A default session lists 42 tools: the 41 in `core` plus `enable_tools`. Enabling every group lists 85. The
`debug` group adds 14 tools (16 with `--debug-writes`), `--observations` adds `report_observation`, and a
`--corpus` server lists `enable_tools` and the 4 `improve` tools only.

- `core`: `triage`, `binary_info`, `list_functions`, `disassemble`, `decompile`, `function_graph`,
  `assemble`, `patch_bytes`, `revert_patch`, `list_patches`, `export_patched`,
  `function_summary`, `xrefs`, `search`, `list_strings`, `list_imports`, `list_exports`, `rename`, `set_comment`,
  `annotate_batch`, `batch`, `check_names`, `undo`, `redo`, `discard_undo`, `list_annotations`, `record_finding`,
  `list_findings`, `triage_report`,
  `find_main`, `network_surface`, `persistence_surface`, `string_decoding`, `diff_builds`, `inspect_data`,
  `decode_file_range`, `probe_compression`, `file_layout`, `inspect_raw_code`, `inspect_sleigh`, `language_metadata`,
  `class_evidence`; with --observations (or RAMPAGE_OBSERVATIONS), also `report_observation`.
- `detection`: `detect_tools`, `identify_functions`, `build_signatures`, `capabilities`, `yara_scan`,
  `capa_detect`, `find_crypto`, `list_packs`.
- `types`: `set_signature`, `set_types`, `set_global`, `import_debug_signatures`, `import_debug_layouts`,
  `import_pdb_names`, `edit_variable`, `declare_types`, `list_types`, `get_type`, `delete_type`, `apply_data_type`,
  `read_data`, `apply_enum`, `apply_offset`, `function_frame`, `propagate_types`, `import_debug_types`.
- `runtime`: `observe_pointer`, `compare_pointer_observations`, `compare_runtime_bytes`, `observe_indirect_branch`,
  `query_debugger`.
- `diagnostics`: `analysis_diagnostics`, `entry_diagnostics`, `inspect_jump_table`.
- `dotnet`: `dotnet_metadata`, `dotnet_il`.
- `carve`: `carve`, `archive_inventory`.
- `formats`: `build_info`, `pe_resources`, `pe_load_config`, `exception_handlers`, `pyinstaller_archive`,
  `wasm_module`.
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
no listing to navigate. It does not offer the file tools (`carve`, `archive_inventory`, `list_packs`,
`query_debugger`, `inspect_data`, `decode_file_range`, `probe_compression`, `file_layout`, `inspect_raw_code`, `inspect_sleigh`,
`pyinstaller_archive`, `wasm_module`) or the `debug` tools.

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
`image_offset` is not the paging `offset`. Native addresses are hexadecimal strings; most queries also accept
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
The [offline corpus pipeline](signature-corpus.md) measures generated databases separately; its failed or unrun
profiles are not default recognition coverage.

`import_debug_types` reviews embedded-DWARF or explicitly selected identity-matched PDB types into the project
library, independently checking retained producer constraints against native measurements. Whole-plan review
hashes bind atomic library/proof/signature edits; pages do not select writes. Unknown producer alignment and
unsupported bitfields/qualifiers remain explicit. See [checked debug-type import](debug-types.md).

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
See [raw-code windows](raw-code.md). `decode_file_range` and `inspect_data` have separate source/coordinate
contracts; see [decoding](decoding.md) and [data inspection](data-inspection.md).

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
not a total; scanning stops at the candidate after the page. It extracts/decompresses nothing.
`archive_inventory` similarly needs no image or sidecar, but inventories bounded standalone ZIP32 central-directory
metadata. Its member ordinals and metadata hashes are not payload validation or extraction-safe paths; whole-record
JSON pages stay within 60,000 bytes and errors within 4,096 bytes. See [archive inventory](archive-inventory.md).
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
nothing writes or kills on its own, and no signal is delivered. [Debug control](debug-control.md) has each tool's
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

## Raw projects

Raw-capable tools (`binary_info`, `list_functions`, `disassemble`, `function_graph`, `xrefs`, `search`,
`analysis_diagnostics`, `entry_diagnostics`, `capabilities`, `rename`, `set_comment`, `annotate_batch`,
`list_annotations`, `undo`, `redo`, `decompile`) take an optional `raw` object in place of a native image:

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
profile; `offset`/`length` select original-file bytes (1..=131072, or up to 4 MiB for `ARM:LE:32:Cortex`);
`base_address`, `entry` and `seeds` (at most 8192) are internal code-space byte offsets, also for word-addressed
processors, and tool addresses use the same coordinates. The mapping is an analyst assertion, not header admission.
`raw` cannot be combined with `arch`, `image_offset` or `image_length`, and other tools refuse it with "tool X does not
accept Raw projects". Tools that cannot answer on Raw code refuse explicitly (immediate search on Sleigh profiles;
decompilation for every profile except MSP430, AVR8 and Cortex-M, which have reviewed C models). Annotations are
memory-only for the server session and the exact interpretation (bytes, profile, mapping, entry, seed set): no sidecar
or log is written, changed seeds or bytes give a fresh project, and at most 32 interpretations are retained. Each tool's
`raw` schema is a compact shape
(about 0.7 KB); the field meanings and profile list appear once in the server instructions to keep the catalog small. See [explicit Sleigh decoding](sleigh-decoding.md#ordinary-raw-projects).

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
moves with the base.

`"pointer_tables": true` (Cortex-M only, off by default) also seeds functions from tables of Thumb code pointers,
such as handler arrays and command tables, so a raw image needs no hand-built symbol list. A table is a run of at
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

`disassemble` with `count` up to 1000 pages through the whole image as text, data included.
The session keeps at most 32 Raw interpretations and 64 MiB of their input bytes, evicting the least recently used.

### Multiple regions, Intel HEX and S-records

A Cortex-M project (experimental) may map up to 15 further regions of the same file beside the primary code region,
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

Each region has a `kind`: `code` (r-x; seeds may lie here, and on Cortex-M its literal pools fold as constants),
`data` (r--, constant bytes) or `ram` (rw-; its bytes, if any, are initial values the program may change, so the
decompiler never folds loads from it). `offset`/`length` select its bytes in the same file; a `ram` region without
`offset` has no bytes (zero-filled or uninitialised RAM, memory-mapped I/O) and `length` is its size. `decode`
maps the in-memory output of the decoder provider over the range instead: it takes `decode_file_range`'s `codec`,
`lzss`, `expected_output_size` (the region's size), `initial_write_offset`, `dictionary_fill` and `timeout_ms`;
nothing is written to disk. Regions never overlap (the refusal names both), all backed regions together hold at
most 4 MiB, and `vector_table`/`pointer_tables` read the primary region only. Discovery, data references, calls and
the decompiler's memory image span every region, so a call from flash through a literal pool into the RAM stage,
and back, resolves.

`binary_info` lists `raw.regions`, the primary region first (`raw.code`, then `raw.<kind>.<n>`), each with `kind`,
`base_address`, `length`, `sha256` of the mapped bytes (absent when unbacked) and `source`: `file_range`
(`offset`, `length`), `decoded` (`offset`, `length` and the provider's `receipt`: codec, parameters, source-range
SHA-256, output SHA-256, consumption and limits, without the path and preview), `records` (`format`) or
`unbacked`. Each region is also a segment and section with its permissions.

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

## Edits and session state

Analysis runs once per binary when first needed and is cached for the session. Annotations share the
[persistent logs](cli-reference.md#persistence-and-shared-edits) used by CLI and UI; the UI reflects incoming edits.
`annotate_batch` validates all entries before applying one undo step; `check_names` pre-flights candidate names.
`batch` extends the same transaction/history path with typed name/comment/signature/types/global operations
and explicit null clears; it does not expose raw patch or export operations. See
[view and batch contracts](tool-views.md) for required fields, prebatch selectors and receipt bounds.
Types/signatures/globals also persist, with dependency checks rather than inferred class layouts.
The explicit [PDB name-import tool](pdb-symbols.md#shared-tool-and-mcp) previews by default and applies eligible
names as one undoable batch only with `apply: true`. Detail pagination does not restrict the batch's writes.

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
