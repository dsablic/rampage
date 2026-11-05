# MCP reference

`rampage server serve` (compatibility `rampage mcp`) serves the
[Model Context Protocol](https://modelcontextprotocol.io) over stdin/stdout. CLI routing does not rename MCP
tools. No API key is needed for local MCP serving; an external AI client controls its model/provider connection.

With the built CLI on `PATH`, Claude Code configuration is:

```sh
claude mcp add rampage -- rampage server serve
claude mcp add rampage -- rampage server serve --all-tools
```

The second form is for clients that do not refresh their tool list. An explicit path to the installed CLI
can replace `rampage`; install the worker beside it for supervised native decompilation.

## Tool groups

By default the server lists `core` plus `enable_tools`, keeping the initial tool list short. Read-only inspectors
that answer common first questions, such as `language_metadata` and `class_evidence` for class names and
hierarchies, are in `core` so that a client deferring schemas still sees their names.

Claude Code shows a model only the first 4,096 characters of the server instructions. The instructions therefore
open with the essentials (how to enable groups, one line per group naming its key tools, the first calls, the debug
consent and endpoints) and mark the start of the details; tests in `crates/rampage-mcp/src/lib.rs` keep the
essentials at least 300 characters short of the cut. Put new detail after that mark or in a tool description.

- `core`: `triage`, `binary_info`, `list_functions`, `disassemble`, `decompile`, `function_graph`,
  `assemble`, `patch_bytes`, `revert_patch`, `list_patches`, `export_patched`,
  `function_summary`, `xrefs`, `search`, `list_strings`, `list_imports`, `list_exports`, `rename`, `set_comment`,
  `annotate_batch`, `batch`, `check_names`, `undo`, `redo`, `discard_undo`, `list_annotations`, `record_finding`,
  `list_findings`, `triage_report`,
  `find_main`, `network_surface`, `persistence_surface`, `string_decoding`, `diff_builds`, `inspect_data`,
  `decode_file_range`, `inspect_raw_code`, `inspect_sleigh`, `language_metadata`, `class_evidence`.
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
- `formats`: `build_info`, `pe_resources`, `pe_load_config`, `pyinstaller_archive`, `wasm_module`.
- `debug`, only on a server started with a debug endpoint: `debug_connect`, `debug_bind`, `debug_status`,
  `debug_registers`, `debug_read_memory`, `debug_modules`, `debug_snapshot`, `debug_continue`, `debug_wait`,
  `debug_interrupt`, `debug_step`, `debug_breakpoints`, `debug_evidence`, `debug_disconnect`; with the
  --debug-writes flag, also `debug_write_memory` and `debug_write_register`.

Calling `enable_tools` without arguments lists each group's description, tool names/count and enabled state.
`{"groups": ["detection"]}` enables that group; `{"groups": ["all"]}` enables every group. Enabling sends
`notifications/tools/list_changed`. A call to a disabled group's tool fails with the group to enable and runs
nothing. `--all-tools` lists all groups at startup; `RAMPAGE_MCP_TOOLS=all` or a comma-separated list such as
`detection,types` also selects startup groups. `core` is always served. The `debug` group exists only on a server
started with an allowed debug endpoint, and its write tools and `kill` argument only with the operator's
`--debug-writes` and `--debug-kill`; the flags and variables are in [debug control](debug-control.md#consent).

Workflow reports name the `group` of suggested next tools. The desktop assistant offers every binary tool
without group gating, plus the interactive `show_address`; it does not offer file tools
`carve`/`archive_inventory`/`list_packs`/`query_debugger`/`inspect_data`/`decode_file_range`/`inspect_raw_code`/
`inspect_sleigh`/`pyinstaller_archive`/`wasm_module` or the `debug` tools.
`show_address` is not an MCP tool because the server has no interactive listing to navigate.

The [parity scorecard](parity-scorecard.md) records static metrics and task definitions separately from
live MCP/model results. Limits: contract checks and scripted transport tests are not AI task-success measurements.
Head-to-head agent runs drive an agent CLI against `rampage mcp` (or another server) through
`tools/agent-bench/claude-runner.py`, with only that server's tools allowed; see the
[parity scorecard](parity-scorecard.md#head-to-head-agent-runs). They do not execute analyzed programs.
The local stripped Lua workload was also inspected through `triage_report`: static toolchain/string evidence
does not imply target execution, and bundled signature results are distinct from matched-twin evaluator scores.

## Inputs, paging and decompiler tokens

`entry_diagnostics` can report ARM ELF32 EHABI candidates using its existing `function_starts` origin. These
are metadata assertions, not verified boundaries; `CantUnwind` and coalesced interiors are not expanded. See
[ARM unwind candidates](arm-unwind-starts.md).

`identify_functions` retains JSON database inputs and its read-only default. Its default detail window is 100
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

`edit_variable` accepts one current display name or complete native storage object, with name/type changes or
clear flags. It atomically persists the changes and returns complete refreshed C, diagnostics and variable
descriptors within the tool budget. Limits: one whole register/stack mapping and same-size types; invalid or
oversized results do not persist. See [local variables](local-variables.md) for selectors and undo/replay.

`inspect_raw_code` reads an explicitly mapped regular-file window with required architecture, mode, instruction
and data byte orders, and base VA; it returns range hashes, source offsets and bounded linear observations.
Limits: 4096 bytes, 256 instructions, little endian only; no target following or validated code identity.
ARM, Thumb and AArch64 rows print decimal `#` immediates of 10 or more in hex too, as GNU objdump does
(`movt r1, #1934 ; 0x78e`). A native binary tool on a file with no recognised header says how to read it as
headerless code: `inspect_raw_code` for ARM/Thumb, AArch64 and x86, or the `raw` selector for the Raw profiles.
See [raw-code windows](raw-code.md). `decode_file_range` and `inspect_data` have separate source/coordinate
contracts; see [decoding](decoding.md) and [data inspection](data-inspection.md).

Binary tools take `path`, optional `arch`, and optional `image_offset`/`image_length` to open an embedded view.
`image_offset` is not the paging `offset`. Native addresses are hexadecimal strings; most queries also accept
symbols, exports, import-stub names and `sub_<hex>`. Runtime comparison slots/ranges and branch windows require
explicit hexadecimal addresses. See [CLI global options](cli-reference.md#global-options-and-addresses).

Project and file tools refuse an argument their schema does not list, and a missing required one, before
running anything, over MCP and in the agent and desktop assistant alike. The one-line error names the tool's
arguments, marks the required ones, and suggests the likely intended name for a habitual one (`address` for
`at`, `length` for `count` or `size`, `query` for `mode` or `contains`), so a client calling before it has
loaded a schema can correct the call at once; at most 8 unknown names are listed, the rest counted. Debug tools
refuse unknown arguments through their own parsing, without the argument list. The CLI builds its own inputs.

With `contains`, `list_strings` rows carry `match_address`, where the text matches inside the string. Go string
data is not NUL-terminated, so in a Go image a run that code references at more than one address carries a
`note`, and a match its `go_literal` bounds: the last address code references at or before the match (with
`start_is_match` saying whether that is the match itself, since otherwise it may begin an earlier literal), the
first one after it (or the run's end), and how many references the start has. Do not count offsets into such a
run by hand. Listing strings in a Go image runs the cached whole-program analysis.

`function_summary` with `view=summary` or `view=code` adds `callees` (distinct call targets with names and call
counts, taken from all of the function's references, not only the 1,000 the native summary keeps) and refuses for
size only when a single graph block exceeds 60,000 bytes. When a large function does not fit, its graph blocks,
references and callees are returned as whole-row pages: `graph.blocks_offset`/`blocks_next_offset`,
`references.items_offset`/`items_next_offset` (in these views `items_offset` replaces the native page
`offset`) and `callees_offset`/`callees_next_offset`, continued with the
`block_offset`, `reference_offset` and `callee_offset` arguments, and a `fitted` receipt lists any optional
analysis omitted to fit. Graph edges keep indexing blocks by their position in the whole function. `view=full`
still refuses when oversized.

A byte or text `search` charges one unit of match work per candidate start for exact text, so the default
budget covers a 50 MB image; byte patterns with wildcards still charge their length per start. When a budget or
cancellation stops a byte/text scan, the report gives `resume_at` (search again with `range.start` there),
the first 32 `unscanned_ranges` with `unscanned_range_count` and `unscanned_bytes`, and the page a `scan_resume`
hint. A regex stopped by its text-run limit gives no `resume_at`, since resuming would meet the same run.

List queries use `offset`/`limit`, generally defaulting to 100 entries and capped at 1000. `list_functions`
filters with `name_contains`; strings/imports/exports filter with `contains`. Disassembly counts are capped at
1000. Large ordinary binary-tool results can be truncated after 60,000 UTF-8 bytes with an added text marker;
workflow reports shrink to remain valid JSON and retain limitations. Page or narrow a query rather than
assuming a large response is complete. Every tool declares `_meta["anthropic/maxResultSizeChars"]` = 61,024 (the
60,000-byte cap plus room for the marker), so Claude Code shows such a page whole instead of a 50,000-character preview.

`decompile` returns C and address-linked semantic tokens alongside structured recovery evidence. Token byte
spans index the rendered C; flow-only records can be spanless. Storage offsets are qualified by address space,
not automatically program virtual addresses. C production and `no_reported_issues` do not establish correct
recovery. See the [decompiler reference](../crates/rampage-decompiler/README.md) for token/output bounds,
diagnostics and worker requirements; `function_summary` remains a structural alternative, not decompiled C.

`dotnet_metadata` selects `types`, `pinvokes`, `attributes` or `resources`, filtering with `contains`/`parent_token` and
paging entries. `dotnet_il` selects a method token or qualified name and pages instructions with `offset`/`limit`,
or starts at an IL label with `at`. Property signatures/accessor tokens and supported attribute values are
metadata evidence. CIL is never treated as native code; see [managed assemblies](features.md#managed-assemblies).
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
[PE resources and load config](features.md#pe-resources-and-load-config).

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
verified against code. See [toolchain build info](features.md#toolchain-build-info).

`pyinstaller_archive` and `wasm_module` are file tools too: they take any file path and open no project. The first
returns the CArchive cookie, package, Python version and a page of TOC entries (null without cookie magic, and
`{archive: null, rejected_candidates}` when magic matches but none validates as a cookie); the second returns a core
WebAssembly module summary and, with `list`, a page of imports, exports or functions (null without the `\0asm`
magic). Both pages hold whole items within 60,000 JSON bytes and report `next_offset` and `byte_capped`. See
[PyInstaller and WebAssembly](features.md#pyinstaller-archives-and-webassembly-modules).
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
alias such as `msp430`, `avr`, `8051` or `z80`. An unknown name gets the closest profiles; an ARM, Thumb,
Cortex-M, AArch64 or x86 name is pointed to `inspect_raw_code` with an example, since those have no Raw profile; `offset`/`length` select original-file bytes (1..=131072); `base_address`,
`entry` and `seeds` (at most 8192) are internal code-space byte offsets, also for word-addressed processors, and
tool addresses use the same coordinates. The mapping is an analyst assertion, not header admission. `raw` cannot
be combined with `arch`, `image_offset` or `image_length`, and other tools refuse it with "tool X does not accept
Raw projects". Tools that cannot answer on Raw code refuse explicitly (immediate search; decompilation for every
profile except MSP430 and AVR8, which have reviewed C models). Annotations are memory-only for the server session and the exact
interpretation (bytes, profile, mapping, entry, seed set): no sidecar or log is written, changed seeds or bytes
give a fresh project, and at most 32 interpretations are retained. Each tool's `raw` schema is a compact shape
(about 0.5 KB); the field meanings and profile list appear once in the server instructions to keep the catalog small. See [explicit Sleigh decoding](sleigh-decoding.md#ordinary-raw-projects).

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
(see [persistence](cli-reference.md#persistence-and-shared-edits)). There is no compaction yet, so a log at its
limits can only be read.

`list_findings` filters by `kind`, `status`, `address`, `function` and `contains`, pages with `offset`/`limit`
(default 50, at most 100, and at most 48 KB of JSON), and reports open/resolved/rejected counts per kind over the
whole ledger. Entries recorded on another build of the binary are kept and flagged `image_changed`; giving an
entry a new `address` or `function` re-records it on this build. Entries with neither record no build and are
never flagged. Raw Projects do not offer the ledger, as their annotations are not persisted.

Builds that predate the ledger skip its log lines when the log holds only ordinary edits, but refuse to open a
log that also holds checked edits (patches, type hints, data or operand types, type libraries or debug layouts)
and ledger entries. Builds from this one on skip edits of fields they do not know in both cases.

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
