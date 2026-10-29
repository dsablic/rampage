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

By default the server lists `core` plus `enable_tools`, keeping the initial tool list short.

- `core`: `triage`, `binary_info`, `list_functions`, `disassemble`, `decompile`, `function_graph`,
  `assemble`, `patch_bytes`, `revert_patch`, `list_patches`, `export_patched`,
  `function_summary`, `xrefs`, `search`, `list_strings`, `list_imports`, `list_exports`, `rename`, `set_comment`,
  `annotate_batch`, `batch`, `check_names`, `undo`, `redo`, `discard_undo`, `list_annotations`, `triage_report`,
  `find_main`, `network_surface`, `persistence_surface`, `string_decoding`, `diff_builds`, `inspect_data`,
  `decode_file_range`, `inspect_raw_code`, `inspect_sleigh`.
- `detection`: `detect_tools`, `identify_functions`, `build_signatures`, `capabilities`, `yara_scan`,
  `capa_detect`, `find_crypto`, `list_packs`.
- `types`: `set_signature`, `set_types`, `set_global`, `import_debug_signatures`, `import_debug_layouts`,
  `import_pdb_names`, `class_evidence`, `language_metadata`, `edit_variable`, `declare_types`, `list_types`, `get_type`, `delete_type`,
  `apply_data_type`, `read_data`, `apply_enum`, `apply_offset`, `function_frame`, `propagate_types`,
  `import_debug_types`.
- `runtime`: `observe_pointer`, `compare_pointer_observations`, `compare_runtime_bytes`, `observe_indirect_branch`,
  `query_debugger`.
- `diagnostics`: `analysis_diagnostics`, `entry_diagnostics`, `inspect_jump_table`.
- `dotnet`: `dotnet_metadata`, `dotnet_il`.
- `carve`: `carve`, `archive_inventory`.
- `formats`: `pe_resources`, `pe_load_config`.

Calling `enable_tools` without arguments lists each group's description, tool names/count and enabled state.
`{"groups": ["detection"]}` enables that group; `{"groups": ["all"]}` enables every group. Enabling sends
`notifications/tools/list_changed`. A call to a disabled group's tool fails with the group to enable and runs
nothing. `--all-tools` lists all groups at startup; `RAMPAGE_MCP_TOOLS=all` or a comma-separated list such as
`detection,types` also selects startup groups. `core` is always served.

Workflow reports name the `group` of suggested next tools. The desktop assistant offers every binary tool
without group gating, plus the interactive `show_address`; it does not offer file tools
`carve`/`archive_inventory`/`list_packs`/`query_debugger`/`inspect_data`/`decode_file_range`/`inspect_raw_code`.
`show_address` is not an MCP tool because the server has no interactive listing to navigate.

The [parity scorecard](parity-scorecard.md) records static metrics and task definitions separately from
live MCP/model results. Limits: contract checks and scripted transport tests are not AI task-success measurements.
The optional OpenCode transport emits one-turn JSON intents; the benchmark executes them through actual MCP
discovery/calls, with host tools disabled and fixture paths restricted. It does not execute analyzed programs.
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
See [raw-code windows](raw-code.md). `decode_file_range` and `inspect_data` have separate source/coordinate
contracts; see [decoding](decoding.md) and [data inspection](data-inspection.md).

Binary tools take `path`, optional `arch`, and optional `image_offset`/`image_length` to open an embedded view.
`image_offset` is not the paging `offset`. Native addresses are hexadecimal strings; most queries also accept
symbols, exports, import-stub names and `sub_<hex>`. Runtime comparison slots/ranges and branch windows require
explicit hexadecimal addresses. See [CLI global options](cli-reference.md#global-options-and-addresses).

List queries use `offset`/`limit`, generally defaulting to 100 entries and capped at 1000. `list_functions`
filters with `name_contains`; strings/imports/exports filter with `contains`. Disassembly counts are capped at
1000. Large ordinary binary-tool results can be truncated after 60,000 UTF-8 bytes with an added text marker;
workflow reports shrink to remain valid JSON and retain limitations. Page or narrow a query rather than
assuming a large response is complete.

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

`pe_resources` pages PE resource leaves with `offset`/`limit`, filtered by `type` (`RT_VERSION`, `VERSION`, `16` or a
string type name). Each leaf carries its type, name, language, data RVA, size, code page, image offset and whether
its bytes are in the file. RT_VERSION and RT_MANIFEST leaves on the page are decoded until 24,000 payload bytes are
spent (`decode_skipped` counts the rest); other payloads are located only. `pe_load_config` reads the load config
up to its own declared Size, listing later fields in `absent_fields`, and adds CET flags and findings against the
DllCharacteristics that triage reports. Both return null for a non-PE image. See
[PE resources and load config](features.md#pe-resources-and-load-config).

`carve` accepts any file path rather than requiring a loadable binary. Pages use `offset`/`limit` and `more`,
not a total; scanning stops at the candidate after the page. It extracts/decompresses nothing.
`archive_inventory` similarly needs no image or sidecar, but inventories bounded standalone ZIP32 central-directory
metadata. Its member ordinals and metadata hashes are not payload validation or extraction-safe paths; whole-record
JSON pages stay within 60,000 bytes and errors within 4,096 bytes. See [archive inventory](archive-inventory.md).
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

`profile` is a closed Raw language ID, listed in the server instructions; `offset`/`length` select original-file bytes (1..=131072); `base_address`,
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
These tools analyze data and explicit annotations, not arbitrary shell commands or execution of the target.
Debugger queries can expose process bytes, registers and module paths to the MCP client. Authorization to inspect
that process is not authorization to upload its contents to a model provider.
