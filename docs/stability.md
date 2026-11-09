# Stability policy

Takes effect with the first public release (1.0.0 or its release candidates).

This page says which parts of rampage you can build on across releases, which parts may change, and how changes
are announced. rampage's product is its MCP server, so the policy is written around what an agent, a client
configuration or a script depends on.

## Versioning

rampage follows [Semantic Versioning 2.0.0](https://semver.org). The whole workspace shares one version, which the
MCP server reports in its `serverInfo` and `rampage --version` prints.

- **Major** (2.0.0): may make breaking changes to the stable surface below.
- **Minor** (1.1.0): adds tools, arguments, result fields, commands, flags and formats; deprecates without removing.
- **Patch** (1.0.1): fixes bugs without changing the stable surface, except to close a security problem.

Before 1.0.0, any release could break anything. Release candidates (`1.0.0-rc.N`) are previews of the stable
surface; changes between candidates are listed in the [changelog](../CHANGELOG.md).

## Stable

These are covered by the rules in [What counts as breaking](#what-counts-as-breaking).

| Surface | What is stable |
| --- | --- |
| MCP tools | Tool names, their group, argument names and meanings, and result field names and meanings, for every tool in the groups `core`, `detection`, `types`, `runtime`, `diagnostics`, `dotnet`, `carve`, `formats` and `debug`, plus `enable_tools`. The [tool-group list](mcp.md#tool-groups) is the catalog. The `debug` group (GDB remote stubs) is stable; see the experimental paths below. |
| CLI | Command names (the noun/verb routes and the compatibility spellings), flag names and meanings, and exit status zero on success. `--json` output field names follow the same rules as MCP result fields. |
| Annotation log | The `.rampage` and `.rampage-image` sidecar logs, and the capture-identity logs kept for memory snapshots: their location, the JSON Lines record format, the image identity lines and log format 1 (see [annotation log format](#annotation-log-format)). The project type library, debug-type and debug-signature imports and the findings ledger are stored in this log and covered by it; there is no separate export format. |
| Runtime snapshots | The `rampage-snapshot-v1` format, as described in [runtime snapshots](runtime-snapshots.md#snapshot-format). A v1 reader refuses fields it does not know, so v1 never gains a field: a new field means `rampage-snapshot-v2`. |
| Pack archives | The `.rpack` format, `format_version` 1, as described in [data packs](data-packs.md#export-and-import). A reader accepts every archive of a format version it supports whose `min_rampage_version` it meets; there is no upper bound. Archives exported by 0.1.x keep loading. |
| Data packs | The `rampage-pack.toml` manifest (`format_version` 1) and the content formats it names: signature JSON (hash schemes 1 and 2), PeID `userdb.txt`, YARA, capa rules and constant tables (`format_version` 1). See [data packs](data-packs.md#format-versions). |

## Experimental

These may change or disappear in any minor release. Each is marked as experimental where it is documented.

- **The desktop UI** (`rampage-ui`): its views, keys, local manifests and window behaviour.
- **The macOS `debugserver` and Windows-target debugging paths:** implemented but not live-verified. The `debug`
  tools' names and arguments are stable; behaviour specific to these stubs may change once they are verified.
- **Raw processor profiles beyond the reviewed ones:** the Sleigh profiles other than MSP430 (`default`) and AVR8
  (`gcc`), which have reviewed C models. Their names, discovery behaviour and results may change.
- **The `improve` group and the flywheel commands:** the MCP tools served with `--corpus`, the
  `--corpus`, `--flywheel-*`, `--gate`, `--require-novel-gain` and `--observations` options, the
  `report_observation` tool, and the files under `target/flywheel/`.
- **`rampage-eval`:** the evaluation and benchmark harness, its commands and its report formats.
- **Component plugins:** the WebAssembly triage-component host (`--component`) and its WIT interface, which are
  versioned separately (`0.0.1`); see [plugins](plugins.md).
- **Local caches and UI files:** the desktop UI's project-workspace manifests, the historical function-inventory
  cache and derived analysis caches. They can be rebuilt or saved again, and a release may refuse an older one.
- **The Rust crates as libraries.** rampage is used through MCP, the CLI and its file formats. The crates'
  public Rust APIs are internal and may change in any release.

## What counts as breaking

A change to the stable surface is breaking if a client written against the earlier release can fail or
misread a result. For MCP tools and CLI commands that means:

- removing or renaming a tool, command, argument, flag or result field;
- moving a tool to another group, or out of `core`;
- making an optional argument required, or narrowing what an argument accepts;
- changing a field's meaning, type or units, or the meaning of an argument;
- turning a result that was returned into an error for the same input, except where the input was outside the
  documented limits.

These are not breaking:

- adding a tool, group, command, optional argument, flag or result field (clients must ignore fields they do not
  know);
- adding a value to an open-ended string set such as an error kind or a finding category;
- changing tool descriptions, server instructions, error message text, limitations text or the order of fields;
- changing analysis results: better discovery, decompilation or names are improvements, not API changes;
- changing size caps and default page sizes, as long as paging still reports totals and omissions;
- refusing an unknown argument (the argument was never part of the surface).

For file formats:

- A 1.x release reads every file a 1.0 or later 1.x release wrote: annotation logs, snapshots, `.rpack` archives
  and data packs.
- Within a format version, a later release adds information only in ways earlier readers skip, as listed for
  each format below and in [data packs](data-packs.md#format-versions). Earlier readers warn where they can.
- A format change an older reader cannot skip gets a new version marker (`rampage-snapshot-v2`, `.rpack`
  `format_version` 2, a new signature hash scheme), and the new release keeps reading the old version.

### Annotation log format

The log is JSON Lines. Identity lines (`{"image": "<sha256>", "format": 1}`) carry the log format; a log without
one, such as every log 0.1.x wrote, is format 1.

- **Forward, within format 1:** every reader skips edits of a field it does not know (a later release's new kind
  of annotation goes in as an edit of a new field) and ignores keys it does not know on lone edits and identity
  lines. New line kinds, and new keys on batch headers and batch members, are not skipped by every reader (a
  checked read refuses them), so they need format 2.
- **Newer format:** a reader refuses a log that declares a format newer than it reads, naming it, before applying
  any edit; it appends nothing to it. Readers before 1.0 predate the marker and cannot detect a format-2 log.
- **Backward:** every 1.x release opens every format-1 log, including those 0.1.x wrote. Committed logs in
  `tests/fixtures/annotation-logs/`, written by rampage's own writers (names, comments, a batch, ledger entries,
  a type-library declaration and a data type), pin this.

## How the stable surface is checked

Snapshots under `tests/contract/` pin the stable surface, and tests compare it with the live build:

- `mcp-tools.json`: every tool's name, group and arguments (type and whether required), from `tools/list` on a
  server with every group, a debug server with `--debug-writes` and `--debug-kill`, and a corpus server (the
  `improve` tools, marked experimental).
- `mcp-results-<group>.json`, one per stable group: the result field paths every tool of the group returns on
  committed fixtures (`debug` against the scripted fake stub). Result fields are observed, not derived from types,
  so a field that a fixture does not produce is not pinned. A tool a group adds without being exercised fails the
  test. `query_debugger` runs against a scripted bridge socket, so its envelope is pinned; the fields inside
  `data` follow the bridge protocol (`rampage-lldb-query-v1`).
- `cli-commands.json`: every CLI route, the compatibility spellings included, with its flags and positionals.
- `cli-json.json`: the `--json` field paths of the main commands on committed fixtures.

Each difference is classified. A new tool, command, optional argument, flag or result field, or a widened argument
type, is additive: record it with `RAMPAGE_UPDATE_CONTRACT=1 cargo nextest run --workspace -E 'test(/contract/)'`
and commit the snapshot. A removed or renamed tool, command, argument, flag or field, a newly required argument, a
narrowed type or a tool moved to another group is breaking: the test fails, and the update command refuses it.
Keep the old name working as a deprecated alias, or, for a major release, record the break with
`RAMPAGE_UPDATE_CONTRACT=breaking`. Committed fixtures pin the file formats in the same way: the annotation logs
above, the `compat-v1` data pack and its 0.1.0 `.rpack` archive in `tests/fixtures/packs/`, and the
`rampage-snapshot-v1` files in `tests/data/`.

## Deprecation

- A deprecated tool, argument, command or flag keeps working for at least one minor release, and in practice until
  the next major release.
- Deprecations are listed in the [changelog](../CHANGELOG.md) under the release that made them, with the
  replacement.
- A deprecated MCP tool or argument says so in its description, so an agent sees it. A deprecated CLI command or
  flag prints a warning on stderr.
- The CLI's flat compatibility spellings (`rampage info`, `rampage mcp`, `rampage decompile` and so on) are part of
  the stable surface in 1.x. `rampage server serve` is the primary spelling of `rampage mcp`.

## Security exceptions

A patch release may narrow behaviour to close a vulnerability, for example by refusing an input that crashed a
parser or by tightening a debugger consent check, even where that changes a stable result. The changelog says so.
