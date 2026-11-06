# Stability policy

**Status:** draft for maintainer review; it takes effect with the 1.0.0 release.

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
| MCP tools | Tool names, their group, argument names and meanings, and result field names and meanings, for every tool in the groups `core`, `detection`, `types`, `runtime`, `diagnostics`, `dotnet`, `carve` and `formats`, plus `enable_tools`. The [tool-group list](mcp.md#tool-groups) is the catalog. The core `debug` tools (GDB remote stubs) are stable; see the experimental paths below. |
| CLI | Command names (the noun/verb routes and the compatibility spellings), flag names and meanings, and exit status zero on success. `--json` output field names follow the same rules as MCP result fields. |
| Annotation log | The `.rampage` and `.rampage-image` sidecar logs: their location beside the binary, the JSON Lines record format and the image identity lines. A log written by a 1.x release opens in every later 1.x release. |
| Runtime snapshots | The `rampage-snapshot-v1` format, as described in [runtime snapshots](runtime-snapshots.md#snapshot-format). |
| Pack archives | The `.rpack` format, `format_version` 1, as described in [data packs](data-packs.md#export-and-import). |
| Data packs | The `rampage-pack.toml` manifest and the content formats it names: signature JSON (hash schemes 1 and 2), PeID `userdb.txt`, YARA, capa rules and constant tables. See [data packs](data-packs.md). |

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
- A new record kind in the annotation log is skipped by older readers rather than refused. This already holds:
  every reader skips edits of fields it does not know.
- A format change an older reader cannot skip gets a new version marker (`rampage-snapshot-v2`, `.rpack`
  `format_version` 2, a new signature hash scheme), and the new release keeps reading the old version.

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
