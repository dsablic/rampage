# CLI noun/verb hierarchy

## Scope

The command hierarchy changes discovery and spelling, not analysis behavior, argument interpretation or MCP
tool names. Existing flat command spellings remain accepted as hidden compatibility commands. The primary help
lists noun groups, with each group's help listing its verbs. One argument definition and one execution action
serve both spellings; parsing is handled by clap rather than rewriting raw argument strings.

## Mapping

| Primary noun | Verbs and existing actions |
| --- | --- |
| `binary` | `inspect` → info; triage; analyze; detect; capabilities; audit; carve; inventory |
| `binary` | `list-imports` → imports; `list-exports` → exports; `scan-yara` → yara; `scan-capa` → capa |
| `function` | `list` → funcs; `disassemble` → disasm; decompile; summarize; pseudocode |
| `function` | xrefs; identify; `build-signatures` → signatures; compare; `inspect-table` → jump-table |
| `string` | `list` → strings |
| `language` | `inspect` → metadata |
| `managed` | `inspect FILE` → dotnet metadata; `disassemble FILE --il METHOD` → dotnet IL |
| `annotation` | list; rename; comment; `apply-batch` → annotate-batch; check-names |
| `type` | `import-debug` → debug-types |
| `runtime pointer` | `observe` → observe-pointer; `compare` → compare-pointers |
| `runtime branch` | `inspect` → observe-indirect-branch |
| `runtime bytes` | `compare` → compare-runtime |
| `runtime module` | `correlate` → correlate |
| `pack` | list; check |
| `workflow` | `run WORKFLOW FILE` → report, selecting a registered workflow |
| `server` | `serve` → mcp |

The hidden export-cfg benchmarking action remains accepted. Existing `packs list/check`, `report` and `mcp`
forms remain accepted too. New group names avoid conflicts with those existing top-level spellings.

Managed verbs share the legacy argument definitions, with explicit typed mode validation before opening an
image: `inspect` rejects `--il`; `disassemble` requires it. Legacy `dotnet` retains its dual-mode behavior.
Explicit `--list` conflicts with `--il`; IL conflicts with `--contains`/`--parent-token`. IL `--at` is an IL
offset, requires IL mode and conflicts with explicit `--offset`. Metadata offsets count entries; IL offsets
count instructions. Mode validation adds no silently discarded explicit options.

Runtime verbs preserve their action's existing flags. Pointer comparison takes `--other`, `--at`, `--other-at`;
byte comparison takes `--original`, `--module`, repeatable `--range`; branch inspection takes `--start` and
`--at`. Workflow-specific second-input validation remains before opening the binary.

## Compatibility rules

- Global JSON, architecture, image-offset/length and pack options retain their meanings and supported placement.
- Existing required/conflicting options retain clap validation; side-effecting flags remain explicit.
- Embedded-image restrictions are checked after either spelling maps to the same execution action.
- Workflows still come from their registry; neither workflow names nor MCP tool names change.
- Output structures, annotation paths, worker selection and exit/error behavior remain unchanged by routing.
- Routing introduces no silently discarded options. Existing accepted legacy combinations (including global
  JSON/architecture flags ignored by MCP serving) retain their behavior; tightening them is a separate change.
- The noun labels do not narrow legacy semantics: disassembly is not function-bounded, xrefs can name data or
  instructions, function comparison scores function starts against a reference, and debug import still previews
  unless `--apply` is explicit. Rename/comment retain positional operands and `--clear` validation.

## Acceptance

Pilot inspect, decompile, runtime pointer comparison, workflow run and managed inspection before scaling the
remaining action mappings. Compare output/exit behavior for both spellings; cover required/conflicting options,
global option placement, embedded views, pack propagation and legacy command availability. Review the mapping
and implementation separately, then run existing CLI tests and the complete ordinary workspace suite.
