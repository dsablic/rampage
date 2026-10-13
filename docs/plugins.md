# Extension points

rampage has no dynamic plugin loading. Built-ins register through static registries (plain slices and
functions), so that each surface (CLI, MCP, the UI's assistant) enumerates them instead of listing them by hand.
These registries are the internal shape a later sandboxed (WASM) plugin layer would plug into; they are not a
stable public API.

## Workflows

A guided workflow implements `rampage_api::workflows::Workflow` and is listed in `WORKFLOWS`
(`crates/rampage-api/src/workflows/registry.rs`). The trait gives:

| Method | Used for |
| --- | --- |
| `name` | The tool name (`snake_case`); `rampage report` takes it in kebab-case |
| `summary` | The one-line help of `rampage report <WORKFLOW>` |
| `description`, `group`, `input_schema` | The tool as MCP and the assistant list it |
| `options` | Reading the tool's JSON arguments into `WorkflowOptions` |
| `compares` | Whether it needs a second binary (`--other` / `other`) |
| `run` | Producing the `WorkflowReport` |

From that one entry:

- `rampage_api::tools::tools()` serves it as a tool (its report shrunk to fit one result), so MCP and the
  assistant pick it up;
- `rampage report` accepts it, with its summary in `--help`, and checks `--other` against `compares`.

To add one: write the module under `workflows/`, implement `Workflow` next to the code (the existing ones each
keep theirs above their `impl Project` block), and add it to `WORKFLOWS`. Name it in its tool group's description
(`Group::description`, which the MCP instructions and `enable_tools` show; a test fails until it is there), and
say when to use it in the MCP usage instructions (`rampage-mcp`).

Registry tests (`workflows::registry`, `rampage-mcp`, `rampage-cli`'s `report`) check that names are unique
`snake_case`, that each workflow is a tool of its group with its own description and schema, that it is served by
MCP and named in the instructions and its group's description, and that `rampage report` parses it.

## Tools

`rampage_api::tools::tools()` (binary tools) and `file_tools()` (tools that need no loaded binary) are the tool
registry. Each tool belongs to one `Group`; MCP serves the core group and enables the others on request, and
`tools::group_of` lets reports name the group of a suggested tool. Primitive tools are listed there directly;
workflows contribute theirs through the workflow registry above.

## Not registries (yet)

- Detectors: `detect_tools`, `identify_functions`, `yara_scan`, `capa_detect`, `capabilities` and `find_crypto`'s
  constants each take different inputs (a PeID file, rule text or a rule directory, a signature database, nothing)
  and return different evidence, and nothing dispatches over them; a shared trait would only hide those
  differences. Data packs (`--pack`) are how their databases are extended.
- Loaders: ELF, PE and Mach-O all load through the `object` crate in `Binary::open`, with snapshots and embedded
  images as explicit entry points (`open_with`, `open_at_with`); there is no per-format match to replace. A
  `Loader` trait becomes worthwhile when a format arrives that `object` does not parse.
