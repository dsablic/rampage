# Plugins and extension points

rampage has an experimental, explicitly selected WebAssembly component host for `triage-report`. The Rust guest
composes the report from bounded immutable primitive facts: it classifies strings, groups and ranks findings,
writes summaries and limitations, and selects next steps. It does not call the builtin report through a host
callback. Without `--component`, the builtin workflow remains the default and is unchanged.

This is one executable-extension lane, not a stable public plugin SDK or completion of the broader plugin
roadmap. Read the [plugin security boundaries](plugin-security.md) before selecting a component or worker.

## Extension surfaces

| Layer | Status |
| --- | --- |
| Bounded detector/signature/rule/constants data packs | Implemented; data, not executable code |
| Shared builtin workflow and tool registries | Implemented; statically linked Rust modules |
| Explicit component host and WIT boundary | Experimental triage interface `0.0.1`, JSON schema `1` |
| Component capability and resource controls | Import-free ABI, bounded admission and separate supervised worker |
| Separately loadable workflow composition | `triage-report` Rust guest; builtin still supported |
| Stable public plugin SDK, discovery and general registry integration | Not provided |

Components are not discovered by scanning directories and do not register MCP tools or UI workflows. Other
workflows and primitive tools remain statically linked. Data packs retain their existing data-only behavior.

## Selecting a triage component

The CLI accepts an explicit component and a trusted native worker executable:

```sh
rampage report triage-report sample.elf \
  --component ./triage.component.wasm \
  --component-worker ./target/debug/rampage-plugin-worker \
  --prepare-analysis --json
```

`rampage workflow run triage-report` accepts the same options. `--json` is a global option. The component file
must be a raw binary component, not core Wasm, WAT text or a serialized native Wasmtime artifact.

| Option | Behavior |
| --- | --- |
| `--component FILE` | Selects component execution for `triage-report` only; errors never fall back to the builtin |
| `--component-worker FILE` | Selects the trusted native worker; requires `--component` |
| `--prepare-analysis` | Explicitly starts native whole-program preparation; requires `--component` |
| `--limit N` | Findings retained per section; default 25, maximum 200 |
| `--json` | Emits the host provenance envelope and report as compact JSON followed by a newline |

Worker selection uses `--component-worker`, then `RAMPAGE_PLUGIN_WORKER`, then the `rampage-plugin-worker`
sibling of the running CLI. The selected executable is canonicalized; it must be trusted host code, not a
plugin-supplied dependency. This is a different executable from the native decompiler's `rampage-worker`.

A fresh CLI invocation has no completed analysis, so component execution requires `--prepare-analysis` for
that invocation. Omitting it does not silently start discovery. Preparation is native host work, outside
component fuel, execution deadline and worker memory limits; the flag is not a sandbox for analyzing the input.

### Source admission

Fresh CLI loading admits only a conservative little-endian x86-64 ELF executable/shared-image profile.
PE, Mach-O, universal binaries, CLR sources and Go recovery candidates are currently refused by this preload
profile. Some otherwise valid ELF files are also refused, including unsupported metadata layouts or excessive
metadata expansion. General rampage format support does not imply component-source admission.

The API can prepare an already-loaded, admitted native project, including native PE, without going through
that fresh-load profile. Managed CLR preparation is still refused. The source is limited to 16 MiB and the
complete serialized fact set to 1 MiB. Configured data packs, unavailable bundled signature databases, excessive
facts and changed source/names/configuration reject preparation; they do not produce silently partial inputs.

The host prepares binary metadata, triage, detector results, capabilities, imports, scanned strings, discovered
functions and bundled signature matches. Collections are exhaustive relative to those existing primitives,
not proof that the loader or analysis recovered every fact. `--limit` limits report findings, not input facts.

### Result format

The API returns `PluginTriageReport { provenance, report }`. The host supplies the workflow name, target and
provenance, including the SHA-256 of the actual component bytes. Every report-content field remains a plugin
claim: summaries, evidence, limitations, source labels, confidence (including `observed`) and suggested actions.
Fact-reference validation does not prove the guest's interpretation. Next steps are inert suggestions and are
never dispatched or applied by component execution.

Terminal rendering escapes control and directional-formatting characters in guest prose. Both terminal and
JSON rendering buffer the whole result before writing and reject output over 60,000 bytes; JSON's cap includes
its final newline. Oversized reports are rejected rather than byte-truncated or silently stripped of steps.

## Experimental API and component contract

The API exposes checked component/source opening, completed-analysis preparation and explicit analysis preparation:

- `read_plugin_triage_component` reads the selected component into a bounded execution snapshot.
- `open_plugin_triage_source` performs the restricted fresh-load path.
- `prepare_plugin_triage` requires successful, already-completed native analysis; it never starts discovery.
- `prepare_plugin_triage_with_analysis` explicitly opts into native preparation before collecting facts.
- `PreparedPluginTriage::run_component` runs only the compiled component and revalidates retained host state.

A prepared value retains the exact project, name revision and pack configuration in process. It is not a
serializable report cache or an API accepting arbitrary caller-supplied tool JSON. Cancellation and task-control
checkpoints apply to cooperative host work; whole-program discovery itself is monolithic and checked before
and after, not interrupted internally. The separate cancellation flag reaches the worker supervisor.

The WIT package is `rampage:workflow@0.0.1`, world `triage-plugin`, with exactly one exported interface:

```wit
interface triage {
    run: func(input: list<u8>) -> u32;
    output: func(offset: u32) -> tuple<u64, u64, u64, u64>;
}
```

The full interface name is `rampage:workflow/triage@0.0.1`. There are no host imports. Input and output bytes
carry strict UTF-8 JSON schema `1`, with typed facts, fact IDs, enumerated sources/actions and report-or-failure
responses. Unknown fields, duplicate decoded keys, invalid references and excessive JSON shape are rejected.
This byte transport is not an arbitrary JSON tool-dispatch protocol. The schema can represent managed facts
for guest composition, but the current native source-preparation lane does not admit managed sources.

Each invocation creates a fresh private instance, exclusively owned from `run` through the last output call.
`run` retains a response and returns its byte length. After checking the advertised length, the host copies
32-byte chunks using offsets 0, 32, 64, and so on; the four words are decoded little-endian and the last chunk
is clipped to the admitted length. No guest list pointer is retained across automatic post-return handling.

### Building the guests for local checks

The local oracle wrapper builds the standalone Rust guests as core Wasm, wraps them into real components with
the repository's `rampage-componentize` utility, and runs the supplied command:

```sh
bash tools/ci/plugin-triage-oracle.sh --check \
  cargo test --locked -p rampage-api --test plugin_triage -- --include-ignored --test-threads=1
```

The Rust `wasm32-unknown-unknown` target must already be installed. The wrapper does not install tools. It uses
committed standalone lockfiles, a shared target directory and two Cargo build jobs; guest release builds use
ThinLTO and one codegen unit. Componentization uses pinned `wit-component`, not an external `wasm-tools` CLI.

The supplied command receives `RAMPAGE_TRIAGE_COMPONENT`, `RAMPAGE_RUNTIME_PROBE_COMPONENT` and
`RAMPAGE_PLUGIN_WORKER`. Component files exist only for that command and are removed on wrapper exit. The
runtime-probe guest exercises runtime controls; it is not another migrated user workflow. A native guest oracle
is not evidence of component execution. These local checks are not a general accuracy or performance guarantee.

The example includes the opt-in compiled-component parity check, comparing report bodies with the unchanged
builtin on normal/stripped ELF and an already-loaded native PE at section limits 1 and 25. The PE case exercises
API preparation, not fresh CLI admission. This focused comparison does not establish full format coverage or
close the broader security review.

## Builtin workflow registry

Built-ins register through static registries (plain slices and functions), so CLI, MCP and the UI's assistant
enumerate them instead of listing them by hand. These internal interfaces are not a stable public plugin API.

A guided workflow implements `rampage_api::workflows::Workflow` and is listed in `WORKFLOWS`
(`crates/rampage-api/src/workflows/registry.rs`). The trait gives:

| Method | Used for |
| --- | --- |
| `name` | The tool name (`snake_case`); `rampage workflow run` takes it in kebab-case |
| `summary` | The workflow's one-line CLI help |
| `description`, `group`, `input_schema` | The tool as MCP and the assistant list it |
| `options` | Reading the tool's JSON arguments into `WorkflowOptions` |
| `compares` | Whether it needs a second binary (`--other` / `other`) |
| `run` | Producing the `WorkflowReport` |

From that one entry:

- `rampage_api::tools::tools()` serves it as a tool (its report shrunk to fit one result), so MCP and the
  assistant pick it up;
- `rampage workflow run` accepts it, with its summary in `--help`, and checks `--other` against `compares`.

The flat `report` spelling remains accepted for compatibility. The noun/verb routing shares its argument
definitions and execution action; MCP workflow names and the workflow registry are unchanged.

To add one: write the module under `workflows/`, implement `Workflow` next to the code (the existing ones each
keep theirs above their `impl Project` block), and add it to `WORKFLOWS`. Name it in its tool group's description
(`Group::description`, which the MCP instructions and `enable_tools` show; a test fails until it is there), and
say when to use it in the MCP usage instructions (`rampage-mcp`).

Registry tests (`workflows::registry`, `rampage-mcp`, `rampage-cli`'s `report`) check that names are unique
`snake_case`, that each workflow is a tool of its group with its own description and schema, that it is served by
MCP and named in the instructions and its group's description, and that the CLI workflow selector parses it.

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
