# rampage

An open-source Rust reverse engineering toolkit with AI agents as first-class clients: a scriptable CLI, an MCP server
and a desktop UI share the same analysis API. The long-term goal is a general-purpose IDA Pro alternative.

## Status and scope

This is an early toolkit, not a claim of IDA/Ghidra parity. It provides recursive-descent function discovery,
cross-references, saved annotations, triage and embedded Ghidra decompilation to C. Reports retain evidence,
confidence and limitations; producing C is not proof of correct recovery.

- Native executable analysis: ELF, PE and Mach-O, including universal slices and selected embedded images.
- Instruction decoding: x86/x86-64, AArch64, ARM/Thumb and several additional architectures.
- Investigation: library identification, heuristic/rule scans, guided workflows and bounded multi-slice analysis.
- Managed code: .NET metadata, method/property signatures, attributes and paged CIL disassembly;
  CIL remains separate from native analysis.

Use rampage for files and captures you own or have permission to inspect. Analysis does not execute the target,
launch/attach/resume a target process or bypass protections. Snapshot capture and the LLDB query bridge operate only
inside an existing authorized stopped debugger session. Native decompiler supervision is not an OS sandbox.
See the [feature reference](docs/features.md) for architecture coverage and limits, and
[the design](docs/plans/2026-10-10-rampage-design.md) for the roadmap.

[Development and cleanup](docs/development.md) describes the smaller build profiles, validation and worktree lifecycle.

## Rust quickstart

Build with a Rust toolchain supporting edition 2024, a native C/C++ compiler and zlib development files.
The decompiler engine and processor specifications are bundled; no external Ghidra installation is required.
Replace `sample.elf` and `main` with an authorized binary and a function it contains.

```sh
cargo build --release -p rampage-cli -p rampage-worker
./target/release/rampage binary inspect sample.elf
./target/release/rampage workflow run triage-report sample.elf
./target/release/rampage function decompile sample.elf --at main --isolated
```

Keep `rampage-worker` beside the CLI for supervised native decompilation. `--isolated` requires worker execution;
batch decompilations and workflow previews also require it. See the
[decompiler reference](crates/rampage-decompiler/README.md) for recovery
diagnostics and resource/platform limits. `tools/install.sh [ROOT] [--ui]` installs the worker and CLI together,
optionally with the desktop client. The examples below assume `rampage` is on `PATH`.

## Primary commands

```sh
rampage binary triage sample.elf --json
rampage binary audit sample.elf --entries --at main --json
rampage function list sample.elf --name main
rampage function disassemble sample.elf --at main --count 20
rampage function decompile sample.elf --at main --exact-entry --isolated --json
rampage function xrefs sample.elf --to main
rampage string list sample.elf --contains greeting
rampage binary analyze module.dylib --all-architectures --workflow triage-report --function exported_entry --json
rampage managed inspect sample.dll --list types
rampage managed disassemble sample.dll --il 'Example.Program::Main' --at IL_0000
rampage server serve
```

The noun/verb hierarchy is the primary CLI. Existing flat spellings such as `info`, `funcs`, `decompile`,
`analyze`, `dotnet`, `report` and `mcp` remain accepted for compatibility; MCP tool names are unchanged.
Use `rampage --help` or a group's `--help` to discover routes. The
[CLI reference](docs/cli-reference.md) maps every route to its compatibility spelling and documents flags,
addresses, managed-code paging and annotation persistence. See [CLI batch analysis](docs/cli-analysis.md)
for multi-architecture task selection, failure reporting and output budgets.

`--exact-entry` opts into bounded local host context over the full mapped image, without whole-program discovery;
it is an analyst assertion, not proof of a function boundary. Default decompilation semantics remain unchanged.

## Clients and documentation

Run the desktop client with:

```sh
cargo run --release -p rampage-ui -- sample.elf
```

The UI offers listings, graphs, decompilation and shared annotations. **Open for exact-entry…** defers global
analysis and opens a separate explicit-Run window; **Project workspace…** retains up to eight modules with
qualified navigation and separate local Save, manifest-only Preview and reviewed Open actions. Ordinary open and
Pseudocode behavior remain unchanged. Its optional Assistant tab sends questions
and model-read code/tool results to Anthropic's API; use it only with permission to disclose that material.
Local analysis and MCP serving do not require an API key. See the client references before connecting an AI model.

| Reference | Contents |
| --- | --- |
| [Features](docs/features.md) | Formats, decoders, analysis capabilities, limits and reported measurements |
| [CLI](docs/cli-reference.md) | Command catalog, compatibility map, global flags and shared annotations |
| [MCP](docs/mcp.md) | Setup, tool groups, paging/tokens, edits and client data-disclosure boundaries |
| [Data packs](docs/data-packs.md) | Manifest/schema, precedence, validation and constant databases |
| [Desktop UI](docs/desktop-ui.md) | Views, keys, embedded images, assistant consent and offscreen checks |

Additional focused guides:

- [Runtime snapshots](docs/runtime-snapshots.md) and the [read-only LLDB query bridge](docs/lldb-query.md).
- [Exact-entry analysis](docs/entry-analysis.md): opt-in decompilation, independent entry diagnostics and limits.
- [Desktop exact-entry](docs/exact-entry-ui.md): deferred opening, validation, explicit Run and cooperative Cancel.
- [Project workspaces](docs/project-workspaces.md): retained modules, qualified addresses and reviewed local manifests.
- [Debugger workspace](docs/debugger-workspace.md): explicit local inspection, Prepare/Compare/Save/Open and privacy.
- [Debug signature import](docs/debug-signatures.md) and [ARM64 semantics validation](docs/arm64-development.md).
- [Benchmarks](docs/benchmarks.md) and the [decompiler integration corpus](docs/decompiler-corpus.md).
- [Extension points](docs/plugins.md): internal registries, not dynamic plugin loading or a stable public plugin API.

The [development reference](docs/features.md#measurements-and-development) covers crate layout, fixture rebuilding
and decoder-table generation. Existing benchmark measurements are sample-specific, not general accuracy or
latency guarantees.

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The decompiler embeds Ghidra (Apache-2.0), and the
AArch64/AArch32 decoder tables are generated from Arm's machine-readable architecture specification, which Arm
licenses under the BSD 3-clause license; see [Arm's license](crates/rampage-arch/src/a64/LICENSE-ARM).
