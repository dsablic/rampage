# rampage

An open-source Rust reverse engineering toolkit with AI agents as first-class clients: a scriptable CLI, an MCP server
and a desktop UI share the same analysis API. The long-term goal is a general-purpose IDA Pro alternative.

## Status and scope

This is an early toolkit, not a claim of IDA/Ghidra parity. It provides recursive-descent function discovery,
cross-references, saved annotations, triage and embedded Ghidra decompilation to C. Reports retain evidence,
confidence and limitations; producing C is not proof of correct recovery.

- Native executable analysis: ELF, PE and Mach-O, including universal slices and selected embedded images.
- Instruction decoding: x86/x86-64, AArch64, ARM/Thumb and several additional architectures.
- Investigation: library identification, heuristic/rule scans, guided workflows, a durable findings ledger and
  bounded multi-slice analysis.
- Toolchain and container metadata: Go build info and cargo-auditable dependencies, PE resources and load config,
  PyInstaller archives and WebAssembly modules.
- Managed code: .NET metadata, method/property signatures, attributes and paged CIL disassembly;
  CIL remains separate from native analysis.
- Debugging (opt-in, MCP only): GDB remote stubs, macOS `debugserver` and Windows RSP stubs (the last two not
  yet live-verified); all-stop control, breakpoints, project correlation, and writes or kill behind operator flags.

Use rampage for files, captures and processes you own or have permission to inspect. Static analysis never
executes the target or bypasses protections. The opt-in `debug` tools control a GDB remote stub or `debugserver`
that the operator started and allowed; rampage never launches or attaches to a process. The LLDB query bridge
reads an existing authorized stopped LLDB session. Native decompiler supervision is not an OS sandbox.
See the [feature reference](docs/features.md) for architecture coverage and limits, and
[the parity roadmap](docs/plans/2026-10-16-ida-ghidra-parity-roadmap.md) for planned work.

[Development and cleanup](docs/development.md) describes the smaller build profiles, validation and worktree lifecycle.

## Supported hosts

- **macOS on Apple silicon (ARM64):** the primary development host. Hosted CI builds and tests the whole workspace,
  including the desktop UI snapshots.
- **Linux x86-64 (Ubuntu 24.04):** supported. Hosted CI builds the whole workspace and runs its tests, Clippy and
  the x86-64 layout and component gates, and release archives are built for `x86_64-unknown-linux-gnu`. UI snapshot
  tests are macOS-only; `rampage-ui` builds and ships for Linux but its interface is untested there.
- **Windows:** not supported as a host. The analysis API uses Unix-only file APIs, and supervised decompilation and
  component plugins need 64-bit Linux or macOS. PE binaries can still be analysed, and Windows targets debugged
  through an RSP stub, from a macOS or Linux host.
- Other hosts, such as Intel macOS and Linux ARM64, are untested.

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

- [Debug sessions](docs/debug-control.md): operator-allowed GDB remote stubs, `debugserver` and Windows stubs;
  execution control, project correlation, and writes or kill behind operator flags.
- [Runtime snapshots](docs/runtime-snapshots.md) and the [read-only LLDB query bridge](docs/lldb-query.md).
- [Exact-entry analysis](docs/entry-analysis.md): opt-in decompilation, independent entry diagnostics and limits.
- [Desktop exact-entry](docs/exact-entry-ui.md): deferred opening, validation, explicit Run and cooperative Cancel.
- [Project workspaces](docs/project-workspaces.md): retained modules, qualified addresses and reviewed local manifests.
- [Module references](docs/module-references.md): bounded loaded-PE declarations, coverage and explicit navigation.
- [Historical inventory cache](docs/function-inventory-cache.md): explicit cached/unverified candidate browsing.
- [Owned worker observations](docs/worker-observations.md): host milestones, cleanup ownership and owned measurements.
- [Debugger workspace](docs/debugger-workspace.md): explicit local inspection, Prepare/Compare/Save/Open and privacy.
- [Debug signature import](docs/debug-signatures.md) and [ARM64 semantics validation](docs/arm64-development.md).
- [Library signature inputs](docs/signature-imports.md): native/PAT databases and explicitly configured FID import.
- [Fuzzy library candidates](docs/fuzzy-signatures.md): secondary similarity evidence without automatic naming.
- [Search](docs/search.md): bounded byte/text/regex, instruction and reference queries with native function context.
- [Checked patches/export](docs/patching.md) and [bounded assembly](docs/assembly.md): annotation-backed effective
  views, create-new export and static owned-fixture verification without target execution.
- [Compact views and annotation batches](docs/tool-views.md): complete evidence-aware responses and one-step
  checked annotation transactions, without a parallel patch/history path.
- [Explicit Sleigh decoding](docs/sleigh-decoding.md): bounded processor-profile windows, raw p-code and
  conservative seeded discovery; not ordinary-project or C-ABI admission.
- [Benchmarks](docs/benchmarks.md) and the [decompiler integration corpus](docs/decompiler-corpus.md).
- [Plugins and extension points](docs/plugins.md): experimental explicit triage components and builtin registries.
- [Plugin security boundaries](docs/plugin-security.md): admission, resource limits, claim provenance and exclusions.

The [development reference](docs/features.md#measurements-and-development) covers measurements, fixture rebuilding
and decoder-table generation. Existing benchmark measurements are sample-specific, not general accuracy or
latency guarantees.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for building, testing and how a feature lands. Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md), not in public issues.

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The decompiler embeds Ghidra (Apache-2.0), and the
AArch64/AArch32 decoder tables are generated from Arm's machine-readable architecture specification, which Arm
licenses under the BSD 3-clause license; see [Arm's license](crates/rampage-arch/src/a64/LICENSE-ARM).
