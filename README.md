# rampage

rampage is a reverse-engineering tool built for AI agents. Its product is an
[MCP](https://modelcontextprotocol.io) server: an agent such as Claude Code connects to it and loads, disassembles,
decompiles, searches, types and annotates binaries through tools whose results are compact, paged and
evidence-linked. A CLI and a desktop UI use the same analysis API.

It is for agents doing reverse engineering, and for the people who run them: malware and firmware analysts,
vulnerability researchers, and anyone who wants a model to answer questions about a binary without driving a
GUI disassembler through a bridge.

Why it matters:

- **Built for model context.** Every tool has a size cap, pages large results with explicit cursors and totals,
  and says what it left out. Tools are grouped, so a session starts with a short tool list and enables more on
  demand.
- **Native and self-contained.** Loaders, decoders and analysis are written in Rust. Decompilation uses Ghidra's
  decompiler, embedded with its processor specifications: no Java, no Ghidra install, no project import step.
- **Evidence over assertion.** Results carry their evidence, confidence and limitations. Annotations and an
  investigation ledger persist beside the binary and replay in every client.
- **Heuristics as data.** Library signatures, detection rules, capa and YARA rules and crypto constants are data
  packs, which can be added, exported and checked without rebuilding rampage.

rampage is Apache-2.0. The [changelog](CHANGELOG.md) describes the first public release and the
[stability policy](docs/stability.md) what it promises. Use rampage on files and processes you own or are allowed
to inspect.

## Evidence: agent head-to-head

One model (`claude-sonnet-5-5` through Claude Code) answered the same tasks through one MCP server at a time:
rampage, or REA's MCP server (`morluto/rea` 6.8.0) over headless Ghidra 12.2. Suite v2 has 15 harder tasks
(stripped C++, typing, multi-step investigation, a 49.2 MB stripped Go binary, raw firmware, build diffing),
each run 3 times per server and scored by machine against truth derived independently of both servers.

| Suite v2 | rampage | REA (Ghidra) |
| --- | --: | --: |
| Correct, strict, all 15 tasks | 44/45 | 38/43 |
| Correct, core only (C++, typing, investigation; the fairer view) | 29/30 | 25/28 |
| Server tool calls per run, median | 3 | 6 |
| Wall time per run outside the scale tasks, median | 12.5 s | 27.0 s |
| Reported model cost over the scored runs | $3.63 | $5.57 |

On these tasks with one model, rampage is modestly ahead on accuracy and clearly ahead on tool calls, time
and tokens. The tasks were written by the rampage project and lean towards what it was built for; REA ran without
Rizin, so part of its catalog could not run; 15 tasks × 3 runs is small. REA's denominator is 43 because two of
its runs fell back to another model and are excluded. Read the [suite v2 report](docs/benchmarks/agent-h2h-v2-2026-11-05.md)
for its fairness corrections to scoring, the failure analysis and rampage's own ranked gaps, and the
[first head-to-head run](docs/benchmarks/agent-h2h-2026-11-05.md) for 20 simpler tasks, where both servers were
near 100%.

## Quickstart

### Build and install

Each [GitHub release](https://github.com/dsablic/rampage/releases) has prebuilt archives for macOS on Apple silicon
(`aarch64-apple-darwin`), Linux x64 (`x86_64-unknown-linux-gnu`) and Linux ARM64 (`aarch64-unknown-linux-gnu`), each
with a `.sha256` file. Download both into one
directory and run `tools/install.sh --archive rampage-<version>-<target>.tar.gz` from a checkout; it verifies the
checksum before installing. To build from source instead, you need:

- a Rust toolchain through [rustup](https://rustup.rs) (`rust-toolchain.toml` selects stable, edition 2024);
- a C/C++ compiler and zlib development files, for the embedded decompiler:
  - macOS: the Xcode Command Line Tools (`xcode-select --install`);
  - Debian or Ubuntu: `sudo apt install build-essential zlib1g-dev clang`.

The build compiles Ghidra's C++ decompiler and takes 10 to 30 minutes; see
[getting started](docs/getting-started.md#1-build-and-install).

```sh
git clone https://github.com/dsablic/rampage.git
cd rampage
tools/install.sh            # builds and installs rampage and rampage-worker into ~/.local/bin
```

`tools/install.sh ROOT` installs into `ROOT/bin` instead, and `--ui` adds the desktop client. The rest of this
page assumes `rampage` is on `PATH`.

Keep `rampage-worker` beside `rampage`: decompilation runs in that supervised worker process, with time, memory
and output limits. **If rampage cannot find the worker, it decompiles in-process**, inside `rampage` itself. The
MCP server warns about this at startup, and each `decompile` result says which it used (`"decompiler":
"supervised"` or `"in-process"`). Add `--require-worker` to `rampage server serve` to refuse instead.

### Connect Claude Code

```sh
claude mcp add rampage -- rampage server serve
```

This registers rampage for the current directory only (Claude Code's default `local` scope). To use it in every
project, register it with user scope:

```sh
claude mcp add --scope user rampage -- rampage server serve
```

Then ask Claude about a binary, for example:

> Using rampage, look at tests/fixtures/bench-v2/bin/vault-arm64.macho. It encrypts a message with a stream
> cipher. Which function derives the cipher's key, and what constant does it XOR into each key word?

### Connect another MCP client

rampage speaks MCP over stdio. Most clients take a JSON `mcpServers` entry:

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

Use the absolute path to `rampage` if the client does not inherit your `PATH`. For a client that does not refresh
its tool list when tools change, add `"--all-tools"` to `args` so every group is listed from the start.

The [getting-started tutorial](docs/getting-started.md) walks through a first investigation on a committed
fixture, tool call by tool call.

### Use the CLI

The CLI exposes the same analysis for scripts and quick looks:

```sh
rampage binary triage tests/fixtures/bin/hello-x64.elf
rampage function list tests/fixtures/bin/hello-x64.elf --name main
rampage function disassemble tests/fixtures/bin/hello-x64.elf --at main --count 20
rampage function decompile tests/fixtures/bin/hello-x64.elf --at main
rampage workflow run triage-report tests/fixtures/bin/hello-x64.elf
```

Add `--json` for machine-readable output. `rampage --help` lists every command; the
[CLI reference](docs/cli-reference.md) has the full catalog.

## Capabilities

Areas marked *experimental* may change in any release; see the [stability policy](docs/stability.md).

- **Analysis:** recursive-descent function discovery, control-flow graphs, cross-references, strings, imports
  and exports; stripped Go function names from the pclntab; C++ class names and base classes from RTTI and
  vtables; Objective-C classes, methods and properties; guided reports (`triage_report`, `find_main`,
  `network_surface`, `persistence_surface`, `string_decoding` and `diff_builds` in `core`, `find_crypto` in
  `detection`).
- **Decompilation:** C from the embedded Ghidra decompiler, with address-linked tokens and recovery diagnostics,
  run in a supervised worker with time, memory and output limits when `rampage-worker` is installed, and
  in-process otherwise.
- **Typing:** rename and retype locals and parameters by storage, a project type library with C declarations and
  bundled libc/POSIX/Win32 basics, types on data and operands, stack frames, type propagation across calls, and
  checked DWARF and PDB type import.
- **Search and patching:** byte, text, regex, immediate, instruction and reference search; an assembler for an
  x86/x64/AArch64 subset; checked byte patches kept in the annotation log and exported to a new file.
- **Formats:** ELF, PE and Mach-O (including universal binaries and embedded images), .NET metadata and CIL, Go
  build info, cargo-auditable data, PE resources and load config, PyInstaller archives, WebAssembly module
  summaries, ZIP inventory, embedded-file carving and raw firmware windows.
- **Processors:** x86 and x86-64; AArch64, ARM and Thumb from Arm's machine-readable specification; MIPS,
  PowerPC, RISC-V, SPARC, s390x and m68k through Capstone; sixteen more families (MSP430, AVR8, 8051, Z80,
  Xtensa, eBPF, LoongArch and others) as Raw Projects through Ghidra's Sleigh. Profiles other than MSP430 and AVR8
  are *experimental* and disassemble without decompiling.
- **Library identification and detection:** FLIRT/FunctionID-style signatures with bundled databases, user PAT
  and Ghidra FID input, fuzzy candidates, packer/compiler detection, YARA, a capa subset, capability tags and
  crypto constants, all extendable with data packs.
- **Debugging:** connect to an operator-started GDB remote stub (gdbserver, QEMU, OpenOCD), read state, control
  execution, set breakpoints by function name, and bind the session to a static project. Memory and register
  writes and kill need explicit operator flags. Apple `debugserver` and Windows-target stubs are *experimental*
  and not yet live-verified. rampage never launches or attaches to a process itself.
- **Findings ledger:** `record_finding` and `list_findings` keep what an agent established, what it does not know
  and its open questions, with evidence and confidence, in the annotation log beside the binary.
- **Heuristic flywheel** (*experimental*): an agent proposes library signatures through a restricted MCP server,
  gated against held-out ground truth, and promoted rows ship as `.rpack` data packs. See
  [the flywheel](docs/flywheel.md) for what it has and has not shown.
- **Desktop UI** (*experimental*): listings, graphs, decompilation and shared annotations in one window.

The [feature overview](docs/features.md) and [MCP reference](docs/mcp.md) describe each area and its limits.

## Platforms and known limits

### Supported hosts

| Host | Status |
| --- | --- |
| macOS on Apple silicon | Tested; the primary development host. |
| macOS on Intel | Untested: it should build from source, but no one has run the tests on it. |
| Linux x64 (Ubuntu 24.04) | Supported. CI builds the whole workspace and runs its tests and Clippy; release archives are built for `x86_64-unknown-linux-gnu`. The desktop UI builds but its interface is untested there. |
| Linux ARM64 (Ubuntu 24.04) | Supported. CI builds the whole workspace and runs its tests and Clippy on a native ARM64 runner; release archives are built for `aarch64-unknown-linux-gnu`. The desktop UI builds but its interface is untested there. |
| Windows | Not supported as a host in 1.0; planned for 1.x. |

On any host, rampage analyses PE, ELF and Mach-O binaries alike. Windows PE binaries can be analysed, and Windows
targets debugged through an RSP stub, from a macOS or Linux host.

### Known limits

- Without `rampage-worker` beside `rampage` (or named by `RAMPAGE_WORKER`), decompilation runs in-process,
  without the worker's limits. Use `--require-worker` when you analyse hostile files.
- Decompilation produces C; it does not prove the recovered program is correct. Results report their recovery
  issues.
- Worker supervision bounds time, memory and output; it is not an OS sandbox. Analyse untrusted files in a VM or
  container if you need isolation.
- rampage itself uploads nothing, but an AI client sends tool results (strings, disassembly, decompiled code) to
  its model provider. Make sure you may disclose that material; see
  [data disclosure](docs/mcp.md#authorization-and-data-disclosure).
- Bundled library signatures match the library builds they were made from, not every version.
- Not yet built: DEX/JVM, Intel HEX/SREC and multi-region firmware maps, object-file relocation, Swift metadata,
  C++ layout recovery beyond RTTI evidence, and incremental analysis for very large binaries.
- The benchmarks above use one model and one client; they are not general accuracy guarantees.

[Known limits](docs/known-limits.md) has the full list, and the
[comparison with Ghidra, IDA and REA](docs/comparison.md) sets it against other tools.

### Troubleshooting

- **The server is not listed in `/mcp`.** `claude mcp add` without `--scope user` registers rampage only for the
  directory you ran it in; run `claude mcp list` there, or add it again with `--scope user`. Check that
  `rampage server serve` starts from a shell: it waits for a client on stdin (Ctrl-C ends it), and a
  "command not found" means `rampage` is not on `PATH`.
- **A GUI client cannot start `rampage`.** Desktop apps often do not inherit your shell's `PATH`. Put the
  absolute path in `command`, such as `/Users/you/.local/bin/rampage` (`command -v rampage` prints it).
- **The server warns that no `rampage-worker` was found.** `decompile` then runs in-process. Install both
  executables with `tools/install.sh`, keep them in one directory, or set `RAMPAGE_WORKER` to the worker's path.
- **The build is slow.** `tools/install.sh` compiles Ghidra's C++ decompiler and optimises the whole release
  build from scratch on every run: expect 10 to 30 minutes. See
  [getting started](docs/getting-started.md#1-build-and-install) for a measured time.

## Documentation and project

- [Documentation index](docs/index.md): tutorials, how-to guides, references and explanations.
- [Changelog](CHANGELOG.md) and [stability policy](docs/stability.md).
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md). Report vulnerabilities privately, not in
  public issues.

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The decompiler embeds Ghidra (Apache-2.0), and the
AArch64/AArch32 decoder tables are generated from Arm's machine-readable architecture specification, which Arm
licenses under the BSD 3-clause license; see [Arm's license](crates/rampage-arch/src/a64/LICENSE-ARM).
