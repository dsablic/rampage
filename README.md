# rampage

A high-performance, open source reverse engineering toolkit written in Rust. The goal is a general-purpose
IDA Pro alternative where AI agents are first-class clients: a scriptable CLI and an MCP server come first,
and a GUI arrives later as one more client of the same API.

Status: early. Milestones 1-5 are done: the one-shot CLI, recursive-descent function discovery with
cross-references, the MCP server, an AArch64 decoder generated from Arm's specification, and saved annotations.
Triage and a first desktop UI are in. See [the design](docs/plans/2026-10-10-rampage-design.md) for the roadmap.

## Supported today

- Formats: ELF, PE, Mach-O (including universal binaries)
- Architectures: x86 and x86-64 (via [iced-x86](https://github.com/icedland/iced)), AArch64 and 32-bit ARM (A32 and
  Thumb, with VFP and Advanced SIMD) decode natively; MIPS, PowerPC, RISC-V, SPARC, z/Architecture and m68k decode
  through [Capstone](https://www.capstone-engine.org) for now, in either byte order, with MIPS and SPARC delay slots
  kept in their branch's block. Native decoders replace Capstone where a machine-readable specification exists.
- 32-bit ARM is generated from the same specification as AArch64; on words sampled across every encoding its output
  matches `llvm-mc` on 97.95% (A32), 100% (16-bit Thumb) and 97.49% (32-bit Thumb).
- AArch64 includes SVE and SME, decoded from tables generated out of Arm's open-source
  [machine-readable architecture specification](https://developer.arm.com/Architectures/A-Profile%20Architecture).
  Its output matches `llvm-mc` on every instruction sampled from Chrome's arm64 code and on 99.85% of words
  across all encodings. On AArch64, function
  discovery resolves ADRP+ADD and ADRP+LDR pairs into data references.
- Triage: MD5/SHA-1/SHA-256, entropy per section and as a profile across the file, PE imphash (pefile's
  algorithm, without its ordinal-name tables), overlays, and format details: PE build time, mitigations, Rich
  header and signing; ELF interpreter, needed libraries, NX/RELRO/PIE and build ID; Mach-O dylibs, platform,
  UUID, signing and encryption. Hints point out likely packing and missing hardening.
- Names: symbols and exports, then import stubs and thunks named after their import (`puts`, or `puts@plt` on
  ELF; a bare import name finds its stub), and import slots (GOT entries, Mach-O symbol pointers, the PE import
  address table) as `__imp_<name>`. Disassembly comments
  each branch or data reference with the name or string it points to.

## Usage

```
cargo build --release

rampage triage  <file>                       # hashes, entropy, format details, overlay, packing hints
rampage audit   <file>                       # bounded decode coverage and unreliable-code evidence
rampage metadata <file>                      # demangled symbols, named RTTI/vtables, ObjC selectors
rampage inventory <directory>                # binaries in bundles/extracted packages; no execution
rampage summarize <file> --at <addr|symbol>   # CFG/reference summary, not decompiled source
rampage pseudocode <file> --at <addr|symbol>  # partial ARM64 SSA pseudocode with explicit unknowns
rampage compare <file> --reference <json>     # image-matched, versioned function-start comparisons
rampage jump-table <file> --at <addr> --count N # explicit immutable ARM64 table validation
rampage correlate <snapshot> --original <file> --module <uuid> --at <addr> # runtime/image correlation
rampage info    <file>                       # format, arch, entry, segments, sections
rampage imports <file> [--contains TEXT]     # imported functions, libraries and import slots
rampage exports <file> [--contains TEXT]
rampage disasm  <file> [--at <addr|symbol>] [--count N]
rampage strings <file> [--min-len N]         # ASCII and UTF-16LE
rampage funcs   <file> [--name TEXT]         # recursive-descent function discovery
rampage xrefs   <file> --to|--from <addr|name>
rampage rename  <file> <addr|name> <new name|--clear>
rampage comment <file> <addr|name> <text|--clear>
rampage annotations <file>                   # the user's names and comments
rampage mcp                                  # MCP server on stdin/stdout

# global flags
--json                 machine-readable output for every command
--arch x86_64|aarch64|arm|...  pick a slice from a universal Mach-O
```

Addresses accept `0x` hex, decimal, symbol and export names, or `sub_<hex>`. In JSON output every address is
a `"0x…"` string, because JSON numbers lose precision above 2^53 in common consumers.

Names and comments are saved beside the binary in `<file>.rampage` (`<file>.<arch>.rampage` for a slice of a
universal binary): an append-only JSON Lines log of edits, each recording the value it replaced, so undo is just
another edit and the file is a full history. Several clients can share it: the UI picks up names an agent saves
through MCP within a second.

## Desktop UI

```
cargo run --release -p rampage-ui -- <file> [--arch aarch64]
```

An egui app over the same API: docked functions, strings, imports and exports lists, a disassembly listing with
clickable references (or a hex view for data), a control-flow graph view, cross-references, triage, and a navigation
band across the image. Keys: Space listing/graph, G go to, Esc or Alt+Left back, Alt+Right forward, N rename, `;`
comment, Ctrl/Cmd+Z undo, Shift+Ctrl/Cmd+Z redo. Drop a file on the window to open it. Analysis runs in the
background; on Chrome's framework (190,000 functions, 930,000 strings) frames take a few milliseconds. `cargo test
-p rampage-ui` renders the UI offscreen into `crates/rampage-ui/tests/snapshots`.

The Assistant tab talks to Claude about the open binary: the model reads functions, graphs, strings and
cross-references through rampage's tools, renames and comments what it works out, and points the listing at what it
discusses. Set `ANTHROPIC_API_KEY` (and optionally `RAMPAGE_MODEL`) to use it; questions and the code the model reads
are sent to Anthropic's API.

## Using it from an AI agent

`rampage mcp` serves the [Model Context Protocol](https://modelcontextprotocol.io) over stdio with the tools
`triage`, `binary_info`, `list_functions`, `disassemble`, `list_strings`, `list_imports`, `list_exports`, `xrefs`,
`rename`, `set_comment`, `undo`, `redo` and `list_annotations`. Agents' names and comments land in the same log the
UI and CLI use, and the UI shows them as they arrive. Analysis runs once per binary and is cached for the session.
To add it to Claude Code:

```
claude mcp add rampage -- /path/to/rampage mcp
```

## Performance

On the Chrome framework (stripped), on an M1 Max, `funcs` discovers 176,480 functions and 14.5 million
instructions in the x86_64 slice in about 1.2 s, and 186,252 functions and 13.8 million instructions in the
arm64 slice in about 1.4 s. Repeated MCP queries are answered from the cached analysis in milliseconds.

## Layout

| Crate | Purpose |
|---|---|
| `rampage-loaders` | Memory-mapped PE/ELF/Mach-O loading and address-based reads |
| `rampage-arch` | Instruction decoding with control-flow classification |
| `rampage-analysis` | String scanning, recursive-descent function discovery, cross-references |
| `rampage-api` | Session and query layer shared by every client |
| `rampage-mcp` | MCP server |
| `rampage-cli` | The `rampage` binary |
| `rampage-ui` | The desktop UI |

`tools/armgen` regenerates the decoder tables from an AARCHMRS release, one instruction set at a time:
`cargo run --release -p armgen -- <AARCHMRS directory> A64 crates/rampage-arch/src/a64/spec.rs`.

Test fixtures live in `tests/fixtures`; `tests/fixtures/build.sh` rebuilds them (needs zig and Apple clang).

Runtime images use a validated sparse JSON snapshot with virtual addresses, explicit seeds and provenance.
The same CLI, UI and MCP tools open snapshots and bundle directories. See
[runtime snapshots](docs/runtime-snapshots.md) for the read-only LLDB exporter and format limits.
On AArch64, known ADR/ADRP/ADD/MOV/LDR values can resolve BR/BLR targets through readable, non-writable pointers.
This does not resolve authenticated pointers or replace a debugger/decompiler. `function_summary` exposes
the decoded graph, paginated references and partial typed AArch64 IR to tools, explicitly as a structural
summary rather than recovered source. Bounded register/memory SSA exposes predecessor-indexed phi nodes and
32-bit result truncation. Unsupported instruction semantics are explicit barriers, not inferred no-ops.
The [ARM64 development track](docs/arm64-development.md) records native semantics validation and remaining gates.

## License

MIT OR Apache-2.0. The generated AArch64 tables derive from Arm's specification data, which Arm licenses under
the BSD 3-clause license; see `crates/rampage-arch/src/a64/LICENSE-ARM`.
