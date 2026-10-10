# rampage

A high-performance, open source reverse engineering toolkit written in Rust. The goal is a general-purpose
IDA Pro alternative where AI agents are first-class clients: a scriptable CLI and an MCP server come first,
and a GUI arrives later as one more client of the same API.

Status: early. Milestones 1-4 are done: the one-shot CLI, recursive-descent function discovery with
cross-references, the MCP server, and an AArch64 decoder generated from Arm's specification. See
[the design](docs/plans/2026-10-10-rampage-design.md) for the roadmap.

## Supported today

- Formats: ELF, PE, Mach-O (including universal binaries)
- Disassembly: x86 and x86-64 (via [iced-x86](https://github.com/icedland/iced)), and AArch64 including SVE and
  SME, decoded from tables generated out of Arm's open-source
  [machine-readable architecture specification](https://developer.arm.com/Architectures/A-Profile%20Architecture).
  Its output matches `llvm-mc` on every instruction sampled from Chrome's arm64 code and on 99.85% of words
  across all encodings. On AArch64, function
  discovery resolves ADRP+ADD and ADRP+LDR pairs into data references.
- Names: symbols and exports, then import stubs and thunks named after their import (`puts`, or `puts@plt` on
  ELF; a bare import name finds its stub), and import slots (GOT entries, Mach-O symbol pointers, the PE import
  address table) as `__imp_<name>`. Disassembly comments
  each branch or data reference with the name or string it points to.

## Usage

```
cargo build --release

rampage info    <file>                       # format, arch, entry, segments, sections
rampage disasm  <file> [--at <addr|symbol>] [--count N]
rampage strings <file> [--min-len N]         # ASCII and UTF-16LE
rampage funcs   <file> [--name TEXT]         # recursive-descent function discovery
rampage xrefs   <file> --to|--from <addr|name>
rampage mcp                                  # MCP server on stdin/stdout

# global flags
--json                 machine-readable output for every command
--arch x86_64|aarch64  pick a slice from a universal Mach-O
```

Addresses accept `0x` hex, decimal, symbol and export names, or `sub_<hex>`. In JSON output every address is
a `"0x…"` string, because JSON numbers lose precision above 2^53 in common consumers.

## Using it from an AI agent

`rampage mcp` serves the [Model Context Protocol](https://modelcontextprotocol.io) over stdio with the tools
`binary_info`, `list_functions`, `disassemble`, `list_strings` and `xrefs`. Analysis runs once per binary and is
cached for the session. To add it to Claude Code:

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

`tools/a64gen` regenerates `crates/rampage-arch/src/a64/spec.rs` from an AARCHMRS release:
`cargo run --release -p a64gen -- <AARCHMRS directory> crates/rampage-arch/src/a64/spec.rs`.

Test fixtures live in `tests/fixtures`; `tests/fixtures/build.sh` rebuilds them (needs zig and Apple clang).

## License

MIT OR Apache-2.0. The generated AArch64 tables derive from Arm's specification data, which Arm licenses under
the BSD 3-clause license; see `crates/rampage-arch/src/a64/LICENSE-ARM`.
