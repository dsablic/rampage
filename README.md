# rampage

A high-performance, open source reverse engineering toolkit written in Rust. The goal is a general-purpose
IDA Pro alternative where AI agents are first-class clients: a scriptable CLI and an MCP server come first,
and a GUI arrives later as one more client of the same API.

Status: early. Milestones 1-3 are done: the one-shot CLI, recursive-descent function discovery with
cross-references, and the MCP server. See [the design](docs/plans/2026-10-10-rampage-design.md) for the roadmap.

## Supported today

- Formats: ELF, PE, Mach-O (including universal binaries)
- Disassembly: x86 and x86-64 (via [iced-x86](https://github.com/icedland/iced)). AArch64 binaries load,
  but disassembly arrives with milestone 4.

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

On the 493 MB Chrome framework (x86_64 slice, stripped, no function-start metadata), on an M1 Max:
`funcs` discovers 176,480 functions and 14.5 million instructions in about 1.4 s, and repeated MCP queries are
answered from the cached analysis in milliseconds.

## Layout

| Crate | Purpose |
|---|---|
| `rampage-loaders` | Memory-mapped PE/ELF/Mach-O loading and address-based reads |
| `rampage-arch` | Instruction decoding with control-flow classification |
| `rampage-analysis` | String scanning, recursive-descent function discovery, cross-references |
| `rampage-api` | Session and query layer shared by every client |
| `rampage-mcp` | MCP server |
| `rampage-cli` | The `rampage` binary |

Test fixtures live in `tests/fixtures`; `tests/fixtures/build.sh` rebuilds them (needs zig and Apple clang).

## License

MIT OR Apache-2.0
