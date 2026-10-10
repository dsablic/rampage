# rampage

A high-performance, open source reverse engineering toolkit written in Rust. The goal is a general-purpose
IDA Pro alternative where AI agents are first-class clients: a scriptable CLI and an MCP server come first,
and a GUI arrives later as one more client of the same API.

Status: early. Milestone 1 (one-shot CLI) is done. See [the design](docs/plans/2026-10-10-rampage-design.md)
for the roadmap.

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
rampage funcs   <file>                       # functions from symbols, exports and entry

# global flags
--json                 machine-readable output for every command
--arch x86_64|aarch64  pick a slice from a universal Mach-O
```

## Layout

| Crate | Purpose |
|---|---|
| `rampage-loaders` | Memory-mapped PE/ELF/Mach-O loading and address-based reads |
| `rampage-arch` | Instruction decoding with control-flow classification |
| `rampage-analysis` | String scanning and function discovery |
| `rampage-cli` | The `rampage` binary |

Test fixtures live in `tests/fixtures`; `tests/fixtures/build.sh` rebuilds them (needs zig and Apple clang).

## License

MIT OR Apache-2.0
