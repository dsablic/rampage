# rampage: design

A high-performance, open source reverse engineering toolkit. A general-purpose IDA Pro competitor
where AI agents are first-class clients: MCP, a scriptable CLI and headless operation come first,
and a GUI arrives later as one more client of the same API.

## Decisions

| Topic | Decision |
|---|---|
| Language | Rust (Cargo workspace) |
| Architectures (v1) | x86/x64 and AArch64 |
| x86 decoding | `iced-x86` |
| AArch64 decoding | Own decoder generated from Arm's machine-readable spec (XML/ASL), tested exhaustively against its encoding tables |
| Semantics | Own small SSA-friendly IR; hand-written lifters for compiler-emitted instructions first, validated against Ghidra P-code; generated lifters later |
| File formats | `object` crate for PE / ELF / Mach-O; replace only where deeper or malformed-tolerant parsing is needed |
| Interfaces (v1) | Library API, CLI, MCP server. GUI after v1 |
| v1 scope | Analysis without a decompiler. The decompiler is the v2 headline, built on the v1 IR |

## Two modes of use

- **One-shot tools**, no project required: `rampage info|disasm|strings|funcs|xrefs|search|patch <file>`.
  Text or JSON output, composable with Unix pipes.
- **Projects** for deep, persistent work via CLI, MCP and later the GUI. A one-shot command is an unsaved
  temporary project, so both modes run on the same engine.

## Architecture

```
clients:      rampage CLI      MCP server (`rampage mcp`)      GUI (v2+)
                    \                  |                      /
                     `----------- rampage-api ---------------'
                                       |
  rampage-loaders  rampage-arch  rampage-analysis  rampage-ir  rampage-db
```

- **rampage-db**: source of truth. Segments, bytes, items (instructions and data), functions, names,
  comments, types, cross-references. Every mutation goes through a transaction log, giving undo/redo
  and provenance (user, agent or analyzer).
- **rampage-arch**: `Arch` trait with `decode` and `lift`; x86 and AArch64 implementations.
- **rampage-ir**: the lifted IR.
- **rampage-loaders**: maps PE / ELF / Mach-O into segments, entry points, imports, exports, symbols.
- **rampage-analysis**: worklist engine. Passes (function discovery, xrefs, switch tables, strings)
  react to database changes; user or agent edits trigger incremental reanalysis.
- **rampage-api**: one typed (serde) command/query surface. The CLI, MCP and GUI all call it, so no
  client has abilities the others lack.

## Performance

- Memory-mapped input; loaders and decoders read slices of the mapped file without copying.
- Compact in-memory model: `u64` addresses, sorted arrays and interval maps, compressed xref
  adjacency lists. No per-item heap allocation and no SQL in hot paths.
- Parallel analysis with rayon at function granularity, with a deterministic merge step.
- Snapshot reads: readers see a consistent version while analysis writes new ones.
- Project format: append-only transaction log plus rkyv zero-copy snapshots.
- `rampage sql` exposes the in-memory model as SQLite virtual tables for agents and scripts.
- Benchmarks in CI on large real binaries, compared against IDA and Ghidra.

Following Pike's rules, the simple version of each structure ships first; the optimizations above
land when benchmarks show they are needed.

## Testing

- Decoders: differential tests against reference disassemblers; AArch64 exhaustive per-encoding tests
  generated from the Arm spec.
- Loaders and analysis: a corpus of small compiled fixtures with known functions, imports and strings.
- CLI and MCP: end-to-end snapshot tests of JSON output.

## Milestones

1. Workspace, loaders, x86 decoding, one-shot CLI (`info`, `disasm`, `strings`, `funcs`) with JSON.
2. Analysis engine: recursive-descent function discovery, xrefs, call graph; in-memory db.
3. MCP server over the API.
4. AArch64 decoder generated from the Arm spec.
5. Projects: transaction log, persistence, annotations, undo.
6. IR and lifters for both architectures.
7. `rampage sql`, benchmarks, performance work.

## Decision: Capstone as the fallback decoder (2026-10-10)

Native decoders generated from machine-readable specifications remain the goal (AArch64 is done; A32/T32 come
from the same Arm data next). To support every major architecture now, architectures without a native decoder
use Capstone behind the same `Disassembler` trait: 32-bit ARM and Thumb, MIPS, PowerPC, RISC-V, SPARC,
z/Architecture and m68k. Analysis is architecture-neutral: decoders report control flow, delay slots and data
references, and `Binary::decoder` builds them with the image's endianness and Thumb regions.
