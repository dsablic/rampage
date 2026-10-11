# Analyze a captured runtime image

Use snapshots for programs you own or have permission to inspect. Rampage does not launch processes,
attach debuggers, bypass protections or modify the captured application.

## Export from LLDB

With an authorized process already stopped in LLDB:

```text
command script import /path/to/rampage/tools/lldb_snapshot.py
rampage-snapshot capture.json --region 0x1000:0x100:r-x --region 0x3000:0x20:rw- --seed 0x1000
```

Select ranges explicitly. The exporter reads those ranges, refuses partial reads and existing output files,
and limits captured bytes to 64 MiB. It does not resume, launch or attach. Use `--thumb` for Thumb code.
Preserve the actual runtime addresses: they already include ASLR.

## Open in rampage

```sh
rampage info capture.json
rampage disasm capture.json --at 0x1000 --count 20
rampage funcs capture.json
rampage audit capture.json
cargo run -p rampage-ui -- capture.json
```

Snapshots use the same listing, graph, annotation and MCP interfaces as executable files. Captured writable
regions retain their permissions. Writable regions are not used as branch-target evidence: a frozen file
does not prove that a later architectural load still observes the captured value.
Stores and calls invalidate subsequent captured-memory inference conservatively; unknown memory effects
are not simulated.
Missing memory remains unavailable instead of being fabricated as zeros.

## Snapshot format

```json
{
  "format": "rampage-snapshot-v1",
  "arch": "aarch64",
  "provenance": "controlled test process stopped before execution",
  "regions": [
    {"name": "text", "address": "0x1000", "permissions": "r-x", "bytes": "c0035fd6"}
  ],
  "seeds": ["0x1000"],
  "entry": "0x1000"
}
```

Addresses are hexadecimal strings. Regions must be nonempty and nonoverlapping; seeds and entry must be in
captured executable memory. `big_endian` selects instruction byte order, `data_big_endian` selects data byte
order, and `thumb` on an executable ARM region selects Thumb. Unknown fields and malformed hex are rejected.

## Limits

Snapshots may include module UUIDs/paths, original/runtime header bases and selected-thread register values.
These are provenance, not inputs to static register inference. A module slide is the runtime base minus its
original image base; it must be applied explicitly when correlating addresses. Relocations, types and execution
history are not captured. Authenticated pointers and unknown indirect targets are not guessed.
A capture is not a decompiler
or a complete debugger integration. `audit` reports evidence and limitations, not proof of encryption.

`rampage summarize capture.json --at 0x1000 --json` includes partial IR alongside the graph and references.
`complete` applies to each lifted instruction, not the function. Unimplemented instruction semantics produce
barriers. ARM64 integer coverage includes immediate/shifted ADD/SUB and NZCV, logical operations, wide moves,
variable shifts, multiply/divide, ADR/ADRP, common scalar/pair memory operations and branch conditions.
Plain BL/BLR calls retain pre-call arguments, X8 result-buffer and SP dependencies and conservatively clobber
caller-saved registers/memory; unknown, FP/SIMD and authenticated operations remain barriers.

The `ssa` field in AArch64 summaries gives each register and memory definition a unique ID. Block-entry phi
nodes name incoming definitions by predecessor block, including an external input edge when the entry has
a backedge. Stores create memory versions; loads retain references even when dataflow reports a forwarded constant.
Unknown
instructions invalidate register and memory knowledge. A 32-bit result is represented as `low32`, zero-extended
into its architectural register. Scalar signed loads use explicit width-extension expressions.
Unreachable blocks contribute no phi inputs.
Loads/stores retain their access widths; conditional controls retain polarity and the tested bit where applicable.

SSA is omitted with a limitation message for functions exceeding 512 blocks, 20,000 instructions or 4,096
edges, or budgets of 20,000 generated definitions and 80,000 input value nodes. Budgets are checked before
SSA allocation. It represents data flow over partial IR, not source-level variable recovery or a decompiler.

`rampage pseudocode capture.json --at 0x1000` prints an explicitly partial SSA-style view, retaining labels,
phi nodes, memory widths and unknowns. It does not claim structured C source. Function summaries also include
bounded constant and entry-SP-relative stack-slot evidence; conflicting predecessor values stay unknown.
Exact-width constant spill/reloads can be forwarded with source-store evidence. This does not infer values
from captured memory: unknown aliases, partial overlaps, calls and cyclic memory stop forwarding.

Optional `modules` entries have `name`, `path`, `uuid`, `image_base` and `runtime_base`. Optional `registers`
entries have hexadecimal `thread_id`/`value` and a register `name`. Both lists are limited to 4,096 entries;
module UUIDs and per-thread register names must be unique. The LLDB adapter exports those fields from the
stopped target without evaluating expressions or executing target code. The opt-in controlled ARM64 integration
test verifies live export and original-image correlation with ASLR enabled; the earlier launch stall was avoided
by leaving ASLR enabled rather than requesting its disablement.

`rampage correlate capture.json --original module.dylib --module <uuid> --at 0x1010` checks the recorded UUID
against the explicitly supplied Mach-O image and translates the runtime address using the recorded header
slide. It never opens paths stored inside a snapshot. UUID correlation does not assert that runtime bytes
equal the original file and does not reconstruct relocations or authenticated pointers.
