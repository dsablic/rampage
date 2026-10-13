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
and limits captured bytes to 64 MiB. Requested permissions must exactly match every underlying readable mapped
range reported by LLDB; writable memory cannot be labelled immutable and non-executable memory cannot be
labelled code. Initial and publication-time mapping inspections share a 16,384-query budget.
Captures are published atomically without
overwriting existing files, and failed writes leave no partial destination. The stop identity includes
expression-evaluation stops and is checked during capture and before publication.
It does not resume, launch or attach. Use `--thumb` for Thumb code.
Preserve the actual runtime addresses: they already include ASLR.

Top-frame registers default to the selected thread. Repeat `--thread ID` to select specific thread IDs, or
use `--all-threads` to capture the stopped process's complete thread set; these options are mutually exclusive
and bounded to 64 threads. Explicit selections require valid top frames and core registers: `pc/sp` on ARM64,
`pc/sp/cpsr` on ARM32, and `rip/rsp` on x86-64. Other named registers remain optional.
Thread IDs/stop context, target context and module UUID/header mappings are checked before publication.
Selecting threads does not change debugger selection or process execution state.

The exporter accepts little-endian ARM64, ARM32 and x86-64 targets with matching address widths. Selected
module architecture, byte order and address width must agree with the target. Unknown and big-endian target
byte orders are rejected rather than guessing separate code/data order; ARM BE8 and heterogeneous module
endian context remain unsupported by this exporter. The snapshot loader retains its explicit endian fields.
ARM32 requires readable CPSR with its data-endian bit clear, even for the default selected-thread capture.
Current top frames, core registers and selected section mappings are rechecked at publication. These checks
detect observed changes, not process-wide atomicity: keep debugger operations and external writers quiescent.

For an explicitly selected loaded module, use a UUID and original-image address instead of calculating ASLR
addresses manually:

```text
rampage-snapshot capture.json --module-region 01234567-89ab-cdef-0123-456789abcdef:0x100001000:0x100:r-x
```

`--module-region UUID:IMAGE_ADDRESS:SIZE:PERMS` and `--module-seed UUID:IMAGE_ADDRESS` may be repeated and mixed
with explicit runtime ranges/seeds. Module selection requires an unambiguous compact or standard dashed UUID,
matching architecture/byte order/address width, checked header slide and coverage by loaded section leaves.
Every intersecting leaf
must agree with that slide; mapping holes and contradictory section mappings are rejected. Enumeration is
limited to 4,096 modules. Initial and publication-time section traversal share a 16,384-item budget across
selected modules. Opaque identifiers
remain available as provenance for explicit runtime captures but cannot be used as UUID selectors. No module
file is loaded or debugger expression evaluated, and no unselected section bytes are captured.

Bytes come from LLDB `ReadMemory`, which normalizes inserted software-breakpoint traps. Provenance records
that normalization; do not interpret a capture as a byte-for-byte view of breakpoint-patched process memory.

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

`audit` samples bounded code-region prefixes without running whole-program discovery. Add `--include-discovery`
to correlate candidate entries with those exact samples and use branch-learned ARM/Thumb modes. The MCP
`analysis_diagnostics` tool accepts `include_discovery`; otherwise it reuses existing cached discovery when
available. Tiny-candidate counts and region signals are evidence, not verified function counts. Unsampled
candidate entries are reported separately; flagged prefixes do not assess every byte of a function.

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

Optional `target` metadata contains `platform` (`default`, `darwin` or `windows`) and an optional compiler
specification ID. The LLDB exporter records the platform from its target triple; `--compiler` records an
explicit compiler choice. Native and isolated decompilation use that context by default, including Darwin
ARM64's `apple` model. Explicit project/CLI compiler options override it; resetting project options restores
the captured context. Older snapshots without `target` keep generic defaults. Compiler IDs are syntax-checked
when loading and must resolve to the selected processor specification when decompiling; invalid IDs never
silently fall back. Recorded target context is a declaration, not independent proof of ABI correctness.

`triage` reports an optional `capture_identity` (`rampage-capture-identity-v1`) for snapshots. Its SHA-256
covers canonical architecture, instruction/data byte order, declared target context, region addresses/sizes/
permissions/backed bytes, Thumb ranges, seeds/entry and module identities/header bases. Region/module ordering
and equivalent UUID/address spellings do not affect it. Opaque non-UUID module identifiers remain exact.
Names, paths, descriptive provenance and register metadata are excluded; this is a mapping/analysis-context
identity, not a whole-process-state fingerprint, execution proof or authenticity guarantee. Ordinary raw
image/file hashes remain available and must not substitute for mapping identity in snapshot comparisons.

`rampage summarize capture.json --at 0x1000 --json` includes partial IR alongside the graph and references.
`complete` applies to each lifted instruction, not the function. Unimplemented instruction semantics produce
barriers. ARM64 integer coverage includes immediate/shifted ADD/SUB and NZCV, logical operations, wide moves,
variable shifts, multiply/divide, ADR/ADRP, common scalar/pair memory operations and branch conditions. It also
covers carry arithmetic (ADC/ADCS/SBC/SBCS, NGC/NGCS), conditional compares (CCMP/CCMN), every SBFM/UBFM/BFM
bitfield shape including the wrapping SBFIZ/UBFIZ/BFI forms and BFXIL/BFC, long and high multiplies
(S/UMADDL, S/UMSUBL and their aliases, SMULH/UMULH), EXTR/ROR immediate and CLZ/CLS/RBIT/REV/REV16/REV32.
FEAT_CSSC, RMIF and SETF8/SETF16 remain barriers.
Plain BL/BLR calls retain pre-call arguments, X8 result-buffer and SP dependencies and conservatively clobber
caller-saved registers/memory; unknown, FP/SIMD and authenticated operations remain barriers.

The IR is JSON tagged by `kind`. Carry arithmetic is a `carry_arithmetic` effect (`destination`, `left`, `right`,
`subtract`, `set_flags`): `left + right + C`, or `left - right - !C` when `subtract`, reading the operands and
the incoming C before writing either the destination or the flags. A conditional compare is a `conditional_flags`
effect: when `condition` holds on the incoming flags, the flags become those of `operation` (`add`, `subtract` or
`and`) on `left` and `right`, otherwise the packed `nzcv` immediate. A `unary` value applies `operation` to
`value` at `bits` width: `count_leading_zeros`, `count_leading_sign_bits`, `reverse_bits`, `reverse_bytes`,
`reverse_bytes_in_halfwords` or `reverse_bytes_in_words`. The `binary` operations include
`unsigned_multiply_high` and `signed_multiply_high`, the upper half of the double-width product.

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

## Compare selected runtime bytes with an original image

```sh
rampage compare-runtime capture.json --original module.dylib \
  --module 01234567-89ab-cdef-0123-456789abcdef --range 0x1010:0x100 --json
```

Select 1–256 non-overlapping runtime `--range ADDRESS:SIZE` arguments, totaling at most one MiB. The original
Mach-O must match the recorded UUID, architecture and original header base. The report includes capture
identity, selected original-slice SHA-256, header bases, requested/equal/changed/unavailable byte totals and
coalesced spans. Unavailable spans distinguish capture-only, original-only and both-side gaps. Unreadable,
unbacked and truncated bytes remain unavailable, including declared original zero-fill. Reports exceeding
16,384 spans are rejected; select smaller ranges instead.

Comparison opens only the explicit snapshot and original, not annotation sidecars or paths stored in metadata.
It does not apply symbol/type annotations. Differences can be relocations, runtime changes or debugger
breakpoint normalization; neither differences nor equality prove transformed-code recovery or ABI correctness.
The `compare_runtime_bytes` API uses the same rules.

Agents and MCP can call `compare_runtime_bytes` with an explicit `original` path, `module` UUID and
`ranges: [{"address": "0x1010", "size": 256}]`. Addresses must be hexadecimal, not annotation aliases.
Span pagination uses `offset` and `limit` (default 100, capped at 200); `spans_total` describes the complete
span list, while totals and hashes always cover every requested range. Each page recomputes the comparison;
check capture/original identities before combining pages. MCP loads fresh explicit inputs without sidecars
for this tool, rather than reusing an annotation-bearing session. No whole-program discovery is performed.

## Observe a captured pointer slot

```sh
rampage observe-pointer capture.json --at 0x3000 --json
```

`observe-pointer` and the API/MCP `observe_pointer` read one complete captured pointer word using the snapshot's
pointer width and data byte order. JSON/API/MCP output includes raw value, slot permissions, capture identity and an
optional code-candidate address. Writable slots may be observed but are never treated as proven future loads
or added as call/discovery edges. Code candidates require readable executable backing for the minimum aligned
instruction span; that does not verify instruction semantics or a function boundary. ARM mode bits must match
the captured Thumb context before tag clearing. Other tags and pointer authentication are not stripped.
Missing, unreadable or truncated slot words remain unavailable. CLI observations ignore annotation sidecars.

## Link an indirect branch to a captured slot

```sh
rampage observe-indirect-branch capture.json --start 0x1000 --at 0x1008 --json
```

The API/MCP `observe_indirect_branch` accepts explicit hexadecimal `start` and `at` addresses for a
little-endian ARM64 snapshot. The aligned window ends at an indirect branch and contains at most 64
instructions. It tracks ADR/ADRP, ADD-immediate, 64-bit literal/unsigned-offset LDR, MOV-register and NOP;
address arithmetic follows ARM64 wrapping semantics. Other instructions or control-flow boundaries stop
linking rather than retaining possibly stale register evidence. Unknown incoming registers remain unknown.

JSON output retains the branch's indirect `flow`, bytes/text, `slot_status`, optional `evidence_stopped_at`,
load instruction address and nested pointer observation. A decoded load/branch relationship can be linked
even when its slot bytes are unavailable; that observation still has no raw value or candidate target.
Authenticated branches remain explicitly unresolved. Missing instruction backing stops the window, and an
incomplete/non-indirect ending instruction is rejected. No discovery, target execution or annotation edits
are performed; MCP/CLI do not load sidecars. This is conditional evidence for the selected straight-line
window, not proof the path executed or the branch consumed the currently captured slot value. Module ownership
is not inferred from header proximity.

## Compare pointer observations across captures

```sh
rampage compare-pointers before.json --other after.json --at 0x3000 --other-at 0x7000 --json
```

API/MCP `compare_pointer_observations` accepts an explicit second capture `other` and hexadecimal `at`/`other_at`
slot addresses. Captures must agree on architecture and data byte order. CLI/MCP open both explicit captures
without annotation sidecars; metadata paths are not opened. Results retain both complete observations and capture
identities, plus `raw_value_change`, `slot_permissions_changed` and `target_assessment_changed`. Missing words
produce `before_unavailable`, `after_unavailable` or `both_unavailable`, never an equality claim or invented zero.

Before/after is analyst-supplied ordering, not verified chronology or same-process provenance. Slot correspondence
is also supplied explicitly: this operation does not infer ASLR slides or module ownership, normalize pointer tags,
establish a branch's loaded value or insert a discovery edge. Equal raw values can still have different permission
or target assessments, which remain separate evidence.

## Persist snapshot annotations by capture identity

Sessions use `.rampage-capture-identity-v1-<sha256>.jsonl` logs in the canonical snapshot directory.
Identical analysis identities share annotations within that directory even when file names, producer labels,
register observations or metadata paths differ. Projects retain each file's own provenance and registers; they
are not merged solely because analysis identities match. Changed capture bytes, mappings, permissions, modes,
target/compiler context, entry, seeds or module identities select a different annotation log.

`Session::with_capture_annotations(directory)` selects an explicit existing directory for cross-directory reuse.
No global cache or recorded module path is searched. Ordinary binaries retain per-file/per-slice annotation logs.
Legacy snapshot `<file>.rampage` logs are left untouched and reported as ignored: their edits lack a capture
identity and are not silently migrated. Persistence covers annotations, not serialized analysis, decompiler
configuration or proof of capture authenticity.
