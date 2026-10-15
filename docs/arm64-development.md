# Deep ARM64 analysis

Rampage's ARM64 track separates instruction semantics, compiler conventions, SSA/data-flow analysis and
presentation. Supported operations produce explicit effects. Unsupported operations remain barriers instead
of silently preserving stale register or memory state.

Native IR/SSA and pseudocode are complementary diagnostics, not the source-decompilation path. Source-style C
comes from the [embedded Ghidra decompiler](../crates/rampage-decompiler/README.md).

## Ghidra as a reference

[Ghidra](https://github.com/NationalSecurityAgency/ghidra) is primarily Apache-2.0 licensed. Its architecture
separates processor semantics (SLEIGH/p-code), compiler specifications, analysis transformations and printing.
That separation is a useful reference for rampage's native Arm-spec decoder and Rust analysis pipeline.

Borrowing architectural ideas is different from copying implementation. Any direct translation or reused
specification needs its source license, relevant attribution/NOTICE contents and modified-file notices retained.
Third-party components may have different licenses. The native ARM64 decoder/IR does not incorporate Ghidra
code or specifications; the separate embedded decompiler vendors them under Apache-2.0. The Arm-derived
decoder tables retain their BSD-3-Clause license and attribution.

## Validation

Instruction encodings are checked with LLVM. Integer operation/NZCV evaluators are compared with native
AArch64 execution on controlled boundary cases. Synthetic snapshots exercise CFGs, register joins, calls,
stack slots and unknown outcomes. Passing these cases is not full ISA or decompiler coverage.
All sixteen condition codes are checked against native execution for all sixteen NZCV combinations.
An opt-in macOS ARM64 test compiles and executes an optimized C fixture, then executes its lifted arithmetic
and select operations against fixed boundary results. It requires clang and an SDK and is run explicitly:
`cargo test -p rampage-api --test compiled_arm64 -- --ignored`.

Ghidra and IDA executable comparisons require installations and recorded versions. Recorded Ghidra function/CFG
comparisons are in [Accuracy benchmarks](benchmarks.md); these do not establish semantic or decompiler parity.
No IDA comparison is recorded.

The controlled stopped-process capture recorded at `35508ff` used Apple LLDB `2103.0.34.103` with ASLR enabled.
The exporter captured executable bytes, 82 module records and 34 selected-thread registers; the captured
function lifted completely and its UUID/header slide mapped back to the original image address. Those historical
byte/identity measurements remain recorded, but their SDK runtime DATA-order acceptance premise is superseded:
SBTarget/SBProcess byte-order getters derive object ArchSpec order, not independent runtime DATA-order evidence.
The standalone exporter now refuses ARM64/arm64e/aarch64 before thread/map/read/write work. Loading existing manual
ARM64 snapshots remains unchanged and old documents are not automatically invalidated. See the
[runtime data-order review](runtime-data-order.md) for the source-proof boundary.
The opt-in regression runs with `RAMPAGE_LLDB_LIVE=1 python3 -m pytest tools/test_lldb_live.py` after building
the CLI; its ARM64 capture expectation is now refusal, not a rerun of the historical exporter success.
Broader debugger/platform acceptance and derived-analysis cache persistence remain separate gates;
see [Runtime snapshots](runtime-snapshots.md) for capture, identity and annotation persistence behavior.

`rampage function compare program --reference export.json --json` compares function starts against a reference export:

```json
{
  "tool": "Ghidra",
  "version": "version-used-for-export",
  "image_sha256": "sha256-of-the-selected-image-from-rampage-triage",
  "arch": "aarch64",
  "functions": ["0x1000", "0x1010"]
}
```

The tool requires exact image hash and architecture identity, validates addresses, and reports matched,
missing and extra function starts. Export addresses in the selected image's address space; remove runtime
ASLR slides first. A function-start match is not agreement on CFGs, signatures or semantics, and reference
tool output is not itself ground truth. The reference JSON must be regular and no larger than 32 MiB.
This function-start comparator still rejects snapshots: its reference format does not accept capture identity
and mappings, even though snapshot triage has a mapping-aware identity. A hash of concatenated region bytes
alone cannot identify virtual-address mappings. Function entry counts are bounded during JSON parsing.

## Output

Function summaries include partial IR, SSA, constant/stack evidence and SSA-style pseudocode. Pseudocode retains
labels, phi nodes, unknowns and explicit barriers; `structured: false` means no structured-source recovery is
claimed. Input registers are argument evidence, not inferred function signatures. Calls use a conservative
integer AAPCS64 model, preserve callee-saved registers and invalidate caller-saved values and memory.
Discovery-marked noreturn calls are terminal in SSA/structured control; graph lines retain `listed` or `inferred`
evidence. Conditional calls retain their fall-through rather than being treated as unconditional termination.
RET preserves its explicit target, memory version and X0/X1 candidate definitions. Constant candidates are
reported per return site, but do not establish a return type or even that the function returns a value.
Speculative return candidates alone do not count as argument-use evidence.
Function summaries expose immediate dominators and natural-loop membership/backedges/exits. This is structural
evidence for later control-flow reconstruction, not a claim that irreducible cycles have structured source loops.
Selected reducible shapes also expose `structured_control` regions referencing SSA blocks: sequences, branches
with shared joins, simple single-body loops and switch regions (below). Loop-header effects/phis execute before
the test on each iteration. Complex graphs, unknown dispatch and ambiguous/external successors retain the
labeled fallback. `rampage function pseudocode program --at ADDRESS --structured` prints those accepted regions as
`if/else`, header-tested loops and `switch` with a `break` after each case. Explicit predecessor tokens and
parallel phi bindings preserve SSA edge selection.
Unsupported shapes return an error for this opt-in mode; ordinary labeled pseudocode remains available.
Phi simplification aliases only identical incoming definitions (ignoring the phi's own backedge). It does not
inline expression trees or merge distinct predecessor values; changing loop-carried values retain their phis.
Scalar memory effects retain separate 8/16/32/64-bit access widths and signed/unsigned 32/64-bit load results.
Unsigned offsets, unscaled/pre/post-index addresses, register offsets and scalar literal loads are supported.
SP writeback remains 64-bit regardless of the destination width; overlapping writeback remains a barrier.
Word-sized STP/LDP pairs and signed LDPSW pairs retain their 4-byte stride and load-result extensions.
No-writeback pair loads allow base/destination overlap by capturing both original addresses before assigning
either result; writeback overlaps and duplicate load destinations remain barriers.

`dataflow.forwarded_loads` records constant reloads: `definition` is the load result, `store_definitions` names
the reaching memory-store definitions, `bits` is the access width and `value` is the stored value before load extension.
Every incoming memory path must agree. Only provably disjoint writes within the same address domain are skipped;
unknown aliases, calls, partial overlaps and memory cycles stop inference. Snapshot bytes are not used as load
values. Forwarding is limited to eight passes, 200,000 memory visits, 64 levels and 64 source stores per load.

Exact-width nonconstant entry-SP spill/reload recovery separately aliases a finite SSA value agreed on by every
reaching path. The result retains truncation/sign extension, the original `Load` observation and the owning
statement's `recovered_loads` definition IDs. The alias references its source SSA value even after the source
register is clobbered. Recovered pointers do not regain entry-SP address provenance for further memory inference.
Proofs use the original graph, not iterative pointer recovery, and stop at calls, unknown aliases, partial overlaps,
conflicting values, cycles, 64 levels, 64 stores, 200,000 visits or the SSA value-node budget.

`type_evidence` records local integer-width, signed/unsigned operation and address/code-operand uses. Multiple
roles are retained rather than forced into one source type; integer indices used in address expressions are
not declared pointers. Traversal is capped at 100,000 expression visits.
`validated_indirect_targets` records constant BR/BLR targets whose entire aligned instruction lies in backed,
readable executable code. The target may come from a proven reaching store; no CFG edges or function seeds
are inserted from this summary evidence, and unresolved/authenticated operations remain explicit.

Automatic dispatch recovery covers bounded switch tables. An immediate `cmp` proves an unsigned bound only on
the fall-through edge of `b.hi`/`b.hs` or the taken edge of inverse `b.ls`/`b.lo`. The comparison can be scheduled
before its branch across audited NZCV/index-preserving instructions; flag or index clobbers invalidate it.
Cross-block must-dataflow retains only facts agreed on by all incoming paths, including pending comparisons and
bounds tied to the same guard. Function entry and external entries contribute no facts. Added case edges are
revalidated against the expanded graph; a table that no longer proves is dropped.
The table must be read-only backed image data loaded by a register-offset `ldr`/`ldrb`/`ldrh`/`ldrs*`, contain at
most 4,096 entries and select aligned backed code that decodes. Discovery explores each case; `function_graph`,
summaries, SSA and `export-cfg` carry `switch` edges, and xrefs carry jumps, not function seeds. Unknown register
writes forget every bound; unaudited NZCV effects forget pending comparisons. `BC.cond`, other comparison forms
and unproven scheduling/joins remain unresolved. This is not general indirect-flow or authenticated-target recovery.

A resolved switch keeps its entries in table order (`table`, entry `i` selected by index `i`) and the address of
its bounding comparison (`guard`). Pseudocode prints the dispatch as `switch (index) { case N: goto bbX; ...
default: goto bbD; }`, where the index is the comparison's operand when recovered. Entries selecting the same
block share one line (runs of three or more as `case a ... b:`). When recovered, the default comes from the actual
branch consuming the guard's flags, not necessarily the instruction after `cmp`, and is its out-of-range successor.
A missing index remains unknown; an unproven default is omitted rather than fabricated.
Structured control adds a `switch` region when every case is a region of its own (entered only from the dispatch
and dominated by its first block) and all cases leave only for one follow block, or none leave at all. A case that
goes straight to the follow block is an empty case. The bound check stays an ordinary `if`: its out-of-range arm
holds the default and the other arm the dispatch block and the `switch`. Fall-through between cases, case code
shared with other cases or the default (including compiler tail-merging), cases outside the function and tables
that disagree with the CFG are rejected with a limitation, leaving the labeled `switch` form. The recorded
`musl-static-aarch64.elf` check in `e2d0490` found none of its three resolved switch functions structured:
`printf_core` exceeded the SSA definition limit, `pop_arg` tail-merged its case stores, and `sysconf` had nested
loops in a case and early returns joining a shared return block. This is historical fixture evidence, not a
rerun of the current working tree.

The next gates are more scalar/FP/SIMD semantics, alias-aware memory analysis, broader control-flow structuring,
typed arguments/returns, dispatch recovery beyond bounded switch tables and live runtime integration. PAC,
exceptions, TLS, varargs, platform-specific ABI differences and protection wrappers must not be treated as solved
by integer SSA.
Integer conditional selects (CSEL/CSINC/CSINV/CSNEG and their aliases) retain NZCV conditions in SSA.
Extended-register ADD/SUB preserves signed/unsigned byte, halfword and word extensions and SP/ZR rules;
reserved shifts remain barriers. Boundary tests compare extended arithmetic with native ARM64 execution.
SBFM/UBFM/BFM are supported in every allocated shape, including the wrapping `imms < immr` forms (SBFIZ, UBFIZ,
BFI) and BFXIL/BFC. Native optimized integer/select fixtures cover both paths.
ADC/ADCS/SBC/SBCS (and NGC/NGCS) read the incoming carry before writing either the destination or the flags;
in SSA both are selects on the incoming flags' C. CCMP/CCMN select between the compare flags and the encoded
NZCV immediate. Long multiplies (SMADDL/UMADDL/SMSUBL/UMSUBL and their SMULL/UMULL/SMNEGL/UMNEGL aliases),
SMULH/UMULH, EXTR/ROR immediate, CLZ, CLS, RBIT and REV/REV16/REV32 are also lifted. Each family is compared
with native execution over boundary operands, 32/64-bit widths, the zero register and, for flag-dependent
families, all sixteen NZCV inputs; the SSA/dataflow lowering of the flag-dependent families is compared the same
way. FEAT_CSSC (ABS, CNT, CTZ, MIN/MAX), RMIF and SETF8/SETF16 remain barriers.

## Explicit jump-table inspection

`rampage function inspect-table program --at 0x3000 --count 8` validates eight absolute 64-bit entries.
`--relative-base 0x2000` instead reads signed 32-bit offsets from that base. Every entry must be in readable,
non-writable memory and every target must be aligned, backed ARM64 code that decodes. The tool rejects partial,
overflowing and invalid tables; it does not guess dispatch bounds or add CFG edges from analyst-supplied counts.
`inspect_jump_table` exposes the same validation through the shared tool registry.
