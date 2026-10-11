# Deep ARM64 analysis

Rampage's ARM64 track separates instruction semantics, compiler conventions, SSA/data-flow analysis and
presentation. Supported operations produce explicit effects. Unsupported operations remain barriers instead
of silently preserving stale register or memory state.

## Ghidra as a reference

[Ghidra](https://github.com/NationalSecurityAgency/ghidra) is primarily Apache-2.0 licensed. Its architecture
separates processor semantics (SLEIGH/p-code), compiler specifications, analysis transformations and printing.
That separation is a useful reference for rampage's native Arm-spec decoder and Rust analysis pipeline.

Borrowing architectural ideas is different from copying implementation. Any direct translation or reused
specification needs its source license, relevant attribution/NOTICE contents and modified-file notices retained.
Third-party components may have different licenses. No Ghidra code or specifications are incorporated by this
milestone; the Arm-derived decoder tables keep their existing license.

## Validation

Instruction encodings are checked with LLVM. Integer operation/NZCV evaluators are compared with native
AArch64 execution on controlled boundary cases. Synthetic snapshots exercise CFGs, register joins, calls,
stack slots and unknown outcomes. Passing these cases is not full ISA or decompiler coverage.
All sixteen condition codes are checked against native execution for all sixteen NZCV combinations.
An opt-in macOS ARM64 test compiles and executes an optimized C fixture, then executes its lifted arithmetic
and select operations against fixed boundary results. It requires clang and an SDK and is run explicitly:
`cargo test -p rampage-api --test compiled_arm64 -- --ignored`.

Ghidra and IDA executable comparisons require installations and recorded versions. Neither is currently on
the command search path in this environment, so no accuracy-parity result is claimed. A successful stopped-process
The controlled stopped-process capture passes on Apple LLDB `2103.0.34.103` with ASLR enabled.
The exporter captured executable bytes, 82 module records and 34 selected-thread registers; the captured
function lifted completely and its UUID/header slide mapped back to the original image address.
The opt-in regression runs with `RAMPAGE_LLDB_LIVE=1 python3 -m pytest tools/test_lldb_live.py` after building
the CLI. Other debugger/platform combinations and session persistence remain separate gates.

`rampage compare program --reference export.json --json` compares function starts against a reference export:

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
Snapshot comparisons are rejected until mapping-aware identities exist: hashing concatenated region bytes
alone does not identify their virtual-address mapping. Function entry counts are bounded during JSON parsing.

## Output

Function summaries include partial IR, SSA, constant/stack evidence and SSA-style pseudocode. Pseudocode retains
labels, phi nodes, unknowns and explicit barriers; `structured: false` means no structured-source recovery is
claimed. Input registers are argument evidence, not inferred function signatures. Calls use a conservative
integer AAPCS64 model, preserve callee-saved registers and invalidate caller-saved values and memory.
RET preserves its explicit target, memory version and X0/X1 candidate definitions. Constant candidates are
reported per return site, but do not establish a return type or even that the function returns a value.
Speculative return candidates alone do not count as argument-use evidence.
Function summaries expose immediate dominators and natural-loop membership/backedges/exits. This is structural
evidence for later control-flow reconstruction, not a claim that irreducible cycles have structured source loops.
Selected reducible shapes also expose `structured_control` regions referencing SSA blocks: sequences, branches
with shared joins, and simple single-body loops. Loop-header effects/phis execute before the test on each
iteration. Complex graphs, unknown dispatch and ambiguous/external successors retain the labeled fallback.
`rampage pseudocode program --at ADDRESS --structured` prints those accepted regions as `if/else` and
header-tested loops. Explicit predecessor tokens and parallel phi bindings preserve SSA edge selection.
Unsupported shapes return an error for this opt-in mode; ordinary labeled pseudocode remains available.
Phi simplification aliases only identical incoming definitions (ignoring the phi's own backedge). It does not
inline expression trees or merge distinct predecessor values; changing loop-carried values retain their phis.
Scalar memory effects retain separate 8/16/32/64-bit access widths and signed/unsigned 32/64-bit load results.
Unsigned offsets, unscaled/pre/post-index addresses, register offsets and scalar literal loads are supported.
SP writeback remains 64-bit regardless of the destination width; overlapping writeback remains a barrier.
Word-sized STP/LDP pairs and signed LDPSW pairs retain their 4-byte stride and load-result extensions.

`forwarded_loads` records constant reloads from exact-width reaching stores and their source definition IDs.
Every incoming memory path must agree. Only provably disjoint writes within the same address domain are skipped;
unknown aliases, calls, partial overlaps and memory cycles stop inference. Snapshot bytes are not used as load
values. Forwarding is limited to eight passes, 200,000 memory visits, 64 levels and 64 source stores per load.

The next gates are more scalar/FP/SIMD semantics, alias-aware memory analysis, broader control-flow structuring,
typed arguments/returns, automatic dispatch recovery and live runtime integration. PAC, exceptions, TLS, varargs,
platform-specific ABI differences and protection wrappers must not be treated as solved by integer SSA.
Integer conditional selects (CSEL/CSINC/CSINV/CSNEG and their aliases) retain NZCV conditions in SSA.
Extended-register ADD/SUB preserves signed/unsigned byte, halfword and word extensions and SP/ZR rules;
reserved shifts remain barriers. Boundary tests compare extended arithmetic with native ARM64 execution.
Common non-wrapping bitfield aliases, including shifts and signed/unsigned extracts, are supported;
unsupported wrapping field shapes remain barriers. Native optimized integer/select fixtures cover both paths.

## Explicit jump-table inspection

`rampage jump-table program --at 0x3000 --count 8` validates eight absolute 64-bit entries.
`--relative-base 0x2000` instead reads signed 32-bit offsets from that base. Every entry must be in readable,
non-writable memory and every target must be aligned, backed ARM64 code that decodes. The tool rejects partial,
overflowing and invalid tables; it does not guess dispatch bounds or add CFG edges from analyst-supplied counts.
`inspect_jump_table` exposes the same validation through the shared tool registry.
