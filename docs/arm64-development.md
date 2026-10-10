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

Ghidra and IDA executable comparisons require installations and recorded versions. Neither is currently on
the command search path in this environment, so no accuracy-parity result is claimed. A successful stopped-process
LLDB capture is also still a separate integration gate.

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
Function summaries expose immediate dominators and natural-loop membership/backedges/exits. This is structural
evidence for later control-flow reconstruction, not a claim that irreducible cycles have structured source loops.

The next gates are more scalar/FP/SIMD semantics, alias-aware memory analysis, structured loops/conditions,
typed arguments/returns, jump-table evidence and runtime-module correlation. PAC, exceptions, TLS, varargs,
platform-specific ABI differences and protection wrappers must not be treated as solved by integer SSA.

## Explicit jump-table inspection

`rampage jump-table program --at 0x3000 --count 8` validates eight absolute 64-bit entries.
`--relative-base 0x2000` instead reads signed 32-bit offsets from that base. Every entry must be in readable,
non-writable memory and every target must be aligned, backed ARM64 code that decodes. The tool rejects partial,
overflowing and invalid tables; it does not guess dispatch bounds or add CFG edges from analyst-supplied counts.
`inspect_jump_table` exposes the same validation through the shared tool registry.
