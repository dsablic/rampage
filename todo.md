# To do

## Current status

Deep ARM64 support is **in progress**, not IDA/Ghidra parity or complete typed-source recovery.
Checked items below describe bounded, tested capabilities; sections marked partial still have acceptance work remaining.

### Committed milestones

- `ce8d78c`: integer/NZCV semantics, AAPCS64 calls, constant/stack evidence, dominance/natural loops,
  labeled pseudocode, explicit jump-table inspection, snapshot metadata and comparison foundations.
- `e5adb73`: conservative control regions, conditional selects and common bitfield aliases.
- `94d0936`: checked X0/X1 return candidates, without inferring a signature or inventing argument uses.
- `35508ff`: successful controlled live LLDB capture with ASLR enabled and UUID/header-slide correlation.
- `07110f5`: phi-alias simplification without expression expansion; bounded long-chain allocation regression.
- `d969847`: extended-register ADD/SUB, including SP/ZR and signed/unsigned extension rules.
- `1c9c737`: scalar memory widths/extensions, proven constant-store forwarding and complete phi-path validation.
- `a2c9ec0`: word-sized STP/LDP and signed LDPSW pairs with full-width SP writeback.
- `1556f22`: opt-in structured SSA pseudocode, parallel phi bindings and CFG-versus-region execution tests.

### Latest increment — reviewed and committed

- [x] Local operand-use evidence: integer widths, address/code operands, signed/unsigned operation roles.
  This is not source-type inference; shift counts do not inherit pointer roles. Traversal is bounded.
- [x] Explicit indirect-branch target observations in IR/SSA and constant-target evidence from dataflow.
- [x] Image validation requires an entire aligned instruction in backed, readable executable code.
  Evidence does not insert CFG edges or function seeds; mutable snapshot-pointer inference stays disabled.
- [x] Independent reviews completed; reported bugs fixed and retained as regressions.
- [x] Latest release workspace suite and warnings-denied Clippy passed.
- [ ] Complete the latest full debug workspace run: it timed out before completion, with no reported test failure.
  Earlier full debug suites passed; focused current-increment tests pass. Diagnose the timeout before signing off.
- [x] Final formatting/diff checks, line-length cleanup and commit of this increment.

### Validation and external blockers

- [x] LLVM-checked encodings and native ARM64 boundary comparisons, including all 16 conditions × 16 NZCV states.
- [x] Opt-in optimized C fixtures: native execution plus evaluated lifted arithmetic/selects and recovered byte spills.
- [x] Controlled live export on Apple LLDB `2103.0.34.103`: executable bytes, module identities and registers;
  explicit original Mach-O correlation verified with ASLR enabled. Capture artifacts were removed.
- [x] Previous committed milestones passed full debug/release suites and fresh-context review.
- [ ] Actual IDA/Ghidra comparisons: neither executable was found on PATH; no comparative accuracy claim is made.
- [ ] Resolve the local `rust-objcopy` missing-`libLLVM.dylib` stripping warning; release tests still execute.

## Deep ARM64 track and remaining work

### 1. Instruction semantics — partial

- [x] Immediate, shifted and extended ADD/SUB; logical operations; wide moves; multiply/divide; variable shifts.
- [x] NZCV, B.cond, CBZ/CBNZ/TBZ/TBNZ, CSEL/CSINC/CSINV/CSNEG, ADR/ADRP and plain BL/BLR/BR/RET.
- [x] Common non-wrapping bitfield aliases; 8/16/32/64-bit scalar memory with separate result/access widths.
- [x] Literal/register/unsigned/unscaled/pre/post addressing; 32/64-bit pairs and signed LDPSW.
- [ ] Remaining common integer families: carry arithmetic, conditional compares, wrapping bitfields,
  long/high multiply, extracts and other scalar operations. Add native boundary regressions per family.
- [ ] Valid no-writeback pair loads with base/destination overlap; preserve original addresses before assignments.
- [ ] FP/SIMD, atomic/exclusive and selected system semantics, with effects and memory ordering explicit.
- [ ] PAC/authenticated flow, exceptions and platform-specific behavior; unsupported forms must remain barriers.

### 2. Stack, memory and signatures — partial

- [x] Integer AAPCS64 caller clobbers/callee preservation; X8 result-buffer and SP call dependencies.
- [x] Entry-SP-relative slots, conflicting-path unknowns, per-RET X0/X1 candidates and input-use argument evidence.
- [x] Exact-width constant-store forwarding with source IDs and all-path agreement; conservative alias boundaries.
- [ ] Recover nonconstant spills/reloads, partial-width overlaps and safe cyclic-memory fixpoints.
- [ ] Stack-frame boundaries, outgoing stack arguments, saved-register roles and escaped-stack alias handling.
- [ ] Interprocedural signatures: argument count/types, void versus value, aggregate returns, varargs and FP/SIMD ABI.
- [ ] Propagate type constraints and reconstruct pointer/struct/class layouts; local operand roles alone are not types.

### 3. SSA and pseudocode — partial

- [x] Bounded register/memory SSA, predecessor-indexed phis, constants/affine stack reasoning and semantic gaps.
- [x] Redundant phi aliases, dominators, natural-loop evidence and conservative sequence/branch/single-body regions.
- [x] Labeled and `--structured` SSA pseudocode with explicit predecessor tokens and simultaneous phi bindings.
- [x] Execution comparisons cover both diamond arms, repeated loops and both loop-condition polarities.
- [ ] Minimal phi placement, dead-definition elimination and broader expression simplification without amplification.
- [ ] Nested/multi-block loops, broader branch joins, switch regions and explicit irreducible-flow fallback.
- [ ] Typed variables, source-level expressions/returns and readable decompiler output distinct from SSA diagnostics.

### 4. Jump tables and indirect flow — partial

- [x] Conservative ADR/ADRP/ADD/MOV/LDR/BR/BLR discovery; calls/stores invalidate captured-memory assumptions.
- [x] Explicit bounded absolute64/signed-relative32 table inspection, without guessed dispatch bounds.
- [x] Image-validated SSA target evidence, including a spilled constant target.
- [ ] Automatic dispatch recognition, proven index bounds and validated table entries tied to the branch site.
- [ ] Feed proven targets into discovery/CFG/xrefs with deterministic closure and retained source evidence.
- [ ] Mutable pointers only after alias/reaching-store proof; authenticated or unmapped targets remain unresolved.
- [ ] Fixtures for relative tables, duplicate targets, joins, loops, truncation, overflow and hostile index bounds.

### 5. Controlled runtime capture — initial gate complete

- [x] Successful permitted stopped-process capture, module UUIDs/bases, register provenance and original correlation.
- [ ] Reproducible session persistence and mapping-aware snapshot identity, including addresses/permissions/endianness.
- [ ] Multiple modules/threads and stripped/relocated images; module-qualified navigation and cross-module references.
- [ ] Broader debugger/platform integration, capture failure handling and provenance validation on larger fixtures.

### 6. Accuracy benchmark — partial; external comparisons blocked

- [x] Synthetic snapshots, native instruction oracles, compiled fixtures and malformed-input/resource regressions.
- [x] Versioned, hash-/architecture-matched function-start reference imports; snapshot comparisons reject
  ambiguous identity.
- [ ] A reproducible compiler/optimization corpus with recorded tool versions and instruction/CFG/xref/semantic metrics.
- [ ] CI gates for accuracy regressions, unsupported coverage, false positives and analysis time/memory bounds.
- [ ] IDA/Ghidra exports and comparisons once installations are available; reference output is not ground truth.
- [ ] Expand comparisons beyond function starts to CFGs, dispatch targets, stack/signature evidence and semantics.

### Next execution order

1. Investigate the full-debug timeout and complete the remaining workspace-validation gate.
2. Extend common integer semantics and nonconstant spill recovery, keeping alias boundaries conservative.
3. Recover bounded dispatch tables and integrate proven targets into CFG/discovery with regression fixtures.
4. Broaden structuring and type/signature propagation; keep SSA diagnostics separate from recovered source.
5. Build the versioned accuracy corpus/CI gates and complete persistence/cross-module runtime work.

Ghidra's architecture is a reference, not a wholesale decompiler port. No Ghidra implementation or specifications
have been incorporated; any future copied/ported components require their applicable license and attribution.

## General-purpose reverse-engineering roadmap

Acceptance gate for each milestone: behavioral regressions, malformed-input tests, `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, workspace tests, and independent review. Commercial samples are
read-only triage inputs, never bypass or patch fixtures. Runtime tests use programs we build ourselves.

- [x] Initial runtime images: validated sparse snapshot format, CLI/API/UI loading, explicit code seeds, provenance,
  virtual-address handling and controlled LLDB export/correlation. Persistence and cross-module work remain above.
- [ ] Indirect flow: conservative known-register and readable-pointer resolution, starting with AArch64
  ADR/ADRP/ADD/MOV/LDR/BR/BLR. Unknown, authenticated, mutable and unmapped targets must remain unresolved.
- [ ] Analysis confidence: explain suspected encoded code and decode coverage without presenting random bytes
  as trustworthy functions; support sparse memory and retain evidence rather than asserting encryption.
- [ ] Language metadata: C++/Rust demangling while preserving original lookup names, bounded Itanium vtable/RTTI
  discovery, and Objective-C class/method/selector metadata with malformed-pointer tests.
- [ ] Data-flow/decompilation: first ship an explicitly limited, structured function summary with CFG and
  references; then build a typed instruction IR, SSA, calling conventions, structuring and decompiler coverage.
  Do not label a disassembly rewrite or model-generated prose a decompiler.
- [ ] Containers and workspaces: bundle executable discovery, inventory of nested binaries, safe package
  inspection without executing installers, and cross-module navigation with address/module identities.

### Implemented foundations

- [x] Sparse snapshot loader with virtual addresses, region/seed validation, provenance and resource bounds.
- [x] Snapshot loading through CLI/API/MCP/UI and controlled integration fixtures.
- [x] Read-only LLDB snapshot export command with preflight validation and no-overwrite behavior.
  Mocked export tests and the opt-in controlled live ARM64 capture pass with ASLR left enabled. Module UUID/header
  mapping and selected-thread register provenance are verified against the explicitly supplied original image.
- [x] AArch64 conservative ADR/ADRP/ADD/MOV/LDR/BR/BLR tracking with stores/calls invalidating memory inference.
  Writable capture regions remain excluded from pointer evidence. Exact-store forwarding exists in summaries,
  but is not a general alias proof or a reason to enable mutable-pointer discovery.
- [x] Final discovery closure and retained per-function resolved flows, keeping CFGs/listings consistent.
- [x] `audit`/`analysis_diagnostics`: bounded coverage and unreliable-code evidence, not proof of encryption.
- [x] Bounded C++/Rust demangling; original lookup aliases and collision-safe display names.
- [x] Sized, named Itanium vtable targets/RTTI labels and Objective-C selector string inventory.
- [x] Plist-authoritative bundle opening and bounded inventory of already-extracted packages/directories.
- [x] Structural function summaries with paginated references, CFG and explicit non-decompiler limitations.
- [x] Partial typed AArch64 IR for the integer/NZCV/scalar-memory families listed in track 1 above.
  Unsupported instructions remain explicit barriers; no source-level reconstruction is claimed.
- [x] Bounded register/memory SSA with block-entry phi nodes, entry/backedge inputs, unreachable-block handling,
  zero-extended 32-bit results and full semantic barriers; exposed through structural function summaries.
  Memory access widths and conditional polarity/tested bits are retained. Generated-definition and input-node
  budgets reject amplification before SSA allocation.
  Minimal phi placement, alias analysis and decompilation remain open; bounded dominance queries are available.

Full instruction semantics, production decompilation, arbitrary debugger control and multi-module runtime
resolution are separate substantial deliverables; keep their acceptance cases explicit rather than calling
an initial foundation complete.

### Next acceptance-driven milestones

1. **Runtime integration:** extend the verified controlled capture to persistence, mapping-aware identities,
   multiple modules/threads and module-qualified navigation.
2. **Data-flow:** extend exact constant-store forwarding to nonconstant values, partial overlaps and safe loops;
   establish alias proofs before enabling mutable snapshot pointer inference.
3. **IR and SSA:** extend semantics/calling conventions, minimal phi placement and expression simplification;
   compare lifted execution with native fixtures at overflow, width, zero-register and flag boundaries.
4. **Language recovery:** stripped Itanium/MSVC vtables, class layouts, Objective-C method/class references,
   relative/authenticated pointers, DWARF/PDB integration and fixture-based malformed metadata validation.
5. **Decompilation:** expressions, conditions, loops, returns and typed variables over SSA; output must explicitly
   show semantic gaps and must not present unsupported paths as recovered source.
6. **Containers/workspaces:** safe archive indexing/extraction budgets, module-qualified names/addresses,
   dependencies, cross-module references and UI/MCP navigation; never execute installer scripts.

Committed-foundation validation includes full debug/release suites, warnings-denied Clippy, UI snapshots,
CLI/API/MCP regressions, malformed-input bounds, native/compiled fixtures, seven exporter tests, the opt-in live
capture test, two debugger-cleanup regressions, Ruff/ty and fresh-context reviews. The latest increment's
full-debug timeout is tracked separately above; it is not represented as a passing suite.

Checklist from the second code-review round. Most of it is in `crates/rampage-arch/src/aarch32/flow.rs`.
After each group: `cargo fmt`, `cargo clippy --all-targets`, `cargo test`, and the AArch32 golden tests
(`tests/data/{a32,t16,t32}_golden.tsv`; current rates A32 97.95%, T16 100%, T32 97.49%). Add cases to
`crates/rampage-arch/tests/flow.rs` with encodings checked against llvm-mc.

## Prerequisites

- [x] `Target::data_big_endian`, set by `Binary::target()` and read by literal-pool tracking.
- [x] PowerPC64 `addis` starts an address; the TOC-pair regression reports only the completed sum.

## AArch32 flow and tracking bugs

- [x] **Thumb high registers.** T16 encodings split the destination into `D:Rd`, `DN:Rdn` or `DM:Rdm`, but `kind()`
   and `track()` read only the low 3 bits. So `mov pc, lr` (f746), `mov pc, r0` (8746) and `add pc, r3` (9f44)
   are classified as `Next`, and `mov r8, r1` (8846) and `add r8, pc` (f844) track the wrong register.
   Fix: one helper that reads a register operand by name (`<Rd>`, `<Rdn>`, `<Rdm>`, `<Rm>`, ...) through
   `Encoding::operand_bits`, which concatenates all of the operand's fields; fall back to the plain field.
- [x] **PC writers.** `subs pc, lr, #4` (A32 04f05ee2, T32 def3048f) is `Next`: SUBS is missing from the PC-writer
   list, and the `SUBS_PC_LR` name prefix never matches (the T32 encoding is `SUBS_PC_T5_AS`). It should be a
   return, as `movs pc, lr` is. Shifted moves such as `lsl pc, r0, #2` (A32 00f1a0e1) are also `Next`. Accept the
   S-suffixed and shift mnemonics (LSL, LSR, ASR, ROR, RRX) when the destination is PC.
- [x] **Unclear destinations.** Registers written as RdLo/RdHi (UMULL), Rt (MRC, VMOV to core registers, loads) and
   STREX's status Rd are never cleared. Clear every destination operand, treating Rt/Rt2 as written except for
   stores, MCR and PUSH. Over-clearing only loses tracking.
- [x] **LDRD.** T32 LDRD's Rt2 is not cleared (covered by 3). A32 literal LDRD doesn't clear Rt, or Rt+1.
- [x] **16-bit LDM/STM writeback.** T16 LDM/STM have no W field but write back the base (LDM unless the base is in the
   list). Clear Rn for them.
- [x] **Offset scaling.** T32 LDRD/STRD/LDREX imm8 is a word offset (x4). The T16 imm5 forms are not tracked at all:
   LDR/STR imm5 scales x4, LDRH/STRH x2, LDRB/STRB x1; SP-relative imm8 x4.
- [x] **ADD (register).** It ignores the shift (`add r0, pc, r1, lsl #2`, 01018fe0), and RRX encodings. Track only
   unshifted forms. It also reports data references for conditional ADDs (`addeq r0, pc, r1`, 01008f00); report
   only unconditional ones.
- [x] **Literal pools.** Read in instruction byte order, which is wrong for BE8 images (code little-endian, data
   big-endian). Read them with `Target::data_big_endian`.
- [x] **Over-strong classifications.**
   - `ldm r0, {r1, pc}` (A32 028090e8, T32 90e80280) is a `Return`; only a POP or SP-based LDM should be. Others
     are `IndirectJump`.
   - `ldr pc, [pc, #x]` should jump to the literal's value when the pool is readable (keeping the Thumb bit's
     meaning: even in A32, odd in T32), not be an `IndirectJump`.
   - Thumb `blx label` switches to A32, but `Target::thumb` is a fixed set of ranges, so the target decodes in the
      wrong mode. Decoders now report mode hints; discovery merges them between rounds and records instruction
      modes for listing/graph decoding, including when the target was already seeded.
- [x] **Overflow.** `address + size` overflows (and panics in debug builds) near `u64::MAX`: flow.rs `flow()`,
    `track()`'s `pc`, `decode()`'s `next`, and cs.rs:241. Use `wrapping_add`.

## AArch32 rendering bugs

- [x] The `hint` alias renders as `clrbhb`.
- [x] VCVT_is shows u32 where it should be s32.
- [x] VCVT_xs prints the wrong types and fbits.

## DRY and refactors (behaviour must not change)

- [x] One mnemonic helper instead of three: `aarch32/mod.rs` `mnemonic`, mrs `root_mnemonic`, operands
  `Context::mnemonic`.
- [x] Remove the `field()` wrapper in flow.rs; call `Decoded::field`.
- [x] One destination-register helper in flow.rs (from bug 1), used by `kind()` and `track()`.
- [x] The LDM/POP mnemonic list appears twice in flow.rs; make it one constant or function.
- [x] A `wide_immediate` helper for the MOVW/MOVT imm4:i:imm3:imm8 (T32) and imm4:imm12 (A32) values.
- [x] `is_non_canonical` should reuse `operands::canonical_rotation`.
- [x] One `read_u32(bytes, offset, big_endian)` for the A32 word, literal pools and similar reads.
- [x] Share the kind-to-`Flow` mapping (conditions applied) between flow.rs and cs.rs.
- [x] An `or()` helper in track.rs for the MIPS/PowerPC/SPARC `ori`/`or` arms.
- [x] Move `sign_extend`, `ones` and `Field::mask` into mrs; `a64/helpers.rs` and `aarch32/spec_types.rs` duplicate
  them. Keep A64 armgen output byte-identical (hash 9814543386b94709d07f666db386d8bdede961c3 over
  scratchpad `words.txt`). The original scratchpad is unavailable; a 500,000-word deterministic rendering sweep
  is byte-identical to HEAD (SHA-1 `e5ac54acb63f7e70a31d5a9bb2965f48b984ea75`), and generated tables are unchanged.
- [x] Consolidate the `.w` qualifier handling and the chain of text `.replace` passes in `aarch32::format`.

## Smaller, outside rampage-arch (optional)

- [x] The UI assistant (`rampage-ui/src/assistant.rs`) recognises effects by tool-name strings ("rename",
  "set_comment", "show_address"); have the tool registry say which tools change annotations or move the view.
- [x] `rampage-api/src/graph.rs` recomputes block ends from line bytes; it could use the analysis `Block.end`.
- [x] The `binary_info` tool serializes its result twice.
- [x] The graph view computes row widths twice.

## Verification

- Debug/release workspace tests, including unchanged UI snapshots; Clippy with warnings denied; format/diff checks.
- The ignored Chrome large-binary UI test passes (debug build; subsequent frames 5–9 ms).
- Debug and release decoder suites, llvm-mc-checked regressions, and the A32/T16/T32 golden corpora.
- Interworking tested in both directions, with one/four threads and pre-existing/new call-target seeds.
- Review regressions cover stale mode hints, conditional fall-through calls, BLX-to-next, formatting and boundaries.
- Mode changes rebuild discovery from original seeds; contradictory mode cycles terminate without phantom functions.
- SP implicit writes, split DM operands, comparison/vector source preservation and graph layer centering are covered.
- Known seeds inherit incoming modes; cycle handling preserves downstream modes; invalid bytes retain decode mode.
- Invalid instructions advance IT slots; backward/interior interworking cycles have bounded termination regressions.
- Every Thumb halfword tested at the top of the address space in both byte orders; all 32 VCVT fraction widths.
- Literal pools tested with all code/data byte-order combinations and truncated reads.
- A64 rendering compared against the pre-change code on 500,000 deterministic words (identical SHA-1 above).
- Release builds report a local `rust-objcopy`/`libLLVM.dylib` stripping warning; the tests still pass.
