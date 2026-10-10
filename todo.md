# To do

## Deep ARM64 track

1. [ ] Integer instruction semantics: arithmetic/logical shifts, wide moves, multiply/divide, NZCV, common
   scalar/pair memory operations and AAPCS64 call effects. Verify encodings with LLVM and execution on fixtures.
2. [ ] Stack/signature analysis: preserve callee-saved registers, identify SP-relative slots and conservatively
   report argument/return evidence; unknown instructions and conflicting paths must remain unknown.
3. [ ] SSA simplification and pseudocode: bounded constant/affine reasoning and explicit semantic gaps, then
   structured conditions/loops and types. Do not claim complete source recovery from partial IR.
4. [ ] Jump tables/indirect flow: recover only bounded, validated tables and targets, with evidence and no guesses
   for mutable/authenticated pointers. Extend the controlled corpus before enabling new recovery rules.
5. [x] Runtime capture: successful permitted live capture, module identities/slides, original-file correlation
   and register provenance. Existing exporter mocks alone do not satisfy this gate.
6. [ ] Accuracy benchmark: checked fixture results for instructions, CFGs, xrefs and semantics, plus versioned
   IDA/Ghidra comparison imports when those tools are available. Record missing tools rather than claiming parity.

Current ARM64 increment: integer logical/shift/multiply/divide/wide-move semantics, NZCV and B.cond,
ADR/ADRP, common 32/64-bit scalar and 64-bit pair memory effects, conservative integer AAPCS64 calls,
monotone constant/entry-SP-relative stack evidence, and bounded SSA-style pseudocode. Native ARM64 evaluator
comparisons and controlled fixtures cover these cases; full semantic/ABI/structured-source coverage is open.
Ghidra/IDA are not on the command path. Controlled live LLDB capture passes with ASLR enabled.
Ghidra's architecture is a reference; no Ghidra implementation code or specifications have been incorporated.
Explicit bounded absolute64/signed-relative32 jump-table inspection is available without guessing dispatch
bounds or injecting CFG edges. Snapshots record bounded module/register provenance; explicit UUID-matched
Mach-O correlation maps runtime header slides without opening metadata-supplied paths. Function-start
comparisons accept bounded, versioned exports for hash-matched regular images; snapshots are excluded until
mapping-aware comparison identities exist.
Bounded immediate-dominator and natural-loop analysis now accompanies SSA; structured-source rendering,
minimal SSA, full signatures/type recovery and automatic dispatch reconstruction remain acceptance gates.
Selected sequence/branch/single-body-loop control regions are represented over SSA block references; phis,
header execution and unsupported graph shapes remain explicit. This does not yet constitute typed source recovery.
Conditional selects and common bitfield shift/extract aliases now retain semantics in IR/SSA. Optimized native
C fixtures exercise arithmetic and select paths end-to-end, alongside boundary-level execution comparisons.
Per-RET integer-return candidates retain X0/X1 definitions and constants without claiming a recovered signature.
SSA removes redundant phi aliases without expression expansion; changing loop values retain predecessor inputs.
Native checks cover all condition codes and all NZCV combinations.
Extended-register ADD/SUB, including SP address calculations and signed/unsigned extensions, is now lifted.

## General-purpose reverse-engineering roadmap

Acceptance gate for each milestone: behavioral regressions, malformed-input tests, `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, workspace tests, and independent review. Commercial samples are
read-only triage inputs, never bypass or patch fixtures. Runtime tests use programs we build ourselves.

- [ ] Runtime images: validated sparse snapshot format, CLI/API/UI loading, explicit code seeds, provenance,
  ASLR-safe address handling, deterministic analysis, and an LLDB export adapter for authorized processes.
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
  Writable capture regions are excluded from pointer evidence until reaching-store analysis exists; joins do
  not treat a frozen file as proof that later loads keep their captured value.
- [x] Final discovery closure and retained per-function resolved flows, keeping CFGs/listings consistent.
- [x] `audit`/`analysis_diagnostics`: bounded coverage and unreliable-code evidence, not proof of encryption.
- [x] Bounded C++/Rust demangling; original lookup aliases and collision-safe display names.
- [x] Sized, named Itanium vtable targets/RTTI labels and Objective-C selector string inventory.
- [x] Plist-authoritative bundle opening and bounded inventory of already-extracted packages/directories.
- [x] Structural function summaries with paginated references, CFG and explicit non-decompiler limitations.
- [x] Partial typed AArch64 IR for immediate ADD/SUB, MOVZ/register moves, 64-bit loads/stores and NOP.
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

1. **Runtime integration:** verify a successful LLDB capture on a permitted stopped fixture; module identities,
   ASLR slides and captured register state; snapshot-to-original mapping and reproducible session persistence.
2. **Data-flow:** reaching-store/alias analysis before enabling mutable snapshot pointer inference; per-edge
   register state, joins/loops, bounded fixpoints, source-attributed resolution evidence and unknown outcomes.
3. **IR and SSA:** extend instruction semantics/calling conventions, then dominance/phi construction; compare
   lifted execution to controlled native fixtures at boundaries, overflow, zero registers and flag writes.
4. **Language recovery:** stripped Itanium/MSVC vtables, class layouts, Objective-C method/class references,
   relative/authenticated pointers, DWARF/PDB integration and fixture-based malformed metadata validation.
5. **Decompilation:** expressions, conditions, loops, returns and typed variables over SSA; output must explicitly
   show semantic gaps and must not present unsupported paths as recovered source.
6. **Containers/workspaces:** safe archive indexing/extraction budgets, module-qualified names/addresses,
   dependencies, cross-module references and UI/MCP navigation; never execute installer scripts.

Foundation validation: full debug/release workspace suites, warnings-denied Clippy, unchanged existing UI
snapshots, new snapshot UI/CLI/API regressions, malformed input bounds, six LLDB exporter tests, Ruff/ty,
and fresh-context reviews with each reported reproduction retained as a regression.

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
