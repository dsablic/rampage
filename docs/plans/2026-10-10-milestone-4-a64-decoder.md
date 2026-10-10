# Milestone 4: AArch64 decoder from the Arm specification

**Goal:** disassemble and analyze AArch64 binaries with a decoder generated from Arm's specification rather than
written by hand or borrowed from another disassembler.

## Source data

Arm publishes an open-source subset of its A-profile machine-readable specification (AARCHMRS) under the BSD
3-clause license: `Instructions.json` (every encoding, its decode conditions, aliases and assembly grammar) and
`Registers.json` (system registers and system instruction encodings). The open-source subset leaves out the
decode and execute pseudocode and the operand descriptions.

## Approach

- `tools/a64gen` reads the JSON and writes `crates/rampage-arch/src/a64/spec.rs`:
  - every encoding's fixed bits and its decode condition, compiled from the specification's condition AST
    (feature checks are treated as implemented);
  - a decision tree over the encodings, so a lookup tests only a few candidates;
  - each instruction's and alias's assembly syntax, flattened from the grammar into tokens (text, operands,
    optional groups, alternatives), with each operand's source fields and legal spellings;
  - system register and system operation names keyed by encoding.
- What the open-source data leaves out is written by hand in `rampage-arch/src/a64`:
  - operand semantics (`operands.rs`): how field values become registers, immediates, labels and arrangements.
    Where the grammar lists an operand's legal spellings, the value is mapped to them by enumerating which field
    values still decode to the same encoding, so reserved values are skipped using the specification itself;
  - Arm pseudocode helpers (`DecodeBitMasks`, `MoveWidePreferred`, `BFXPreferred`, `SVEMoveMaskPreferred`);
  - the most important UNDEFINED rules from the decode pseudocode (`undefined.rs`);
  - control flow and data references (`flow.rs`), including ADRP+ADD and ADRP+LDR address formation.
    The `Disassembler` trait gained `reset()`, which discovery calls at each block start.

## Verification

LLVM's disassembler (`llvm-mc -mattr=+all`) served as the oracle on 485,000 words: the 400,000 most common and
a random sample of rarer instruction words from Chrome and dyld, plus 20 random words per encoding. Output
matches on all 399,952 sampled real instruction words that LLVM decodes (45 million instructions in Chrome and
dyld), and on 99.85% of all distinct words including the per-encoding samples; the remainder is mostly SME
ZA-array forms. Accepted differences: Arm's preferred aliases (UXTL rather than `USHLL #0`, BFC rather than
`BFI ..., wzr`) and Arm's register-range syntax. `crates/rampage-arch/tests/data/a64_golden.tsv` freezes 6,607
verified words as a regression test; other tests check the decision tree against a linear scan and format every
encoding with random operands in debug builds to catch arithmetic overflow.

## Results

Chrome's arm64 slice: 186,252 functions and 13.8 million instructions in 1.4 s, on par with x86-64 through
iced-x86.

## Follow-ups

- Name stubs and PLT entries after the imports they jump through (both architectures).
- Finish SME ZA-array and MOP4 operand forms.
- More decode-pseudocode UNDEFINED rules for SIMD and SVE.
