# To do

Remaining work from the second code-review round. Most of it is in `crates/rampage-arch/src/aarch32/flow.rs`.
After each group: `cargo fmt`, `cargo clippy --all-targets`, `cargo test`, and the AArch32 golden tests
(`tests/data/{a32,t16,t32}_golden.tsv`; current rates A32 97.7%, T16 100%, T32 97.2%). Add cases to
`crates/rampage-arch/tests/flow.rs` with encodings checked against llvm-mc.

## In the working tree, uncommitted

- `Target::data_big_endian` (rampage-arch `lib.rs`), set by `Binary::target()` (`load.rs`) and the `big_endian`
  test helper. Nothing reads it yet; see "Literal pools" below.
- `track.rs`: PowerPC64 `addis` counts as the first half of an address, like `lis`, so its intermediate value is
  no longer reported as a data reference. Needs a test (`addis r3, r2, X; addi r3, r3, Y` reports only the sum).

## AArch32 flow and tracking bugs

1. **Thumb high registers.** T16 encodings split the destination into `D:Rd`, `DN:Rdn` or `DM:Rdm`, but `kind()`
   and `track()` read only the low 3 bits. So `mov pc, lr` (f746), `mov pc, r0` (8746) and `add pc, r3` (9f44)
   are classified as `Next`, and `mov r8, r1` (8846) and `add r8, pc` (f844) track the wrong register.
   Fix: one helper that reads a register operand by name (`<Rd>`, `<Rdn>`, `<Rdm>`, `<Rm>`, ...) through
   `Encoding::operand_bits`, which concatenates all of the operand's fields; fall back to the plain field.
2. **PC writers.** `subs pc, lr, #4` (A32 04f05ee2, T32 def3048f) is `Next`: SUBS is missing from the PC-writer
   list, and the `SUBS_PC_LR` name prefix never matches (the T32 encoding is `SUBS_PC_T5_AS`). It should be a
   return, as `movs pc, lr` is. Shifted moves such as `lsl pc, r0, #2` (A32 00f1a0e1) are also `Next`. Accept the
   S-suffixed and shift mnemonics (LSL, LSR, ASR, ROR, RRX) when the destination is PC.
3. **Unclear destinations.** Registers written as RdLo/RdHi (UMULL), Rt (MRC, VMOV to core registers, loads) and
   STREX's status Rd are never cleared. Clear every destination operand, treating Rt/Rt2 as written except for
   stores, MCR and PUSH. Over-clearing only loses tracking.
4. **LDRD.** T32 LDRD's Rt2 is not cleared (covered by 3). A32 literal LDRD doesn't clear Rt, or Rt+1.
5. **16-bit LDM/STM writeback.** T16 LDM/STM have no W field but write back the base (LDM unless the base is in the
   list). Clear Rn for them.
6. **Offset scaling.** T32 LDRD/STRD/LDREX imm8 is a word offset (x4). The T16 imm5 forms are not tracked at all:
   LDR/STR imm5 scales x4, LDRH/STRH x2, LDRB/STRB x1; SP-relative imm8 x4.
7. **ADD (register).** It ignores the shift (`add r0, pc, r1, lsl #2`, 01018fe0), and RRX encodings. Track only
   unshifted forms. It also reports data references for conditional ADDs (`addeq r0, pc, r1`, 01008f00); report
   only unconditional ones.
8. **Literal pools.** Read in instruction byte order, which is wrong for BE8 images (code little-endian, data
   big-endian). Read them with `Target::data_big_endian`.
9. **Over-strong classifications.**
   - `ldm r0, {r1, pc}` (A32 028090e8, T32 90e80280) is a `Return`; only a POP or SP-based LDM should be. Others
     are `IndirectJump`.
   - `ldr pc, [pc, #x]` should jump to the literal's value when the pool is readable (keeping the Thumb bit's
     meaning: even in A32, odd in T32), not be an `IndirectJump`.
   - Thumb `blx label` switches to A32, but `Target::thumb` is a fixed set of ranges, so the target decodes in the
     wrong mode. Needs a design decision (feed mode switches back to the analysis).
10. **Overflow.** `address + size` overflows (and panics in debug builds) near `u64::MAX`: flow.rs `flow()`,
    `track()`'s `pc`, `decode()`'s `next`, and cs.rs:241. Use `wrapping_add`.

## AArch32 rendering bugs

- The `hint` alias renders as `clrbhb`.
- VCVT_is shows u32 where it should be s32.
- VCVT_xs prints the wrong types and fbits.

## DRY and refactors (behaviour must not change)

- One mnemonic helper instead of three: `aarch32/mod.rs` `mnemonic`, mrs `root_mnemonic`, operands
  `Context::mnemonic`.
- Remove the `field()` wrapper in flow.rs; call `Decoded::field`.
- One destination-register helper in flow.rs (from bug 1), used by `kind()` and `track()`.
- The LDM/POP mnemonic list appears twice in flow.rs; make it one constant or function.
- A `wide_immediate` helper for the MOVW/MOVT imm4:i:imm3:imm8 (T32) and imm4:imm12 (A32) values.
- `is_non_canonical` should reuse `operands::canonical_rotation`.
- One `read_u32(bytes, offset, big_endian)` for the A32 word, literal pools and similar reads.
- Share the kind-to-`Flow` mapping (conditions applied) between flow.rs and cs.rs.
- An `or()` helper in track.rs for the MIPS/PowerPC/SPARC `ori`/`or` arms.
- Move `sign_extend`, `ones` and `Field::mask` into mrs; `a64/helpers.rs` and `aarch32/spec_types.rs` duplicate
  them. Keep A64 armgen output byte-identical (hash 9814543386b94709d07f666db386d8bdede961c3 over
  scratchpad `words.txt`).
- Consolidate the `.w` qualifier handling and the chain of text `.replace` passes in `aarch32::format`.

## Smaller, outside rampage-arch (optional)

- The UI assistant (`rampage-ui/src/assistant.rs`) recognises effects by tool-name strings ("rename",
  "set_comment", "show_address"); have the tool registry say which tools change annotations or move the view.
- `rampage-api/src/graph.rs` recomputes block ends from line bytes; it could use the analysis `Block.end`.
- The `binary_info` tool serializes its result twice.
- The graph view computes row widths twice.
