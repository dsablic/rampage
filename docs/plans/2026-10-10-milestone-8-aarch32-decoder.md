# Milestone 8: AArch32 (A32 and T32) decoder from the Arm specification

**Goal:** decode 32-bit ARM and Thumb natively from the same open AARCHMRS data the A64 decoder uses, replacing
Capstone for `Arch::Arm`, with output verified against llvm-mc.

## Source data

`Instructions.json` holds three instruction sets: A64, A32 (1099 instructions, 95 aliases) and T32 (1121
instructions, 224 aliases). A32 encodings are 32-bit words. T32 is modelled as a 32-bit word read 16 bits at a
time: the 16-bit groups (`n`, `b16`) use bits 15..0 of the first halfword; the 32-bit group (`w`) puts the first
halfword in bits 31..16. Decode conditions call `InITBlock`, `UInt`, `SInt`, `BitCount`, `T32ExpandImm`,
`IsFeatureImplemented` (treated as true) and `A32EncodingExists`/`T32EncodingExists`.

## Approach

1. **Share the runtime.** Move the instruction-set-independent parts of `a64/` (table types, decision-tree
   lookup, alias choice, syntax rendering) into `mrs/`, parameterized by a set's generated tables. A64 output
   must stay byte-for-byte identical (the golden test and a full-sweep comparison check it).
2. **Generalize the generator.** `tools/a64gen` becomes `tools/armgen`, taking the instruction set to emit.
   Conditions referring to processor state (`InITBlock`) compile to a context argument.
3. **AArch32 runtime** (`aarch32/`): A32 and T32 lookup, halfword-width detection for T32, IT-block state,
   hand-written operand semantics for the ~60 operand kinds (registers, shifts, modified immediates,
   register lists, labels, VFP/Advanced SIMD registers, data types, alignment, coprocessor fields).
4. **Flow and addresses natively:** branches, calls (BL/BLX), returns (BX LR, POP/LDM with PC, MOV PC, LR),
   conditions, and the address tracking `track.rs` does for ARM today (literal pools, MOVW/MOVT, PC-relative
   ADD, PLT entries).
5. **Verification:** a golden file sampled per encoding and checked with llvm-mc 22 (`armv8a` and `thumbv8a`
   with VFP and Advanced SIMD), plus a per-encoding fuzz test for panics. Then switch `Arch::Arm` to the native
   decoder once its golden match rate and fixture analysis are at least as good as Capstone's.
