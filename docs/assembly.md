# Assembly reference

## Contract

The native assembler is a bounded pure encoder for x86, x86-64 and little-endian AArch64. It returns bytes,
canonical disassembly, instruction count and an evidence profile. Encoding does not execute instructions,
modify a project, apply a patch or write a file.

The Rust entry point is `rampage_arch::assemble::assemble(target, address, source)`. The base address affects
relative branches and is checked for architectural width/alignment and arithmetic overflow.

## Source grammar

- One instruction per nonempty line; case-insensitive mnemonics and registers.
- Comma-separated operands; decimal or `0x` integer literals. AArch64 immediates may start with `#`.
- No symbols, labels, comments, expressions, memory operands, prefixes, directives, macros or includes.
- Unsupported input rejects the entire batch with a one-based line number, not a partial byte result.

## Supported instructions

| Architecture | Subset |
| --- | --- |
| x86/x86-64 | `NOP`, `RET`, register/register and register/immediate `MOV`/`CMP`, numeric `JMP`/`CALL`/`Jcc` |
| AArch64 | `NOP`, `RET [Xn]`, numeric `B`/`BL`/`B.cond`, same-width register `MOV`, single-instruction immediate `MOV`/`MOVZ`, immediate `CMP` |

x86 general-purpose registers are 16/32/64-bit; 64-bit registers and `r8`–`r15` require x86-64. Branches use
checked rel32 encodings, not implicit short-branch relaxation or wraparound. Immediates must fit the
instruction's actual width/sign-extension semantics.

AArch64 register `MOV` does not accept SP. Immediate `MOV` emits exactly one `MOVZ`, never a synthesized
sequence. Its unsigned 16-bit value may use `LSL #0/#16/#32/#48` where valid for the register width.
Immediate `CMP` accepts an appropriate register/SP, an unsigned 12-bit value and `LSL #0/#12`.

## Bounds and verification

Source is ASCII and at most 16 KiB. A batch has 1–64 instructions and at most 4,096 output bytes.
Unsupported architectures and big-endian instruction modes reject explicitly.

x86 encoding uses iced-x86 and checks decoded instruction/operand semantics. AArch64 encoding binds the
generated encoding fields and fixed bits, then verifies through the native decoder. These checks and owned
encoding vectors are static evidence, not execution or a guarantee of arbitrary source-language semantics.

Assembly output can be supplied to the separately checked patch API after explicit review. The assembler
does not bypass patch identity, preimage, mapping, overlap, revision or export checks.
