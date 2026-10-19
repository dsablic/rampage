; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; z80:LE:16:default / default; all left-column offsets are bytes.
; Byte base 0x4000; static host analysis only; no target execution.
0000  cd0840  CALL callee
0003  00  NOP
0004  20fa  JR NZ,main
0006  c9  RET
0007  00  NOP padding
0008  00  callee: NOP
0009  c9  RET
; RAM code and separate IO space must remain distinct; prefixes are multi-byte instructions, not extra function starts. No eZ80/Z180 substitution.
