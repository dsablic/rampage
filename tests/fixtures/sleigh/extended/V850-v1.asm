; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; V850:LE:32:default / default; all left-column offsets are bytes.
; Byte base 0x1000; static host analysis only; no target execution.
0000  80ff1000  JARL callee,r31
0004  0000  NOP
0006  dafd  BNE main
0008  7f00  JMP [r31] ; return alias
000a  0000  NOP padding
000c  0000  NOP padding
000e  0000  NOP padding
0010  0000  callee: NOP
0012  7f00  JMP [r31]
; Variable 16/32-bit instructions; JARL displacement is relative to inst_start and has split fields. JMP [r31] is the SDK return-special case.
; Selected SDK description covers E1/E2/E2M; no stronger CPU subset or ABI claim.
