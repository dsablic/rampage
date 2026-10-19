; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; Xtensa:LE:32:default / default; all left-column offsets are bytes.
; Byte base 0x4000; static host analysis only; no target execution.
0000  c50000  CALL0 callee
0003  f02000  NOP
0006  3792f6  BNE a2,a3,main
0009  0df0  RET.N
000b  3df0  NOP.N padding
000d  f02000  NOP padding
0010  3df0  callee: NOP.N
0012  0df0  RET.N
; Only scalar 16/24-bit forms and non-windowed CALL0/RET.N; no FLIX, custom instruction, call4/8/12 window semantics.
; CALL0 target is aligned inst_start plus signed18<<2 plus4; byte/word guesses are not Java API evidence.
