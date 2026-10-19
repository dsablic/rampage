; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; tricore:LE:32:default / default; all left-column offsets are bytes.
; Byte base 0x1000; static host analysis only; no target execution.
0000  5c08  CALL callee ; short disp8
0002  0000  NOP
0004  eefe  JNZ d15,main
0006  0090  RET
0008  0000  NOP padding
000a  0000  NOP padding
000c  0000  NOP padding
000e  0000  NOP padding
0010  0000  callee: NOP
0012  0090  RET
; Only PCPMode=0 scalar core and selected root TRICORE_V2 macro; PCP is not a sibling profile substitute.
; SDK call/return source contains CSA/state TODOs; planned decode/flow evidence must not authenticate CSA semantics or CPU behavior.
