; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; HCS-12:BE:24:default / default; all left-column offsets are bytes.
; Byte base 0x2000; static host analysis only; no target execution.
0000  0706  BSR callee
0002  a7  NOP
0003  26fb  BNE main
0005  3d  RTS
0006  a7  NOP padding
0007  a7  NOP padding
0008  a7  callee: NOP
0009  3d  RTS
; Use unbanked low 0x002000 near-relative BSR, not paged CALL. PPAGE/global translation and 24-bit space behavior remain unobserved until actual Java addresses are recorded.
; Do not substitute HCS12X/XGATE or treat 16-bit stored return values as proof of flat 24-bit ABI.
