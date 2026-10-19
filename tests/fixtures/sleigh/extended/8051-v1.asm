; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; 8051:BE:16:default / default; all left-column offsets are bytes.
; Byte base 0x1000; static host analysis only; no target execution.
0000  121008  LCALL callee
0003  00  NOP
0004  70fa  JNZ main
0006  22  RET
0007  00  NOP padding
0008  00  callee: NOP
0009  22  RET
; Harvard CODE bytes only; RAM/INTMEM/SFR are not alias-backed by code bytes. LCALL absolute operands use big-endian byte order; conditional displacement is signed from inst_next. No ABI claim.
