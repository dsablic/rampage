; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; 6805:BE:16:default / default; all left-column offsets are bytes.
; Byte base 0x1000; static host analysis only; no target execution.
0000  cd1008  JSR callee
0003  9d  NOP
0004  26fa  BNE main
0006  81  RTS
0007  9d  NOP padding
0008  9d  callee: NOP
0009  81  RTS
; Only selected 6805 source; do not use sibling 6809 opcodes. Big-endian absolute JSR and signed relative branch; no ABI claim.
