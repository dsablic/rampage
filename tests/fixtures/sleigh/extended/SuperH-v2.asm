; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; SuperH:BE:32:SH-2 / default; all left-column offsets are bytes.
; Byte base 0x1000; static host analysis only; no target execution.
0000  b006  BSR callee
0002  0009  NOP ; call delay slot
0004  89fc  BT main
0006  000b  RTS
0008  0009  NOP ; return delay slot
000a  0009  NOP padding
000c  0009  NOP padding
000e  0009  NOP padding
0010  0009  callee: NOP
0012  000b  RTS
0014  0009  NOP ; return delay slot
; BSR and RTS each require the following 16-bit delay-slot instruction; preserve whole two-instruction bundles. BT here has no /S delay slot.
; SH-2 only: no SH-2A /N variants or invented SH-4 ABI.
