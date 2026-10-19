; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; Loongarch:LE:64:lp64d / default; all left-column offsets are bytes.
; Byte base 0x1000; static host analysis only; no target execution.
0000  00100054  BL callee
0004  00004003  NOP ; ANDI zero,zero,0 alias
0008  20f8ff5f  BNE r0,r1,main
000c  2000004c  RET ; JIRL r0,r1,0 alias
0010  00004003  callee: NOP
0014  2000004c  RET
; Selected lp64d root only; scalar 4-byte forms. RET alias source matches word0x4c000020 (bytes2000004c). No LSX/LASX/privileged/ABI proof.
; BL has a specialized SDK branch-alias case when imm10_16=1; proposed call uses4, deliberately avoiding that case.
