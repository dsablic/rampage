; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; eBPF:LE:64:default / default; all left-column offsets are bytes.
; Byte base 0x1000; static host analysis only; no target execution.
0000  8510000003000000  CALL callee ; src=1 pseudo-call, imm=3
0008  b700000000000000  MOV r0,0 ; 64-bit class
0010  1500fdff00000000  JEQ r0,0,main ; off=-3
0018  9500000000000000  EXIT
0020  b700000000000000  callee: MOV r0,0
0028  9500000000000000  EXIT
; 8-byte base instructions; LDDW consumes two slots and is excluded from this short candidate.
; EXIT is exactly 9500000000000000; b7 is MOV, not EXIT. CALL src=1 is code-relative pseudo-call; src=0 helper uses syscall space and is not an owned callee edge.
; This is static SDK pcode, not kernel verifier or BPF runtime validity.
