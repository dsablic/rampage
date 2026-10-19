; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; PIC-16:LE:16:PIC-16 / default; all left-column offsets are bytes.
; Byte base 0x200; static host analysis only; no target execution.
0000  0821  CALL 0x108 ; encoded word address, PCLATH context required
0002  0000  NOP
0004  201c  BTFSS 0x20,0
0006  0000  NOP ; skip-context consumer
0008  0800  RETURN
000a  0000  NOP padding
000c  0000  NOP padding
000e  0000  NOP padding
0010  0000  callee: NOP
0012  0800  RETURN
; CODE declares wordsize=2; DATA and HWSTACK are distinct spaces. Preserve both Java offset getters when eventually run.
; CALL operand combines PCLATH<4:3> and k11; proposed low-word target 0x108 requires explicit PCLATH=0 context. Selected source uses call [absAddr11], so a direct static target is NOT currently promised.
; BTFSS uses possibleSkip/SkipNext propagation; isolate-only decoding is insufficient for conditional coverage. No PIC16F relative BRA substituted for selected PIC_16.
