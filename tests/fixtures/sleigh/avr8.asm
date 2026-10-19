; SPDX-License-Identifier: Apache-2.0
; Hand-authored encoding ledger, not assembler output. No target execution.
; Profile avr8:LE:16:default / gcc. Code byte base 0x200, word base 0x100.
; Encodings checked against installed avr8.sinc and avr8.ldefs.
; All left-column offsets below are bytes, never program-counter words.
;
; main: bytes [0,10). CALL second word 0x0108 is little-endian 08 01.
0000  0e 94 08 01   CALL callee    ; byte 0x210, encoded word target 0x108
0004  00 00         NOP
0006  e1 f7         BRNE main      ; Ghidra canonical mnemonic: brbc target,Zflg
0008  08 95         RET
;
; Disconnected diagnostic probes, not additional functions.
000a  0a c0         RJMP 0x110     ; word 0x110 = byte 0x220, mapped end exclusive
000c  09 95         ICALL          ; target in Z is unknown
000e  09 94         IJMP
;
; callee: bytes [16,20), independently declared before reference function creation.
0010  03 95         INC R16
0012  08 95         RET
0014  fc cf         RJMP 0x107     ; backward to byte 0x20e
0016  01 10         CPSE R0,R1     ; Ghidra skip context affects following instruction
0018  00 00         NOP
001a  0b 94         DES 0          ; static pcode includes instruction-local conditional labels
001c  ff ff         .word 0xffff   ; invalid in the selected profile
001e  0e 94         .word 0x940e   ; truncated 4-byte CALL, second word absent
