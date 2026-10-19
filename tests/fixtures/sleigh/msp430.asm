; SPDX-License-Identifier: Apache-2.0
; Hand-authored encoding ledger, not assembler output. No target execution.
; Profile TI_MSP430:LE:16:default / default. RAM byte base 0x4400.
; Encodings checked against installed Ghidra TI430Common.sinc and TI_MSP430.ldefs.
; Columns: byte offset, owned bytes, intended source instruction.
;
; main: bytes [0,10), with a direct call to callee and a backward conditional loop.
0000  b0 12 10 44   CALL #callee
0004  03 43         NOP
0006  fc 23         JNE main
0008  30 41         RET
;
; Disconnected diagnostic probes are not additional function truth.
000a  30 40 20 44   BR #0x4420     ; beyond mapped end 0x441e
000e  03 43         NOP
;
; callee: bytes [16,20), independently declared before reference function creation.
0010  14 53         INC.W R4
0012  30 41         RET
0014  85 12         CALL R5        ; unknown computed target
0016  00 46         BR R6          ; unknown computed target
0018  30 40 00 44   BR #main
001c  b0 12         .byte 0xb0,0x12 ; truncated CALL immediate; extension word absent
