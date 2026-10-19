; SPDX-License-Identifier: Apache-2.0
; Hand-authored encoding ledger, not assembler output. No target execution.
; Profile 6502:LE:16:default / default. RAM byte base 0x8000.
; Encodings checked against installed 6502.slaspec and 6502.ldefs.
; No C ABI or decompilation correctness is asserted for this processor.
;
; main: bytes [0,8), with direct JSR to callee and backward BNE.
0000  20 10 80      JSR callee
0003  a9 01         LDA #1
0005  d0 f9         BNE main
0007  60            RTS
;
; Disconnected diagnostic probes are not additional function truth.
0008  4c 19 80      JMP 0x8019     ; mapped end exclusive
000b  6c 00 20      JMP (0x2000)   ; unknown indirect target, not a direct edge to 0x2000
000e  ea            NOP
000f  ea            NOP
;
; callee: bytes [16,18), independently declared before reference function creation.
0010  e8            INX
0011  60            RTS
0012  d0 ec         BNE main
0014  4c 00 80      JMP main
0017  02            .byte 0x02     ; invalid in the selected profile
0018  20            .byte 0x20     ; truncated JSR, absolute address absent
