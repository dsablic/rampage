; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; Hexagon:LE:32:default / default; all left-column offsets are bytes.
; Byte base 0x1000; static host analysis only; no target execution.
0000  08c0005a  { CALL callee } ; one-word packet
0004  00c0007f  { NOP } ; one-word packet
0008  fce0df5c  { IF (p0) JUMP main } ; one-word packet, no extender
000c  00c09f52  { JUMPR r31 } ; return packet
0010  00c0007f  callee: { NOP }
0014  00c09f52  { JUMPR r31 }
; CPU version remains unspecified by selected default language: no v73, HVX, hardware packet or ABI acceptance claim.
; All proposed words set parse bits14:15=3 and form separate one-word packets; no duplex, extenders, loops, .new predicates, multi-slot hazards, or packet splitting.
; RelDest uses packet start, not necessarily instruction start; proposed offsets assume packetOffset=0. Future oracle must use fresh ProgramDB flow context and real EndPacket/crossbuild semantics, never just isolated pseudo rows.
; Conditional branch/local pcode labels and packet commit order remain acceptance blockers until independently observed.
