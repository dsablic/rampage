; SPDX-License-Identifier: Apache-2.0
; Hand-owned explanatory encoding ledger, not assembler output.
; CR16C:LE:16:default / default; all left-column offsets are bytes.
; Byte base 0x1000; static host analysis only; no target execution.
0000  00c01000  BAL (RA),callee
0004  002c  NOP
0006  1d1f  BRne main
0008  ee0a  JUMP RA ; return alias
000a  002c  NOP padding
000c  002c  NOP padding
000e  002c  NOP padding
0010  002c  callee: NOP
0012  ee0a  JUMP RA
; Selected CR16C declares ram size=4 despite language ID size16. RA stores inst_next>>1 and return expands RA<<1; these are link-value semantics, not a claim that ram addressable units are two bytes.
; Split signed displacement fields and return alias must be checked with actual Java getOffset/getAddressableWordOffset; never multiply API target offsets speculatively.
