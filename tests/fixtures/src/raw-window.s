.syntax unified
.thumb
.text
.globl owned_raw_window
.thumb_func
owned_raw_window:
    movw r0, #0x1234
    ldr r1, .Lconstant
    bx lr
    .balign 4
.Lconstant:
    .word 0x89abcdef
