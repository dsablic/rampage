/* SPDX-License-Identifier: Apache-2.0 */
/* Relocatable-object fixture (build-objects.sh): a branch to an undefined function. */
    .text
    .globl sibling
    .type sibling,%function
sibling:
    stp x29, x30, [sp, #-16]!
    bl ext_a
    cbz w0, 1f
    mov w0, #2
1:
    ldp x29, x30, [sp], #16
    ret
    .size sibling, .-sibling
