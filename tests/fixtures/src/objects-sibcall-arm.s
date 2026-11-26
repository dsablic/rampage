/* SPDX-License-Identifier: Apache-2.0 */
/* Relocatable-object fixture (build-objects.sh): a branch to an undefined function. */
    .syntax unified
    .arm
    .text
    .globl sibling
    .type sibling,%function
sibling:
    cmp r0, #0
    bne ext_a
    add r0, r0, #1
    bx lr
    .size sibling, .-sibling
