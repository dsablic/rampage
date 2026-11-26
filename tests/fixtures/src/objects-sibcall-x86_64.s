/* SPDX-License-Identifier: Apache-2.0 */
/* Relocatable-object fixture (build-objects.sh): a branch to an undefined function. */
    .text
    .globl sibling
    .type sibling,@function
sibling:
    testl %edi, %edi
    jne ext_a
    leal 1(%rdi), %eax
    ret
    .size sibling, .-sibling
