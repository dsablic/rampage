/* SPDX-License-Identifier: Apache-2.0 */
/* Mach-O object fixtures (build-objects.sh): objects.c, plus what Mach-O spells its own way: stores of immediates
 * to globals (x86-64 SIGNED_1 and SIGNED_4), a symbol plus an offset (arm64 ADDEND pairs), externs reached through
 * the GOT, and differences of two symbols (SUBTRACTOR pairs). */
#include "objects.c"

extern int ext_array[];
char flag;
int counter;
int local_array[2000];

int bump(int x) {
    flag = 1;
    counter = 7;
    ext_array[3] = x;
    return ext_array[100];
}

int *far_element(void) { return &local_array[1500]; }

__asm__(".section __DATA,__data\n"
        ".globl _differences\n"
        ".p2align 3\n"
        "_differences:\n"
        ".quad _greeting - _sum\n"
        ".long _main - _differences\n"
        ".quad _greeting + 8\n");
