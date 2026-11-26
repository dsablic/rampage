/* SPDX-License-Identifier: Apache-2.0 */
/* COFF object fixtures (build-objects.sh): objects.c, plus what only COFF has: imports through `__imp_` pointers
 * (a dllimport function and a dllimport variable), a weak definition and an undefined weak function (weak
 * externals), a COMDAT variable (selectany), a linker directive (`.drectve`), and stores of immediates to globals
 * (x64 REL32_1 and REL32_4). */
#include "objects.c"

#pragma comment(lib, "kernel32")
__declspec(dllimport) unsigned long GetTickCount(void);
__declspec(dllimport) extern int imported_flag;
__attribute__((weak)) int weak_hook(int x) { return x + 1; }
extern int maybe_hook(int) __attribute__((weak));
__declspec(selectany) int shared_table[4] = {5, 6, 7, 8};

int uses_imports(int x) {
    int t = (int)GetTickCount() + imported_flag + weak_hook(x) + shared_table[x & 3];
    if (maybe_hook) t += maybe_hook(t);
    return t;
}

char flag;
int counter;

void set_flags(void) {
    flag = 1;
    counter = 7;
}
