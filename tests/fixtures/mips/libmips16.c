// SPDX-License-Identifier: Apache-2.0
// A small MIPS16e shared library (see build-mips16.sh), shipped without section headers as OpenWrt's sstrip
// leaves its libraries: exports in both instruction sets, an import, and a constructor run from DT_INIT_ARRAY.
#include <string.h>

static int counter;

__attribute__((constructor, noinline)) static void library_setup(void) { counter = 7; }

__attribute__((noinline)) int lib_add(int a, int b) { return a + b + counter; }

__attribute__((noinline, nomips16)) int lib_mul32(int a, int b) { return a * b; }

int lib_length(const char *text) { return (int)strlen(text) + lib_mul32(2, 3) + lib_add(1, 2); }
