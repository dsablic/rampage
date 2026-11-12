// SPDX-License-Identifier: Apache-2.0
// Owned identical-code-folding fixture, linked with /OPT:ICF: pairs of byte-identical functions fold into one
// body, so the PDB names one address several times. No CRT or SDK code is included or linked.

#define NOINLINE __declspec(noinline)

volatile int g_value = 3;

extern "C" NOINLINE int c_twice(int value) { return value * 2 + 1; }
extern "C" NOINLINE int c_double(int value) { return value * 2 + 1; }

NOINLINE int cpp_triple(int value) { return value * 3 - 7; }
NOINLINE int cpp_thrice(int value) { return value * 3 - 7; }

NOINLINE int distinct(int value) { return value ^ 0x55; }

extern "C" int icf_entry() {
    int (*volatile pointers[])(int) = {c_twice, c_double, cpp_triple, cpp_thrice, distinct};
    int total = 0;
    for (auto pointer : pointers) total += pointer(g_value);
    return total;
}
