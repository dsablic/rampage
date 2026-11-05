// SPDX-License-Identifier: Apache-2.0
// The Windows debug fixture: a program that calls a named function, `tick`, in a loop, and `tick` adds to a global,
// `counter`. `start` (the entry point; no C runtime, so the image stays small) calls `tick` with a `call`, so a
// breakpoint on `tick` stops at its first instruction with the return address in `start` at [rsp] ([esp] on x86).
// `tick` and `start` are exported, so the image names them without its PDB.
//
// `counter_pointer` loads `counter`'s absolute address into a register (`movabs` on x86-64, `mov` on x86), so .text
// holds a pointer that a base relocation (DIR64 or HIGHLOW) patches when the loader moves the image (ASLR): a moved
// image's code differs from the file there, which slide verification must skip. `counter_address` is a second such
// pointer, in .data.

__declspec(dllimport) void __stdcall Sleep(unsigned long milliseconds);

volatile unsigned long long counter;
volatile unsigned long long *volatile counter_address = &counter;

__declspec(noinline) static volatile unsigned long long *counter_pointer(void) {
    volatile unsigned long long *pointer;
#if defined(__x86_64__)
    __asm__ volatile("movabsq $counter, %0" : "=r"(pointer));
#else
    __asm__ volatile("movl $_counter, %0" : "=r"(pointer));
#endif
    return pointer;
}

__declspec(dllexport) __declspec(noinline) unsigned long long tick(unsigned long long step) {
    *counter_pointer() += step;
    return *counter_address;
}

__declspec(dllexport) void start(void) {
    for (;;) {
        tick(1);
        Sleep(1);
    }
}
