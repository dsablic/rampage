// SPDX-License-Identifier: Apache-2.0
// Suite v3, switch tables: a dense switch whose first case is not zero and in which several case values share
// one block. VARIANT picks the case numbering, so the three builds (non-PIC x86-64 executable, PIC x86-64 shared
// library, PIC 32-bit x86 shared library) have different answers. The handlers differ in arity and effect, so
// the compiler keeps a jump table instead of a table of constants.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define NOINLINE __attribute__((noinline))
#ifdef OPCODES_SHARED
#define API __attribute__((visibility("default")))
#else
#define API
#endif

#ifndef VARIANT
#define VARIANT 1
#endif

#if VARIANT == 1
#define BASE 0x40
#define SHARED_A 2
#define SHARED_B 7
#define SHARED_C 11
#elif VARIANT == 2
#define BASE 0x15
#define SHARED_A 1
#define SHARED_B 6
#define SHARED_C 9
#else
#define BASE 0x68
#define SHARED_A 4
#define SHARED_B 5
#define SHARED_C 12
#endif

// The values 0..12 that are not in the shared group, in ascending order, name the ten single-case handlers.
#if VARIANT == 1
#define SINGLES {0, 1, 3, 4, 5, 6, 8, 9, 10, 12}
#define S0 0
#define S1 1
#define S2 3
#define S3 4
#define S4 5
#define S5 6
#define S6 8
#define S7 9
#define S8 10
#define S9 12
#elif VARIANT == 2
#define S0 0
#define S1 2
#define S2 3
#define S3 4
#define S4 5
#define S5 7
#define S6 8
#define S7 10
#define S8 11
#define S9 12
#else
#define S0 0
#define S1 1
#define S2 2
#define S3 3
#define S4 6
#define S5 7
#define S6 8
#define S7 9
#define S8 10
#define S9 11
#endif

API uint32_t vm_state[4];
API const char *vm_last = "none";

API NOINLINE int op_load(int arg) {
    vm_last = "op_load";
    vm_state[0] = (uint32_t)arg;
    return arg + 1;
}

API NOINLINE int op_store(int arg, int slot) {
    vm_last = "op_store";
    vm_state[slot & 3] ^= (uint32_t)arg;
    return slot;
}

API NOINLINE int op_jump(int arg, uint32_t *state) {
    vm_last = "op_jump";
    state[1] += (uint32_t)arg * 3u;
    return (int)state[1];
}

API NOINLINE int op_add(int left, int right, int carry) {
    vm_last = "op_add";
    return left + right + carry;
}

API NOINLINE void op_halt(void) {
    vm_last = "op_halt";
    vm_state[3] = 0xDEADu;
}

API NOINLINE int op_swap(uint32_t *state) {
    vm_last = "op_swap";
    uint32_t first = state[0];
    state[0] = state[2];
    state[2] = first;
    return (int)first;
}

API NOINLINE int op_shift(int arg, unsigned count) {
    vm_last = "op_shift";
    return (int)((uint32_t)arg << (count & 31u));
}

API NOINLINE int op_mask(int arg) {
    vm_last = "op_mask";
    return arg & 0x0FF0;
}

API NOINLINE int op_test(const uint32_t *state, int arg) {
    vm_last = "op_test";
    return state[0] == (uint32_t)arg;
}

API NOINLINE int op_push(int arg, int depth, uint32_t *state) {
    vm_last = "op_push";
    state[depth & 3] = (uint32_t)arg;
    return depth + 1;
}

API NOINLINE int op_trap(const char *reason) {
    vm_last = "op_trap";
    return reason[0];
}

API NOINLINE int vm_dispatch(int opcode, int arg) {
    switch (opcode) {
    case BASE + S0:
        return op_load(arg);
    case BASE + S1:
        return op_store(arg, 2) * 5;
    case BASE + SHARED_A:
    case BASE + SHARED_B:
    case BASE + SHARED_C:
        return op_jump(arg, vm_state) - 9;
    case BASE + S2:
        return op_add(arg, 17, 1);
    case BASE + S3:
        op_halt();
        return 0;
    case BASE + S4:
        return op_swap(vm_state) ^ arg;
    case BASE + S5:
        return op_shift(arg, 4) + 2;
    case BASE + S6:
        return op_mask(arg) | 1;
    case BASE + S7:
        return op_test(vm_state, arg) * 7;
    case BASE + S8:
        return op_push(arg, 1, vm_state);
    case BASE + S9:
        return op_trap("bad opcode") + arg;
    default:
        vm_last = "default";
        return -1;
    }
}

#ifndef OPCODES_SHARED
// Host harness and program entry: print the handler each opcode in the given range reaches.
int main(int argc, char **argv) {
    int first = argc > 1 ? (int)strtol(argv[1], NULL, 0) : 0;
    int last = argc > 2 ? (int)strtol(argv[2], NULL, 0) : first;
    for (int opcode = first; opcode <= last; opcode++) {
        vm_dispatch(opcode, argc);
        printf("%d %s\n", opcode, vm_last);
    }
    return 0;
}
#endif
