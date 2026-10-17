/* SPDX-License-Identifier: Apache-2.0
 * Original owned fixture. Freestanding entry points are for analysis, not execution. */

#define KEEP __attribute__((noinline))

_Static_assert(sizeof(void *) == 8, "This fixture requires eight-byte pointers");
_Static_assert(sizeof(int) == 4, "This fixture requires four-byte integers");

struct phase_state {
    int gain;
    int bias;
};

KEEP void phase_pointer_barrier(void **slot);

/* Keep the stack-local case first so a simple link can use it as the entry point. */
KEEP int phase_update(void *input, int delta) {
    void *state = input;
    phase_pointer_barrier(&state);
    return *(int *)state + *(int *)((unsigned char *)state + 4) + delta;
}

KEEP int phase_parameter(void *state, int delta) {
    return *(int *)state + *(int *)((unsigned char *)state + 4) + delta;
}

KEEP void phase_pointer_barrier(void **slot) {
    __asm__ volatile ("" : "+m" (*slot) : : "memory");
}

int main(int argc, char **argv) {
    struct phase_state state = {argc, argv != 0};
    int local_result = phase_update(&state, argc);
    return local_result + phase_parameter(&state, argc);
}
