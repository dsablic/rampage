/* SPDX-License-Identifier: Apache-2.0; original frame fixture, never executed. */
__attribute__((noinline)) void frame_barrier(volatile long *slots)
{
    __asm__ volatile ("" : : "m" (*slots) : "memory");
}

__attribute__((noinline)) long frame_probe(long input, long second)
{
    volatile long slots[2] = { input, second };
    frame_barrier(slots);
    return slots[0] + slots[1] + input;
}
