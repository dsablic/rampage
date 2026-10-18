/* SPDX-License-Identifier: Apache-2.0; original metadata/discovery fixture, never executed. */
volatile unsigned int arm_exidx_seed = 17;

__attribute__((noinline)) unsigned int arm_exidx_unreferenced(unsigned int value)
{
#if defined(RAMPAGE_DISTINCT_UNWIND)
    __asm__ volatile ("" : : : "r4", "r5", "r6", "memory");
#endif
    volatile unsigned int words[5];
    words[0] = value + 19;
    words[1] = words[0] ^ 0x351;
    words[2] = words[1] * 7;
    words[3] = words[2] - value;
    words[4] = words[3] ^ (words[0] << 2);
    return words[4] + words[1];
}

__attribute__((noinline)) unsigned int arm_exidx_reachable(unsigned int value)
{
#if defined(RAMPAGE_DISTINCT_UNWIND)
    __asm__ volatile ("" : : : "r4", "r5", "memory");
#endif
    volatile unsigned int words[3];
    words[0] = value * 13;
    words[1] = words[0] + 29;
    words[2] = words[1] ^ value;
    return words[2] + words[0];
}

int main(void)
{
    return (int)(arm_exidx_reachable(arm_exidx_seed) & 255);
}
