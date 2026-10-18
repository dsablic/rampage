/* SPDX-License-Identifier: Apache-2.0 */
#ifdef HOLDOUT
__attribute__((noinline)) unsigned layout_noise(unsigned value) {
    return (value * 73u + 19u) ^ (value >> 5);
}
#endif

__attribute__((noinline)) unsigned owned_fid_leaf(unsigned value) {
    value ^= 0x31415927u;
#ifdef NEGATIVE
    value = (value << 9) | (value >> 23);
    value += 0x27182819u;
#else
    value = (value << 7) | (value >> 25);
    value += 0x27182818u;
#endif
    return value ^ (value >> 11);
}

__attribute__((noinline)) unsigned owned_fid_mix(unsigned value) {
    unsigned result = owned_fid_leaf(value + 0x1717u);
    result ^= value * 37u;
#ifdef NEGATIVE
    result += (value >> 3) ^ 0x12346u;
#else
    result += (value >> 3) ^ 0x12345u;
#endif
    return (result << 3) | (result >> 29);
}

void _start(void) {
    volatile unsigned result = owned_fid_mix(53u);
    (void) result;
    for (;;) {}
}
