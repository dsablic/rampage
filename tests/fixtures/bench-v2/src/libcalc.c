// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: two builds of one shared library. CALC_V2 changes exactly three exported functions
// (calc_scale, calc_clamp, calc_checksum); everything else is the same source, though addresses shift. Built for
// x86-64 Linux and stripped of its symbol table (exports stay in the dynamic symbol table).
#include <stddef.h>
#include <stdint.h>

#define EXPORT __attribute__((visibility("default"), noinline))

EXPORT int calc_add(int a, int b) { return a + b; }

EXPORT int calc_scale(int value) {
#ifdef CALC_V2
    return value * 7 + 3;
#else
    return value * 5 + 3;
#endif
}

EXPORT int calc_clamp(int value, int low, int high) {
#ifdef CALC_V2
    if (low > high) {
        int swap = low;
        low = high;
        high = swap;
    }
#endif
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

EXPORT int calc_average(const int *values, size_t n) {
    long sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum += values[i];
    }
    return n ? (int)(sum / (long)n) : 0;
}

EXPORT uint32_t calc_checksum(const uint8_t *data, size_t n) {
    uint32_t sum = 1;
    for (size_t i = 0; i < n; i++) {
#ifdef CALC_V2
        sum = (sum << 5) + sum + data[i];
#else
        sum = (sum << 5) - sum + data[i];
#endif
    }
    return sum;
}

EXPORT int calc_max(const int *values, size_t n) {
    int best = n ? values[0] : 0;
    for (size_t i = 1; i < n; i++) {
        if (values[i] > best) {
            best = values[i];
        }
    }
    return best;
}

EXPORT int calc_scaled_sum(const int *values, size_t n) {
    int sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum = calc_add(sum, calc_scale(values[i]));
    }
    return sum;
}

EXPORT const char *calc_version(void) { return "libcalc 1.4"; }
