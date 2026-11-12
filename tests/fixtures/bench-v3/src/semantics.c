// SPDX-License-Identifier: Apache-2.0
// Suite v3, decompiler-heavy semantics: what a function returns for given inputs. Built for 32-bit x86 and 32-bit
// ARM; every type is fixed-width, so a host build of this file returns the same values (the truth source).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))

// Loop over the set bits of `value`, lowest first, for at most `rounds` bits.
NOINLINE uint32_t fold_bits(uint32_t value, uint32_t rounds) {
    uint32_t acc = 0x9E3779B9u;
    while (rounds != 0 && value != 0) {
        uint32_t low = value & (0u - value);
        acc = ((acc << 5) | (acc >> 27)) ^ low;
        value &= value - 1;
        acc += value >> 3;
        rounds--;
    }
    return acc ^ (acc >> 16);
}

// Decoy with the same shape and another constant, so the functions are not merged or confused by constant.
NOINLINE uint32_t fold_bytes(uint32_t value, uint32_t rounds) {
    uint32_t acc = 0x85EBCA6Bu;
    while (rounds != 0 && value != 0) {
        acc = ((acc << 7) | (acc >> 25)) + (value & 0xFFu);
        value >>= 8;
        rounds--;
    }
    return acc ^ (acc >> 13);
}

// 64-bit arithmetic from 32-bit inputs: a widening multiply, a shift across the word boundary, a 64-bit
// subtraction with borrow.
NOINLINE uint64_t scale64(uint32_t a, uint32_t b) {
    uint64_t wide = (uint64_t)a * b;
    wide += (uint64_t)a << 21;
    wide ^= wide >> 29;
    wide -= 0x100000001ull * (b & 7u);
    return wide;
}

// 64-bit rotate by a variable count, a 64-bit add with carry and an unsigned 64-bit division by a constant.
NOINLINE uint64_t mix64(uint64_t x, uint32_t k) {
    k = (k & 31u) + 1u;
    uint64_t y = (x << k) | (x >> (64u - k));
    y += (uint64_t)k * 0xFFFFFFFFu;
    return y / 7u + ((y % 7u) << 40);
}

// Count the steps of a halving/tripling walk and keep the largest value seen.
NOINLINE uint32_t walk(uint32_t n, uint32_t limit) {
    uint32_t steps = 0, peak = n;
    while (n > 1 && steps < limit) {
        n = (n & 1u) ? 3u * n + 1u : n >> 1;
        if (n > peak) {
            peak = n;
        }
        steps++;
    }
    return (peak << 8) | steps;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        puts("usage: semantics FUNCTION A B");
        return 2;
    }
    uint64_t a = strtoull(argv[2], NULL, 0);
    uint64_t b = strtoull(argv[3], NULL, 0);
    uint64_t result;
    if (strcmp(argv[1], "fold_bits") == 0) {
        result = fold_bits((uint32_t)a, (uint32_t)b);
    } else if (strcmp(argv[1], "fold_bytes") == 0) {
        result = fold_bytes((uint32_t)a, (uint32_t)b);
    } else if (strcmp(argv[1], "scale64") == 0) {
        result = scale64((uint32_t)a, (uint32_t)b);
    } else if (strcmp(argv[1], "mix64") == 0) {
        result = mix64(a, (uint32_t)b);
    } else if (strcmp(argv[1], "walk") == 0) {
        result = walk((uint32_t)a, (uint32_t)b);
    } else {
        return 2;
    }
    printf("0x%llx\n", (unsigned long long)result);
    return 0;
}
