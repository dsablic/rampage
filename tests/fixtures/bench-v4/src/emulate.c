/* SPDX-License-Identifier: Apache-2.0 */
/* Suite-v4 emulation fixture: functions whose result is impractical to work out by hand from correct pseudocode
 * (hundreds of loop iterations, a 256-byte table, C library calls), compiled for several targets by build.sh. Each
 * task asks about one function in one build. Built with -DHOST_MAIN for the host, main() runs one function on the
 * command-line arguments and prints the result; derive-truth.py takes the truths from there. Unsigned arithmetic
 * only, so no result depends on undefined behaviour. */
#include <stddef.h>
#include <stdint.h>
#ifndef FREESTANDING
#include <string.h>
#endif

#define NOINLINE __attribute__((noinline, used))

static const uint8_t SBOX[256] = {
    0xc5, 0x92, 0x16, 0xc9, 0x25, 0x65, 0xca, 0x20, 0xab, 0xa1, 0x0f, 0x3b, 0x8b, 0x5d, 0x77, 0xa9,
    0x1b, 0x4f, 0x17, 0xf2, 0x05, 0x4d, 0x31, 0x39, 0xd2, 0x43, 0x49, 0x81, 0x9a, 0xa2, 0x21, 0x67,
    0x47, 0x7b, 0xf6, 0x79, 0x2a, 0xcd, 0x75, 0x33, 0xa7, 0x55, 0x76, 0x35, 0xb3, 0xfc, 0x37, 0x52,
    0x01, 0xef, 0x11, 0xbe, 0x23, 0x95, 0xd1, 0x98, 0x19, 0x60, 0x6a, 0x41, 0xc1, 0x61, 0x5a, 0x51,
    0x07, 0x62, 0x2e, 0xe7, 0x27, 0xac, 0xb2, 0x72, 0x4c, 0xe0, 0x78, 0x97, 0xde, 0x70, 0x1d, 0x44,
    0xb6, 0x5f, 0x57, 0xbb, 0x29, 0x6b, 0xf4, 0xc2, 0x59, 0x6d, 0x28, 0x30, 0xb0, 0x85, 0xec, 0x7f,
    0x69, 0xa5, 0xf9, 0xd7, 0x9b, 0xd5, 0x9e, 0xd8, 0xed, 0xda, 0x2d, 0xba, 0x3d, 0xcb, 0x09, 0x83,
    0xc7, 0x91, 0xb5, 0x48, 0x6e, 0x6c, 0x22, 0x74, 0x13, 0x56, 0xe5, 0x18, 0x99, 0xa0, 0x7d, 0xe3,
    0xbd, 0x36, 0x10, 0xd3, 0xeb, 0x1a, 0x7a, 0xdd, 0xfd, 0xb9, 0x3f, 0x8f, 0x82, 0x96, 0x7e, 0xf7,
    0xfa, 0xb4, 0xd0, 0xaf, 0x5b, 0x00, 0x3e, 0xdb, 0x8a, 0xe8, 0x9d, 0x88, 0xad, 0x12, 0xe6, 0xbf,
    0x93, 0xa3, 0xe4, 0xb1, 0xee, 0x1e, 0x73, 0xb7, 0x4b, 0x32, 0x54, 0x40, 0x71, 0xe1, 0x26, 0x84,
    0x15, 0x80, 0x1f, 0x3c, 0xc3, 0xa8, 0x0d, 0xcc, 0x87, 0xd6, 0x68, 0xb8, 0x63, 0x50, 0x53, 0xf0,
    0x0a, 0x3a, 0x24, 0x38, 0xcf, 0x64, 0xea, 0xbc, 0x8e, 0x4a, 0x0b, 0xce, 0x5c, 0x02, 0xc8, 0xc4,
    0x2f, 0xae, 0x4e, 0xa4, 0x9c, 0xdc, 0xd9, 0xf1, 0xf8, 0x0c, 0x66, 0x2c, 0x0e, 0xf3, 0x2b, 0xff,
    0x7c, 0xe9, 0x42, 0x90, 0x89, 0xa6, 0x45, 0x04, 0x06, 0xf5, 0x8d, 0x08, 0xe2, 0x5e, 0xaa, 0x94,
    0xdf, 0xd4, 0x86, 0x1c, 0xfb, 0x58, 0x03, 0x34, 0x6f, 0xc6, 0x9f, 0x8c, 0xc0, 0x46, 0xfe, 0x14,
};

/* x86-64: xorshift, a byte substitution and a rotation per round. */
NOINLINE uint32_t mix_rounds(uint32_t seed, uint32_t rounds) {
  uint32_t x = seed;
  for (uint32_t i = 0; i < rounds; i++) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x = (x & 0xFFFFFF00u) | SBOX[x & 0xFFu];
    uint32_t r = i & 31u;
    x = (r ? (x << r) | (x >> (32u - r)) : x) + i;
  }
  return x;
}

#ifndef FREESTANDING
/* AArch64, dynamically linked: strlen, memset and memcpy are C library imports. */
NOINLINE uint32_t token_digest(const char *text) {
  unsigned char buffer[64];
  size_t length = strlen(text);
  if (length > 48) {
    length = 48;
  }
  memset(buffer, 0x5C, sizeof buffer);
  memcpy(buffer + 8, text, length);
  uint32_t hash = 0x811C9DC5u;
  for (uint32_t round = 0; round < 4; round++) {
    for (uint32_t index = 0; index < sizeof buffer; index++) {
      hash ^= (uint32_t)buffer[index] ^ round;
      hash *= 0x01000193u;
    }
  }
  return hash;
}
#endif

/* Thumb-2 (Cortex-M4): a fixed-point control loop with hardware division and remainders. */
NOINLINE uint32_t settle(uint32_t target, uint32_t steps) {
  uint32_t position = 0, velocity = 0, accumulated = 0;
  for (uint32_t i = 0; i < steps; i++) {
    uint32_t error = target - position;
    accumulated += error >> 3;
    velocity = (velocity * 7u) / 8u + error / 5u + (accumulated % 97u);
    position += velocity / 11u;
    if (position > target * 2u) {
      position -= target;
    }
  }
  return position ^ (accumulated << 7) ^ velocity;
}

/* 32-bit MIPS: 64-bit arithmetic in register pairs, a few hundred iterations. */
NOINLINE uint64_t collatz_weight(uint64_t n) {
  uint64_t steps = 0, peak = n;
  while (n != 1 && steps < 100000u) {
    n = (n & 1u) ? 3u * n + 1u : n >> 1;
    if (n > peak) {
      peak = n;
    }
    steps++;
  }
  return (steps << 40) ^ peak;
}

#if defined(HOST_MAIN)
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  if (argc < 3) {
    return 2;
  }
  unsigned long long a = strtoull(argv[2], NULL, 0);
  unsigned long long b = argc > 3 ? strtoull(argv[3], NULL, 0) : 0;
  if (!strcmp(argv[1], "mix_rounds")) {
    printf("%#x\n", mix_rounds((uint32_t)a, (uint32_t)b));
  } else if (!strcmp(argv[1], "token_digest")) {
    printf("%#x\n", token_digest(argv[2]));
  } else if (!strcmp(argv[1], "settle")) {
    printf("%#x\n", settle((uint32_t)a, (uint32_t)b));
  } else if (!strcmp(argv[1], "collatz_weight")) {
    printf("%#llx\n", (unsigned long long)collatz_weight(a));
  } else {
    return 2;
  }
  return 0;
}
#elif defined(FREESTANDING)
/* A minimal Cortex-M program around the functions, so the ELF has an entry and keeps them reachable. */
extern uint32_t __stack_top;
volatile uint32_t sink __attribute__((section(".ram")));
void reset_handler(void) {
  sink = settle(sink, 500) ^ mix_rounds(sink, 1000) ^ (uint32_t)collatz_weight(sink | 1u);
  for (;;) {
  }
}
__attribute__((section(".vectors"), used)) const void *const VECTORS[2] = {&__stack_top, reset_handler};
#else
#include <stdio.h>
int main(int argc, char **argv) {
  printf("%x %x %x %llx\n", mix_rounds((uint32_t)argc, 1000), token_digest(argc > 1 ? argv[1] : "x"),
         settle((uint32_t)argc * 1000u, 500), (unsigned long long)collatz_weight((uint64_t)argc + 27u));
  return 0;
}
#endif
