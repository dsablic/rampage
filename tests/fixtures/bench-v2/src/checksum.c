// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: a bitwise reflected CRC-32 with the Castagnoli polynomial and a non-standard
// initial value, built stripped for big-endian 32-bit MIPS Linux. The task asks for the polynomial, the
// initial register value and the final XOR.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

__attribute__((noinline)) uint32_t frame_check(const uint8_t *data, size_t n) {
    uint32_t crc = 0x0BADC0DEu;
    for (size_t i = 0; i < n; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

__attribute__((noinline)) uint32_t mix(uint32_t a, uint32_t b) { return (a * 0x01000193u) ^ b; }

int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "123456789";
    uint32_t value = frame_check((const uint8_t *)text, strlen(text));
    printf("%08x %08x\n", value, mix(value, (uint32_t)argc));
    return 0;
}
