/* SPDX-License-Identifier: Apache-2.0 */
/* SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104), CRC-32 (IEEE, reflected, table driven) and a byte compare. */
#include "crypto.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint32_t IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)block[4 * i] << 24 | (uint32_t)block[4 * i + 1] << 16 | (uint32_t)block[4 * i + 2] << 8 |
               block[4 * i + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_init(sha256_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->state[i] = IV[i];
    }
    ctx->length = 0;
    ctx->used = 0;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        ctx->block[ctx->used++] = data[i];
        if (ctx->used == 64) {
            compress(ctx->state, ctx->block);
            ctx->used = 0;
        }
    }
    ctx->length += (uint64_t)size * 8;
}

void sha256_final(sha256_ctx *ctx, uint8_t digest[32]) {
    uint64_t length = ctx->length;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    pad = 0;
    while (ctx->used != 56) {
        sha256_update(ctx, &pad, 1);
    }
    for (int i = 7; i >= 0; i--) {
        uint8_t byte = (uint8_t)(length >> (8 * i));
        sha256_update(ctx, &byte, 1);
    }
    for (int i = 0; i < 8; i++) {
        digest[4 * i] = (uint8_t)(ctx->state[i] >> 24);
        digest[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[4 * i + 3] = (uint8_t)ctx->state[i];
    }
}

void sha256(const uint8_t *data, size_t size, uint8_t digest[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, size);
    sha256_final(&ctx, digest);
}

void hmac_sha256(const uint8_t *key, size_t key_size, const uint8_t *data, size_t size, uint8_t mac[32]) {
    uint8_t pad[64] = {0};
    uint8_t inner[32];
    sha256_ctx ctx;
    if (key_size > 64) {
        sha256(key, key_size, pad);
    } else {
        for (size_t i = 0; i < key_size; i++) {
            pad[i] = key[i];
        }
    }
    for (int i = 0; i < 64; i++) {
        pad[i] ^= 0x36;
    }
    sha256_init(&ctx);
    sha256_update(&ctx, pad, 64);
    sha256_update(&ctx, data, size);
    sha256_final(&ctx, inner);
    for (int i = 0; i < 64; i++) {
        pad[i] ^= 0x36 ^ 0x5c;
    }
    sha256_init(&ctx);
    sha256_update(&ctx, pad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, mac);
}

static uint32_t crc_table[256];

uint32_t crc32(const uint8_t *data, size_t size) {
    if (crc_table[1] == 0) {
        for (uint32_t n = 0; n < 256; n++) {
            uint32_t c = n;
            for (int k = 0; k < 8; k++) {
                c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            }
            crc_table[n] = c;
        }
    }
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < size; i++) {
        crc = crc_table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    }
    return ~crc;
}

int equal_bytes(const uint8_t *a, const uint8_t *b, size_t size) {
    uint8_t difference = 0;
    for (size_t i = 0; i < size; i++) {
        difference |= a[i] ^ b[i];
    }
    return difference == 0;
}
