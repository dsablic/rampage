/* SPDX-License-Identifier: Apache-2.0 */
/* Small, owned crypto for the lock-mechanism fixtures: SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104), a CRC-32
 * table routine, ECDSA P-256 verification and RSA PKCS#1 v1.5 SHA-256 verification over one Montgomery
 * multiplier. Written for test fixtures: correct but neither fast nor constant-time. */
#ifndef LOCKS_CRYPTO_H
#define LOCKS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t length;
    uint8_t block[64];
    size_t used;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t size);
void sha256_final(sha256_ctx *ctx, uint8_t digest[32]);
void sha256(const uint8_t *data, size_t size, uint8_t digest[32]);
void hmac_sha256(const uint8_t *key, size_t key_size, const uint8_t *data, size_t size, uint8_t mac[32]);
uint32_t crc32(const uint8_t *data, size_t size);
int equal_bytes(const uint8_t *a, const uint8_t *b, size_t size);

/* 1 when (r, s) signs digest under the uncompressed public key x || y (big-endian), else 0. */
int p256_verify(const uint8_t public_key[64], const uint8_t digest[32], const uint8_t signature[64]);
/* 1 when signature is a PKCS#1 v1.5 SHA-256 signature of digest under (modulus, 65537), else 0. */
int rsa2048_verify(const uint8_t modulus[256], const uint8_t digest[32], const uint8_t signature[256]);

#endif
