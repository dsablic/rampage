/* SPDX-License-Identifier: Apache-2.0 */
/* Host self-test of the fixtures' crypto (build.sh runs it before building the fixtures): SHA-256 and HMAC-SHA256
 * against FIPS 180-4 / RFC 4231 vectors, CRC-32 against its check value, and the synthetic signatures in
 * test_keys.c, accepted as made and refused with one bit changed. */
#include <stdio.h>
#include <string.h>

#include "crypto.h"

extern const uint8_t test_p256_public_key[64], test_p256_signature[64];
extern const uint8_t test_rsa_modulus[256], test_rsa_signature[256];

static int expect(const char *what, int ok) {
    printf("%s: %s\n", what, ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}

static int hex_equal(const uint8_t *bytes, const char *hex) {
    char text[65];
    for (int i = 0; i < 32; i++) {
        snprintf(text + 2 * i, 3, "%02x", bytes[i]);
    }
    return strcmp(text, hex) == 0;
}

int main(void) {
    int failures = 0;
    uint8_t digest[32], mac[32], key[20];
    sha256((const uint8_t *)"abc", 3, digest);
    failures += expect("sha256", hex_equal(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    memset(key, 0x0b, sizeof key);
    hmac_sha256(key, sizeof key, (const uint8_t *)"Hi There", 8, mac);
    failures += expect("hmac", hex_equal(mac, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    failures += expect("crc32", crc32((const uint8_t *)"123456789", 9) == 0xCBF43926u);
    const char *message = "lock fixture self-test";
    sha256((const uint8_t *)message, strlen(message), digest);
    failures += expect("p256 accepts", p256_verify(test_p256_public_key, digest, test_p256_signature) == 1);
    failures += expect("rsa accepts", rsa2048_verify(test_rsa_modulus, digest, test_rsa_signature) == 1);
    digest[5] ^= 1;
    failures += expect("p256 refuses", p256_verify(test_p256_public_key, digest, test_p256_signature) == 0);
    failures += expect("rsa refuses", rsa2048_verify(test_rsa_modulus, digest, test_rsa_signature) == 0);
    return failures != 0;
}
