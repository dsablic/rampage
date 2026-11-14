/* SPDX-License-Identifier: Apache-2.0 */
/* Owned synthetic Linux program for lock_mechanisms, in the style of an embedded-Linux update and service daemon:
 * an update accepted only with an RSA-2048 PKCS#1 v1.5 signature, a service mode unlocked by an HMAC-SHA256
 * response to a random challenge, and negative controls (a CRC-checked settings file and a log digest that gate
 * nothing a user could repair). All keys are synthetic (test_keys.c and service_key below). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "crypto.h"

extern const uint8_t test_rsa_modulus[256];
static const uint8_t service_key[32] = "synthetic service key, tests!!";

static uint8_t nonce[32];
static int service_mode;
static uint8_t image[1 << 20];

__attribute__((noinline)) static size_t read_file(const char *path, uint8_t *buffer, size_t capacity) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        return 0;
    }
    size_t size = fread(buffer, 1, capacity, file);
    fclose(file);
    return size;
}

/* Signature verification gating an update. */
__attribute__((noinline)) static int update_signed(const uint8_t *data, size_t size) {
    uint8_t digest[32];
    if (size < 256) {
        return 0;
    }
    sha256(data, size - 256, digest);
    return rsa2048_verify(test_rsa_modulus, digest, data + size - 256);
}

__attribute__((noinline)) static int install_update(const char *path) {
    size_t size = read_file(path, image, sizeof image);
    if (!update_signed(image, size)) {
        fprintf(stderr, "update rejected\n");
        exit(2);
    }
    FILE *flash = fopen("/tmp/lock-fixture-flash.img", "wb");
    if (!flash) {
        return 1;
    }
    fwrite(image, 1, size - 256, flash);
    fclose(flash);
    return 0;
}

/* Challenge-response unlocking a service mode. */
__attribute__((noinline)) static void issue_challenge(void) {
    if (getrandom(nonce, sizeof nonce, 0) != (ssize_t)sizeof nonce) {
        exit(1);
    }
    for (size_t i = 0; i < sizeof nonce; i++) {
        printf("%02x", nonce[i]);
    }
    printf("\n");
}

__attribute__((noinline)) static int enter_service_mode(const uint8_t response[32]) {
    uint8_t expected[32];
    hmac_sha256(service_key, sizeof service_key, nonce, sizeof nonce, expected);
    if (memcmp(expected, response, 32) != 0) {
        return -1;
    }
    service_mode = 1;
    return 0;
}

/* Negative control: settings protected by a CRC-32 only. */
__attribute__((noinline)) static int load_settings(const char *path) {
    uint8_t settings[68];
    if (read_file(path, settings, sizeof settings) != sizeof settings) {
        return -1;
    }
    uint32_t stored;
    memcpy(&stored, settings + 64, 4);
    if (crc32(settings, 64) != stored) {
        puts("settings damaged, using defaults");
        return 1;
    }
    return 0;
}

/* Negative control: a digest of the log, printed for the user. */
__attribute__((noinline)) static void log_digest(const char *line) {
    uint8_t digest[32];
    sha256((const uint8_t *)line, strlen(line), digest);
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("  %s\n", line);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    log_digest(argv[1]);
    if (strcmp(argv[1], "update") == 0 && argc > 2) {
        return install_update(argv[2]);
    }
    if (strcmp(argv[1], "challenge") == 0) {
        issue_challenge();
        return 0;
    }
    if (strcmp(argv[1], "respond") == 0 && argc > 2 && strlen(argv[2]) == 64) {
        uint8_t response[32];
        for (int i = 0; i < 32; i++) {
            unsigned byte;
            sscanf(argv[2] + 2 * i, "%2x", &byte);
            response[i] = (uint8_t)byte;
        }
        if (enter_service_mode(response) == 0) {
            puts("service mode");
        }
        return service_mode ? 0 : 1;
    }
    if (strcmp(argv[1], "settings") == 0 && argc > 2) {
        return load_settings(argv[2]) < 0;
    }
    return 2;
}
