/* SPDX-License-Identifier: Apache-2.0 */
/* Owned negative control for lock_mechanisms: a program that uses HMAC-SHA256 and SHA-256, where a generic request
 * handler reaches the MAC routine on one path and its status code drives ordinary error handling. Nothing here
 * decides on a MAC or a signature, so nothing may be reported as a lock. The key is synthetic. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

static const uint8_t tag_key[32] = "synthetic tagging key, tests!!!";

enum { REQUEST_CHECK = 1, REQUEST_TAG = 2, REQUEST_DIGEST = 3 };

/* Dispatches one request; the status says whether the request was well formed, never whether a MAC matched. */
__attribute__((noinline)) static int handle_request(int kind, const char *argument, uint8_t out[32]) {
    switch (kind) {
    case REQUEST_CHECK:
        if (!argument) {
            return -1;
        }
        return strlen(argument) > 64 ? -2 : 0;
    case REQUEST_TAG:
        hmac_sha256(tag_key, sizeof tag_key, (const uint8_t *)argument, strlen(argument), out);
        return 0;
    case REQUEST_DIGEST:
        sha256((const uint8_t *)argument, strlen(argument), out);
        return 0;
    default:
        return -3;
    }
}

int main(int argc, char **argv) {
    uint8_t out[32] = {0};
    if (argc < 3) {
        return 2;
    }
    int status = handle_request(atoi(argv[1]), argv[2], out);
    if (status != 0) {
        fprintf(stderr, "bad request (%d)\n", status);
        return 1;
    }
    for (int i = 0; i < 32; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
    return 0;
}
