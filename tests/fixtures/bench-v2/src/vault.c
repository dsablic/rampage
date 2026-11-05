// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: an RC4-style stream cipher whose key comes from one of two similar derivation
// routines, built stripped for arm64 macOS. The task asks which routine derives the cipher's key and the
// constant it XORs with; the other routine feeds a checksum and is a decoy.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct stream {
    uint8_t s[256];
    uint8_t i, j;
};

__attribute__((noinline)) static void stream_init(struct stream *st, const uint8_t *key, size_t n) {
    for (int k = 0; k < 256; k++) {
        st->s[k] = (uint8_t)k;
    }
    uint8_t j = 0;
    for (int k = 0; k < 256; k++) {
        j = (uint8_t)(j + st->s[k] + key[k % n]);
        uint8_t t = st->s[k];
        st->s[k] = st->s[j];
        st->s[j] = t;
    }
    st->i = st->j = 0;
}

__attribute__((noinline)) static void stream_apply(struct stream *st, uint8_t *data, size_t n) {
    for (size_t k = 0; k < n; k++) {
        st->i++;
        st->j = (uint8_t)(st->j + st->s[st->i]);
        uint8_t t = st->s[st->i];
        st->s[st->i] = st->s[st->j];
        st->s[st->j] = t;
        data[k] ^= st->s[(uint8_t)(st->s[st->i] + st->s[st->j])];
    }
}

// Decoy: same shape as derive_key, different constant; its output only feeds the checksum.
__attribute__((noinline)) static void derive_tag(uint32_t out[4], const char *text) {
    size_t n = strlen(text);
    for (int w = 0; w < 4; w++) {
        uint32_t word = 0;
        for (int b = 0; b < 4; b++) {
            word = (word << 8) | (uint8_t)text[(size_t)(w * 4 + b) % (n ? n : 1)];
        }
        out[w] = word ^ 0x36363636u;
    }
}

__attribute__((noinline)) static void derive_key(uint32_t out[4], const char *text) {
    size_t n = strlen(text);
    for (int w = 0; w < 4; w++) {
        uint32_t word = 0;
        for (int b = 0; b < 4; b++) {
            word = (word << 8) | (uint8_t)text[(size_t)(w * 4 + b) % (n ? n : 1)];
        }
        out[w] = word ^ 0x5EC12E7Au;
    }
}

__attribute__((noinline)) static uint32_t checksum(const uint32_t *words, size_t n, const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t k = 0; k < n; k++) {
        sum = sum * 33 + words[k];
    }
    for (size_t k = 0; k < len; k++) {
        sum = sum * 33 + data[k];
    }
    return sum;
}

int main(int argc, char **argv) {
    const char *pass = argc > 1 ? argv[1] : "correct horse";
    const char *label = argc > 2 ? argv[2] : "vault";
    uint32_t tag[4], key[4];
    derive_tag(tag, label);
    derive_key(key, pass);
    uint8_t message[] = "attack at dawn";
    struct stream st;
    stream_init(&st, (const uint8_t *)key, sizeof key);
    stream_apply(&st, message, sizeof message - 1);
    printf("%08x\n", checksum(tag, 4, message, sizeof message - 1));
    return 0;
}
