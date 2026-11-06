/* Flywheel negative program: owned text processing (a hash table of words, base64), no library. Never run. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DRV_BUCKETS 64

struct drv_word {
    struct drv_word *next;
    unsigned count;
    char text[32];
};

static struct drv_word *drv_table[DRV_BUCKETS];

static unsigned drv_hash(const char *text) {
    unsigned hash = 2166136261u;
    while (*text) hash = (hash ^ (unsigned char)*text++) * 16777619u;
    return hash % DRV_BUCKETS;
}

static void drv_count(const char *word) {
    unsigned bucket = drv_hash(word);
    for (struct drv_word *entry = drv_table[bucket]; entry; entry = entry->next) {
        if (strcmp(entry->text, word) == 0) {
            entry->count++;
            return;
        }
    }
    struct drv_word *entry = calloc(1, sizeof *entry);
    if (!entry) return;
    snprintf(entry->text, sizeof entry->text, "%s", word);
    entry->count = 1;
    entry->next = drv_table[bucket];
    drv_table[bucket] = entry;
}

static size_t drv_base64(const uint8_t *in, size_t length, char *out) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t written = 0;
    for (size_t i = 0; i < length; i += 3) {
        uint32_t chunk = (uint32_t)in[i] << 16;
        if (i + 1 < length) chunk |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < length) chunk |= in[i + 2];
        out[written++] = alphabet[(chunk >> 18) & 63];
        out[written++] = alphabet[(chunk >> 12) & 63];
        out[written++] = i + 1 < length ? alphabet[(chunk >> 6) & 63] : '=';
        out[written++] = i + 2 < length ? alphabet[chunk & 63] : '=';
    }
    out[written] = '\0';
    return written;
}

int main(int argc, char **argv) {
    char text[] = "the flywheel counts the words the corpus holds";
    for (char *word = strtok(text, " "); word; word = strtok(NULL, " ")) drv_count(word);
    char encoded[128];
    drv_base64((const uint8_t *)argv[0], strlen(argv[0]) % 90, encoded);
    unsigned total = 0;
    for (int i = 0; i < DRV_BUCKETS; i++) {
        for (struct drv_word *entry = drv_table[i]; entry; entry = entry->next) total += entry->count;
    }
    printf("%d %u %s\n", argc, total, encoded);
    return 0;
}
