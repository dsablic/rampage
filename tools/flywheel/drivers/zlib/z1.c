/* Flywheel corpus driver: one-shot compress/uncompress and checksums. Never run; it only has to link. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static unsigned char drv_input[4096];

static void drv_fill(unsigned char *buffer, size_t length, unsigned seed) {
    for (size_t i = 0; i < length; i++) {
        seed = seed * 1103515245u + 12345u;
        buffer[i] = (unsigned char)(seed >> 16);
    }
}

static int drv_roundtrip(const unsigned char *data, uLong length, int level) {
    uLongf packed_length = compressBound(length);
    unsigned char *packed = malloc(packed_length);
    unsigned char *unpacked = malloc(length);
    if (!packed || !unpacked) return -1;
    if (compress2(packed, &packed_length, data, length, level) != Z_OK) return -2;
    uLongf unpacked_length = length;
    if (uncompress(unpacked, &unpacked_length, packed, packed_length) != Z_OK) return -3;
    int same = unpacked_length == length && memcmp(unpacked, data, length) == 0;
    free(packed);
    free(unpacked);
    return same ? (int)packed_length : -4;
}

int main(int argc, char **argv) {
    drv_fill(drv_input, sizeof drv_input, (unsigned)argc);
    uLong adler = adler32(adler32(0L, Z_NULL, 0), drv_input, sizeof drv_input);
    uLong crc = crc32(crc32(0L, Z_NULL, 0), drv_input, sizeof drv_input);
    int packed = drv_roundtrip(drv_input, sizeof drv_input, argc > 1 ? atoi(argv[1]) : Z_DEFAULT_COMPRESSION);
    printf("%s %lx %lx %d\n", zlibVersion(), adler, crc, packed);
    return packed < 0;
}
