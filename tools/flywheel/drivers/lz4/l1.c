/* Flywheel corpus driver: LZ4 block compression and safe decompression. Never run; it only has to link. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lz4.h"

static void drv_fill(char *buffer, int length, unsigned seed) {
    for (int i = 0; i < length; i++) {
        seed = seed * 69069u + 1u;
        buffer[i] = (char)("abcdefgh"[(seed >> 24) & 7]);
    }
}

int main(int argc, char **argv) {
    static char source[16384], back[16384];
    drv_fill(source, sizeof source, (unsigned)argc);
    int bound = LZ4_compressBound(sizeof source);
    char *packed = malloc((size_t)bound);
    if (!packed) return 1;
    int packed_length = LZ4_compress_default(source, packed, sizeof source, bound);
    int fast_length = LZ4_compress_fast(source, packed, sizeof source, bound, argc + 1);
    int back_length = LZ4_decompress_safe(packed, back, fast_length, sizeof back);
    printf("%s %d %d %d %d\n", LZ4_versionString(), packed_length, fast_length, back_length,
           memcmp(source, back, sizeof back));
    free(packed);
    return back_length != (int)sizeof source;
}
