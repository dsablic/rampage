/* Flywheel corpus driver: LZ4 high-compression blocks and partial decompression. Never run. */
#include <stdio.h>
#include <string.h>
#include "lz4.h"
#include "lz4hc.h"

static int drv_compress_levels(const char *source, int length, char *packed, int capacity) {
    int best = 0;
    for (int level = LZ4HC_CLEVEL_MIN; level <= LZ4HC_CLEVEL_DEFAULT; level += 3) {
        int size = LZ4_compress_HC(source, packed, length, capacity, level);
        if (best == 0 || (size > 0 && size < best)) best = size;
    }
    return best;
}

int main(int argc, char **argv) {
    static char source[20000], packed[21000], back[20000];
    for (int i = 0; i < (int)sizeof source; i++) source[i] = (char)(i % 251 + argc);
    int packed_length = drv_compress_levels(source, sizeof source, packed, sizeof packed);
    int partial = LZ4_decompress_safe_partial(packed, back, packed_length, 4096, sizeof back);
    int whole = LZ4_decompress_safe(packed, back, packed_length, sizeof back);
    printf("%s %d %d %d\n", argv[0], packed_length, partial, whole);
    return whole != (int)sizeof source;
}
