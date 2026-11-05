/* Flywheel corpus driver: LZ4 streaming compression with a dictionary, and default blocks. Never run. */
#include <stdio.h>
#include <string.h>
#include "lz4.h"

static const char drv_dictionary[] = "flywheel lz4 streaming dictionary for the signature corpus";

static int drv_stream(const char *source, int length, char *packed, int capacity) {
    LZ4_stream_t *stream = LZ4_createStream();
    if (!stream) return -1;
    LZ4_loadDict(stream, drv_dictionary, (int)sizeof drv_dictionary - 1);
    int total = 0;
    for (int offset = 0; offset < length; offset += 4096) {
        int chunk = length - offset < 4096 ? length - offset : 4096;
        int size = LZ4_compress_fast_continue(stream, source + offset, packed + total, chunk, capacity - total, 1);
        if (size <= 0) break;
        total += size;
    }
    LZ4_freeStream(stream);
    return total;
}

int main(int argc, char **argv) {
    static char source[16384], packed[18000], back[16384];
    for (int i = 0; i < (int)sizeof source; i++) source[i] = drv_dictionary[(i + argc) % (int)(sizeof drv_dictionary - 1)];
    int streamed = drv_stream(source, sizeof source, packed, sizeof packed);
    int single = LZ4_compress_default(source, packed, sizeof source, sizeof packed);
    int back_length = LZ4_decompress_safe_usingDict(packed, back, single, sizeof back, drv_dictionary, 8);
    printf("%s %d %d %d %d\n", argv[0], streamed, single, back_length, LZ4_versionNumber());
    return 0;
}
