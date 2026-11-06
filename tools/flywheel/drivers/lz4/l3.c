/* Flywheel corpus driver: the LZ4 frame format with a content checksum, compress and decompress. Never run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lz4frame.h"

static size_t drv_frame_compress(const char *source, size_t length, char *out, size_t capacity) {
    LZ4F_preferences_t preferences;
    memset(&preferences, 0, sizeof preferences);
    preferences.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
    preferences.compressionLevel = 3;
    size_t bound = LZ4F_compressFrameBound(length, &preferences);
    if (bound > capacity) return 0;
    return LZ4F_compressFrame(out, capacity, source, length, &preferences);
}

static size_t drv_frame_decompress(const char *packed, size_t length, char *out, size_t capacity) {
    LZ4F_dctx *context = NULL;
    if (LZ4F_isError(LZ4F_createDecompressionContext(&context, LZ4F_VERSION))) return 0;
    size_t produced = capacity, consumed = length;
    size_t status = LZ4F_decompress(context, out, &produced, packed, &consumed, NULL);
    LZ4F_freeDecompressionContext(context);
    return LZ4F_isError(status) ? 0 : produced;
}

int main(int argc, char **argv) {
    static char source[12000], packed[14000], back[12000];
    for (size_t i = 0; i < sizeof source; i++) source[i] = (char)((i * 13) ^ (size_t)argc);
    size_t packed_length = drv_frame_compress(source, sizeof source, packed, sizeof packed);
    size_t back_length = drv_frame_decompress(packed, packed_length, back, sizeof back);
    printf("%s %zu %zu %s\n", argv[0], packed_length, back_length, LZ4F_getErrorName(packed_length));
    return back_length != sizeof source;
}
