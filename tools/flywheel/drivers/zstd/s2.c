/* Flywheel corpus driver: zstd streaming compression and decompression. Never run; it only has to link. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "streaming streaming streaming corpus driver";
    ZSTD_CStream *compressor = ZSTD_createCStream();
    ZSTD_initCStream(compressor, 5);
    size_t capacity = ZSTD_CStreamOutSize();
    char *packed = malloc(capacity);
    ZSTD_inBuffer input = {text, strlen(text), 0};
    ZSTD_outBuffer output = {packed, capacity, 0};
    while (input.pos < input.size) ZSTD_compressStream(compressor, &output, &input);
    size_t remaining = ZSTD_endStream(compressor, &output);
    ZSTD_freeCStream(compressor);
    ZSTD_DStream *decompressor = ZSTD_createDStream();
    ZSTD_initDStream(decompressor);
    char *plain = malloc(ZSTD_DStreamOutSize());
    ZSTD_inBuffer packed_input = {packed, output.pos, 0};
    ZSTD_outBuffer plain_output = {plain, ZSTD_DStreamOutSize(), 0};
    size_t result = ZSTD_decompressStream(decompressor, &plain_output, &packed_input);
    printf("%zu %zu %zu %s\n", output.pos, remaining, plain_output.pos, ZSTD_isError(result) ? "error" : "ok");
    ZSTD_freeDStream(decompressor);
    free(plain);
    free(packed);
    return 0;
}
