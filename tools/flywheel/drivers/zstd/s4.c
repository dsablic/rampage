/* Flywheel corpus driver: zstd with a prepared dictionary. Never run; it only has to link. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

static const char dictionary[] = "flywheel corpus driver dictionary content: common words repeat repeat repeat";

int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "flywheel corpus driver words repeat";
    size_t size = strlen(text);
    ZSTD_CDict *cdict = ZSTD_createCDict(dictionary, sizeof dictionary, 7);
    ZSTD_DDict *ddict = ZSTD_createDDict(dictionary, sizeof dictionary);
    ZSTD_CCtx *context = ZSTD_createCCtx();
    ZSTD_DCtx *decoder = ZSTD_createDCtx();
    size_t bound = ZSTD_compressBound(size);
    void *packed = malloc(bound);
    size_t packed_size = ZSTD_compress_usingCDict(context, packed, bound, text, size, cdict);
    char *plain = malloc(size + 1);
    size_t plain_size = ZSTD_decompress_usingDDict(decoder, plain, size, packed, packed_size, ddict);
    printf("%s %zu %zu %u\n", ZSTD_versionString(), packed_size, plain_size, ZSTD_getDictID_fromDDict(ddict));
    ZSTD_freeDCtx(decoder);
    ZSTD_freeCCtx(context);
    ZSTD_freeDDict(ddict);
    ZSTD_freeCDict(cdict);
    free(plain);
    free(packed);
    return 0;
}
