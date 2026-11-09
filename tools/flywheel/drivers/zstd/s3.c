/* Flywheel corpus driver: zstd contexts with advanced parameters. Never run; it only has to link. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "parameters parameters parameters corpus driver";
    size_t size = strlen(text);
    ZSTD_CCtx *context = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(context, ZSTD_c_compressionLevel, argc > 2 ? atoi(argv[2]) : 19);
    ZSTD_CCtx_setParameter(context, ZSTD_c_checksumFlag, 1);
    ZSTD_CCtx_setParameter(context, ZSTD_c_windowLog, 20);
    size_t bound = ZSTD_compressBound(size);
    void *packed = malloc(bound);
    size_t packed_size = ZSTD_compress2(context, packed, bound, text, size);
    ZSTD_DCtx *decoder = ZSTD_createDCtx();
    ZSTD_DCtx_setParameter(decoder, ZSTD_d_windowLogMax, 24);
    char *plain = malloc(size + 1);
    size_t plain_size = ZSTD_decompressDCtx(decoder, plain, size, packed, packed_size);
    printf("%zu %s %u\n", packed_size, ZSTD_getErrorName(plain_size), ZSTD_versionNumber());
    ZSTD_freeDCtx(decoder);
    ZSTD_freeCCtx(context);
    free(plain);
    free(packed);
    return 0;
}
