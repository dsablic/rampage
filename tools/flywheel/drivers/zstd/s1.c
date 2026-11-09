/* Flywheel corpus driver: zstd one-shot compress and decompress. Never run; it only has to link. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "flywheel flywheel flywheel corpus driver";
    size_t size = strlen(text);
    size_t bound = ZSTD_compressBound(size);
    void *packed = malloc(bound);
    size_t packed_size = ZSTD_compress(packed, bound, text, size, argc > 2 ? atoi(argv[2]) : 3);
    if (ZSTD_isError(packed_size)) {
        printf("compress: %s\n", ZSTD_getErrorName(packed_size));
        return 1;
    }
    unsigned long long content = ZSTD_getFrameContentSize(packed, packed_size);
    char *plain = malloc(content + 1);
    size_t plain_size = ZSTD_decompress(plain, content, packed, packed_size);
    printf("%zu -> %zu -> %zu\n", size, packed_size, ZSTD_isError(plain_size) ? 0 : plain_size);
    free(plain);
    free(packed);
    return 0;
}
