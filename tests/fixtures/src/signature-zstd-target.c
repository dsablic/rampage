/* SPDX-License-Identifier: Apache-2.0 */

#include <string.h>
#include "zstd.h"

static __attribute__((noinline)) unsigned target_seed(unsigned value) {
    for (unsigned index = 0; index < 53; ++index)
        value = (value * 29u + index) ^ (value >> 7);
    return value;
}

int main(int argc, char **argv) {
    const char *argument = argc > 1 ? argv[1] : "distinct zstd target payload";
    size_t input_size = strlen(argument);
    unsigned seed = target_seed((unsigned)argc);
    unsigned char input[192];
    unsigned char compressed[512];
    unsigned char restored[192];
    if (input_size > sizeof(input))
        input_size = sizeof(input);
    for (size_t index = 0; index < input_size; ++index)
        input[index] = (unsigned char)argument[index] ^ (unsigned char)(seed + (unsigned)index);

    ZSTD_CCtx *compressor = ZSTD_createCCtx();
    ZSTD_DCtx *decompressor = ZSTD_createDCtx();
    if (compressor == NULL || decompressor == NULL) {
        ZSTD_freeCCtx(compressor);
        ZSTD_freeDCtx(decompressor);
        return 1;
    }
    size_t compressed_size = ZSTD_compressCCtx(
        compressor, compressed, sizeof(compressed), input, input_size, 1 + (int)(seed % 9u));
    ZSTD_freeCCtx(compressor);
    if (ZSTD_isError(compressed_size)) {
        ZSTD_freeDCtx(decompressor);
        return 2;
    }
    size_t restored_size = ZSTD_decompressDCtx(
        decompressor, restored, sizeof(restored), compressed, compressed_size);
    ZSTD_freeDCtx(decompressor);
    if (ZSTD_isError(restored_size) || restored_size != input_size)
        return 3;
    if (memcmp(input, restored, input_size) != 0)
        return 4;
    return (int)((ZSTD_versionNumber() + seed + (unsigned)compressed_size) & 255u);
}
