/* SPDX-License-Identifier: Apache-2.0 */

#include <string.h>
#include "zstd.h"

int main(int argc, char **argv) {
    const char *input = argc > 1 ? argv[1] : "zstd reference corpus input";
    size_t input_size = strlen(input);
    unsigned char compressed[512];
    unsigned char restored[256];
    if (input_size > sizeof(restored))
        input_size = sizeof(restored);

    size_t compressed_size = ZSTD_compress(compressed, sizeof(compressed), input, input_size, 3);
    if (ZSTD_isError(compressed_size))
        return 1;
    size_t restored_size = ZSTD_decompress(restored, sizeof(restored), compressed, compressed_size);
    if (ZSTD_isError(restored_size) || restored_size != input_size)
        return 2;
    if (memcmp(input, restored, input_size) != 0)
        return 3;
    return (int)((ZSTD_versionNumber() ^ (unsigned)compressed_size ^ (unsigned)argc) & 255u);
}
