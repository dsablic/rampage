#include "lz4.h"
#include "xxhash.h"

int main(int argc, char **argv) {
    char output[128];
    int size = LZ4_compress_default(argv[0], output, argc, sizeof(output));
    return size + (int)XXH32(argv[0], (size_t)argc, 0);
}
