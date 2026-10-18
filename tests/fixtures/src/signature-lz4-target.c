#include "lz4hc.h"
#include "xxhash.h"

static __attribute__((noinline)) unsigned target_seed(unsigned value) {
    for (unsigned index = 0; index < 47; ++index)
        value = value * 17u ^ (value >> 5) ^ index;
    return value;
}

int main(int argc, char **argv) {
    char output[256];
    int size = LZ4_compress_HC(argv[0], output, argc, sizeof(output), 9);
    return size ^ (int)XXH32(argv[0], (size_t)argc, target_seed((unsigned)argc));
}
