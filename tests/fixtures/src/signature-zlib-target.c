#include "zlib.h"

static __attribute__((noinline)) unsigned target_seed(unsigned value) {
    for (unsigned index = 0; index < 31; ++index)
        value = (value ^ (value >> 3)) * 33u + index;
    return value;
}

int main(int argc, char **argv) {
    z_stream stream = {0};
    int result = inflateInit(&stream);
    if (result == Z_OK) inflateEnd(&stream);
    return result ^ (int)crc32(target_seed((unsigned)argc), (const Bytef *)argv[0], (uInt)argc);
}
