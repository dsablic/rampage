#include "zlib.h"

int main(int argc, char **argv) {
    z_stream stream = {0};
    int result = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
    if (result == Z_OK) deflateEnd(&stream);
    return result + (int)adler32(0, (const Bytef *)argv[0], (uInt)argc);
}
