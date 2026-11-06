/* Flywheel corpus driver: raw deflate with parameters and dictionaries, compress/uncompress2. Never run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static const char drv_dictionary[] = "flywheel signature corpus dictionary";

static int drv_raw_deflate(const unsigned char *in, unsigned length, unsigned char *out, unsigned capacity, int level) {
    z_stream stream;
    memset(&stream, 0, sizeof stream);
    if (deflateInit2(&stream, level, Z_DEFLATED, -15, 9, Z_FILTERED) != Z_OK) return -1;
    deflateSetDictionary(&stream, (const Bytef *)drv_dictionary, sizeof drv_dictionary - 1);
    stream.next_in = (Bytef *)in;
    stream.avail_in = length / 2;
    stream.next_out = out;
    stream.avail_out = capacity;
    deflate(&stream, Z_SYNC_FLUSH);
    deflateParams(&stream, 1, Z_HUFFMAN_ONLY);
    stream.avail_in = length - length / 2;
    int status = deflate(&stream, Z_FINISH);
    unsigned produced = capacity - stream.avail_out;
    deflateEnd(&stream);
    return status == Z_STREAM_END ? (int)produced : -2;
}

int main(int argc, char **argv) {
    static unsigned char data[6000], packed[7000], back[6000];
    for (unsigned i = 0; i < sizeof data; i++) data[i] = (unsigned char)(i * 7 + argc);
    int raw = drv_raw_deflate(data, sizeof data, packed, sizeof packed, argc > 2 ? 9 : 4);
    uLongf packed_length = sizeof packed;
    compress(packed, &packed_length, data, sizeof data);
    uLongf back_length = sizeof back;
    uLong source_length = packed_length;
    int status = uncompress2(back, &back_length, packed, &source_length);
    printf("%s %d %lu %d %s\n", argv[0], raw, (unsigned long)back_length, status, zError(status));
    return status != Z_OK;
}
