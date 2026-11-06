/* Flywheel corpus driver: streaming deflate with a gzip header, then streaming inflate. Never run. */
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#define DRV_CHUNK 1024

static int drv_deflate_gzip(const unsigned char *in, unsigned length, unsigned char *out, unsigned capacity) {
    z_stream stream;
    memset(&stream, 0, sizeof stream);
    if (deflateInit2(&stream, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return -1;
    gz_header header;
    memset(&header, 0, sizeof header);
    header.name = (Bytef *)"driver";
    deflateSetHeader(&stream, &header);
    stream.next_in = (Bytef *)in;
    stream.avail_in = length;
    stream.next_out = out;
    stream.avail_out = capacity;
    int status = deflate(&stream, Z_FINISH);
    unsigned produced = capacity - stream.avail_out;
    deflateEnd(&stream);
    return status == Z_STREAM_END ? (int)produced : -2;
}

static int drv_inflate_any(const unsigned char *in, unsigned length, unsigned char *out, unsigned capacity) {
    z_stream stream;
    memset(&stream, 0, sizeof stream);
    if (inflateInit2(&stream, 15 + 32) != Z_OK) return -1;
    stream.next_in = (Bytef *)in;
    stream.avail_in = length;
    int status;
    unsigned produced = 0;
    do {
        stream.next_out = out + produced;
        stream.avail_out = capacity - produced < DRV_CHUNK ? capacity - produced : DRV_CHUNK;
        status = inflate(&stream, Z_NO_FLUSH);
        produced = capacity - (capacity - (unsigned)stream.total_out);
    } while (status == Z_OK && produced < capacity);
    inflateEnd(&stream);
    return status == Z_STREAM_END ? (int)produced : -2;
}

int main(int argc, char **argv) {
    static unsigned char text[8192], packed[9000], unpacked[8192];
    for (unsigned i = 0; i < sizeof text; i++) text[i] = (unsigned char)("flywheel"[i % 8] + argc);
    int packed_length = drv_deflate_gzip(text, sizeof text, packed, sizeof packed);
    int unpacked_length = packed_length > 0 ? drv_inflate_any(packed, (unsigned)packed_length, unpacked, sizeof unpacked) : -1;
    printf("%s %d %d %d\n", argv[0], packed_length, unpacked_length, memcmp(text, unpacked, sizeof text));
    return 0;
}
