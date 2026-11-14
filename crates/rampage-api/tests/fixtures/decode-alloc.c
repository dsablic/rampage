/* A rolling-XOR string decoder that copies its NUL-terminated input to the heap with strlen, malloc and memcpy and
 * decodes the copy in place, for tests that run the decoder (string_decoding with evaluate, evaluate_function's
 * library stand-ins). The blobs decode to "open sesame", "token: 7f3a" and "connect: ok". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char door[] = {0xca, 0xf8, 0x2b, 0xb7, 0xd0, 0x6d, 0x1c, 0x5c, 0xfa, 0x19, 0x40, 0};
static const unsigned char token[] = {0xd1, 0xe7, 0x25, 0xbc, 0x9e, 0x24, 0x59, 0x18, 0xfd, 0x47, 0x44, 0};
static const unsigned char peer[] = {0xc6, 0xe7, 0x20, 0xb7, 0x95, 0x7d, 0x0d, 0x15, 0xbb, 0x1b, 0x4e, 0};

__attribute__((noinline)) static char *reveal(const unsigned char *in) {
    size_t length = strlen((const char *)in);
    char *out = malloc(length + 1);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, in, length + 1);
    unsigned char key = 0xa5;
    for (size_t index = 0; index < length; index++) {
        out[index] = (char)(out[index] ^ key);
        key = (unsigned char)((key << 1) | (key >> 7)) + 0x3d;
    }
    return out;
}

int main(void) {
    char *text = reveal(door);
    puts(text);
    free(text);
    text = reveal(token);
    puts(text);
    free(text);
    text = reveal(peer);
    puts(text);
    free(text);
    return 0;
}
