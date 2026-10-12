/* A single-byte rolling-XOR string decoder called from several sites with encoded blobs, for workflow tests.
 * The blobs decode to "hello, world", "see you later" and "status: ready"; the tests only analyze the compiled
 * program, they never run it. */
#include <stdio.h>

static const unsigned char greeting[] = {0x32, 0x94, 0x4c, 0x11, 0x58, 0x87, 0xb4, 0x11, 0x66, 0x3d, 0xb7, 0x90};
static const unsigned char farewell[] = {0x29, 0x94, 0x45, 0x5d, 0x4e, 0xc4, 0xe1, 0x46, 0x65, 0x2e, 0xaf, 0x91, 0x54};
static const unsigned char status[] = {0x29, 0x85, 0x41, 0x09, 0x42, 0xd8, 0xae, 0x46, 0x7b, 0x2a, 0xba, 0x90, 0x5f};

__attribute__((noinline)) static void decode(char *out, const unsigned char *in, unsigned length, unsigned char key) {
    for (unsigned index = 0; index < length; index++) {
        out[index] = (char)(in[index] ^ key);
        key = (unsigned char)((key << 1) | (key >> 7)) + 0x3d;
    }
    out[length] = 0;
}

int main(void) {
    char text[32];
    decode(text, greeting, sizeof greeting, 0x5a);
    puts(text);
    decode(text, farewell, sizeof farewell, 0x5a);
    puts(text);
    decode(text, status, sizeof status, 0x5a);
    puts(text);
    return 0;
}
