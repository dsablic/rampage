#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static volatile unsigned long long divisor = 19;
static volatile double input = 1.75;
#if defined(__SIZEOF_INT128__)
static volatile unsigned __int128 wide = ((unsigned __int128)1 << 96) + 71;
#endif

int main(int argc, char **argv) {
    char buffer[96];
    const char *text = argc > 1 ? argv[1] : "runtime-reference";
    size_t length = strlen(text);
#if defined(__SIZEOF_INT128__)
    length += (size_t)(wide / divisor) & 7;
#endif
    void *allocation = calloc(length + 8, 1);
    if (!allocation) return 3;
    memcpy(allocation, text, strlen(text));
    int result = snprintf(buffer, sizeof(buffer), "%s:%llu:%.4f", (char *)allocation,
                          (unsigned long long)length * 1000000007ULL / divisor, sqrt(input));
    free(allocation);
    return result < 0;
}
