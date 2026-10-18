#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static volatile unsigned long long divisor = 31;
static volatile double input = 2.25;
#if defined(__SIZEOF_INT128__)
static volatile unsigned __int128 wide = ((unsigned __int128)1 << 95) + 97;
#endif

int main(int argc, char **argv) {
    char buffer[128];
    const char *text = argc > 1 ? argv[1] : "runtime-target-distinct";
    size_t length = strlen(text);
    unsigned long long quotient = (unsigned long long)length * 1000000009ULL / divisor;
#if defined(__SIZEOF_INT128__)
    quotient ^= (unsigned long long)(wide / divisor);
#endif
    void *allocation = malloc(length + 1);
    if (!allocation) return 5;
    memcpy(allocation, text, length + 1);
    int result = snprintf(buffer, sizeof(buffer), "%llu:%s:%.3f",
                          quotient, (char *)allocation, sqrt(input));
    free(allocation);
    return result < 0;
}
