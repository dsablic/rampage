/* Program B of the flywheel synthetic corpus: another owned program over minilib. Freestanding, never run. */
#include "minilib.h"

static unsigned char program_text[] = "flywheel synthetic corpus";

static unsigned program_b_fold(unsigned seed) {
    unsigned value = seed;
    for (int i = 0; i < 4; i++) value = ml_mix(value, (unsigned)i, seed);
    return value;
}

int main(void) {
    ml_reverse(program_text, sizeof program_text - 1);
    unsigned total = ml_checksum(program_text, sizeof program_text - 1);
    int values[4] = {(int)total, 2, 3, 4};
    return (int)(program_b_fold(total) + ml_sum_squares(values, 4) + (unsigned)ml_find(program_text, 8, 'f'));
}
