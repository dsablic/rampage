/* Program A of the flywheel synthetic corpus: calls every minilib function. Freestanding, never run. */
#include "minilib.h"

static unsigned char program_buffer[64];
static int program_values[8] = {1, -2, 3, -4, 5, -6, 7, -8};

unsigned program_a_entry(void) {
    for (unsigned i = 0; i < sizeof program_buffer; i++) program_buffer[i] = (unsigned char)(i * 7);
    ml_reverse(program_buffer, sizeof program_buffer);
    unsigned total = ml_checksum(program_buffer, sizeof program_buffer);
    total += (unsigned)ml_find(program_buffer, sizeof program_buffer, 21);
    total += (unsigned)ml_sum_squares(program_values, 8);
    total += ml_scale((const unsigned *)program_values, 8);
    return total ^ ml_mix(total, 3, 5) ^ ml_lookup(total);
}

int main(void) {
    return (int)program_a_entry();
}
