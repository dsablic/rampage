/* Variadic formatting imports for evaluate_function's models where the convention places them unusually: on 32-bit
 * ARM a 64-bit argument after snprintf's three fixed words starts at the next even word (the stack, skipping r3), and
 * Apple arm64 passes every variadic argument on the stack. Built by build.sh. */
#include <stdio.h>

#define NOINLINE __attribute__((noinline))

NOINLINE int wide(char *out, unsigned long size, long long value) { return snprintf(out, size, "%lld|%d", value, 7); }

NOINLINE int label(char *out, int value) { return sprintf(out, "%d|%lld|%s", value, (long long)value << 33, "ok"); }

int main(int argc, char **argv) {
    char text[64];
    (void)argv;
    return wide(text, sizeof text, argc) + label(text, argc);
}
