/* Flywheel negative driver: evaluate expressions with tinyexpr. Never run. */
#include <stdio.h>
#include "tinyexpr.h"

int main(int argc, char **argv) {
    int error = 0;
    double value = te_interp(argc > 1 ? argv[1] : "sqrt(5^2 + 7^2 + 11^2 + (8 - 2)^2)", &error);
    printf("%f %d\n", value, error);
    return error != 0;
}
