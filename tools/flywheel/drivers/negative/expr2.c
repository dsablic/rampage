/* Flywheel negative driver: compile a tinyexpr expression with variables and sample it. Never run. */
#include <stdio.h>
#include "tinyexpr.h"

static double drv_sample(te_expr *expression, double *x, double from, double to, int steps) {
    double sum = 0;
    for (int i = 0; i <= steps; i++) {
        *x = from + (to - from) * i / steps;
        sum += te_eval(expression);
    }
    return sum / (steps + 1);
}

int main(int argc, char **argv) {
    double x = 0, y = argc;
    te_variable variables[] = {{"x", &x, TE_VARIABLE, 0}, {"y", &y, TE_VARIABLE, 0}};
    int error = 0;
    te_expr *expression = te_compile(argc > 1 ? argv[1] : "sin(x) * y + x^2", variables, 2, &error);
    if (!expression) return 1;
    printf("%f\n", drv_sample(expression, &x, 0, 3.14159, 100));
    te_free(expression);
    return 0;
}
