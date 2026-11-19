/* Float arguments, float arithmetic and float results for evaluate_function: SSE scalar code on x86-64, x87 on
 * i686 (no SSE), VFP on 32-bit ARM (hard and soft float ABIs) and AArch64. Built by build.sh. */
#define NOINLINE __attribute__((noinline))

NOINLINE double poly(double x) { return 3.0 * x * x - 2.5 * x + 0.125; }

NOINLINE float grow(float start, int rounds) {
    float value = start;
    for (int round = 0; round < rounds; round++) {
        value = value * 1.5f + 0.25f;
    }
    return value;
}

NOINLINE double mean(const int *values, int count) {
    double sum = 0.0;
    for (int index = 0; index < count; index++) {
        sum += values[index];
    }
    return sum / count;
}

NOINLINE int to_fixed(double value) { return (int)(value * 65536.0); }

NOINLINE int compare(double a, double b) { return a < b ? -1 : a > b ? 1 : 0; }

NOINLINE double mixed(int a, double b, float c, long long d) { return a * b + c - (double)d; }

NOINLINE float halve(double value) { return (float)(value / 2.0); }

int main(int argc, char **argv) {
    (void)argv;
    int values[3] = {argc, 2, 4};
    return to_fixed(poly(argc) + grow(1.0f, argc) + mean(values, 3) + halve(argc)) + compare(argc, 2) +
           (int)mixed(argc, 0.5, 0.25f, 3);
}
