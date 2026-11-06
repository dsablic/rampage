/* The negative program of the flywheel synthetic corpus: unrelated owned code, except for one function that is a
 * copy of minilib's ml_sum_squares under another name. A signature for ml_sum_squares therefore also names this
 * program's function, and the negatives gate must refuse it. Freestanding, never run. */

unsigned long negative_sum_squares(const int *values, unsigned count) {
    unsigned long total = 0;
    for (unsigned i = 0; i < count; i++) total += (unsigned long)((long)values[i] * values[i]);
    return total;
}

unsigned negative_collatz(unsigned value) {
    unsigned steps = 0;
    while (value > 1 && steps < 1000) {
        value = value % 2 ? value * 3 + 1 : value / 2;
        steps++;
    }
    return steps;
}

int main(void) {
    int values[5] = {1, 2, 3, 4, 5};
    return (int)(negative_sum_squares(values, 5) + negative_collatz(27));
}
