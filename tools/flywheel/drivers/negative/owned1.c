/* Flywheel negative program: owned utility code (sorting, searching, a checksum), no library. Never run. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void drv_insertion_sort(int *values, size_t count) {
    for (size_t i = 1; i < count; i++) {
        int value = values[i];
        size_t j = i;
        while (j > 0 && values[j - 1] > value) {
            values[j] = values[j - 1];
            j--;
        }
        values[j] = value;
    }
}

static long drv_binary_search(const int *values, size_t count, int wanted) {
    size_t low = 0, high = count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (values[middle] < wanted) low = middle + 1;
        else high = middle;
    }
    return low < count && values[low] == wanted ? (long)low : -1;
}

static uint32_t drv_fletcher(const uint8_t *data, size_t length) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < length; i++) {
        a = (a + data[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

static int drv_compare(const void *left, const void *right) {
    return *(const int *)left - *(const int *)right;
}

int main(int argc, char **argv) {
    int values[64];
    for (int i = 0; i < 64; i++) values[i] = (i * 37 + argc) % 101;
    drv_insertion_sort(values, 32);
    qsort(values + 32, 32, sizeof values[0], drv_compare);
    long found = drv_binary_search(values, 32, 50);
    uint32_t sum = drv_fletcher((const uint8_t *)argv[0], strlen(argv[0]));
    printf("%ld %08x %d\n", found, sum, values[0]);
    return 0;
}
