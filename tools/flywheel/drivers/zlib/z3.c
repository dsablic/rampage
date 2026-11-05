/* Flywheel corpus driver: gzip file reading and writing through the gz* API, plus crc32_combine. Never run. */
#include <stdio.h>
#include <string.h>
#include <zlib.h>

static int drv_write_file(const char *path, const char *text, int repeat) {
    gzFile file = gzopen(path, "wb9");
    if (!file) return -1;
    for (int i = 0; i < repeat; i++) {
        if (gzputs(file, text) < 0) break;
        gzprintf(file, " line %d\n", i);
    }
    return gzclose(file);
}

static long drv_read_file(const char *path, uLong *crc) {
    char buffer[512];
    gzFile file = gzopen(path, "rb");
    if (!file) return -1;
    long total = 0;
    int got;
    while ((got = gzread(file, buffer, sizeof buffer)) > 0) {
        *crc = crc32(*crc, (const Bytef *)buffer, (uInt)got);
        total += got;
    }
    if (!gzeof(file)) total = -2;
    gzclose(file);
    return total;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "driver.gz";
    if (drv_write_file(path, "flywheel corpus", 64) != Z_OK) return 1;
    uLong first = crc32(0L, Z_NULL, 0), second = crc32(0L, (const Bytef *)"tail", 4);
    long total = drv_read_file(path, &first);
    uLong combined = crc32_combine(first, second, 4);
    printf("%ld %lx %lx\n", total, first, combined);
    return total < 0;
}
