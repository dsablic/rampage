// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: command-line options map to flag bits through a table, and one bit enables the
// code path that opens backup.tar. Built stripped for x86-64 Linux. The task asks which option enables it.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct option_entry {
    const char *name;
    uint32_t bit;
};

static const struct option_entry options[] = {
    {"--verbose", 0x01}, {"--color", 0x10}, {"--snapshot", 0x08}, {"--archive", 0x02},
    {"--dry-run", 0x04}, {"--trace", 0x20}, {"--compact", 0x40},
};

static uint32_t flags;

__attribute__((noinline)) static int parse(int argc, char **argv) {
    for (int a = 1; a < argc; a++) {
        int known = 0;
        for (size_t o = 0; o < sizeof options / sizeof options[0]; o++) {
            if (strcmp(argv[a], options[o].name) == 0) {
                flags |= options[o].bit;
                known = 1;
            }
        }
        if (!known) {
            return -1;
        }
    }
    return 0;
}

__attribute__((noinline)) static int write_snapshot(void) {
    FILE *file = fopen("state.snap", "wb");
    if (!file) {
        return -1;
    }
    fputs("snapshot\n", file);
    return fclose(file);
}

__attribute__((noinline)) static int write_archive(void) {
    FILE *file = fopen("backup.tar", "wb");
    if (!file) {
        return -1;
    }
    fputs("archive\n", file);
    return fclose(file);
}

int main(int argc, char **argv) {
    if (parse(argc, argv) != 0) {
        fputs("unknown option\n", stderr);
        return 2;
    }
    if (flags & 0x01) {
        puts("verbose");
    }
    if ((flags & 0x04) == 0) {
        if (flags & 0x02) {
            write_snapshot();
        }
        if (flags & 0x08) {
            write_archive();
        }
    }
    return 0;
}
