/* Flywheel negative driver: parse an INI string with inih and count sections and keys. Never run. */
#include <stdio.h>
#include <string.h>
#include "ini.h"

struct drv_counts {
    int sections;
    int keys;
    char last_section[64];
};

static int drv_handler(void *user, const char *section, const char *name, const char *value) {
    struct drv_counts *counts = user;
    if (strcmp(section, counts->last_section) != 0) {
        counts->sections++;
        snprintf(counts->last_section, sizeof counts->last_section, "%s", section);
    }
    counts->keys += name[0] != '\0' && value != NULL;
    return 1;
}

int main(int argc, char **argv) {
    struct drv_counts counts = {0, 0, ""};
    const char *text = argc > 1 ? argv[1] : "[core]\nname = flywheel\n[paths]\nroot = /tmp\nmode = 3\n";
    int error = ini_parse_string(text, drv_handler, &counts);
    printf("%d %d %d\n", error, counts.sections, counts.keys);
    return error != 0;
}
