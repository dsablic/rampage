/* Flywheel negative driver: read an INI file with inih into a small table. Never run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ini.h"

#define DRV_SLOTS 16

struct drv_table {
    char keys[DRV_SLOTS][32];
    long values[DRV_SLOTS];
    int used;
};

static int drv_store(void *user, const char *section, const char *name, const char *value) {
    struct drv_table *table = user;
    (void)section;
    if (table->used >= DRV_SLOTS) return 0;
    snprintf(table->keys[table->used], sizeof table->keys[0], "%s", name);
    table->values[table->used] = strtol(value, NULL, 0);
    table->used++;
    return 1;
}

int main(int argc, char **argv) {
    struct drv_table table;
    memset(&table, 0, sizeof table);
    int error = ini_parse(argc > 1 ? argv[1] : "settings.ini", drv_store, &table);
    long total = 0;
    for (int i = 0; i < table.used; i++) total += table.values[i];
    printf("%d %d %ld\n", error, table.used, total);
    return 0;
}
