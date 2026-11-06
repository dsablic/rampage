/* Flywheel corpus driver: building cJSON documents and printing them unformatted. Never run. */
#include <stdio.h>
#include "cJSON.h"

static cJSON *drv_build(int count) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "tool", "rampage");
    cJSON_AddNumberToObject(root, "count", count);
    cJSON_AddBoolToObject(root, "stripped", count % 2);
    cJSON *items = cJSON_AddArrayToObject(root, "items");
    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "index", i);
        cJSON_AddItemToObject(item, "label", cJSON_CreateString("function"));
        cJSON_AddItemToArray(items, item);
    }
    cJSON_AddNullToObject(root, "parent");
    return root;
}

int main(int argc, char **argv) {
    cJSON *root = drv_build(argc + 3);
    char *compact = cJSON_PrintUnformatted(root);
    char buffer[2048];
    int fits = cJSON_PrintPreallocated(root, buffer, sizeof buffer, 1);
    printf("%s %s %d %s\n", argv[0], compact, fits, cJSON_Version());
    cJSON_free(compact);
    cJSON_Delete(root);
    return 0;
}
