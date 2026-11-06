/* Flywheel corpus driver: cJSON duplication, comparison, replacement and minification. Never run. */
#include <stdio.h>
#include <string.h>
#include "cJSON.h"

static int drv_edit(cJSON *root) {
    cJSON *copy = cJSON_Duplicate(root, 1);
    cJSON_ReplaceItemInObjectCaseSensitive(copy, "mode", cJSON_CreateString("changed"));
    cJSON_DeleteItemFromObject(copy, "drop");
    int equal = cJSON_Compare(root, copy, 1);
    cJSON_Delete(copy);
    return equal;
}

int main(int argc, char **argv) {
    char text[256];
    snprintf(text, sizeof text, "{ \"mode\" : \"orig\", \"drop\" : [ 1, 2 ], \"n\" : %d }", argc);
    cJSON_Minify(text);
    cJSON *root = cJSON_ParseWithLength(text, strlen(text));
    if (!root) return 1;
    int equal = drv_edit(root);
    cJSON *numbers = cJSON_CreateIntArray((const int[]){1, 2, 3}, 3);
    cJSON_AddItemToObject(root, "numbers", numbers);
    char *printed = cJSON_Print(root);
    printf("%s %s %d\n", argv[0], printed, equal);
    cJSON_free(printed);
    cJSON_Delete(root);
    return 0;
}
