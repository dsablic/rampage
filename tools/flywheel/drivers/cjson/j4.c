/* Flywheel corpus driver: cJSON arrays, detaching items and parse options. Never run. */
#include <stdio.h>
#include "cJSON.h"

static int drv_count_strings(const cJSON *array) {
    int count = 0;
    for (int i = 0; i < cJSON_GetArraySize(array); i++) {
        if (cJSON_IsString(cJSON_GetArrayItem(array, i))) count++;
    }
    return count;
}

int main(int argc, char **argv) {
    const char *end = NULL;
    const char *text = argc > 1 ? argv[1] : "[\"a\", \"b\", 3, {\"k\": null}] trailing";
    cJSON *array = cJSON_ParseWithOpts(text, &end, 0);
    if (!array) return 1;
    int strings = drv_count_strings(array);
    cJSON *detached = cJSON_DetachItemFromArray(array, 0);
    cJSON_InsertItemInArray(array, 1, detached);
    cJSON_AddItemToArray(array, cJSON_CreateNumber(argc));
    char *printed = cJSON_PrintBuffered(array, 64, 0);
    printf("%s %d %s %s\n", argv[0], strings, printed, end ? end : "");
    cJSON_free(printed);
    cJSON_Delete(array);
    return 0;
}
