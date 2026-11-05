/* Flywheel corpus driver: cJSON parse, query and print. Never run; it only has to link. */
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

static double drv_sum_numbers(const cJSON *array) {
    double sum = 0;
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, array) {
        if (cJSON_IsNumber(item)) sum += item->valuedouble;
    }
    return sum;
}

int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "{\"name\":\"flywheel\",\"values\":[1,2,3.5],\"ok\":true}";
    cJSON *root = cJSON_Parse(text);
    if (!root) {
        printf("error before: %s\n", cJSON_GetErrorPtr());
        return 1;
    }
    const cJSON *name = cJSON_GetObjectItemCaseSensitive(root, "name");
    const cJSON *values = cJSON_GetObjectItem(root, "values");
    char *printed = cJSON_Print(root);
    printf("%s %g %d %s\n", cJSON_IsString(name) ? name->valuestring : "?", drv_sum_numbers(values),
           cJSON_GetArraySize(values), printed);
    cJSON_free(printed);
    cJSON_Delete(root);
    return 0;
}
