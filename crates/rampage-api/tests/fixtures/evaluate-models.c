/* Imports evaluate_function models: sprintf, snprintf, strdup and C++ operator new/delete (declared under their
 * Itanium names, linked from a stub libstdc++ that build.sh makes, so they are real imports). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))

void *operator_new(unsigned long size) __asm__("_Znwm");
void *operator_new_array(unsigned long size) __asm__("_Znam");
void operator_delete(void *block) __asm__("_ZdlPv");
void operator_delete_array(void *block) __asm__("_ZdaPv");

NOINLINE int describe(char *out, unsigned long size, const char *name, int value) {
    return snprintf(out, size, "%s=%05d/%x/%c%%|%-6s|%8u|%-4X|%+d|%ld|%lld", name, value, value, 'A' + value % 26,
                    "ab", (unsigned)value, (unsigned)value, -value, (long)value * 3, (long long)value << 33);
}

NOINLINE int label(char *out, int value) { return sprintf(out, "[%3d:%-3s:%03x]", value, "id", (unsigned)value); }

NOINLINE unsigned shout(const char *text) {
    char *copy = strdup(text);
    unsigned hash = 2166136261u;
    for (char *cursor = copy; *cursor != 0; cursor++) {
        if (*cursor >= 'a' && *cursor <= 'z') {
            *cursor = (char)(*cursor - 32);
        }
        hash = (hash ^ (unsigned char)*cursor) * 16777619u;
    }
    free(copy);
    return hash;
}

struct node {
    int value;
    struct node *next;
};

NOINLINE int list_sum(int count) {
    struct node *head = NULL;
    for (int index = 0; index < count; index++) {
        struct node *node = operator_new(sizeof *node);
        node->value = index * index;
        node->next = head;
        head = node;
    }
    int *squares = operator_new_array(sizeof(int) * (unsigned long)count + 1);
    int sum = 0;
    while (head != NULL) {
        struct node *next = head->next;
        squares[head->value % count] += head->value;
        sum += head->value;
        operator_delete(head);
        head = next;
    }
    sum += squares[0];
    operator_delete_array(squares);
    return sum;
}

int main(int argc, char **argv) {
    char text[128];
    describe(text, sizeof text, argv[0], argc);
    label(text, argc);
    return (int)shout(text) + list_sum(argc);
}
