#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
/* A different program that links the same static musl; its libc functions should match the reference DB. */
int main(int argc, char **argv) {
    const char *s = argc > 1 ? argv[1] : "another-program-entirely";
    size_t n = strlen(s);
    char *dup = strdup(s);
    for (size_t i = 0; i < n; i++) dup[i] = (char)toupper((unsigned char)dup[i]);
    int c = strcmp(dup, s) + strncmp(dup, s, 3);
    char *p = malloc(64);
    memcpy(p, dup, n < 63 ? n : 63);
    p[63] = 0;
    long v = strtol(s, NULL, 10) + atoi(s);
    printf("%s %d %ld\n", p, c, v);
    free(p); free(dup);
    return 0;
}
