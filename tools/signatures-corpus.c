#define _GNU_SOURCE
/* Broad libc reference corpus: touches many functions so a static link pulls them in for signaturing. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <wchar.h>
#include <wctype.h>
#include <stdint.h>
#include <inttypes.h>

volatile uintptr_t sink;
static int cmp(const void *a, const void *b) { return *(const char *)a - *(const char *)b; }

int main(int argc, char **argv) {
    const char *s = argc > 1 ? argv[1] : "corpus";
    char buf[512], *dup = strdup(s);
    size_t n = strlen(s);
    strcpy(buf, s); strncpy(buf, s, sizeof buf - 1); strcat(buf, "!"); strncat(buf, s, 4);
    sink += strcmp(buf, s) + strncmp(buf, s, 3) + strcasecmp(buf, s) + strncasecmp(buf, s, 2);
    sink += (uintptr_t)memchr(buf, 'c', n) + (uintptr_t)memrchr(buf, 'c', n) + memcmp(buf, s, 2);
    sink += (uintptr_t)strchr(buf, 'o') + (uintptr_t)strrchr(buf, 'o') + (uintptr_t)strstr(buf, "rp");
    sink += (uintptr_t)strpbrk(buf, "xyz") + strspn(buf, "corpus") + strcspn(buf, "!") + (uintptr_t)strtok(dup, "r");
    memset(buf, 0, 4); memmove(buf + 1, buf, 3);
    for (size_t i = 0; i < n; i++) { sink += toupper(buf[i]) + tolower(buf[i]) + isalpha(buf[i]) + isdigit(buf[i]); }
    long v = strtol(s, NULL, 0) + atol(s) + atoi(s); double d = strtod(s, NULL) + atof(s);
    sink += v + (long)d + (long)llabs(v) + labs((long)v) + abs((int)v);
    d += sqrt(d) + pow(d, 2.0) + sin(d) + cos(d) + tan(d) + exp(d) + log(d + 10) + floor(d) + ceil(d) + fabs(d);
    sink += (uintptr_t)d;
    void *p = malloc(256); p = realloc(p, 512); void *q = calloc(4, 32);
    char *big = malloc(1024); snprintf(big, 1024, "%s %ld %f %d", buf, v, d, (int)n);
    sscanf(s, "%s", buf); 
    time_t t = time(NULL); struct tm *lt = localtime(&t); char tb[64]; strftime(tb, sizeof tb, "%Y", lt);
    sink += (uintptr_t)gmtime(&t) + (uintptr_t)mktime(lt) + (uintptr_t)difftime(t, 0);
    wchar_t wb[32]; mbstowcs(wb, s, 32); char mb[64]; wcstombs(mb, wb, 64); sink += wcslen(wb) + wcscmp(wb, wb);
    fputs(big, stdout); fprintf(stderr, "%zu\n", n); fwrite(buf, 1, 4, stdout); putchar('\n');
    qsort(buf, n ? n : 1, 1, cmp); void *bs = bsearch(s, buf, n ? n : 1, 1, cmp); sink += (uintptr_t)bs;
    sink += (uintptr_t)p + (uintptr_t)q + errno;
    free(p); free(q); free(big); free(dup);
    return (int)(sink & 1);
}
