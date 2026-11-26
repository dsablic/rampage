/* SPDX-License-Identifier: Apache-2.0 */
/* Relocatable-object fixtures (build-objects.sh): calls to undefined (extern) functions and to local ones, data
 * reached through relocations (a string, a global, an extern global, a table of function pointers), and a common
 * symbol. Declarations stand in for headers so the objects build freestanding for every target. */
int printf(const char *format, ...);
__SIZE_TYPE__ strlen(const char *text);
extern int ext_counter;
extern void hal_init(int pin, int mode);

int shared_total; /* common with -fcommon */
static int table[4] = {1, 2, 3, 4};
const char *greeting = "hello object";

static int scale(int x) { return table[x & 3] * x + ext_counter; }

int sum(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += scale(i);
    shared_total = s;
    return s;
}

static int twice(int x) { return 2 * x; }
static int thrice(int x) { return 3 * x; }
int (*const handlers[2])(int) = {twice, thrice};

int dispatch(int which, int value) { return handlers[which & 1](value); }

int main(int argc, char **argv) {
    hal_init(5, 1);
    printf("%s %d\n", greeting, sum(argc) + dispatch(argc, 7));
    return (int)strlen(argv[0]);
}
