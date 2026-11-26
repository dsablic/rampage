/* SPDX-License-Identifier: Apache-2.0 */
/* What a program statically linked against the object library fixtures (build-objects.sh) needs besides the
 * library, without a C library: the calls objects.c makes, and an entry point. The linked, stripped program is
 * what signatures built from the library are checked against. */
int main(int argc, char **argv);

int printf(const char *format, ...) { return format[0]; }

__SIZE_TYPE__ strlen(const char *text) {
    __SIZE_TYPE__ length = 0;
    while (text[length]) length++;
    return length;
}

static char *arguments[] = {"objects", 0};

void _start(void) {
    main(1, arguments);
    for (;;) {
    }
}
