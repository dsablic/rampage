#include <stdio.h>

static const char *greeting = "rampage fixture greeting";

int add(int a, int b) { return a + b; }

int main(void) {
    puts(greeting);
    return add(2, 3);
}
