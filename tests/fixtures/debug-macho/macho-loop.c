// SPDX-License-Identifier: Apache-2.0
// The debugserver fixture: an arm64 macOS program that calls a named function, `tick`, in a loop, and `tick`
// increments a global, `counter`. `main` calls `tick` with a `bl`, so a breakpoint on `tick` stops at its first
// instruction with x30 holding the return address in `main` (signed on arm64e).

#include <unistd.h>

volatile unsigned long counter;

__attribute__((noinline)) unsigned long tick(unsigned long step) {
    counter += step;
    return counter;
}

int main(void) {
    for (;;) {
        tick(1);
        usleep(1000);
    }
}
