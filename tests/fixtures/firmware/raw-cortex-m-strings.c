// SPDX-License-Identifier: Apache-2.0
// Odd-aligned string literals in a Cortex-M3 image: zig 0.17.1 -O1 packs "A", "Bc", "Cde" and "Defg" so that some
// start at odd addresses, which a movw/movt pair forms like a Thumb code pointer. None of them is a function.
#include <stdint.h>

extern uint32_t __stack_top;

__attribute__((noinline)) void uart_puts(const char *s) {
  volatile char *uart = (volatile char *)0x40000000;
  while (*s) {
    *uart = *s++;
  }
}

__attribute__((noinline)) void a(void) { uart_puts("A"); }
__attribute__((noinline)) void b(void) { uart_puts("Bc"); }
__attribute__((noinline)) void c(void) { uart_puts("Cde"); }
__attribute__((noinline)) void d(void) { uart_puts("Defg"); }

__attribute__((noreturn)) void reset_handler(void) {
  a();
  b();
  c();
  d();
  for (;;) {
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[2] = {&__stack_top, reset_handler};
