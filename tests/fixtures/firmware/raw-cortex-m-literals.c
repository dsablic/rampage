// SPDX-License-Identifier: Apache-2.0
// Two versions of one headerless Cortex-M3 firmware whose constants live in literal pools (built without
// movw/movt, as GCC does for most Cortex-M code), for diff_firmware: build-raw-cortex-m-literals.sh builds this
// file as raw-cortex-m-literals-v1 and, with -DV2, as raw-cortex-m-literals-v2. v2 changes one constant only:
// the timeout check_timeout compares against (0x00012345 -> 0x00054321), a word in its literal pool. The bytes of
// every instruction stay the same, so only the pool word tells the versions apart: check_timeout must be reported
// as changed, and nothing else.
#include <stdint.h>

#define UART_DR (*(volatile uint32_t *)0x40011004u)
#define TIMER_CNT (*(volatile uint32_t *)0x40000024u)

extern uint32_t __stack_top;

#ifdef V2
#define TIMEOUT 0x00054321u
#else
#define TIMEOUT 0x00012345u
#endif

volatile uint32_t status_word __attribute__((section(".ram")));

__attribute__((noinline)) void uart_puts(const char *text) {
  while (*text) {
    UART_DR = (uint8_t)*text++;
  }
}

/* Reads a free-running timer and reports whether TIMEOUT ticks have passed: the constant is a pool literal. */
__attribute__((noinline)) int check_timeout(uint32_t start) { return TIMER_CNT - start > TIMEOUT; }

__attribute__((noinline)) void log_line(void) { uart_puts("timer check done"); }

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void reset_handler(void) {
  uint32_t start = TIMER_CNT;
  while (!check_timeout(start)) {
  }
  status_word = 1;
  log_line();
  for (;;) {
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};
