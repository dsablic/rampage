// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M3 firmware for volatile peripheral registers (tests/fixtures/svd/ARM_Example.svd timers):
// two consecutive writes to one register, and a read right after a write, both of which a decompiler that treats
// the registers as ordinary memory would merge or forward. The .elf keeps the symbols as the test truth.
#include <stdint.h>

#define TIMER0_CR (*(volatile uint32_t *)0x40010000u)
#define TIMER0_MATCH (*(volatile uint32_t *)0x40010024u)

extern uint32_t __stack_top;

/* Resets then enables: both stores reach the register. */
__attribute__((noinline)) void timer0_pulse(void) {
  TIMER0_CR = 2u;
  TIMER0_CR = 1u;
}

/* Writes MATCH and reads it back: the read is the register's, not the value written. */
__attribute__((noinline)) uint32_t timer0_echo(uint32_t value) {
  TIMER0_MATCH = value;
  return TIMER0_MATCH;
}

__attribute__((noreturn)) void reset_handler(void) {
  for (;;) {
    timer0_pulse();
    timer0_echo(7);
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top, reset_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
