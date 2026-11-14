// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M3 firmware that drives the timers of tests/fixtures/svd/ARM_Example.svd through raw MMIO
// addresses, for the CMSIS-SVD peripheral-map tests. raw-cortex-m-svd.elf keeps the symbols (the truth for tests);
// raw-cortex-m-svd.bin is its flash image at 0x08000000. Registers (TIMER0 at 0x40010000, TIMER1 at 0x40010100):
//   CR 0x00 (32-bit: EN bit 0, RST bit 1, MODE bits 4..6), SR 0x04 (16-bit: MATCH bit 8), COUNT 0x20,
//   MATCH 0x24, RELOAD[4] 0x50.
#include <stdint.h>

#define TIMER0_BASE 0x40010000u
#define TIMER1_BASE 0x40010100u
#define REG32(base, offset) (*(volatile uint32_t *)((base) + (offset)))
#define REG16(base, offset) (*(volatile uint16_t *)((base) + (offset)))

extern uint32_t __stack_top;

volatile uint32_t elapsed __attribute__((section(".ram")));

/* Enables TIMER0 in Single_MATCH mode (MODE = 2) with EN set. */
__attribute__((noinline)) void timer0_start(uint32_t match) {
  REG32(TIMER0_BASE, 0x24) = match;
  REG32(TIMER0_BASE, 0x00) = REG32(TIMER0_BASE, 0x00) | 0x21u;
}

/* Clears EN. */
__attribute__((noinline)) void timer0_stop(void) {
  REG32(TIMER0_BASE, 0x00) = REG32(TIMER0_BASE, 0x00) & ~1u;
}

/* Polls SR.MATCH, then returns COUNT. */
__attribute__((noinline)) uint32_t timer0_wait(void) {
  while ((REG16(TIMER0_BASE, 0x04) & 0x100u) == 0) {
  }
  return REG32(TIMER0_BASE, 0x20);
}

/* Writes RELOAD[2]. */
__attribute__((noinline)) void timer0_reload(uint32_t value) { REG32(TIMER0_BASE, 0x58) = value; }

/* Reads TIMER1's COUNT. */
__attribute__((noinline)) uint32_t timer1_count(void) { return REG32(TIMER1_BASE, 0x20); }

/* Never touches a peripheral. */
__attribute__((noinline)) uint32_t scale(uint32_t value) { return value * 3u + 1u; }

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void reset_handler(void) {
  for (;;) {
    timer0_start(scale(1000));
    elapsed = timer0_wait() + timer1_count();
    timer0_reload(elapsed);
    timer0_stop();
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};
