// SPDX-License-Identifier: Apache-2.0
// Bare-metal Cortex-M3 firmware for live QEMU debugger acceptance tests (lm3s6965evb).
// Reset writes the 16-byte PATTERN to 0x20000100, then increments the word at 0x20000200 forever.
#include <stdint.h>

#define PATTERN_ADDR ((volatile uint8_t *)0x20000100u)
#define COUNTER_ADDR ((volatile uint32_t *)0x20000200u)

extern uint32_t __stack_top;

static const char PATTERN[16] = "RAMPAGE-DEBUG-91";

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void reset_handler(void) {
  for (unsigned i = 0; i < sizeof PATTERN; i++) {
    PATTERN_ADDR[i] = (uint8_t)PATTERN[i];
  }
  *COUNTER_ADDR = 0;
  for (;;) {
    *COUNTER_ADDR = *COUNTER_ADDR + 1;
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,
    reset_handler,
    default_handler, /* NMI */
    default_handler, /* HardFault */
    default_handler, /* MemManage */
    default_handler, /* BusFault */
    default_handler, /* UsageFault */
    0,
    0,
    0,
    0,
    default_handler, /* SVCall */
    default_handler, /* DebugMonitor */
    0,
    default_handler, /* PendSV */
    default_handler, /* SysTick */
};
