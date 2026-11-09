// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M3 firmware for the ARM:LE:32:Cortex Raw profile: a vector table with system handlers and
// external interrupts, a few functions that call each other and reference string literals through literal pools.
// raw-cortex-m.elf keeps the symbols (the truth for tests); raw-cortex-m.bin is its flash image at 0x08000000.
#include <stdint.h>

#define UART_DR (*(volatile uint32_t *)0x40011004u)
#define UART_SR (*(volatile uint32_t *)0x40011000u)

extern uint32_t __stack_top;

volatile uint32_t ticks __attribute__((section(".ram")));
volatile uint32_t last_irq __attribute__((section(".ram")));

static const char BANNER[] = "rampage cortex-m fixture v1";
static const char PROMPT[] = "cmd> ";
static const char UNKNOWN[] = "unknown command";

__attribute__((noinline)) void uart_putc(char c) {
  while ((UART_SR & 0x80u) == 0) {
  }
  UART_DR = (uint32_t)(uint8_t)c;
}

__attribute__((noinline)) void uart_puts(const char *text) {
  while (*text) {
    uart_putc(*text++);
  }
  uart_putc('\n');
}

__attribute__((noinline)) uint32_t checksum(const uint8_t *data, uint32_t length) {
  uint32_t sum = 0x811c9dc5u;
  for (uint32_t i = 0; i < length; i++) {
    sum = (sum ^ data[i]) * 0x01000193u;
  }
  return sum;
}

__attribute__((noinline)) void format_hex(uint32_t value, char *out) {
  static const char DIGITS[] = "0123456789abcdef";
  for (int i = 7; i >= 0; i--) {
    out[i] = DIGITS[value & 0xfu];
    value >>= 4;
  }
  out[8] = 0;
}

__attribute__((noinline)) int dispatch(const char *command) {
  switch (command[0]) {
  case 'r':
    uart_puts("cmd: reset");
    return 1;
  case 's':
    uart_puts("cmd: status");
    return 2;
  case 'v':
    uart_puts(BANNER);
    return 3;
  default:
    uart_puts(UNKNOWN);
    return -1;
  }
}

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void hardfault_handler(void) {
  uart_puts("hard fault");
  for (;;) {
  }
}

void systick_handler(void) { ticks = ticks + 1; }

void uart_irq_handler(void) {
  last_irq = UART_DR;
  dispatch((const char *)&last_irq);
}

void timer_irq_handler(void) { last_irq = 0x54u; }

__attribute__((noreturn)) void reset_handler(void) {
  char hex[9];
  ticks = 0;
  uart_puts(BANNER);
  format_hex(checksum((const uint8_t *)BANNER, sizeof BANNER - 1), hex);
  uart_puts(hex);
  for (;;) {
    uart_puts(PROMPT);
    dispatch(PROMPT);
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16 + 8] = {
    &__stack_top,
    reset_handler,
    default_handler,   /* NMI */
    hardfault_handler, /* HardFault */
    default_handler,   /* MemManage */
    default_handler,   /* BusFault */
    default_handler,   /* UsageFault */
    0,
    0,
    0,
    0,
    default_handler, /* SVCall */
    default_handler, /* DebugMonitor */
    0,
    default_handler, /* PendSV */
    systick_handler, /* SysTick */
    default_handler, /* IRQ0 */
    timer_irq_handler,
    0,
    uart_irq_handler,
    default_handler,
    0,
    0,
    default_handler,
};
