// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M3 firmware for peripheral_map (a peripheral map built from loads and stores, no SVD). Built
// without MOVW/MOVT, so every peripheral base is a literal-pool word. raw-cortex-m-peripherals.elf keeps the symbols
// (the truth for tests); raw-cortex-m-peripherals.bin is its flash image at 0x08000000.
//   0x40015800  a UART-like block: CTRL 0x00, CFG 0x04, BAUD 0x0c, FMT 0x10, IE 0x14, STATUS 0x18, DATA 0x20
//   0x40020000  a GPIO-like block: IDR 0x10 (8-bit read), BSRR 0x18 (16-bit write)
//   0xe000e010  SysTick (CTRL, LOAD), 0xe000e100 NVIC ISER0, 0xe000ed08 SCB VTOR
// `routing` holds address-like words that no instruction dereferences: they must not reach the map.
#include <stdint.h>

typedef struct {
  volatile uint32_t CTRL;
  volatile uint32_t CFG;
  volatile uint32_t RESERVED;
  volatile uint32_t BAUD;
  volatile uint32_t FMT;
  volatile uint32_t IE;
  volatile uint32_t STATUS;
  volatile uint32_t CLEAR;
  volatile uint32_t DATA;
} uart_t;

#define UART ((uart_t *)0x40015800u)
#define GPIO_IDR (*(volatile uint8_t *)0x40020010u)
#define GPIO_BSRR (*(volatile uint16_t *)0x40020018u)
#define SYST_CTRL (*(volatile uint32_t *)0xe000e010u)
#define SYST_LOAD (*(volatile uint32_t *)0xe000e014u)
#define NVIC_ISER0 (*(volatile uint32_t *)0xe000e100u)
#define SCB_VTOR (*(volatile uint32_t *)0xe000ed08u)

extern uint32_t __stack_top;

volatile uint32_t ticks __attribute__((section(".ram")));

const uint32_t routing[4] = {0x40015800u, 0x40015804u, 0x40030000u, 0x4003ff00u};

/* Sets the UART's baud divisor and frame format, then enables it. */
__attribute__((noinline)) void uart_configure(uint32_t format) {
  UART->CFG = 0;
  UART->CTRL = 1;
  UART->BAUD = 0x3fu;
  UART->FMT = format;
  UART->IE = 1;
  UART->CFG = UART->CFG | 0x10001u;
}

/* Sends words, waiting on STATUS before each one: the base is loaded once, outside the loop. */
__attribute__((noinline)) void uart_write(const uint32_t *words, uint32_t count) {
  for (uint32_t i = 0; i < count; i++) {
    while ((UART->STATUS & 8u) != 0) {
    }
    UART->DATA = words[i];
  }
}

__attribute__((noinline)) uint32_t gpio_read(void) { return GPIO_IDR; }

__attribute__((noinline)) void gpio_set(uint16_t value) { GPIO_BSRR = value; }

/* Core peripherals: vector table, an interrupt enable, a 1 kHz tick. */
__attribute__((noinline)) void core_setup(void) {
  SCB_VTOR = 0x08000000u;
  NVIC_ISER0 = 1u << 5;
  SYST_LOAD = 999u;
  SYST_CTRL = 7u;
}

/* Reads a routing word: the table is data, never a peripheral access. */
__attribute__((noinline)) uint32_t route(uint32_t index) { return routing[index & 3u]; }

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

void systick_handler(void) { ticks = ticks + 1; }

__attribute__((noreturn)) void reset_handler(void) {
  static const uint32_t silence[2] = {0, 0};
  core_setup();
  uart_configure(route(gpio_read()));
  for (;;) {
    uart_write(silence, 2);
    gpio_set((uint16_t)ticks);
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, systick_handler,
};
