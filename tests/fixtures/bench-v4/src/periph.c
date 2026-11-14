/* SPDX-License-Identifier: Apache-2.0 */
/* Suite-v4 peripheral-map fixture: headerless Cortex-M4 firmware for the made-up BENCHM4 device
 * (../companions/benchm4.svd). Every register access goes through RD/WR (device.h), so the host harness can replay
 * each function and record its accesses in program order. Every function below the vector table is a leaf: none
 * calls another of these functions, so "the registers a function accesses" is the same on the target and in the
 * harness. */
#include "device.h"

NOINLINE void clock_init(void) {
  WR(CLKCTRL_DIV, (2u << 4) | 1u);
  WR(CLKCTRL_ENR, RD(CLKCTRL_ENR) | (1u << 0) | (1u << 1) | (1u << 4) | (1u << 9));
  while ((RD(CLKCTRL_STAT) & 1u) == 0) {
  }
}

NOINLINE void gpio_setup(void) {
  WR(GPIOA_MODE, 0x0000000Fu);
  WR(GPIOA_CLR, 0x0000000Fu);
  WR(GPIOB_MODE, 0x00000000u);
}

NOINLINE void uart_init(uint32_t baud) {
  WR(UART0_CTRL, 0);
  WR(UART0_BAUD, 16000000u / (16u * baud));
  WR(UART0_STATUS, 1u << 3);
  WR(UART0_CTRL, (1u << 0) | (1u << 1) | (1u << 2) | (2u << 3) | (1u << 8));
}

NOINLINE void uart_putc(uint32_t c) {
  while ((RD(UART0_STATUS) & (1u << 0)) == 0) {
  }
  WR(UART0_DATA, c & 0xFFu);
}

NOINLINE uint32_t uart_getc(void) {
  while ((RD(UART0_STATUS) & (1u << 1)) == 0) {
  }
  return RD(UART0_DATA) & 0xFFu;
}

NOINLINE void uart_flush(void) {
  while (RD(UART0_STATUS) & (1u << 2)) {
  }
}

NOINLINE uint32_t uart_overrun(void) {
  uint32_t status = RD(UART0_STATUS);
  if (status & (1u << 3)) {
    WR(UART0_STATUS, 1u << 3);
    return 1;
  }
  return 0;
}

NOINLINE void timer_setup(uint32_t period) {
  WR(TIMER1_CTRL, 0);
  WR(TIMER1_LOAD, period - 1u);
  WR(TIMER1_INTCLR, 1);
  WR(TIMER1_CTRL, (1u << 0) | (1u << 2) | (3u << 8));
}

NOINLINE uint32_t timer_elapsed(uint32_t period) { return period - 1u - RD(TIMER1_COUNT); }

NOINLINE void watchdog_start(uint32_t timeout) {
  WR(WDOG_RELOAD, timeout);
  WR(WDOG_CTRL, 1);
  WR(WDOG_KEY, 0xAAAAu);
}

NOINLINE void watchdog_kick(void) { WR(WDOG_KEY, 0xAAAAu); }

NOINLINE void led_set(uint32_t mask, uint32_t on) {
  if (on) {
    WR(GPIOA_SET, mask);
  } else {
    WR(GPIOA_CLR, mask);
  }
}

NOINLINE uint32_t button_pressed(void) { return (RD(GPIOB_IN) & 1u) == 0; }

#ifndef HOST
extern uint32_t __stack_top;
void reset_handler(void);
static void default_handler(void) { HALT(); }

__attribute__((section(".vectors"), used)) const void *const VECTORS[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};

void reset_handler(void) {
  clock_init();
  gpio_setup();
  uart_init(115200);
  timer_setup(16000);
  watchdog_start(4000);
  uint32_t lit = 0;
  for (;;) {
    uint32_t c = uart_getc();
    if (c == '?') {
      uart_putc('0' + (timer_elapsed(16000) & 7u));
      uart_flush();
    } else {
      uart_putc(c);
    }
    if (uart_overrun()) {
      led_set(2, 1);
    }
    if (button_pressed()) {
      lit ^= 1u;
      led_set(1, lit);
    }
    watchdog_kick();
  }
}
#endif
