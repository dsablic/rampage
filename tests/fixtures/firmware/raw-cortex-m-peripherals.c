// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M3 firmware for peripheral_map (a peripheral map built from loads and stores, no SVD). Built
// without MOVW/MOVT, so every peripheral base is a literal-pool word. raw-cortex-m-peripherals.elf keeps the symbols
// (the truth for tests); raw-cortex-m-peripherals.bin is its flash image at 0x08000000.
//   0x40015800  a serial-audio-like block: GCR 0x00, CR1 0x04, FRCR 0x0c, SLOTR 0x10, IMR 0x14, SR 0x18, DR 0x20
//   0x40020000  a GPIO-like block: IDR 0x10 (8-bit read), BSRR 0x18 (16-bit write)
//   0xe000e010  SysTick (CTRL, LOAD), 0xe000e100 NVIC ISER0, 0xe000ed08 SCB VTOR
// `routing` holds address-like words that no instruction dereferences: they must not reach the map.
#include <stdint.h>

typedef struct {
  volatile uint32_t GCR;
  volatile uint32_t CR1;
  volatile uint32_t CR2;
  volatile uint32_t FRCR;
  volatile uint32_t SLOTR;
  volatile uint32_t IMR;
  volatile uint32_t SR;
  volatile uint32_t CLRFR;
  volatile uint32_t DR;
} audio_t;

#define AUDIO ((audio_t *)0x40015800u)
#define GPIO_IDR (*(volatile uint8_t *)0x40020010u)
#define GPIO_BSRR (*(volatile uint16_t *)0x40020018u)
#define SYST_CTRL (*(volatile uint32_t *)0xe000e010u)
#define SYST_LOAD (*(volatile uint32_t *)0xe000e014u)
#define NVIC_ISER0 (*(volatile uint32_t *)0xe000e100u)
#define SCB_VTOR (*(volatile uint32_t *)0xe000ed08u)

extern uint32_t __stack_top;

volatile uint32_t ticks __attribute__((section(".ram")));

const uint32_t routing[4] = {0x40015800u, 0x40015804u, 0x40030000u, 0x4003ff00u};

/* Configures the audio block's frame and slots, then enables it. */
__attribute__((noinline)) void audio_configure(uint32_t slots) {
  AUDIO->CR1 = 0;
  AUDIO->GCR = 1;
  AUDIO->FRCR = 0x3fu;
  AUDIO->SLOTR = slots;
  AUDIO->IMR = 1;
  AUDIO->CR1 = AUDIO->CR1 | 0x10001u;
}

/* Feeds samples, waiting on SR before each one: the base is loaded once, outside the loop. */
__attribute__((noinline)) void audio_write(const uint32_t *samples, uint32_t count) {
  for (uint32_t i = 0; i < count; i++) {
    while ((AUDIO->SR & 8u) != 0) {
    }
    AUDIO->DR = samples[i];
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
  audio_configure(route(gpio_read()));
  for (;;) {
    audio_write(silence, 2);
    gpio_set((uint16_t)ticks);
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, systick_handler,
};
