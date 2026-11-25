// SPDX-License-Identifier: Apache-2.0
// A headerless Cortex-M0 application that runs from the memory it is loaded into, as a decoded update image does:
// code, constants and initialised globals all lie inside the image, and the code stores into its own globals.
//   raw-cortex-m-ramapp.bin       linked at 0x20000000 (SRAM): a writable mapping by its address alone.
//   raw-cortex-m-ramapp-lo.bin    linked at 0x01000000, an address in the code region of the Cortex-M map that
//                                 vendors also use for RAM; mapped plain it is read-only, as flash is.
//   raw-cortex-m-ramapp-lzss.bin  the -lo image LZSS-compressed (4096-byte ring, see gen-stages.py): decoded, the
//                                 stores into its globals make it writable.
// `set_mode` and `get_mode` load the address of `mode` (initially 3) from their literal pool in one basic block and
// store or read through it in the next, so on a read-only mapping the decompiler reports the store as a write to
// read-only memory and folds the read into the initial value. `tick` updates two globals in straight-line code;
// the reset handler passes `uart_puts` a string constant through its literal pool.
// The .elf files keep the symbols (the truth for tests).
#include <stdint.h>

#define UART_DR (*(volatile uint32_t *)0x40011004u)
// Keeps a pointer in a register from here on, so its literal-pool load stays in this block.
#define PIN(pointer) __asm__("" : "+r"(pointer))

int32_t mode = 3;
uint32_t counter = 0x10;
uint32_t last_value = 0x20;

__attribute__((noinline)) void set_mode(int32_t value) {
  int32_t *slot = &mode;
  PIN(slot);
  if (value < 0) {
    return;
  }
  *slot = value;
}

__attribute__((noinline)) int32_t get_mode(int32_t fallback) {
  int32_t *slot = &mode;
  PIN(slot);
  if (fallback < 0) {
    return fallback;
  }
  return *slot;
}

__attribute__((noinline)) void tick(uint32_t value) {
  counter = counter + 1;
  last_value = value;
}

__attribute__((noinline)) void uart_puts(const char *text) {
  while (*text != 0) {
    UART_DR = (uint8_t)*text++;
  }
}

__attribute__((noreturn)) void reset_handler(void) {
  uart_puts("ramapp v1");
  set_mode(5);
  for (;;) {
    tick(UART_DR);
    if ((uint32_t)get_mode(0) + counter > 0x1234u) {
      set_mode(1);
    }
    UART_DR = (uint32_t)get_mode(0);
  }
}
