// SPDX-License-Identifier: Apache-2.0
// Cortex-M3 firmware kept as its static ELF32 executable (no interpreter, no dynamic section), for patching native
// firmware ELFs in place: integrity_checks fixes the application's CRC-32 as a patch to the ELF and export_image
// writes the patched ELF or a flat binary of its loaded segments. Layout (see elf-cortex-m-crc32.ld): vector table and
// boot code at 0x08000000, the .data initial values after them in flash (copied to SRAM at boot), the application at
// 0x08000800..0x08000bfc padded with 0xff, and its CRC-32 (IEEE, reflected) little-endian at 0x08000bfc, computed by
// build-elf-cortex-m-crc.sh after linking. .bss is zero-fill SRAM with no file bytes.
#include <stdint.h>

#define APP_START 0x08000800u
#define APP_SIZE 0x3fcu
#define APP_CRC (*(const volatile uint32_t *)0x08000bfcu)
#define GPIO_OUT (*(volatile uint32_t *)0x40020014u)

extern uint32_t __stack_top, __data_start, __data_end, __data_load, __bss_start, __bss_end;

/* Initialised SRAM: its initial values live in flash at the segment's load address. */
volatile uint32_t blink_period = 0x00012345u;
volatile uint32_t boot_status;

/* Bitwise CRC-32 (IEEE 802.3, reflected polynomial 0xedb88320). */
__attribute__((noinline)) uint32_t crc32_compute(const uint8_t *data, uint32_t length) {
  uint32_t crc = 0xffffffffu;
  while (length--) {
    crc ^= *data++;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
  }
  return ~crc;
}

__attribute__((noreturn, noinline)) void boot_fail(void) {
  boot_status = 0xbad;
  for (;;) {
  }
}

__attribute__((section(".app"), noinline)) uint32_t app_scale(uint32_t value) { return value * 5u + blink_period; }

static const uint32_t app_table[8] __attribute__((section(".app.rodata"), used)) = {
    0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u, 0x55555555u, 0x66666666u, 0x77777777u, 0x88888888u,
};

/* The application: blinks an output with a table-driven pattern. */
__attribute__((section(".app"), noreturn, noinline)) void app_main(void) {
  uint32_t step = 0;
  for (;;) {
    GPIO_OUT = app_scale(app_table[step & 7u]);
    step++;
  }
}

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void reset_handler(void) {
  const uint32_t *from = &__data_load;
  for (uint32_t *to = &__data_start; to < &__data_end;) {
    *to++ = *from++;
  }
  for (uint32_t *to = &__bss_start; to < &__bss_end;) {
    *to++ = 0;
  }
  if (crc32_compute((const uint8_t *)APP_START, APP_SIZE) != APP_CRC) {
    boot_fail();
  }
  boot_status = 1;
  app_main();
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};

/* Placeholder the build replaces with the application's CRC-32. */
__attribute__((section(".app_crc"), used)) const uint32_t app_crc = 0xffffffffu;
