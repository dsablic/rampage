// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M3 firmware whose boot code verifies a CRC-32 (IEEE, reflected) over its application region
// before running it, for the integrity_checks and export_image tests. Layout (see raw-cortex-m-crc.ld): boot code
// and the vector table at 0x08000000, the application at 0x08000400..0x080007fc padded with 0xff, and the
// application's CRC-32 stored little-endian at 0x080007fc. build-raw-cortex-m-crc.sh computes the CRC after linking
// and packages the image as raw binary, Intel HEX and S-records; raw-cortex-m-crc.elf keeps the symbols as truth.
#include <stdint.h>

#define APP_START 0x08000400u
#define APP_SIZE 0x3fcu
#define APP_CRC (*(const volatile uint32_t *)0x080007fcu)
#define GPIO_OUT (*(volatile uint32_t *)0x40020014u)

extern uint32_t __stack_top;

volatile uint32_t boot_status __attribute__((section(".ram")));

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

__attribute__((section(".app"), noinline)) uint32_t app_scale(uint32_t value) { return value * 5u + 3u; }

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
