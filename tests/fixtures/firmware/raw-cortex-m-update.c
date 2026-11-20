// SPDX-License-Identifier: Apache-2.0
// Two versions of one headerless Cortex-M3 firmware, for diff_firmware: build-raw-cortex-m-update.sh builds this
// file as raw-cortex-m-update-v1 and, with -DV2, as raw-cortex-m-update-v2. The boot code at 0x08000000 checks a
// CRC-32 over the application region at 0x08000800 against the word stored right after it (as
// raw-cortex-m-crc.c does), then reports its version and status over a UART and runs the application.
// What v2 changes, and nothing else:
//   - the version string (fw-version 2.0.7 -> 2.1.0);
//   - a second endpoint URL, sent by report_status (which therefore changes);
//   - the CRC range: the application region grows from 0x3fc to 0x5fc bytes, so the stored CRC moves;
//   - a debugger check in reset_handler that halts when C_DEBUGEN is set (a debug lock);
//   - legacy_selftest is removed.
// Code before the unchanged functions grows or shrinks, so they move: a diff must match them as unchanged.
#include <stdint.h>

#define APP_START 0x08000800u
#ifdef V2
#define APP_SIZE 0x5fcu
#else
#define APP_SIZE 0x3fcu
#endif
#define APP_CRC (*(const volatile uint32_t *)(APP_START + APP_SIZE))
#define UART_DR (*(volatile uint32_t *)0x40011004u)
#define GPIO_OUT (*(volatile uint32_t *)0x40020014u)
#define GPIO_IN (*(volatile uint32_t *)0x40020010u)
#define DHCSR (*(volatile uint32_t *)0xe000edf0u)

extern uint32_t __stack_top;

volatile uint32_t boot_status __attribute__((section(".ram")));

#ifdef V2
const char firmware_version[] = "fw-version 2.1.0";
#else
const char firmware_version[] = "fw-version 2.0.7";
#endif
const char status_url[] = "https://api.example.com/v1/status";
#ifdef V2
const char upload_url[] = "https://telemetry.example.net/v2/upload";
#endif

__attribute__((noinline)) void uart_puts(const char *text) {
  while (*text) {
    UART_DR = (uint8_t)*text++;
  }
}

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
  uart_puts("image check failed");
  for (;;) {
  }
}

#ifndef V2
/* Drives a walking-ones pattern onto the outputs and reads it back. */
__attribute__((noinline)) int legacy_selftest(void) {
  for (uint32_t bit = 0; bit < 8; bit++) {
    GPIO_OUT = 1u << bit;
    if ((GPIO_IN & 0xffu) != (1u << bit)) {
      uart_puts("selftest failed");
      return 0;
    }
  }
  uart_puts("selftest passed");
  return 1;
}
#endif

#ifdef V2
/* Debugger detection: C_DEBUGEN in DHCSR. */
__attribute__((noinline)) int debugger_attached(void) { return DHCSR & 1u; }

__attribute__((noreturn, noinline)) void halt(void) {
  boot_status = 0xdead;
  for (;;) {
  }
}
#endif

__attribute__((noinline)) void report_status(void) {
  uart_puts("POST ");
  uart_puts(status_url);
#ifdef V2
  uart_puts("POST ");
  uart_puts(upload_url);
#endif
}

__attribute__((section(".app"), noinline)) uint32_t app_scale(uint32_t value) { return value * 5u + 3u; }

static const uint32_t app_table[8] __attribute__((section(".app.rodata"), used)) = {
    0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u, 0x55555555u, 0x66666666u, 0x77777777u, 0x88888888u,
};

/* The application: drives an output with a table-driven pattern. */
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
#ifdef V2
  if (debugger_attached()) {
    halt();
  }
#endif
  if (crc32_compute((const uint8_t *)APP_START, APP_SIZE) != APP_CRC) {
    boot_fail();
  }
  boot_status = 1;
  uart_puts(firmware_version);
#ifndef V2
  legacy_selftest();
#endif
  report_status();
  app_main();
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};

/* Placeholder the build replaces with the application's CRC-32. */
__attribute__((section(".app_crc"), used)) const uint32_t app_crc = 0xffffffffu;
