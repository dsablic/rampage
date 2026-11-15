// SPDX-License-Identifier: Apache-2.0
// Cortex-M3 firmware kept as its static ELF32 executable whose boot code verifies a configuration block with a
// table-less CRC-16/ARC (reflected polynomial 0xa001). Built at -Os, the loop forms the polynomial with one movw and
// no movt, so no 32-bit literal or movw/movt pair names it: integrity_checks must recognise the 16-bit immediate.
// Layout (see elf-cortex-m-crc16.ld): vector table and boot code at 0x08000000, the configuration block at
// 0x08000c00 with its CRC-16 little-endian in its last halfword, computed by build-elf-cortex-m-crc.sh after linking.
// The block covers 66 bytes: integrity_checks considers a 16-bit value only after a range of at least 64.
#include <stdint.h>

#define UART_BAUD (*(volatile uint32_t *)0x40011008u)

extern uint32_t __stack_top;

struct config {
  uint32_t magic;
  uint32_t baud;
  uint8_t label[58];
  uint16_t crc;
};

/* Placeholder CRC the build replaces. */
__attribute__((section(".config"), used)) const struct config device_config = {
    0x47464e43u, 115200u, "fixture configuration: owner-editable settings, revision", 0xffffu,
};

volatile uint32_t boot_status;

/* Bitwise CRC-16/ARC: reflected 0x8005, initial value 0, no final XOR. */
__attribute__((noinline)) uint16_t crc16_compute(const uint8_t *data, uint32_t length) {
  uint16_t crc = 0;
  while (length--) {
    crc ^= *data++;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc & 1u) ? (uint16_t)((crc >> 1) ^ 0xa001u) : (uint16_t)(crc >> 1);
    }
  }
  return crc;
}

__attribute__((noreturn, noinline)) void boot_fail(void) {
  boot_status = 0xbad;
  for (;;) {
  }
}

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void reset_handler(void) {
  const struct config *config = &device_config;
  if (crc16_compute((const uint8_t *)config, __builtin_offsetof(struct config, crc)) != config->crc) {
    boot_fail();
  }
  UART_BAUD = config->baud;
  boot_status = 1;
  for (;;) {
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};
