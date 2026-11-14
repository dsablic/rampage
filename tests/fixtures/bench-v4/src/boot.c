/* SPDX-License-Identifier: Apache-2.0 */
/* Suite-v4 firmware-patching fixture: a headerless Cortex-M4 image whose boot code checks two integrity fields
 * before it starts the application:
 *
 *   0x0800..0x083F  configuration block (struct config)
 *   0x0840          CRC-16/CCITT-FALSE of 0x0800..0x083F, 16-bit little-endian
 *   0x1000..0x13FB  application (code, then 0xFF fill)
 *   0x13FC          CRC-32 (IEEE, reflected 0xEDB88320) of 0x0800..0x13FB, 32-bit little-endian; it covers the
 *                   configuration block and its CRC, so changing the configuration changes both values
 *
 * build.sh links with both fields zero and writes the real values into the flat image. A failed check is not a
 * lock: it detects damage and the image's owner can recompute it. The host harness (-DHOST) compiles the checksum
 * routines only (derive-truth.py runs them on the patched images). */
#include <stddef.h>

#include "device.h"

#define CONFIG_BASE 0x0800u
#define CONFIG_SIZE 0x40u
#define CONFIG_CRC 0x0840u
#define APP_BASE 0x1000u
#define APP_CRC 0x13FCu

NOINLINE uint16_t crc16_ccitt(const uint8_t *data, uint32_t length) {
  uint16_t crc = 0xFFFFu;
  while (length--) {
    crc ^= (uint16_t)(*data++) << 8;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u) : (uint16_t)(crc << 1);
    }
  }
  return crc;
}

NOINLINE uint32_t crc32_ieee(const uint8_t *data, uint32_t length) {
  uint32_t crc = 0xFFFFFFFFu;
  while (length--) {
    crc ^= *data++;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
  }
  return ~crc;
}

#ifndef HOST
struct config {
  uint32_t magic;
  uint32_t version;
  uint32_t baud;
  uint8_t flags;
  uint8_t channel;
  uint16_t timeout_ms;
  char label[16];
  uint8_t reserved[32];
};

__attribute__((section(".cfg"), used)) const struct config CONFIG = {
    0x31474643u, 3, 115200, 0x01, 4, 250, "BENCH-UNIT-0001", {0},
};
__attribute__((section(".cfg_crc"), used)) const uint16_t CONFIG_CHECK = 0;
__attribute__((section(".app_crc"), used)) const uint32_t APP_CHECK = 0;

extern uint32_t __stack_top;
void reset_handler(void);
static void default_handler(void) { HALT(); }

__attribute__((section(".vectors"), used)) const void *const VECTORS[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};

NOINLINE static void blink_error(uint32_t code) {
  WR(GPIOA_MODE, 0xFu);
  WR(GPIOA_OUT, code);
  HALT();
}

NOINLINE static uint32_t config_valid(void) {
  return crc16_ccitt((const uint8_t *)CONFIG_BASE, CONFIG_SIZE) == *(const volatile uint16_t *)CONFIG_CRC;
}

NOINLINE static uint32_t app_valid(void) {
  return crc32_ieee((const uint8_t *)CONFIG_BASE, APP_CRC - CONFIG_BASE) == *(const volatile uint32_t *)APP_CRC;
}

/* The application: it reads its settings from the configuration block. */
__attribute__((section(".app"), noinline, used)) void app_main(void) {
  const volatile struct config *config = (const volatile struct config *)CONFIG_BASE;
  WR(CLKCTRL_ENR, (1u << 0) | (1u << 4));
  WR(UART0_BAUD, 16000000u / (16u * config->baud));
  WR(UART0_CTRL, (config->flags & 2u) ? 0x0Fu : 0x07u);
  for (uint32_t index = 0; index < sizeof config->label && config->label[index]; index++) {
    while ((RD(UART0_STATUS) & 1u) == 0) {
    }
    WR(UART0_DATA, (uint32_t)config->label[index]);
  }
  for (;;) {
    WR(GPIOA_OUT, RD(GPIOA_OUT) ^ config->channel);
    for (volatile uint32_t delay = 0; delay < config->timeout_ms * 1000u; delay++) {
    }
  }
}

void reset_handler(void) {
  if (!config_valid()) {
    blink_error(1);
  }
  if (!app_valid()) {
    blink_error(2);
  }
  app_main();
}
#endif
