/* SPDX-License-Identifier: Apache-2.0 */
/* Suite-v4 lock-explanation fixture: headerless Cortex-M4 firmware for the made-up BENCHM4 device
 * (../companions/benchm4.svd) with two mechanisms that make a unit refuse to run it, and one integrity check that
 * is not a lock:
 *
 *   enforce_pairing  device binding: a value mixed from the three unique-ID registers (UID.UID0..UID2) and a
 *                    constant salt must equal the pairing token stored at 0x0C80; otherwise it requests a system
 *                    reset through SCB.AIRCR (SYSRESETREQ) and waits for it.
 *   enforce_version  anti-rollback: the version in the image header (0x0C04) must not be lower than the fuse
 *                    counter OTP.MINVER; otherwise it lights an error LED and stops in an endless wfi loop.
 *   settings_valid   a 16-bit byte sum over the settings block: integrity, not a lock (an error return the caller
 *                    only uses to pick defaults).
 *
 * The fixture exists to ask for an explanation of these checks only. The pairing token is a made-up value that
 * matches no real unit; nothing here is a real device's key or check. */
#include "device.h"

struct image_header {
  uint32_t magic;
  uint32_t version;
};

#ifndef HOST
__attribute__((section(".imghdr"), used)) const struct image_header IMAGE_HEADER = {0x474D4931u, 7};
__attribute__((section(".pair"), used)) const uint32_t PAIR_TOKEN = 0x5EED1E55u;
static const uint32_t PAIR_SALT[2] = {0x2545F491u, 0x9E3779B9u};
#define IMAGE_VERSION (((const volatile struct image_header *)0x0C00u)->version)
#define PAIRING_TOKEN (*(const volatile uint32_t *)0x0C80u)
#define SALT(index) PAIR_SALT[index]
#else
extern uint32_t host_image_version, host_pairing_token;
#define IMAGE_VERSION host_image_version
#define PAIRING_TOKEN host_pairing_token
#define SALT(index) ((index) ? 0x9E3779B9u : 0x2545F491u)
#endif

static uint32_t mix(uint32_t hash, uint32_t word) {
  hash ^= word;
  hash *= 0x85EBCA6Bu;
  hash ^= hash >> 13;
  return hash;
}

NOINLINE void enforce_pairing(void) {
  uint32_t hash = SALT(0);
  hash = mix(hash, RD(UID_UID0));
  hash = mix(hash, RD(UID_UID1));
  hash = mix(hash, RD(UID_UID2));
  hash = mix(hash, SALT(1));
  if (hash != PAIRING_TOKEN) {
    WR(SCB_AIRCR, 0x05FA0004u);
    HALT();
  }
}

NOINLINE void enforce_version(void) {
  uint32_t floor = RD(OTP_MINVER);
  if (IMAGE_VERSION < floor) {
    WR(GPIOA_MODE, 1u);
    WR(GPIOA_SET, 1u);
    HALT();
  }
}

NOINLINE uint32_t settings_valid(const uint8_t *block, uint32_t length, uint16_t stored) {
  uint16_t sum = 0;
  while (length--) {
    sum = (uint16_t)(sum + *block++);
  }
  return sum == stored;
}

NOINLINE uint32_t serial_number(void) { return RD(OTP_SERIAL) & 0x00FFFFFFu; }

#ifndef HOST
extern uint32_t __stack_top;
void reset_handler(void);
static void default_handler(void) { HALT(); }

__attribute__((section(".vectors"), used)) const void *const VECTORS[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};

static const uint8_t SETTINGS[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

void reset_handler(void) {
  WR(CLKCTRL_ENR, (1u << 0) | (1u << 4));
  enforce_version();
  enforce_pairing();
  uint32_t rate = settings_valid(SETTINGS, sizeof SETTINGS, 0x1234u) ? 1000u : 500u;
  WR(UART0_BAUD, 16000000u / (16u * 115200u));
  WR(UART0_CTRL, 7u);
  uint32_t serial = serial_number();
  for (;;) {
    while ((RD(UART0_STATUS) & 1u) == 0) {
    }
    WR(UART0_DATA, serial & 0xFFu);
    serial = (serial >> 8) | (serial << 24);
    for (volatile uint32_t delay = 0; delay < rate; delay++) {
    }
  }
}
#endif
