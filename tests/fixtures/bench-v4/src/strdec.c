/* SPDX-License-Identifier: Apache-2.0 */
/* Suite-v4 string-decoding fixture: messages stored encoded and decoded at run time just before they are printed.
 * VARIANT 1 (x86-64) uses a rolling-key XOR, VARIANT 2 (AArch64) a position-shifted 64-entry alphabet. Each variant
 * has three call sites; a task asks what one of them prints. Built with -DHOST_MAIN, main() prints what each call
 * site prints; derive-truth.py takes the truths from there. The encoded bytes were produced once by the encoders
 * that are the inverses of the decoders below. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define NOINLINE __attribute__((noinline))

#if VARIANT == 1 || defined(HOST_MAIN)
static const uint8_t MESSAGE_CALIBRATION[42] = {
    0x4f, 0xd2, 0x11, 0x17, 0x13, 0x81, 0x0f, 0xb3, 0x7d, 0x73, 0xe6, 0xde, 0x4e, 0xda, 0x6b, 0xe1, 0xd3, 0x49, 0x9f, 0xc0, 0x7d,
    0x61, 0x03, 0x65, 0x3c, 0x6c, 0x47, 0xa9, 0xff, 0xe0, 0x4c, 0x4d, 0x51, 0xb7, 0x92, 0xad, 0x0f, 0xbe, 0xce, 0x04, 0x7f, 0x57,
};
static const uint8_t MESSAGE_RESTORED[34] = {
    0x32, 0xa1, 0xa6, 0x56, 0x47, 0x12, 0x8f, 0x03, 0x50, 0x2f, 0x2c, 0xbf, 0x7f, 0x85, 0x15, 0xb3, 0xae,
    0x92, 0x1f, 0xdb, 0x95, 0x46, 0xcc, 0xf8, 0xa4, 0x20, 0x76, 0xda, 0xdb, 0x21, 0x23, 0x0b, 0x85, 0xb3,
};
static const uint8_t MESSAGE_LOW_POWER[23] = {
    0x4f, 0x73, 0x49, 0xbb, 0x50, 0x98, 0x8b, 0x45, 0xd2, 0x61, 0x8a, 0x59,
    0x9a, 0x91, 0xf2, 0xc5, 0xaf, 0x5f, 0xbd, 0xc3, 0x4d, 0x85, 0xe0,
};

NOINLINE char *decode_rolling(char *out, const uint8_t *in, size_t length, uint8_t key) {
  uint8_t k = key;
  for (size_t i = 0; i < length; i++) {
    out[i] = (char)(in[i] ^ k);
    k = (uint8_t)((uint8_t)(k * 37u + 11u) ^ (uint8_t)i);
  }
  out[length] = '\0';
  return out;
}

NOINLINE void report_calibration_error(void) {
  char text[64];
  puts(decode_rolling(text, MESSAGE_CALIBRATION, sizeof MESSAGE_CALIBRATION, 0x3C));
}

NOINLINE void report_restored(void) {
  char text[64];
  puts(decode_rolling(text, MESSAGE_RESTORED, sizeof MESSAGE_RESTORED, 0x51));
}

NOINLINE void report_low_power(void) {
  char text[64];
  puts(decode_rolling(text, MESSAGE_LOW_POWER, sizeof MESSAGE_LOW_POWER, 0x2A));
}
#endif

#if VARIANT == 2 || defined(HOST_MAIN)
static const char ALPHABET[65] = "q7w e3r.t9y1u-i0o5p:a2s8d4f6g_hjklzxcvbnmQWERTYUIOPASDFGHJKLZXCV";
static const uint8_t MESSAGE_SERVICE[33] = {
    0x16, 0x0b, 0x14, 0x3a, 0x2a, 0x07, 0x2e, 0x34, 0x0a, 0x0f, 0x0c, 0x15, 0x17, 0x2b, 0x34, 0x2d, 0x17,
    0x3b, 0x16, 0x08, 0x20, 0x1b, 0x1d, 0x2c, 0x31, 0x04, 0x05, 0x0c, 0x07, 0x31, 0x26, 0x25, 0x38,
};
static const uint8_t MESSAGE_DIAGNOSTIC[25] = {
    0x18, 0x15, 0x22, 0x31, 0x03, 0x33, 0x00, 0x39, 0x06, 0x23, 0x09, 0x23, 0x18,
    0x31, 0x38, 0x37, 0x00, 0x1e, 0x01, 0x29, 0x2d, 0x23, 0x30, 0x25, 0x00,
};
static const uint8_t MESSAGE_TEST_MODE[26] = {
    0x1a, 0x1b, 0x32, 0x1d, 0x2c, 0x29, 0x34, 0x34, 0x00, 0x03, 0x1c, 0x15, 0x17,
    0x03, 0x32, 0x01, 0x34, 0x3a, 0x16, 0x13, 0x22, 0x27, 0x00, 0x02, 0x2c, 0x07,
};

NOINLINE char *decode_shifted(char *out, const uint8_t *in, size_t length) {
  for (size_t i = 0; i < length; i++) {
    out[i] = ALPHABET[(in[i] - i * 7u) & 63u];
  }
  out[length] = '\0';
  return out;
}

NOINLINE void announce_service(void) {
  char text[64];
  puts(decode_shifted(text, MESSAGE_SERVICE, sizeof MESSAGE_SERVICE));
}

NOINLINE void announce_diagnostic(void) {
  char text[64];
  puts(decode_shifted(text, MESSAGE_DIAGNOSTIC, sizeof MESSAGE_DIAGNOSTIC));
}

NOINLINE void announce_test_mode(void) {
  char text[64];
  puts(decode_shifted(text, MESSAGE_TEST_MODE, sizeof MESSAGE_TEST_MODE));
}
#endif

int main(int argc, char **argv) {
  (void)argv;
#if VARIANT == 1 || defined(HOST_MAIN)
  if (argc == 1) {
    report_calibration_error();
  } else if (argc == 2) {
    report_restored();
  } else {
    report_low_power();
  }
#endif
#if VARIANT == 2 || defined(HOST_MAIN)
  if (argc == 1) {
    announce_service();
  } else if (argc == 2) {
    announce_diagnostic();
  } else {
    announce_test_mode();
  }
#endif
  return 0;
}
