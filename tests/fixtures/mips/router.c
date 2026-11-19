// SPDX-License-Identifier: Apache-2.0
// A small router-style userland program for the MIPS fixtures (see build-mips.sh): libc imports reached through
// the GOT, strings referenced from code, a table-driven CRC-32 (constants for find_crypto), an XOR string decoder
// and small pure functions for evaluate_function. The same source builds for mips, mipsel and mips64, dynamic and
// static, so results compare across them.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t crc_table[256];

__attribute__((noinline)) void crc32_init(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++) {
      c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
    }
    crc_table[i] = c;
  }
}

__attribute__((noinline)) uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t length) {
  crc = ~crc;
  while (length--) {
    crc = crc_table[(crc ^ *data++) & 0xff] ^ (crc >> 8);
  }
  return ~crc;
}

/* Pure helpers for evaluate_function. */
__attribute__((noinline)) int scale_add(int a, int b, int c) { return a * 3 + b - c; }

__attribute__((noinline)) uint32_t checksum16(const uint8_t *data, int length) {
  uint32_t sum = 0;
  for (int i = 0; i + 1 < length; i += 2) {
    sum += (uint32_t)(data[i] << 8 | data[i + 1]);
  }
  if (length & 1) {
    sum += (uint32_t)data[length - 1] << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return ~sum & 0xffff;
}

/* An obfuscated admin password, XOR 0x5a. */
static const uint8_t secret[] = {0x3b, 0x3e, 0x37, 0x33, 0x34, 0x68, 0x6a, 0x68, 0x6b, 0x00};

__attribute__((noinline)) void decode_secret(char *out, size_t size) {
  size_t i = 0;
  for (; i + 1 < size && secret[i]; i++) {
    out[i] = (char)(secret[i] ^ 0x5a);
  }
  out[i] = 0;
}

__attribute__((noinline)) int check_login(const char *user, const char *password) {
  char expected[16];
  decode_secret(expected, sizeof expected);
  if (strcmp(user, "admin") != 0) {
    return 0;
  }
  return strcmp(password, expected) == 0;
}

__attribute__((noinline)) int handle_request(const char *path) {
  if (strncmp(path, "/cgi-bin/", 9) == 0) {
    printf("cgi request: %s\n", path + 9);
    return 200;
  }
  if (strcmp(path, "/firmware/upgrade") == 0) {
    puts("firmware upgrade requested");
    return 403;
  }
  fprintf(stderr, "not found: %s\n", path);
  return 404;
}

int main(int argc, char **argv) {
  crc32_init();
  const char *user = getenv("ROUTER_USER");
  const char *password = getenv("ROUTER_PASSWORD");
  if (user && password && check_login(user, password)) {
    puts("login ok");
  }
  for (int i = 1; i < argc; i++) {
    uint32_t crc = crc32_update(0, (const uint8_t *)argv[i], strlen(argv[i]));
    printf("%s crc=%08x status=%d\n", argv[i], crc, handle_request(argv[i]));
  }
  return scale_add(argc, 2, 1) == 0 ? (int)checksum16((const uint8_t *)argv[0], 4) : 0;
}
