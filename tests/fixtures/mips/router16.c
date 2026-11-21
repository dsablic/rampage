// SPDX-License-Identifier: Apache-2.0
// router.c's shape built as MIPS16e (see build-mips16.sh): most functions are MIPS16e, as OpenWrt builds its
// packages, and the `nomips16` ones are MIPS32, so calls cross between the two instruction sets in both directions
// (jalx, or jalr through a GOT entry whose low bit selects the mode). A constructor runs from DT_INIT_ARRAY.
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

__attribute__((noinline, nomips16)) uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t length) {
  crc = ~crc;
  while (length--) {
    crc = crc_table[(crc ^ *data++) & 0xff] ^ (crc >> 8);
  }
  return ~crc;
}

__attribute__((noinline)) int scale_add(int a, int b, int c) { return a * 3 + b - c; }

__attribute__((noinline, nomips16)) int scale_twice(int a) { return scale_add(a, a, 1) * 2; }

static const char *const words[] = {"alpha", "beta", "gamma"};

static int ready;

__attribute__((constructor, noinline)) static void setup(void) { ready = 1; }

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
  for (int i = 1; i < argc; i++) {
    uint32_t crc = crc32_update(0, (const uint8_t *)argv[i], strlen(argv[i]));
    printf("%s crc=%08x status=%d %s\n", argv[i], crc, handle_request(argv[i]), words[i % 3]);
  }
  return scale_twice(argc) + ready;
}
