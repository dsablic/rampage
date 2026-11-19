// SPDX-License-Identifier: Apache-2.0
// A bare-metal MIPS32 boot ROM for the Raw fixtures (see build-mips.sh and boot.ld): the reset vector at
// 0xbfc00000 (kseg1, uncached) sets the stack and jumps to C, which prints a banner on a 16550-style UART,
// verifies a CRC-32 over an image header's payload and either boots it or loops on the error. Non-PIC, no $gp.
#include <stdint.h>

#define UART_BASE 0xb8000000u
#define UART_THR (*(volatile uint8_t *)(UART_BASE + 0x00))
#define UART_LSR (*(volatile uint8_t *)(UART_BASE + 0x14))
#define IMAGE_BASE 0xbf020000u

struct image_header {
  uint32_t magic;
  uint32_t length;
  uint32_t crc;
  uint32_t entry;
};

__asm__(".section .reset,\"ax\",@progbits\n"
        ".set noreorder\n"
        ".globl _reset\n"
        "_reset:\n"
        "  lui $sp, 0x8001\n"
        "  la $t0, boot_main\n"
        "  jr $t0\n"
        "  nop\n"
        ".set reorder\n"
        ".text\n");

__attribute__((noinline)) void uart_putc(char c) {
  while ((UART_LSR & 0x20) == 0) {
  }
  UART_THR = (uint8_t)c;
}

__attribute__((noinline)) void uart_puts(const char *s) {
  while (*s) {
    uart_putc(*s++);
  }
}

__attribute__((noinline)) uint32_t crc32_bitwise(const uint8_t *data, uint32_t length) {
  uint32_t crc = 0xffffffffu;
  while (length--) {
    crc ^= *data++;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
  }
  return ~crc;
}

__attribute__((noinline)) uint32_t mix(uint32_t a, uint32_t b) { return (a << 5) + (b >> 3) + 0x1234u; }

__attribute__((noreturn, noinline)) void boot_fail(const char *why) {
  uart_puts("boot failed: ");
  uart_puts(why);
  for (;;) {
  }
}

__attribute__((noreturn)) void boot_main(void) {
  const struct image_header *header = (const struct image_header *)IMAGE_BASE;
  uart_puts("MIPS boot ROM v1.2\r\n");
  if (header->magic != 0x27051956u) {
    boot_fail("bad image magic\r\n");
  }
  if (crc32_bitwise((const uint8_t *)(header + 1), header->length) != header->crc) {
    boot_fail("image CRC mismatch\r\n");
  }
  uart_puts("booting image\r\n");
  void (*entry)(uint32_t) = (void (*)(uint32_t))header->entry;
  entry(mix(header->length, header->crc));
  boot_fail("image returned\r\n");
}
