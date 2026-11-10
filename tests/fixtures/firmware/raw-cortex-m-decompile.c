// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M3 firmware for decompiler accuracy on the Raw profile. Built without movw/movt so addresses
// come from literal pools, as GCC-built firmware does. raw-cortex-m-decompile.elf keeps the symbols (the truth for
// tests); raw-cortex-m-decompile.bin is its flash image at 0x08000000.
//   - verify_image keeps its length in r2 across a call to probe_status, which leaves r2 alone, and passes it to
//     checksum(data, length); checksum_after_quiet does the same with r1 itself.
//   - unpack_field shifts and masks a packed register field.
//   - RAM globals and a peripheral register are reached through literal-pool words.
#include <stdint.h>

#define STATUS_REG (*(volatile uint32_t *)0x40021000u)
#define CONTROL_REG (*(volatile uint32_t *)0x40021004u)

extern uint32_t __stack_top;

volatile uint32_t boot_count __attribute__((section(".ram")));
volatile uint32_t last_checksum __attribute__((section(".ram")));
uint32_t *volatile cursor __attribute__((section(".ram")));
uint8_t image_buffer[64] __attribute__((section(".ram")));

__attribute__((noinline)) uint32_t checksum(const uint8_t *data, uint32_t length) {
  uint32_t sum = 0;
  for (uint32_t i = 0; i < length; i++) {
    sum = (sum << 5) + sum + data[i];
  }
  return sum;
}

// A leaf that only touches r0: under interprocedural register allocation the caller may keep r1 live across it.
__attribute__((noinline)) void probe_status(void) { boot_count = boot_count + 1; }

__attribute__((noinline)) uint32_t verify_image(uint32_t length) {
  probe_status();
  uint32_t sum = checksum(image_buffer, length);
  last_checksum = sum;
  return sum;
}

// Hand-written, so register use is exact: quiet_leaf writes only r3 and scratch_r1 overwrites r1. Each caller keeps
// its length argument in r1 across one of them; only across quiet_leaf does it reach checksum.
__attribute__((naked, noinline)) void quiet_leaf(void) { __asm volatile("movs r3, #1\n\tbx lr"); }

__attribute__((naked, noinline)) void scratch_r1(void) { __asm volatile("movs r1, #0\n\tbx lr"); }

__attribute__((naked, noinline)) uint32_t checksum_after_quiet(const uint8_t *data, uint32_t length) {
  __asm volatile("push {r4, lr}\n\tmov r4, r0\n\tbl quiet_leaf\n\tmov r0, r4\n\tbl checksum\n\tpop {r4, pc}");
}

__attribute__((naked, noinline)) uint32_t checksum_after_scratch(const uint8_t *data, uint32_t length) {
  __asm volatile("push {r4, lr}\n\tmov r4, r0\n\tbl scratch_r1\n\tmov r0, r4\n\tbl checksum\n\tpop {r4, pc}");
}

__attribute__((noinline)) uint32_t unpack_field(uint32_t packed) { return (packed >> 4) & 0xfffu; }

__attribute__((noinline)) uint32_t place_field(uint32_t value) { return (value & 0xfffu) << 4; }

__attribute__((noinline)) void advance_cursor(void) {
  cursor = cursor + 1;
  CONTROL_REG = STATUS_REG | 0x100u;
}

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void reset_handler(void) {
  cursor = (uint32_t *)image_buffer;
  for (;;) {
    uint32_t length = unpack_field(STATUS_REG);
    CONTROL_REG = place_field(verify_image(length));
    last_checksum = checksum_after_quiet(image_buffer, length);
    boot_count = checksum_after_scratch(image_buffer, length);
    advance_cursor();
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};
