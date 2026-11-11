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
void quiet_leaf(void);

void scratch_r1(void);

uint32_t checksum_after_quiet(const uint8_t *data, uint32_t length);

uint32_t checksum_after_scratch(const uint8_t *data, uint32_t length);

__attribute__((noinline)) uint32_t unpack_field(uint32_t packed) { return (packed >> 4) & 0xfffu; }

__attribute__((noinline)) uint32_t place_field(uint32_t value) { return (value & 0xfffu) << 4; }

__attribute__((noinline)) void advance_cursor(void) {
  cursor = cursor + 1;
  CONTROL_REG = STATUS_REG | 0x100u;
}

// A supervisor-call wrapper: the status reaches the handler in r1, which the p-code of `svc` never shows, so the
// wrapper's own decompilation sees no parameter.
void sys_report(uint32_t status);

__attribute__((noinline)) void report_length(uint32_t length) {
  sys_report(length * 3u + 1u);
  last_checksum = length;
}

// A tail-call thunk and a conditional tail call into checksum.
uint32_t checksum_tail(const uint8_t *data, uint32_t length);

uint32_t checksum_if_data(const uint8_t *data, uint32_t length);

__attribute__((noinline)) uint32_t sum_through_tail(uint32_t length) { return checksum_tail(image_buffer, length) + 1u; }

__attribute__((noinline)) uint32_t sum_if_data(uint32_t length) { return checksum_if_data(image_buffer, length) + 2u; }

// The shape of musl's __syscall_ret: its input on one path, a constant on the other, after a call.
// error_slot is hand-written below, like musl's __errno_location: a computed int-shaped address.
volatile uint32_t *error_slot(void);

__attribute__((noinline)) uint32_t syscall_ret(uint32_t result) {
  if (result > 0xfffff000u) {
    *error_slot() = -result;
    return 0xffffffffu;
  }
  return result;
}

// Keeps the length in r2 across a callee that itself calls probe_status (which writes r0 and r1 only).
void probe_twice(void);

uint32_t checksum_after_probes(const uint8_t *data, uint32_t length);

// A call chain longer than the 64 callee decompilations one request may make: whether chain0's parameters are
// derived depends on how much of the chain is already locked, so it shows whether one decompilation leaks into the
// next.
__attribute__((noinline)) uint32_t chain70(uint32_t a, uint32_t b) { return a ^ b; }
#define LINK(n, next)                                                                                                \
  __attribute__((noinline)) uint32_t chain##n(uint32_t a, uint32_t b) { return chain##next(a, b) + n##u; }
LINK(69, 70) LINK(68, 69) LINK(67, 68) LINK(66, 67) LINK(65, 66) LINK(64, 65) LINK(63, 64) LINK(62, 63)
LINK(61, 62) LINK(60, 61) LINK(59, 60) LINK(58, 59) LINK(57, 58) LINK(56, 57) LINK(55, 56) LINK(54, 55)
LINK(53, 54) LINK(52, 53) LINK(51, 52) LINK(50, 51) LINK(49, 50) LINK(48, 49) LINK(47, 48) LINK(46, 47)
LINK(45, 46) LINK(44, 45) LINK(43, 44) LINK(42, 43) LINK(41, 42) LINK(40, 41) LINK(39, 40) LINK(38, 39)
LINK(37, 38) LINK(36, 37) LINK(35, 36) LINK(34, 35) LINK(33, 34) LINK(32, 33) LINK(31, 32) LINK(30, 31)
LINK(29, 30) LINK(28, 29) LINK(27, 28) LINK(26, 27) LINK(25, 26) LINK(24, 25) LINK(23, 24) LINK(22, 23)
LINK(21, 22) LINK(20, 21) LINK(19, 20) LINK(18, 19) LINK(17, 18) LINK(16, 17) LINK(15, 16) LINK(14, 15)
LINK(13, 14) LINK(12, 13) LINK(11, 12) LINK(10, 11) LINK(9, 10) LINK(8, 9) LINK(7, 8) LINK(6, 7) LINK(5, 6)
LINK(4, 5) LINK(3, 4) LINK(2, 3) LINK(1, 2) LINK(0, 1)

__attribute__((noinline)) uint32_t chain_head(uint32_t a, uint32_t b) { return chain0(a, b) + 100u; }

// Hand-written below: keeps its argument in r2 across chain54, whose callees reach chain70 exactly 16 calls down
// (the deepest the register scan follows), right after calling chain53, which is one call too deep. Whether r2
// survives must not depend on having looked at chain54 through chain53 first.
uint32_t depth_probe(const uint8_t *data);

// The hand-written functions, as file-level assembly: a caller cannot see their register use, so interprocedural
// register allocation treats them as the calling convention says rather than trusting an empty naked body.
__asm__(
    ".syntax unified\n"
    ".thumb\n"
    ".text\n"
    ".p2align 1\n"
    ".global quiet_leaf\n"
    ".type quiet_leaf, %function\n"
    ".thumb_func\n"
    "quiet_leaf:\n"
    "movs r3, #1\n"
    "bx lr\n"
    ".p2align 1\n"
    ".global scratch_r1\n"
    ".type scratch_r1, %function\n"
    ".thumb_func\n"
    "scratch_r1:\n"
    "movs r1, #0\n"
    "bx lr\n"
    ".p2align 1\n"
    ".global checksum_after_quiet\n"
    ".type checksum_after_quiet, %function\n"
    ".thumb_func\n"
    "checksum_after_quiet:\n"
    "push {r4, lr}\n"
    "mov r4, r0\n"
    "bl quiet_leaf\n"
    "mov r0, r4\n"
    "bl checksum\n"
    "pop {r4, pc}\n"
    ".p2align 1\n"
    ".global checksum_after_scratch\n"
    ".type checksum_after_scratch, %function\n"
    ".thumb_func\n"
    "checksum_after_scratch:\n"
    "push {r4, lr}\n"
    "mov r4, r0\n"
    "bl scratch_r1\n"
    "mov r0, r4\n"
    "bl checksum\n"
    "pop {r4, pc}\n"
    ".p2align 1\n"
    ".global sys_report\n"
    ".type sys_report, %function\n"
    ".thumb_func\n"
    "sys_report:\n"
    "mov r1, r0\n"
    "svc #0\n"
    "bx lr\n"
    ".p2align 1\n"
    ".global checksum_tail\n"
    ".type checksum_tail, %function\n"
    ".thumb_func\n"
    "checksum_tail:\n"
    "b.w checksum\n"
    ".p2align 1\n"
    ".global checksum_if_data\n"
    ".type checksum_if_data, %function\n"
    ".thumb_func\n"
    "checksum_if_data:\n"
    "cmp r0, #0\n"
    "bne.w checksum\n"
    "movs r0, #0\n"
    "bx lr\n"
    ".p2align 1\n"
    ".global error_slot\n"
    ".type error_slot, %function\n"
    ".thumb_func\n"
    "error_slot:\n"
    "movw r0, #0x48\n"
    "movt r0, #0x2000\n"
    "ldr r0, [r0]\n"
    "subs r0, #0x5c\n"
    "bx lr\n"
    ".p2align 1\n"
    ".global depth_probe\n"
    ".type depth_probe, %function\n"
    ".thumb_func\n"
    "depth_probe:\n"
    "push {r4, lr}\n"
    "mov r4, r0\n"
    "bl chain53\n"
    "mov r2, r4\n"
    "bl chain54\n"
    "mov r1, r2\n"
    "mov r0, r4\n"
    "bl checksum\n"
    "pop {r4, pc}\n"
    ".p2align 1\n"
    ".global probe_twice\n"
    ".type probe_twice, %function\n"
    ".thumb_func\n"
    "probe_twice:\n"
    "push {r7, lr}\n"
    "bl probe_status\n"
    "bl probe_status\n"
    "pop {r7, pc}\n"
    ".p2align 1\n"
    ".global checksum_after_probes\n"
    ".type checksum_after_probes, %function\n"
    ".thumb_func\n"
    "checksum_after_probes:\n"
    "push {r4, lr}\n"
    "mov r4, r0\n"
    "mov r2, r1\n"
    "bl probe_twice\n"
    "mov r0, r4\n"
    "mov r1, r2\n"
    "bl checksum\n"
    "pop {r4, pc}\n");

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
    report_length(length);
    last_checksum = syscall_ret(sum_through_tail(length)) + sum_if_data(length);
    boot_count = checksum_after_probes(image_buffer, length);
    boot_count = chain_head(length, last_checksum);
    last_checksum = depth_probe(image_buffer);
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};
