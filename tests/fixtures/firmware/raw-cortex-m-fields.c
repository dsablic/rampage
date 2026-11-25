// SPDX-License-Identifier: Apache-2.0
// A headerless Cortex-M3 image whose code reaches the fields of a structure in SRAM through a base register: the
// base comes from a literal pool (or a MOVW/MOVT pair) and each access adds an immediate offset, as embedded code
// does. build-raw-cortex-m-fields.sh builds raw-cortex-m-fields.bin, a flash image at 0x08000000; `link` is at
// 0x20000100 in SRAM, which the Raw project leaves unmapped, and its `state` field at 0x2000010b.
//
// xrefs to 0x2000010b must list link_up (read, 1 byte), set_link (write), poll_link (read, its base loaded before
// a loop the access is inside) and stepped (read, its base the pool address plus 8). The negatives must not:
// redefined (the base register is overwritten before the access), on_one_path (the base is loaded on one path
// into the access only), stack_slot (SP-relative), and low_base (a base in unmapped code space).
#include <stdint.h>

struct link {
  uint32_t id;
  uint8_t mode;
  uint8_t reserved[6];
  uint8_t state; /* offset 11 */
  uint16_t count; /* offset 12 */
  uint16_t flags;
  uint32_t last;
};

extern uint32_t __stack_top;

volatile struct link link_state __attribute__((section(".ram")));

__attribute__((noinline)) int link_up(void) { return link_state.state; }

__attribute__((noinline)) void set_link(int up) {
  link_state.state = (uint8_t)up;
  link_state.mode = 1;
}

__attribute__((noinline)) void wait_tick(void) { __asm volatile("wfi"); }

/* The base is loaded once into a callee-saved register; the field is read inside the loop after a join. */
__attribute__((naked, noinline)) void poll_link(void) {
  __asm volatile("push {r4, lr}\n"
                 "ldr r4, =link_state\n"
                 "1: bl wait_tick\n"
                 "ldrb r0, [r4, #11]\n"
                 "cmp r0, #0\n"
                 "beq 1b\n"
                 "pop {r4, pc}\n"
                 ".ltorg\n");
}

/* A MOVW/MOVT base and a halfword field. */
__attribute__((naked, noinline)) int link_count(void) {
  __asm volatile("movw r1, #:lower16:link_state\n"
                 "movt r1, #:upper16:link_state\n"
                 "ldrh r0, [r1, #12]\n"
                 "bx lr\n");
}

/* The pool base plus 8, then the field at +3 from there: still `state`. */
__attribute__((naked, noinline)) int stepped(void) {
  __asm volatile("ldr r1, =link_state\n"
                 "adds r1, #8\n"
                 "ldrb r0, [r1, #3]\n"
                 "bx lr\n"
                 ".ltorg\n");
}

/* Negative: the base register is overwritten before the access. */
__attribute__((naked, noinline)) int redefined(void) {
  __asm volatile("ldr r1, =link_state\n"
                 "ldr r1, [r2]\n"
                 "ldrb r0, [r1, #11]\n"
                 "bx lr\n"
                 ".ltorg\n");
}

/* Negative: only one path into the access loads the base. */
__attribute__((naked, noinline)) int on_one_path(int which) {
  __asm volatile("cbz r0, 2f\n"
                 "ldr r1, =link_state\n"
                 "2: ldrb r0, [r1, #11]\n"
                 "bx lr\n"
                 ".ltorg\n");
}

/* Negative: stack slots, directly and through a copy of SP. */
__attribute__((naked, noinline)) int stack_slot(int value) {
  __asm volatile("sub sp, #16\n"
                 "strb r0, [sp, #11]\n"
                 "add r1, sp, #0\n"
                 "ldrb r0, [r1, #11]\n"
                 "add sp, #16\n"
                 "bx lr\n");
}

/* Negative: a base in unmapped code space is no structure in RAM. */
__attribute__((naked, noinline)) int low_base(void) {
  __asm volatile("ldr r1, =0x00000400\n"
                 "ldrb r0, [r1, #11]\n"
                 "bx lr\n"
                 ".ltorg\n");
}

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void reset_handler(void) {
  set_link(1);
  poll_link();
  (void)link_count();
  (void)stepped();
  (void)redefined();
  (void)on_one_path(link_up());
  (void)stack_slot(2);
  (void)low_base();
  for (;;) {
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, default_handler, default_handler,
    default_handler, 0,               0,               0,               0,               default_handler,
    default_handler, 0,               default_handler, default_handler,
};
