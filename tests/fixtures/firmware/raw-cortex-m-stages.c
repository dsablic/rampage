// SPDX-License-Identifier: Apache-2.0
// Two-stage headerless Cortex-M3 firmware for multi-region Raw projects. Stage 1 runs from flash at 0x08000000,
// puts stage 2 into SRAM at 0x20000000 and calls it; stage 2 calls back into a flash routine. Both calls go
// through literal-pool addresses, as code linked for another region must. Stage 2's initialised data lives at
// 0x20000800 (stored at flash 0x08000800) and is written at run time.
//   raw-cortex-m-stages.bin       stage 2 stored as it runs, at flash 0x08000400; stage 1 copies it.
//   raw-cortex-m-stages-lzss.bin  built with -DSTAGE2_LZSS: flash 0x08000400 holds {encoded size, decoded size}
//                                 and an LZSS stream (4096-byte ring, see gen-stages.py) that stage 1 decodes.
// The .elf files keep the symbols (the truth for tests).
#include <stdint.h>

#define UART_DR (*(volatile uint32_t *)0x40011004u)
#define STAGE2_STORE ((const uint8_t *)0x08000400u)
#define STAGE2_DATA_STORE ((const uint8_t *)0x08000800u)

extern uint32_t __stack_top;
extern uint8_t __stage2_start[], __stage2_end[], __stage2_data_start[], __stage2_data_end[];

#define STAGE2 __attribute__((noinline, section(".stage2.text")))

volatile uint32_t stage2_counter __attribute__((section(".stage2.data"))) = 0x1234u;
volatile uint32_t stage2_limit __attribute__((section(".stage2.data"))) = 0x2000u;
volatile uint32_t boot_reason __attribute__((section(".ram")));

// Calls `target` through a register, so the address comes from a literal pool whatever region it is linked in.
static inline __attribute__((always_inline)) uint32_t far_call(uint32_t (*target)(uint32_t), uint32_t argument) {
  __asm__("" : "+r"(target));
  return target(argument);
}

__attribute__((noinline)) uint32_t flash_service(uint32_t value) {
  UART_DR = value;
  return value ^ 0x5a5a5a5au;
}

STAGE2 uint32_t stage2_mix(uint32_t a, uint32_t b) { return (a << 3) + (b ^ 0x9e3779b9u); }

STAGE2 uint32_t stage2_step(uint32_t seed) {
  uint32_t count = stage2_counter;
  stage2_counter = count + 1;
  return stage2_mix(seed, count);
}

STAGE2 uint32_t stage2_entry(uint32_t reason) {
  uint32_t value = reason;
  while (stage2_counter < stage2_limit) {
    value = far_call(flash_service, stage2_step(value));
    value = stage2_mix(value, reason);
  }
  return value;
}

__attribute__((noinline)) void copy_bytes(uint8_t *to, const uint8_t *from, uint32_t length) {
  for (uint32_t i = 0; i < length; i++) {
    to[i] = from[i];
  }
}

#ifdef STAGE2_LZSS
// LZSS with a 4096-byte ring written from 0xfee, flag bits LSB first (1 = literal), references of a 12-bit ring
// position and a length nibble + 3.
__attribute__((noinline)) void lzss_decode(uint8_t *to, const uint8_t *from, uint32_t decoded) {
  static uint8_t ring[4096] __attribute__((section(".ram")));
  uint32_t write = 0xfee, produced = 0, flags = 0, bits = 0;
  while (produced < decoded) {
    if (bits == 0) {
      flags = *from++;
      bits = 8;
    }
    if (flags & 1u) {
      uint8_t byte = *from++;
      to[produced++] = byte;
      ring[write] = byte;
      write = (write + 1) & 0xfffu;
    } else {
      uint32_t low = *from++, high = *from++;
      uint32_t read = low | ((high & 0xf0u) << 4);
      for (uint32_t length = (high & 0x0fu) + 3; length != 0 && produced < decoded; length--) {
        uint8_t byte = ring[read];
        to[produced++] = byte;
        ring[write] = byte;
        read = (read + 1) & 0xfffu;
        write = (write + 1) & 0xfffu;
      }
    }
    flags >>= 1;
    bits--;
  }
}
#endif

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void reset_handler(void) {
#ifdef STAGE2_LZSS
  const uint32_t *header = (const uint32_t *)STAGE2_STORE;
  lzss_decode(__stage2_start, STAGE2_STORE + 8, header[1]);
#else
  copy_bytes(__stage2_start, STAGE2_STORE, (uint32_t)(__stage2_end - __stage2_start));
#endif
  copy_bytes(__stage2_data_start, STAGE2_DATA_STORE, (uint32_t)(__stage2_data_end - __stage2_data_start));
  boot_reason = far_call(stage2_entry, 1);
  for (;;) {
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,
    reset_handler,
    default_handler, /* NMI */
    default_handler, /* HardFault */
    default_handler, /* MemManage */
    default_handler, /* BusFault */
    default_handler, /* UsageFault */
    0,
    0,
    0,
    0,
    default_handler, /* SVCall */
    default_handler, /* DebugMonitor */
    0,
    default_handler, /* PendSV */
    default_handler, /* SysTick */
};
