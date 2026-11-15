// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M4 firmware whose startup copies a function and initialised data from flash to their run
// addresses, zeroes .bss, and then calls the copied function, for scatter-load following in Raw projects.
//   raw-cortex-m-scatter-gcc.bin    GCC-style startup: inline loops over pairs of linker symbols.
//   raw-cortex-m-scatter-table.bin  built with -DREGION_TABLE: Arm-style startup walking a table of (load, run,
//                                   size, handler) entries in flash with a copy and a zero handler.
// The copied code (.ramfunc) runs from 0x10000000; it sets VTOR to a vector table copied with it, whose SysTick
// handler is reachable only through that table. .data runs from 0x20000000 and .bss follows it. The .elf files keep
// the symbols and section addresses (the truth for tests).
#include <stdint.h>

#define UART_DR (*(volatile uint32_t *)0x40011004u)
#define SCB_VTOR (*(volatile uint32_t *)0xe000ed08u)

extern uint32_t __stack_top;
extern uint32_t __ramfunc_load[], __ramfunc_start[], __ramfunc_end[];
extern uint32_t __data_load[], __data_start[], __data_end[];
extern uint32_t __bss_start[], __bss_end[];

#define RAMFUNC __attribute__((noinline, section(".ramfunc.text")))

volatile uint32_t tick_count;
volatile uint32_t mix_state = 0x13579bdfu;
volatile uint32_t mix_table[8] = {3, 1, 4, 1, 5, 9, 2, 6};
uint32_t scratch[24];

void default_handler(void);

RAMFUNC void ram_systick_handler(void) {
  tick_count = tick_count + 1;
  UART_DR = tick_count;
}

__attribute__((section(".ramfunc.vectors"), used, aligned(128))) void (*const ram_vectors[16])(void) = {
    (void (*)(void))&__stack_top,
    default_handler, /* Reset is never taken from RAM */
    default_handler, default_handler, default_handler, default_handler, default_handler, 0, 0, 0, 0,
    default_handler, default_handler, 0, default_handler,
    ram_systick_handler, /* SysTick */
};

RAMFUNC uint32_t ram_mix(uint32_t value) {
  uint32_t state = mix_state;
  for (uint32_t i = 0; i < 8; i++) {
    state = (state << 5) ^ (state >> 3) ^ mix_table[i] ^ value;
  }
  mix_state = state;
  return state;
}

RAMFUNC void ram_main(void) {
  SCB_VTOR = (uint32_t)ram_vectors;
  for (;;) {
    UART_DR = ram_mix(scratch[tick_count & 7]);
  }
}

// Calls `target` through a register, so the address comes from a literal pool whatever region it is linked in.
static inline __attribute__((always_inline)) void far_call(void (*target)(void)) {
  __asm__("" : "+r"(target));
  target();
}

__attribute__((noinline, noreturn)) void start_main(void) {
  far_call(ram_main);
  for (;;) {
  }
}

#ifdef REGION_TABLE
// Arm scatter-load style: each entry names its load address, run address, size and the routine that fills it.
typedef void (*region_handler)(const uint32_t *load, uint32_t *run, uint32_t size);

__attribute__((noinline)) void region_copy(const uint32_t *load, uint32_t *run, uint32_t size) {
  for (; size >= 4; size -= 4) {
    *run++ = *load++;
  }
}

__attribute__((noinline)) void region_zero(const uint32_t *load, uint32_t *run, uint32_t size) {
  (void)load;
  for (; size >= 4; size -= 4) {
    *run++ = 0;
  }
}

struct region {
  const uint32_t *load;
  uint32_t *run;
  uint32_t size;
  region_handler handler;
};

// The sizes are absolute linker symbols; the loop reads the table through its linker-script bounds, so the
// compiler cannot unroll it into direct calls.
extern char __ramfunc_size[], __data_size[], __bss_size[];
extern const struct region __region_table_start[], __region_table_end[];

__attribute__((section(".region_table"), used)) const struct region region_table[] = {
    {__ramfunc_load, __ramfunc_start, (uint32_t)__ramfunc_size, region_copy},
    {__data_load, __data_start, (uint32_t)__data_size, region_copy},
    {0, __bss_start, (uint32_t)__bss_size, region_zero},
};

__attribute__((noreturn)) void reset_handler(void) {
  for (const struct region *entry = __region_table_start; entry < __region_table_end; entry++) {
    __asm__("" : : "r"(entry) : "memory");
    entry->handler(entry->load, entry->run, entry->size);
  }
  start_main();
}
#else
__attribute__((noreturn)) void reset_handler(void) {
  uint32_t *load = __ramfunc_load;
  for (uint32_t *run = __ramfunc_start; run < __ramfunc_end;) {
    *run++ = *load++;
  }
  load = __data_load;
  for (uint32_t *run = __data_start; run < __data_end;) {
    *run++ = *load++;
  }
  for (uint32_t *run = __bss_start; run < __bss_end;) {
    *run++ = 0;
  }
  start_main();
}
#endif

__attribute__((noreturn)) void default_handler(void) {
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
