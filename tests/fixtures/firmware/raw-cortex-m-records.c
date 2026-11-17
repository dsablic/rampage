// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M4 firmware shaped like a small RTOS application, for Raw discovery, xrefs, find_main and
// integrity seeding. Built without movw/movt, so addresses come from literal pools as in GCC-built firmware.
//   - reset_handler copies .data, zeroes .bss, walks a table of init hooks (hidden from the compiler, so the walk
//     stays a loop of indirect calls) and calls main, which never returns: it registers a task, runs a CRC and
//     starts the scheduler (PendSV and svc #0).
//   - worker_task is named only by the entry field of a task-definition record that main passes by address, as
//     RTOS thread definitions are; nothing calls it or loads its address directly.
//   - the worker reports errors through strings loaded three ways: a literal-pool word ("image sum err"), a
//     movw/movt pair ("HEADER ERROR") and adr from a string placed in the code ("COMPARE ERROR").
//   - crc32_update (reflected polynomial 0xedb88320, loaded from a literal pool) is called only through a pointer
//     stored with a bias, so discovery cannot reach it; integrity_checks finds it from its polynomial literal.
// raw-cortex-m-records.elf keeps the symbols (the truth for tests); raw-cortex-m-records.bin is the flash image at
// 0x08000000.
#include <stdint.h>

#define UART_DR (*(volatile uint32_t *)0x40011004u)
#define SCB_ICSR (*(volatile uint32_t *)0xe000ed04u)
#define CRC_BIAS 0x00100000u

extern uint32_t __stack_top;
extern uint32_t __data_load[], __data_start[], __data_end[];
extern uint32_t __bss_start[], __bss_end[];

volatile uint32_t ready_flags = 1;
volatile uint32_t expected_sum = 0x1234;
uint8_t image[64];
volatile uint32_t task_slot;
volatile uint32_t crc_result;
volatile uint32_t ticks;

__attribute__((noinline)) void uart_puts(const char *text) {
  while (*text) {
    UART_DR = (uint8_t)*text++;
  }
}

__attribute__((noinline)) void progress_tick(void) { ticks = ticks + 1; }

__attribute__((noinline)) int check_sum(void) {
  uint32_t sum = 0;
  for (uint32_t i = 0; i < sizeof image; i++) {
    sum += image[i];
  }
  if (sum != expected_sum) {
    uart_puts("image sum err");
    return 0;
  }
  return 1;
}

__attribute__((used)) const char header_error[] = "HEADER ERROR";

__attribute__((noinline)) void report_header(void) {
  const char *text;
  __asm__("movw %0, #:lower16:header_error\n\tmovt %0, #:upper16:header_error" : "=r"(text));
  uart_puts(text);
}

// The string sits in the code right after the function, so adr can form its address.
__attribute__((naked, noinline)) const char *compare_error_text(void) {
  __asm__("adr r0, 1f\n\tbx lr\n\t.p2align 2\n1:\n\t.asciz \"COMPARE ERROR\"\n\t.p2align 1\n");
}

__attribute__((noreturn)) void worker_task(void *argument) {
  (void)argument;
  for (;;) {
    if (!check_sum()) {
      report_header();
      uart_puts(compare_error_text());
    }
    progress_tick();
  }
}

struct task_definition {
  const char *name;
  void (*entry)(void *);
  uint32_t stack_size;
  uint32_t priority;
};

const struct task_definition worker_definition = {"worker", worker_task, 1024, 3};

__attribute__((noinline)) void start_task(const struct task_definition *definition) {
  task_slot = (uint32_t)definition->entry;
  progress_tick();
}

/* Bitwise CRC-32 (IEEE 802.3, reflected polynomial 0xedb88320). */
__attribute__((noinline)) uint32_t crc32_update(uint32_t crc, const uint8_t *data, uint32_t length) {
  crc = ~crc;
  while (length--) {
    crc ^= *data++;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
  }
  progress_tick();
  return ~crc;
}

typedef uint32_t (*crc_routine)(uint32_t, const uint8_t *, uint32_t);

// The routine's address plus a bias, read from memory at run time: no word in the image points at it.
const volatile uintptr_t crc_entry_biased = (uintptr_t)crc32_update + CRC_BIAS;

__attribute__((noreturn, noinline)) void start_scheduler(void) {
  SCB_ICSR = 1u << 28;
  __asm__ volatile("svc #0");
  for (;;) {
  }
}

__attribute__((noinline)) int main(void) {
  start_task(&worker_definition);
  uintptr_t entry = crc_entry_biased;
  crc_result = ((crc_routine)(entry - CRC_BIAS))(0, image, sizeof image);
  start_scheduler();
}

__attribute__((noinline)) void init_clock(void) {
  progress_tick();
  ready_flags |= 2;
}

__attribute__((noinline)) void init_uart(void) {
  progress_tick();
  UART_DR = 0;
}

__attribute__((noinline)) void init_timer(void) {
  progress_tick();
  ready_flags |= 4;
}

typedef void (*init_hook)(void);

const init_hook init_hooks[] = {init_clock, init_uart, init_timer, 0};

__attribute__((noreturn)) void reset_handler(void) {
  uint32_t *load = __data_load;
  for (uint32_t *run = __data_start; run < __data_end;) {
    *run++ = *load++;
  }
  for (uint32_t *run = __bss_start; run < __bss_end;) {
    *run++ = 0;
  }
  for (const init_hook *hook = init_hooks;; hook++) {
    __asm__("" : "+r"(hook));
    if (!*hook) {
      break;
    }
    (*hook)();
  }
  main();
  for (;;) {
  }
}

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
