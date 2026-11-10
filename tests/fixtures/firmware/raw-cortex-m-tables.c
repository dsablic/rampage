// SPDX-License-Identifier: Apache-2.0
// Headerless Cortex-M0 firmware whose functions are mostly reached through tables of code pointers, for
// `raw.pointer_tables`: a command table of {name, handler} pairs (stride 8), a state-handler array (stride 4), a
// callback table with an empty slot, and decoys that must not seed anything: a string-pointer array with odd
// string addresses, a table of odd constants inside the image that point at strings, and a switch whose clang
// ARMv6-M jump table holds Thumb case-label addresses. The vector table is read separately (`vector_table`).
// raw-cortex-m-tables.elf keeps the symbols (the truth for tests); raw-cortex-m-tables.bin is its flash image.
#include <stdint.h>

#define UART_DR (*(volatile uint32_t *)0x40011004u)
#define UART_SR (*(volatile uint32_t *)0x40011000u)

extern uint32_t __stack_top;

volatile uint32_t ticks __attribute__((section(".ram")));
volatile uint32_t state __attribute__((section(".ram")));
volatile uint32_t sink __attribute__((section(".ram")));

__attribute__((noinline)) void uart_putc(char c) {
  while ((UART_SR & 0x80u) == 0) {
  }
  UART_DR = (uint32_t)(uint8_t)c;
}

__attribute__((noinline)) void uart_puts(const char *text) {
  while (*text) {
    uart_putc(*text++);
  }
}

/* Reached only through the command table. */
__attribute__((noinline)) int cmd_help(const char *args) {
  uart_puts("help: h s v r");
  return args[0];
}
__attribute__((noinline)) int cmd_status(const char *args) {
  uart_puts(args);
  uart_puts("status ok");
  return 2;
}
__attribute__((noinline)) int cmd_version(const char *args) {
  (void)args;
  uart_puts("fixture tables v1");
  return 3;
}
__attribute__((noinline)) int cmd_reboot(const char *args) {
  sink = (uint32_t)args[1];
  return 4;
}

struct command {
  const char *name;
  int (*handler)(const char *);
};

static const struct command COMMANDS[] = {
    {"help", cmd_help},
    {"status", cmd_status},
    {"version", cmd_version},
    {"reboot", cmd_reboot},
};

/* Reached only through the state-handler array; two are leaves. */
__attribute__((noinline)) void state_idle(void) { state = 1; }
__attribute__((noinline)) void state_run(void) {
  uart_puts("run");
  state = 2;
}
__attribute__((noinline)) void state_stop(void) { state = 0; }
__attribute__((noinline)) void state_fault(void) {
  uart_puts("fault");
  state = 3;
}

static void (*const STATES[])(void) = {state_idle, state_run, state_stop, state_fault};

/* Reached only through the callback table, which has an empty slot. */
__attribute__((noinline)) void on_tick(void) {
  ticks = ticks + 1;
  uart_putc('.');
}
__attribute__((noinline)) void on_rx(void) { uart_puts("rx"); }
__attribute__((noinline)) void on_tx(void) { uart_puts("tx"); }

static void (*const CALLBACKS[])(void) = {on_tick, 0, on_rx, on_tx};

/* Decoys: string pointers (some odd) and odd constants that land inside the image. */
static const char *const NAMES[] = {"a", "bc", "def", "ghij", "k", "lm", "nop", "qrst"};
static const uint32_t MAGIC[] = {0x08000201u, 0x08000203u, 0x08000205u, 0x08000207u};

__attribute__((noinline)) uint32_t classify(uint32_t value) {
  switch (value) {
  case 0:
    return ticks + 3;
  case 1:
    return state * 7;
  case 2:
    return sink ^ 0x55u;
  case 3:
    return ticks - state;
  case 4:
    return 0x1234u;
  case 5:
    return sink + 9;
  default:
    return 0;
  }
}

int run_command(const char *line) {
  for (uint32_t i = 0; i < sizeof COMMANDS / sizeof COMMANDS[0]; i++) {
    if (COMMANDS[i].name[0] == line[0]) {
      return COMMANDS[i].handler(line);
    }
  }
  return -1;
}

void systick_handler(void) {
  void (*callback)(void) = CALLBACKS[ticks & 3u];
  if (callback) {
    callback();
  }
}

__attribute__((noreturn)) void default_handler(void) {
  for (;;) {
  }
}

__attribute__((noreturn)) void reset_handler(void) {
  for (;;) {
    STATES[state & 3u]();
    sink = (uint32_t)run_command(NAMES[ticks & 7u]) + MAGIC[ticks & 3u] + classify(ticks);
  }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,    reset_handler,   default_handler, default_handler, 0, 0, 0, 0, 0, 0, 0,
    default_handler, 0,               0,               default_handler, systick_handler,
};
