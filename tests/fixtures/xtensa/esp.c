// SPDX-License-Identifier: Apache-2.0
// A small ESP32/ESP8266-style application for the Xtensa fixtures (see build.sh). It links nothing but itself: no
// libc, libgcc, HAL or ESP-IDF code. The startup chain has ESP-IDF's shape (call_start_cpu0 -> start_cpu0 -> a
// "main" task created through a function pointer -> main_task, which logs around its call to app_main), ROM
// functions are called at their fixed ROM addresses (-mlongcalls keeps those as l32r + callx), strings and
// constants are reached through l32r literal pools, and there is a bitwise CRC-32, the SHA-256 initial hash
// words, a command switch, a handler table and an endpoint URL. ESP8266 builds the same code for the call0 ABI.
// FIXTURE_V2 builds the next version of the ESP32 application for diff_firmware: version 1.5.0, an "update"
// command that names a second endpoint, and no walk().
#include <stdint.h>

typedef unsigned int size_t;

#ifdef ESP8266
#define UART0_FIFO ((volatile uint32_t *)0x60000000)
#define UART0_STATUS ((volatile uint32_t *)0x6000001c)
#else
#define UART0_FIFO ((volatile uint32_t *)0x3ff40000)
#define UART0_STATUS ((volatile uint32_t *)0x3ff4001c)
#endif

#define IRAM __attribute__((section(".iram1.text"), noinline))

// ESP8266's NONOS SDK names the entry call_user_start.
#ifdef ESP8266
#define call_start_cpu0 call_user_start
#endif

// ROM functions, at addresses the linker script provides (as ESP-IDF's esp32.rom.ld does).
extern int ets_printf(const char *format, ...);
extern void ets_delay_us(uint32_t us);

// esp_app_desc_t as ESP-IDF v5 lays it out: 256 bytes at the start of the first flash data (DROM) segment.
typedef struct {
  uint32_t magic_word;
  uint32_t secure_version;
  uint32_t reserv1[2];
  char version[32];
  char project_name[32];
  char time[16];
  char date[16];
  char idf_ver[32];
  uint8_t app_elf_sha256[32];
  uint16_t min_efuse_blk_rev_full;
  uint16_t max_efuse_blk_rev_full;
  uint8_t mmu_page_size;
  uint8_t reserv3[3];
  uint32_t reserv2[18];
} esp_app_desc_t;

__attribute__((section(".rodata_desc"), used)) const esp_app_desc_t esp_app_desc = {
    .magic_word = 0xabcd5432,
    .secure_version = 0,
#ifdef FIXTURE_V2
    .version = "1.5.0",
#else
    .version = "1.4.2",
#endif
    .project_name = "thermostat",
    .time = "12:00:00",
    .date = "Nov 19 2026",
    .idf_ver = "v5.4-fixture",
    .min_efuse_blk_rev_full = 0,
    .max_efuse_blk_rev_full = 199,
    .mmu_page_size = 16,
};

static const char TAG[] = "app";
static const char *const endpoint = "https://telemetry.example.com/v1/report";
#ifdef FIXTURE_V2
static const char *const update_endpoint = "https://ota.example.com/v2/firmware";
#endif

static uint32_t uptime_ticks;
static char device_name[24] = "thermo-0001";
static uint8_t frame[64];

__attribute__((noinline)) static void uart_putc(char c) {
  while (((*UART0_STATUS >> 16) & 0xff) >= 126) {
  }
  *UART0_FIFO = (uint8_t)c;
}

__attribute__((noinline)) void uart_puts(const char *text) {
  while (*text) {
    uart_putc(*text++);
  }
}

__attribute__((noinline)) size_t str_len(const char *text) {
  size_t length = 0;
  while (text[length]) {
    length++;
  }
  return length;
}

__attribute__((noinline)) int str_eq(const char *a, const char *b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return *a == *b;
}

// Bitwise CRC-32 (reflected, polynomial 0xEDB88320), as firmware integrity checks use it.
__attribute__((noinline)) uint32_t crc32_le(uint32_t crc, const uint8_t *data, size_t length) {
  crc = ~crc;
  while (length--) {
    crc ^= *data++;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
    }
  }
  return ~crc;
}

__attribute__((noinline)) void sha256_start(uint32_t state[8]) {
  state[0] = 0x6a09e667;
  state[1] = 0xbb67ae85;
  state[2] = 0x3c6ef372;
  state[3] = 0xa54ff53a;
  state[4] = 0x510e527f;
  state[5] = 0x9b05688c;
  state[6] = 0x1f83d9ab;
  state[7] = 0x5be0cd19;
}

// Pure helpers for evaluate_function.
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

__attribute__((noinline)) int check_password(const char *attempt) {
  static const char secret[] = "hunter2-esp";
  if (str_len(attempt) != sizeof(secret) - 1) {
    return 0;
  }
  return str_eq(attempt, secret);
}

static int handle_status(const char *argument) {
  ets_printf("%s: status uptime=%u name=%s\n", TAG, uptime_ticks, device_name);
  return (int)str_len(argument);
}

static int handle_reboot(const char *argument) {
  ets_printf("%s: reboot requested (%s)\n", TAG, argument);
  return -1;
}

static int handle_report(const char *argument) {
  uart_puts("POST ");
  uart_puts(endpoint);
  uart_puts("\n");
  return (int)crc32_le(0, (const uint8_t *)argument, str_len(argument));
}

#ifdef FIXTURE_V2
static int handle_update(const char *argument) {
  uart_puts("GET ");
  uart_puts(update_endpoint);
  uart_puts(argument);
  return 0;
}
#endif

typedef int (*handler_t)(const char *argument);
static const struct {
  const char *name;
  handler_t handler;
} commands[] = {
    {"status", handle_status},
    {"reboot", handle_reboot},
    {"report", handle_report},
#ifdef FIXTURE_V2
    {"update", handle_update},
#endif
};

__attribute__((noinline)) int dispatch(const char *name, const char *argument) {
  for (unsigned i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    if (str_eq(name, commands[i].name)) {
      return commands[i].handler(argument);
    }
  }
  ets_printf("%s: unknown command %s\n", TAG, name);
  return -2;
}

__attribute__((noinline)) int classify(int code) {
  switch (code) {
  case 0:
    return 10;
  case 1:
    return 23;
  case 2:
    return 37;
  case 3:
    return 41;
  case 4:
    return 59;
  case 5:
    return 61;
  case 6:
    return 73;
  default:
    return -1;
  }
}

// Recursion whose code after the call is also where the base case branches to: evaluate_function must end a
// call only on its return, not on reaching the return address.
static volatile int visits;

#ifndef FIXTURE_V2
__attribute__((noinline)) int walk(int depth) {
  if (depth > 0) {
    walk(depth - 1);
  }
  visits = visits + depth;
  return visits;
}
#endif

void app_main(void) {
  uint32_t state[8];
  ets_printf("%s: booting %s\n", TAG, esp_app_desc.project_name);
  sha256_start(state);
  for (unsigned i = 0; i < sizeof(frame); i++) {
    frame[i] = (uint8_t)(state[i & 7] >> (i & 3));
  }
  uint32_t crc = crc32_le(0, frame, sizeof(frame));
  ets_printf("%s: frame crc %08x sum %04x\n", TAG, crc, checksum16(frame, sizeof(frame)));
  if (check_password(device_name)) {
    uart_puts("admin unlocked\n");
  }
  dispatch("status", "now");
  dispatch("report", device_name);
#ifdef FIXTURE_V2
  dispatch("update", "?channel=stable");
  uptime_ticks += (uint32_t)classify(scale_add(1, 2, 3)) + (uint32_t)visits;
#else
  uptime_ticks += (uint32_t)classify(scale_add(1, 2, 3)) + (uint32_t)walk(3);
#endif
  ets_delay_us(1000);
}

// The entry of the "main" task, as ESP-IDF's main_task: it logs around its call to app_main.
static void main_task(void *argument) {
  (void)argument;
  ets_printf("I (%u) %s: Calling app_main()\n", uptime_ticks, "main_task");
  app_main();
  ets_printf("I (%u) %s: Returned from app_main()\n", uptime_ticks, "main_task");
  for (;;) {
    ets_delay_us(1000000);
  }
}

typedef void (*task_function_t)(void *);
static task_function_t pending_task;

__attribute__((noinline)) int task_create(task_function_t function, const char *name, uint32_t stack) {
  pending_task = function;
  return name[0] != 0 && stack > 0;
}

__attribute__((noinline)) void scheduler_start(void) {
  if (pending_task) {
    pending_task((void *)0);
  }
}

__attribute__((noinline)) void start_cpu0(void) {
  uptime_ticks = 0;
  task_create(main_task, "main", 3584);
  scheduler_start();
}

// The entry point the bootloader jumps to, in IRAM.
IRAM void call_start_cpu0(void) {
  uart_puts("cpu_start: starting\n");
  start_cpu0();
  for (;;) {
  }
}
