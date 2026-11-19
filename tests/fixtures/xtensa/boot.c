// SPDX-License-Identifier: Apache-2.0
// A minimal ESP32 second-stage bootloader for the flash-layout fixture (see build.sh): it reads the partition table
// at flash 0x8000 through the ROM's SPI flash read, finds the first application partition and reports it. It links
// nothing but itself.
#include <stdint.h>

extern int ets_printf(const char *format, ...);
extern int esp_rom_spiflash_read(uint32_t address, uint32_t *buffer, int32_t length);

typedef struct {
  uint16_t magic;
  uint8_t type;
  uint8_t subtype;
  uint32_t offset;
  uint32_t size;
  char label[16];
  uint32_t flags;
} partition_entry_t;

static partition_entry_t table[8];

__attribute__((noinline)) static int find_app(void) {
  if (esp_rom_spiflash_read(0x8000, (uint32_t *)table, sizeof(table)) != 0) {
    return -1;
  }
  for (int i = 0; i < 8; i++) {
    if (table[i].magic != 0x50aa) {
      break;
    }
    if (table[i].type == 0) {
      return i;
    }
  }
  return -1;
}

void call_start_cpu0(void) {
  ets_printf("boot: ESP-IDF fixture 2nd stage bootloader\n");
  int index = find_app();
  if (index < 0) {
    ets_printf("boot: no bootable app partitions in the partition table\n");
    for (;;) {
    }
  }
  ets_printf("boot: loading app partition %s at offset 0x%x\n", table[index].label, table[index].offset);
  for (;;) {
  }
}
