/* SPDX-License-Identifier: Apache-2.0 */
/* An ESP32 application laid out as ESP-IDF lays one out: IRAM and DRAM loaded by the bootloader, DROM (rodata,
   with esp_app_desc first) and IROM (code) mapped from flash by the MMU. ROM addresses as in esp32.rom.ld. */
ENTRY(call_start_cpu0)

MEMORY
{
  iram0_0_seg (RX) : org = 0x40080000, len = 0x20000
  dram0_0_seg (RW) : org = 0x3ffb0000, len = 0x2c200
  drom0_0_seg (R)  : org = 0x3f400020, len = 0x3fffe0
  iram0_2_seg (RX) : org = 0x400d0020, len = 0x32ffe0
}

PROVIDE(ets_printf = 0x40007d54);
PROVIDE(ets_delay_us = 0x40008534);

SECTIONS
{
  .iram0.text : ALIGN(4)
  {
    *(.iram1.literal .iram1.text .iram1.text.literal .iram1.*)
  } > iram0_0_seg

  .dram0.data : ALIGN(4)
  {
    *(.data .data.* .sdata .sdata.*)
  } > dram0_0_seg

  .dram0.bss (NOLOAD) : ALIGN(8)
  {
    *(.bss .bss.* .sbss .sbss.* COMMON)
  } > dram0_0_seg

  .flash.appdesc : ALIGN(0x10)
  {
    KEEP(*(.rodata_desc .rodata_desc.*))
  } > drom0_0_seg

  .flash.rodata : ALIGN(0x10)
  {
    *(.rodata .rodata.* .srodata .srodata.*)
  } > drom0_0_seg

  .flash.text : ALIGN(4)
  {
    *(.literal .literal.* .text .text.*)
  } > iram0_2_seg

  /DISCARD/ : { *(.comment) *(.xt.prop*) *(.xt.lit*) *(.note*) }
}
