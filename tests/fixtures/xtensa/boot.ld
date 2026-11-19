/* SPDX-License-Identifier: Apache-2.0 */
/* A second-stage ESP32 bootloader laid out as ESP-IDF's: IRAM at 0x40078000 and DRAM at 0x3fff0000, both loaded by
   the ROM from flash 0x1000. ROM addresses as in esp32.rom.ld. */
ENTRY(call_start_cpu0)

MEMORY
{
  iram_seg (RWX) : org = 0x40078000, len = 0x8000
  dram_seg (RW)  : org = 0x3fff0000, len = 0x8000
}

PROVIDE(ets_printf = 0x40007d54);
PROVIDE(esp_rom_spiflash_read = 0x40062ed8);

SECTIONS
{
  .iram.text : ALIGN(4)
  {
    *(.literal .literal.* .text .text.*)
  } > iram_seg

  .dram0.data : ALIGN(4)
  {
    *(.rodata .rodata.* .data .data.*)
  } > dram_seg

  .dram0.bss (NOLOAD) : ALIGN(8)
  {
    *(.bss .bss.* COMMON)
  } > dram_seg

  /DISCARD/ : { *(.comment) *(.xt.prop*) *(.xt.lit*) *(.note*) }
}
