/* SPDX-License-Identifier: Apache-2.0 */
/* Layout of elf-cortex-m-crc16.c: 4 KiB flash at 0x08000000 holding the vector table and boot code, and a
   configuration block at 0x08000c00 with its CRC-16 in its last halfword. 20 KiB SRAM at 0x20000000. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 4K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 20K
}

__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
  .text 0x08000000 :
  {
    KEEP(*(.vectors))
    *(.text .text.*)
    *(.rodata .rodata.*)
  } > FLASH

  .config 0x08000c00 :
  {
    KEEP(*(.config))
  } > FLASH

  .bss (NOLOAD) :
  {
    *(.bss .bss.* COMMON)
  } > SRAM

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment) *(.data*)
  }
}
