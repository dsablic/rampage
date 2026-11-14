/* SPDX-License-Identifier: Apache-2.0 */
/* 2 KiB flash at 0x08000000: boot code, then a CRC-protected application at 0x08000400 with its CRC-32 in the
   last word. 20 KiB SRAM at 0x20000000. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 2K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 20K
}

__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
  .boot 0x08000000 :
  {
    KEEP(*(.vectors))
    *(.text .text.*)
    *(.rodata .rodata.*)
  } > FLASH

  .app 0x08000400 :
  {
    KEEP(*(.app .app.*))
    . = ADDR(.app) + 0x3fc;
  } > FLASH =0xff

  .app_crc 0x080007fc :
  {
    KEEP(*(.app_crc))
  } > FLASH

  .ram 0x20000000 (NOLOAD) :
  {
    *(.ram .ram.*)
  } > SRAM

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment) *(.data*) *(.bss*)
  }
}
