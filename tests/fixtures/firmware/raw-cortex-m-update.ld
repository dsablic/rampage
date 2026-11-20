/* SPDX-License-Identifier: Apache-2.0 */
/* Flash at 0x08000000: boot code, then a CRC-protected application at 0x08000800 of APP_SIZE bytes (replaced
   by the build script) with its CRC-32 in the word after it. 20 KiB SRAM at 0x20000000. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 4K
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

  .app 0x08000800 :
  {
    KEEP(*(.app .app.*))
    . = ADDR(.app) + APP_SIZE;
  } > FLASH =0xff

  .app_crc :
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
