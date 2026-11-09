/* SPDX-License-Identifier: Apache-2.0 */
/* STM32-style map: 128 KiB flash at 0x08000000, 20 KiB SRAM at 0x20000000. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 128K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 20K
}

__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
  .text :
  {
    KEEP(*(.vectors))
    *(.text .text.*)
    *(.rodata .rodata.*)
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
