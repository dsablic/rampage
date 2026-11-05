/* SPDX-License-Identifier: Apache-2.0 */
/* lm3s6965evb: 256 KiB flash at 0x00000000, 64 KiB SRAM at 0x20000000. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
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

  .ram 0x20000200 (NOLOAD) :
  {
    *(.ram .ram.*)
  } > SRAM

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment) *(.data*) *(.bss*)
  }
}
