/* SPDX-License-Identifier: Apache-2.0 */
/* 64 KiB flash at 0x08000000 holds the code, constants and the load image of .data; .data runs from SRAM at
   0x20000000 and .bss follows it. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 64K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 16K
}

__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
  .text :
  {
    KEEP(*(.vectors))
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH

  .data :
  {
    __data_start = .;
    *(.data .data.*)
    . = ALIGN(4);
    __data_end = .;
  } > SRAM AT> FLASH

  .bss (NOLOAD) :
  {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > SRAM

  __data_load = LOADADDR(.data);

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment)
  }
}
