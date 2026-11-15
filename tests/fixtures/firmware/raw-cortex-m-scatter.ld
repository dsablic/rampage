/* SPDX-License-Identifier: Apache-2.0 */
/* Flash at 0x08000000 holds the code, the region table and the load images of .ramfunc and .data. .ramfunc runs
   from tightly coupled RAM at 0x10000000 (with its own vector table first), .data from SRAM at 0x20000000, and
   .bss follows .data. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 64K
  TCM   (rwx) : ORIGIN = 0x10000000, LENGTH = 16K
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
    __region_table_start = .;
    KEEP(*(.region_table))
    __region_table_end = .;
    . = ALIGN(4);
  } > FLASH

  .ramfunc :
  {
    __ramfunc_start = .;
    KEEP(*(.ramfunc.vectors))
    *(.ramfunc.text .ramfunc.text.*)
    . = ALIGN(4);
    __ramfunc_end = .;
  } > TCM AT> FLASH

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

  __ramfunc_load = LOADADDR(.ramfunc);
  __data_load = LOADADDR(.data);
  __ramfunc_size = SIZEOF(.ramfunc);
  __data_size = SIZEOF(.data);
  __bss_size = SIZEOF(.bss);

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment)
  }
}
