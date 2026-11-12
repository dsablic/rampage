/* SPDX-License-Identifier: Apache-2.0 */
/* Two-stage map: stage 1 runs from flash at 0x08000000; stage 2 is stored in flash at 0x08000400 and runs from
   SRAM at 0x20000000, with its initialised data stored at 0x08000800 and living at 0x20000800. */
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

  .stage2 0x20000000 : AT(0x08000400)
  {
    __stage2_start = .;
    *(.stage2.text .stage2.text.*)
    . = ALIGN(4);
    __stage2_end = .;
  } > SRAM

  .stage2data 0x20000800 : AT(0x08000800)
  {
    __stage2_data_start = .;
    *(.stage2.data .stage2.data.*)
    . = ALIGN(4);
    __stage2_data_end = .;
  } > SRAM

  .ram 0x20001000 (NOLOAD) :
  {
    *(.ram .ram.*)
  } > SRAM

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment) *(.data*) *(.bss*)
  }
}
