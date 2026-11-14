/* SPDX-License-Identifier: Apache-2.0 */
/* The lock-mechanism firmware: code and constants in flash at 0x08000000, variables in SRAM at 0x20000000. The
   application slot (0x08020000), pairing record (0x0801F000) and configuration block (0x0801F800) lie outside the
   image. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 64K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 20K
}

__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
  .text 0x08000000 :
  {
    KEEP(*(.vectors))
    *(.text .text.*)
  } > FLASH

  .rodata :
  {
    *(.rodata .rodata.*)
  } > FLASH

  .bss (NOLOAD) :
  {
    *(.bss .bss.* .data .data.* COMMON)
  } > SRAM

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment)
  }
}
