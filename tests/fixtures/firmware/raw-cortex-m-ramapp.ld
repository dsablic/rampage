/* SPDX-License-Identifier: Apache-2.0 */
/* One image that runs where it is loaded: code, constants and initialised data together from IMAGE_BASE (replaced
   by build-raw-cortex-m-ramapp.sh). */
ENTRY(reset_handler)

SECTIONS
{
  . = IMAGE_BASE;
  .text :
  {
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
    *(.data .data.*)
    *(.bss .bss.*)
    . = ALIGN(4);
  }

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment)
  }
}
