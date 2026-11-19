/* SPDX-License-Identifier: Apache-2.0 */
/* A MIPS32 boot ROM mapped at the reset vector 0xbfc00000 (kseg1), 4 KiB; RAM at 0x80000000 (kseg0). */
ENTRY(_reset)

SECTIONS
{
  .text 0xbfc00000 :
  {
    KEEP(*(.reset))
    *(.text .text.*)
    *(.rodata .rodata.*)
  }

  /DISCARD/ :
  {
    *(.comment) *(.data*) *(.bss*) *(.MIPS.abiflags) *(.reginfo) *(.pdr) *(.gnu.attributes)
  }
}
