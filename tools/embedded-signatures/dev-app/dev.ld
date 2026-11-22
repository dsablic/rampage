/* SPDX-License-Identifier: Apache-2.0 */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 1024K
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
}
_estack = ORIGIN(RAM) + LENGTH(RAM);
SECTIONS
{
  .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
  .text : { *(.text .text.*) *(.rodata .rodata.*) KEEP(*(.init)) KEEP(*(.fini)) } > FLASH
  .ARM.exidx : { *(.ARM.exidx*) } > FLASH
  .preinit_array : { KEEP(*(.preinit_array*)) } > FLASH
  .init_array : { KEEP(*(SORT(.init_array.*))) KEEP(*(.init_array*)) } > FLASH
  .fini_array : { KEEP(*(SORT(.fini_array.*))) KEEP(*(.fini_array*)) } > FLASH
  _sidata = LOADADDR(.data);
  .data : { _sdata = .; *(.data .data.*) . = ALIGN(4); _edata = .; } > RAM AT > FLASH
  .bss (NOLOAD) : { _sbss = .; *(.bss .bss.* COMMON) . = ALIGN(4); _ebss = .; } > RAM
  end = .;
  _end = .;
}
