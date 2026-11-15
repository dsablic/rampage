/* SPDX-License-Identifier: Apache-2.0 */
/* Layout of elf-cortex-m-crc32.c: 4 KiB flash at 0x08000000 holding the vector table and boot code, then the .data
   initial values (copied into SRAM by the boot code), and a CRC-protected application at 0x08000800..0x08000bfc with
   its CRC-32 in .app_crc. 20 KiB SRAM at 0x20000000 holds .data and .bss. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 4K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 20K
}

__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
  .text 0x08000000 :
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
  } > SRAM AT > FLASH
  __data_load = LOADADDR(.data);

  .bss (NOLOAD) :
  {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > SRAM

  .app 0x08000800 :
  {
    KEEP(*(.app .app.*))
    . = ADDR(.app) + 0x3fc;
  } > FLASH =0xffffffff

  .app_crc 0x08000bfc :
  {
    KEEP(*(.app_crc))
  } > FLASH

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment)
  }
}
