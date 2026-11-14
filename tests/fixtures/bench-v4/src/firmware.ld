/* SPDX-License-Identifier: Apache-2.0 */
/* Suite-v4 Cortex-M fixtures: 64 KiB flash at 0x0, 16 KiB SRAM at 0x20000000. boot.c and guard.c place their
 * fixed-address blocks (.cfg, .cfg_crc, .imghdr, .pair, .app, .app_crc) at the addresses below; periph.c has none. */
ENTRY(reset_handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 64K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 16K
}

__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
  .text 0x0 :
  {
    KEEP(*(.vectors))
    *(.text .text.*)
  } > FLASH

  .rodata : { *(.rodata .rodata.*) } > FLASH

  .imghdr 0xC00 : { KEEP(*(.imghdr)) } > FLASH
  .cfg 0x800 : { KEEP(*(.cfg)) } > FLASH
  .cfg_crc 0x840 : { KEEP(*(.cfg_crc)) } > FLASH
  .pair 0xC80 : { KEEP(*(.pair)) } > FLASH
  .app 0x1000 : { KEEP(*(.app .app.*)) } > FLASH
  .app_crc 0x13FC : { KEEP(*(.app_crc)) } > FLASH

  .ram 0x20000000 (NOLOAD) :
  {
    *(.ram .ram.*)
  } > SRAM

  /DISCARD/ :
  {
    *(.ARM.exidx*) *(.comment) *(.data*) *(.bss*)
  }
}
