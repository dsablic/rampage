/* SPDX-License-Identifier: Apache-2.0 */
/* An ESP8266 application laid out as the NONOS SDK lays one out: IRAM and DRAM loaded by the boot ROM from the
   image at flash 0, and IROM (code and rodata) mapped from flash 0x10000 at 0x40210000. ROM addresses as in the
   SDK's eagle.rom.addr.v6.ld. */
ENTRY(call_user_start)

MEMORY
{
  dram0_0_seg (RW) : org = 0x3ffe8000, len = 0x14000
  iram1_0_seg (RX) : org = 0x40100000, len = 0x8000
  irom0_0_seg (RX) : org = 0x40210000, len = 0x5c000
}

PROVIDE(ets_printf = 0x400024cc);
PROVIDE(ets_delay_us = 0x40002ecc);

SECTIONS
{
  .text : ALIGN(4)
  {
    *(.iram1.literal .iram1.text .iram1.text.literal .iram1.*)
  } > iram1_0_seg

  .data : ALIGN(4)
  {
    *(.data .data.* .sdata .sdata.*)
  } > dram0_0_seg

  .bss (NOLOAD) : ALIGN(8)
  {
    *(.bss .bss.* .sbss .sbss.* COMMON)
  } > dram0_0_seg

  .irom0.text : ALIGN(16)
  {
    KEEP(*(.rodata_desc .rodata_desc.*))
    *(.rodata .rodata.* .srodata .srodata.*)
    *(.literal .literal.* .text .text.*)
  } > irom0_0_seg

  /DISCARD/ : { *(.comment) *(.xt.prop*) *(.xt.lit*) *(.note*) }
}
