#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild raw-cortex-m-fields.bin (see raw-cortex-m-fields.c): a flash image at 0x08000000 whose code reads and
# writes the fields of a structure at 0x20000100 in SRAM through literal-pool and MOVW/MOVT bases. Needs zig and
# llvm-objcopy; built with -g0, so no local path is recorded.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
scratch=$(mktemp -d)
cat > "$scratch/fields.ld" <<'LD'
ENTRY(reset_handler)
MEMORY { FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 4K  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 4K }
__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
SECTIONS
{
  .text : { KEEP(*(.vectors)) *(.text .text.*) *(.rodata .rodata.*) } > FLASH
  .ram 0x20000100 (NOLOAD) : { *(.ram .ram.*) } > SRAM
  /DISCARD/ : { *(.ARM.exidx*) *(.comment) *(.data*) *(.bss*) }
}
LD
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3+no_movt -O1 -g0 -ffreestanding -nostdlib -fno-builtin \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,"$scratch/fields.ld" \
  -o "$scratch/raw-cortex-m-fields.elf" raw-cortex-m-fields.c
llvm-objcopy -O binary -j .text "$scratch/raw-cortex-m-fields.elf" raw-cortex-m-fields.bin
chmod -x raw-cortex-m-fields.bin
rm -rf "$scratch"
