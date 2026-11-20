#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the literal-pool update pair for diff_firmware (see raw-cortex-m-literals.c): raw-cortex-m-literals-v1.bin
# and -v2.bin are flash images at 0x08000000 whose constants live in literal pools (-mcpu=cortex_m3+no_movt); v2
# changes one pool word. Needs zig and llvm-objcopy; built with -g0, so no local path is recorded.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
build() {
  local name=$1
  shift
  local scratch
  scratch=$(mktemp -d)
  cat > "$scratch/literals.ld" <<'LD'
ENTRY(reset_handler)
MEMORY { FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 4K  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 4K }
__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
SECTIONS
{
  .text : { KEEP(*(.vectors)) *(.text .text.*) *(.rodata .rodata.*) } > FLASH
  .ram (NOLOAD) : { *(.ram .ram.*) } > SRAM
  /DISCARD/ : { *(.ARM.exidx*) *(.comment) *(.data*) *(.bss*) }
}
LD
  zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3+no_movt -O1 -g0 -ffreestanding -nostdlib -fno-builtin \
    -fno-unwind-tables -fno-asynchronous-unwind-tables "$@" \
    -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,"$scratch/literals.ld" \
    -o "$scratch/$name.elf" raw-cortex-m-literals.c
  llvm-objcopy -O binary -j .text "$scratch/$name.elf" "$name.bin"
  chmod -x "$name.bin"
  rm -rf "$scratch"
}
build raw-cortex-m-literals-v1
build raw-cortex-m-literals-v2 -DV2
