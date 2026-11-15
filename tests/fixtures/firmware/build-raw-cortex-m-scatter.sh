#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the scatter-load Cortex-M4 fixtures (see raw-cortex-m-scatter.c):
#   raw-cortex-m-scatter-gcc.bin    flash image at 0x08000000; GCC-style startup loops over linker symbols.
#   raw-cortex-m-scatter-table.bin  the same program with an Arm-style region table walked by the startup code.
# The .elf files keep the symbols. Needs zig and llvm-objcopy; built freestanding with -g0, so no local path is
# recorded (`grep -c -a -e /Users/ -e /home/` on each output prints 0).
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
build() {
  zig cc -target thumb-freestanding-eabi -mcpu=cortex_m4 -O1 -g0 -ffreestanding -nostdlib -fno-builtin \
    -fno-unwind-tables -fno-asynchronous-unwind-tables "${@:2}" \
    -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,raw-cortex-m-scatter.ld \
    -o "$1.elf" raw-cortex-m-scatter.c
  llvm-objcopy -O binary "$1.elf" "$1.bin"
  chmod -x "$1.bin"
}
build raw-cortex-m-scatter-gcc
build raw-cortex-m-scatter-table -DREGION_TABLE
