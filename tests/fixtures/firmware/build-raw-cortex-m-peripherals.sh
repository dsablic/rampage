#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the peripheral_map fixture (see raw-cortex-m-peripherals.c): a Cortex-M3 flash image at 0x08000000 whose
# peripheral bases are literal-pool words. The .elf keeps the symbols as the test truth; the .bin is its .text.
# Needs zig and llvm-objcopy; built with -g0, so no local path is recorded.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
name=raw-cortex-m-peripherals
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3+no_movt -O1 -g0 -ffreestanding -nostdlib -fno-builtin \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,raw-cortex-m.ld -o "$name.elf" "$name.c"
llvm-objcopy -O binary --only-section=.text "$name.elf" "$name.bin"
chmod -x "$name.bin"
