#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the headerless Cortex-M3 Raw Project fixtures. Each .elf keeps its symbols as the test truth; each .bin is
# its flash image (base 0x08000000, vector table at offset 0). Needs zig and llvm-objcopy.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
for name in raw-cortex-m raw-cortex-m-strings; do
  zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 -O1 -g0 -ffreestanding -nostdlib \
    -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,raw-cortex-m.ld -o "$name.elf" "$name.c"
  llvm-objcopy -O binary --only-section=.text "$name.elf" "$name.bin"
  chmod -x "$name.bin"
done
