#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the headerless Cortex-M3 fixture for CMSIS-SVD peripheral maps (see raw-cortex-m-svd.c). The .elf keeps the
# symbols as the test truth; the .bin is its flash image (base 0x08000000, vector table at offset 0). Needs zig and
# llvm-objcopy.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 -O1 -g0 -ffreestanding -nostdlib \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,raw-cortex-m.ld -o raw-cortex-m-svd.elf raw-cortex-m-svd.c
llvm-objcopy -O binary --only-section=.text raw-cortex-m-svd.elf raw-cortex-m-svd.bin
chmod -x raw-cortex-m-svd.bin
