#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the RTOS-shaped Cortex-M4 fixture (see raw-cortex-m-records.c): raw-cortex-m-records.bin is the flash image
# at 0x08000000 (code, constants, then the .data load image), raw-cortex-m-records.elf keeps the symbols. Built
# freestanding with -g0 and without movw/movt, so literal pools hold the addresses and no local path is recorded
# (`python3 tests/fixtures/scrub-paths.py --check` passes on each output). Needs zig and llvm-objcopy.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m4+no_movt -O1 -g0 -ffreestanding -nostdlib -fno-builtin \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,raw-cortex-m-records.ld \
  -o raw-cortex-m-records.elf raw-cortex-m-records.c
llvm-objcopy -O binary raw-cortex-m-records.elf raw-cortex-m-records.bin
chmod -x raw-cortex-m-records.bin
