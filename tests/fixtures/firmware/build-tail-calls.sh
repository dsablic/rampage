#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the generated tail-call Cortex-M3 fixture: functions that a caller's tail call (`b.w f`) reaches before any
# direct call to them. tail-calls.elf keeps its symbols (the test truth), tail-calls-stripped.elf drops them, and
# tail-calls.bin is the flash image (base 0x08000000, vector table at offset 0). Needs python3, zig and llvm-objcopy.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
python3 gen-tail-calls.py 48 7 > tail-calls.c
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 -O2 -g0 -ffreestanding -nostdlib \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,raw-cortex-m.ld -o tail-calls.elf tail-calls.c
llvm-objcopy --strip-all tail-calls.elf tail-calls-stripped.elf
llvm-objcopy -O binary --only-section=.text tail-calls.elf tail-calls.bin
chmod -x tail-calls.bin
