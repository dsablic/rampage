#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the headerless Cortex-M3 Raw Project fixtures. Each .elf keeps its symbols as the test truth; each .bin is
# its flash image (base 0x08000000, vector table at offset 0). raw-cortex-m-tables is built for Cortex-M0, whose
# clang switch tables hold absolute Thumb case-label addresses. Needs zig and llvm-objcopy.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
for build in raw-cortex-m:cortex_m3 raw-cortex-m-strings:cortex_m3 raw-cortex-m-tables:cortex_m0; do
  name=${build%%:*}
  zig cc -target thumb-freestanding-eabi -mcpu=${build##*:} -O1 -g0 -ffreestanding -nostdlib \
    -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,raw-cortex-m.ld -o "$name.elf" "$name.c"
  llvm-objcopy -O binary --only-section=.text "$name.elf" "$name.bin"
  chmod -x "$name.bin"
done
# Literal pools instead of movw/movt (as GCC-built firmware has), and interprocedural register allocation so a
# caller keeps an argument in a call-clobbered register across a call to a leaf that leaves it alone.
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3+no_movt -O1 -g0 -ffreestanding -nostdlib -mllvm -enable-ipra \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,raw-cortex-m.ld \
  -o raw-cortex-m-decompile.elf raw-cortex-m-decompile.c
llvm-objcopy -O binary --only-section=.text raw-cortex-m-decompile.elf raw-cortex-m-decompile.bin
chmod -x raw-cortex-m-decompile.bin
