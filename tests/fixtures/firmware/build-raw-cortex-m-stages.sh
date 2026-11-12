#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the two-stage Cortex-M3 fixtures for multi-region Raw projects (see raw-cortex-m-stages.c).
#   raw-cortex-m-stages.bin       flash image at 0x08000000; stage 2 stored plain at 0x400, its data at 0x800.
#   raw-cortex-m-stages.hex       the same image as Intel HEX: every record at its flash address.
#   raw-cortex-m-stages.srec      S-records with stage 2 and its data at their SRAM run addresses.
#   raw-cortex-m-stages-lzss.bin  stage 2 LZSS-compressed at 0x408 behind a {encoded size, decoded size} header.
# Needs zig, llvm-objcopy and python3.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
build() {
  zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3+no_movt -O1 -g0 -ffreestanding -nostdlib \
    -fno-unwind-tables -fno-asynchronous-unwind-tables "${@:2}" \
    -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,"${script:-raw-cortex-m-stages.ld}" \
    -o "$1.elf" raw-cortex-m-stages.c
}
build raw-cortex-m-stages
llvm-objcopy -O binary raw-cortex-m-stages.elf raw-cortex-m-stages.bin
llvm-objcopy -O ihex raw-cortex-m-stages.elf raw-cortex-m-stages.hex
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# The same link with stage 2 stored where it runs (no AT), for records that state the run addresses.
sed 's/ : AT(0x[0-9a-f]*)/ :/' raw-cortex-m-stages.ld > "$tmp/run.ld"
script="$tmp/run.ld" build "$tmp/run"
llvm-objcopy -O srec "$tmp/run.elf" raw-cortex-m-stages.srec
build raw-cortex-m-stages-lzss -DSTAGE2_LZSS
llvm-objcopy -O binary --only-section=.text raw-cortex-m-stages-lzss.elf "$tmp/stage1.bin"
llvm-objcopy -O binary --only-section=.stage2 raw-cortex-m-stages-lzss.elf "$tmp/stage2.bin"
llvm-objcopy -O binary --only-section=.stage2data raw-cortex-m-stages-lzss.elf "$tmp/stage2data.bin"
python3 gen-stages.py "$tmp/stage1.bin" "$tmp/stage2.bin" "$tmp/stage2data.bin" raw-cortex-m-stages-lzss.bin
chmod -x raw-cortex-m-stages.bin raw-cortex-m-stages.hex raw-cortex-m-stages.srec raw-cortex-m-stages-lzss.bin
