#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the CRC-protected Cortex-M3 fixture (see raw-cortex-m-crc.c): link with a placeholder CRC, compute the
# CRC-32 of the application region (0x08000400..0x080007fc), write it into .app_crc, and package the image as a
# flat binary (gaps 0xff), Intel HEX and S-records. raw-cortex-m-crc.elf keeps the symbols as the test truth.
# Needs zig, llvm-objcopy and python3.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
name=raw-cortex-m-crc
sections=(-j .boot -j .app -j .app_crc)
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 -O1 -g0 -ffreestanding -nostdlib \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,"$name.ld" -o "$name.elf" "$name.c"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
llvm-objcopy -O binary --gap-fill 0xff "${sections[@]}" "$name.elf" "$scratch/image.bin"
python3 -I -c '
import struct, sys, zlib
image = open(sys.argv[1], "rb").read()
assert len(image) == 0x800, len(image)
open(sys.argv[2], "wb").write(struct.pack("<I", zlib.crc32(image[0x400:0x7fc])))
' "$scratch/image.bin" "$scratch/crc.bin"
llvm-objcopy --update-section .app_crc="$scratch/crc.bin" "$name.elf"
llvm-objcopy -O binary --gap-fill 0xff "${sections[@]}" "$name.elf" "$name.bin"
llvm-objcopy -O ihex "${sections[@]}" "$name.elf" "$name.hex"
llvm-objcopy -O srec "${sections[@]}" "$name.elf" "$name.srec"
chmod -x "$name.bin" "$name.hex" "$name.srec"
