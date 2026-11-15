#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the static ELF32 Cortex-M3 firmware fixtures for in-place ELF patching (see elf-cortex-m-crc32.c and
# elf-cortex-m-crc16.c): link each with a placeholder check value, compute it, write it into its section, and for the
# CRC-32 image also write the flat binary of its loaded segments at their load addresses (elf-cortex-m-crc32.bin,
# gaps 0xff), as a flash programmer would. Needs zig, llvm-objcopy and python3.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
# Compiled at -Os (at -O1/-O2 LLVM turns the bitwise CRC loops into table lookups); linked separately because
# zig cc strips the symbol table when it links at -Os, and the symbols are the tests' truth.
link() {
  zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 -Os -g0 -ffreestanding \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -c -o "$scratch/$1.o" "$1.c"
  zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 -O1 -nostdlib \
    -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,"$1.ld" -o "$1.elf" "$scratch/$1.o"
}

name=elf-cortex-m-crc32
link "$name"
llvm-objcopy -O binary --gap-fill 0xff -j .app "$name.elf" "$scratch/app.bin"
python3 -I -c '
import struct, sys, zlib
app = open(sys.argv[1], "rb").read()
assert len(app) == 0x3fc, len(app)
open(sys.argv[2], "wb").write(struct.pack("<I", zlib.crc32(app)))
' "$scratch/app.bin" "$scratch/crc.bin"
llvm-objcopy --update-section .app_crc="$scratch/crc.bin" "$name.elf"
llvm-objcopy -O binary --gap-fill 0xff "$name.elf" "$name.bin"
chmod -x "$name.bin"

name=elf-cortex-m-crc16
link "$name"
llvm-objcopy -O binary -j .config "$name.elf" "$scratch/config.bin"
python3 -I -c '
import struct, sys
config = open(sys.argv[1], "rb").read()
assert len(config) == 68, len(config)
crc = 0
for byte in config[:66]:
    crc ^= byte
    for _ in range(8):
        crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
open(sys.argv[2], "wb").write(config[:66] + struct.pack("<H", crc))
' "$scratch/config.bin" "$scratch/config-crc.bin"
llvm-objcopy --update-section .config="$scratch/config-crc.bin" "$name.elf"
