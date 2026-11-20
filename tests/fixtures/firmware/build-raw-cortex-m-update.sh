#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the firmware update pair for diff_firmware (see raw-cortex-m-update.c): raw-cortex-m-update-v1 and -v2,
# each linked with a placeholder CRC, the CRC-32 of its application region written into .app_crc, and the flash
# image (gaps 0xff) as a flat binary at 0x08000000; the .elf files keep the symbols as the test truth. The tests
# wrap both binaries in the LZSS update container the triage tests use. Needs zig, llvm-objcopy and python3; built
# with -g0, so no local path is recorded (`python3 tests/fixtures/scrub-paths.py --check` passes on each output).
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
build() {
  local name=$1 size=$2
  shift 2
  local scratch
  scratch=$(mktemp -d)
  # zig's linker driver takes no --defsym, so the application size is written into a copy of the script.
  sed "s/APP_SIZE/$size/" raw-cortex-m-update.ld > "$scratch/update.ld"
  zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 -O1 -g0 -ffreestanding -nostdlib -fno-builtin \
    -fno-unwind-tables -fno-asynchronous-unwind-tables "$@" \
    -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,"$scratch/update.ld" \
    -o "$name.elf" raw-cortex-m-update.c
  local sections=(-j .boot -j .app -j .app_crc)
  llvm-objcopy -O binary --gap-fill 0xff "${sections[@]}" "$name.elf" "$scratch/image.bin"
  python3 -I -c '
import struct, sys, zlib
image = open(sys.argv[1], "rb").read()
end = 0x800 + int(sys.argv[3], 16)
assert len(image) == end + 4, (len(image), end)
open(sys.argv[2], "wb").write(struct.pack("<I", zlib.crc32(image[0x800:end])))
' "$scratch/image.bin" "$scratch/crc.bin" "$size"
  llvm-objcopy --update-section .app_crc="$scratch/crc.bin" "$name.elf"
  llvm-objcopy -O binary --gap-fill 0xff "${sections[@]}" "$name.elf" "$name.bin"
  chmod -x "$name.bin"
  rm -rf "$scratch"
}
build raw-cortex-m-update-v1 0x3fc
build raw-cortex-m-update-v2 0x5fc -DV2
