#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the run-from-RAM Cortex-M0 fixtures (see raw-cortex-m-ramapp.c):
#   raw-cortex-m-ramapp.bin       linked at 0x20000000.
#   raw-cortex-m-ramapp-lo.bin    linked at 0x01000000.
#   raw-cortex-m-ramapp-lzss.bin  raw-cortex-m-ramapp-lo.bin as one LZSS stream (the lzss-4k variant of gen-stages.py).
# Needs zig, llvm-objcopy and python3; built with -g0, so no local path is recorded.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
build() {
  sed "s/IMAGE_BASE/$2/" raw-cortex-m-ramapp.ld > "$tmp/$1.ld"
  zig cc -target thumb-freestanding-eabi -mcpu=cortex_m0 -O1 -g0 -ffreestanding -nostdlib -fno-builtin \
    -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler \
    -Wl,-T,"$tmp/$1.ld" -o "$1.elf" raw-cortex-m-ramapp.c
  llvm-objcopy -O binary --only-section=.text "$1.elf" "$1.bin"
}
build raw-cortex-m-ramapp 0x20000000
build raw-cortex-m-ramapp-lo 0x01000000
python3 -I -c '
import importlib.util, sys
spec = importlib.util.spec_from_file_location("stages", sys.argv[1])
stages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stages)
data = open(sys.argv[2], "rb").read()
encoded = stages.lzss(data)
open(sys.argv[3], "wb").write(encoded)
print(f"{len(data)} bytes -> {len(encoded)} encoded")
' gen-stages.py raw-cortex-m-ramapp-lo.bin raw-cortex-m-ramapp-lzss.bin
chmod -x raw-cortex-m-ramapp.bin raw-cortex-m-ramapp-lo.bin raw-cortex-m-ramapp-lzss.bin
