#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the owned suite-v4 head-to-head benchmark fixtures from src/. Requires zig 0.17, Homebrew LLVM
# (llvm-strip, llvm-objcopy) and python3.
#
# bin/        what an agent analyzes: stripped executables, and headerless Cortex-M flash images (flat binary,
#             and for the patching tasks Intel HEX and S-records of the same bytes)
# twins/      the same builds before stripping, with their symbol tables: the truth source, never given to an
#             agent. Stripping changes no loaded byte or address; tools/agent-bench/v4/derive-truth.py checks that.
# companions/ files an agent gets beside the fixture (the made-up device's CMSIS-SVD file)
#
# Executables are non-PIE, so every tool shows the same addresses. The Cortex-M images map at 0x0 with the vector
# table first. boot-cm4.bin carries the two checksum values build.sh computes (see src/boot.c); its twin ELF keeps
# zero placeholders there.
set -euo pipefail
cd "$(dirname "$0")"
llvm=/opt/homebrew/opt/llvm/bin
mkdir -p bin twins
zig version
set -x
c=(-g0 -fno-omit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -Wl,--build-id=none)

# Emulation: the same source for four targets; each task asks about one function in one build.
zig cc -target x86_64-linux-musl -O2 "${c[@]}" -fno-pie -no-pie -o twins/emulate-x64.elf src/emulate.c
zig cc -target aarch64-linux-gnu.2.36 -O2 "${c[@]}" -fno-builtin -fno-pie -no-pie -o twins/emulate-arm64-dyn.elf \
  src/emulate.c
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m4 -O2 "${c[@]}" -DFREESTANDING -ffreestanding -nostdlib \
  -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,src/firmware.ld -o twins/emulate-thumb.elf src/emulate.c
zig cc -target mips-linux-musleabi -O2 "${c[@]}" -fno-pie -no-pie -o twins/emulate-mips.elf src/emulate.c

# String decoding: rolling XOR on x86-64 (dynamically linked, puts imported), shifted alphabet on AArch64 (static).
zig cc -target x86_64-linux-gnu.2.36 -O2 "${c[@]}" -fno-pie -no-pie -DVARIANT=1 -o twins/strdec-x64.elf src/strdec.c
zig cc -target aarch64-linux-musl -O2 "${c[@]}" -fno-pie -no-pie -DVARIANT=2 -o twins/strdec-arm64.elf src/strdec.c

for name in emulate-x64.elf emulate-arm64-dyn.elf emulate-thumb.elf emulate-mips.elf strdec-x64.elf \
  strdec-arm64.elf; do
  "$llvm/llvm-strip" --strip-all -o "bin/$name" "twins/$name"
  # The twin keeps its symbol table and drops the C library's debug info (build-machine paths, size).
  "$llvm/llvm-strip" --strip-debug "twins/$name"
done

# Headerless Cortex-M4 firmware for the made-up BENCHM4 device (companions/benchm4.svd).
fw=(-target thumb-freestanding-eabi -mcpu=cortex_m4 -O1 -g0 -ffreestanding -nostdlib -fno-unwind-tables
  -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,src/firmware.ld)
for name in periph guard boot; do
  zig cc "${fw[@]}" -o "twins/$name-cm4.elf" "src/$name.c"
done
"$llvm/llvm-objcopy" -O binary --gap-fill 0xff -j .text -j .rodata twins/periph-cm4.elf bin/periph-cm4.bin
"$llvm/llvm-objcopy" -O binary --gap-fill 0xff -j .text -j .rodata -j .imghdr -j .pair twins/guard-cm4.elf \
  bin/guard-cm4.bin
"$llvm/llvm-objcopy" -O binary --gap-fill 0xff -j .text -j .rodata -j .cfg -j .cfg_crc -j .app -j .app_crc \
  twins/boot-cm4.elf bin/boot-cm4.bin
# The two integrity fields of boot-cm4 (src/boot.c), then the same bytes as Intel HEX and as S-records.
python3 -I ../../../tools/agent-bench/v4/image.py seal bin/boot-cm4.bin
python3 -I ../../../tools/agent-bench/v4/image.py ihex bin/boot-cm4.bin 0 bin/boot-cm4.hex
python3 -I ../../../tools/agent-bench/v4/image.py srec bin/boot-cm4.bin 0 bin/boot-cm4.srec
chmod -x bin/*.bin bin/*.hex bin/*.srec
