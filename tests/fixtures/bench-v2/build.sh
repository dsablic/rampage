#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the suite-v2 head-to-head benchmark fixtures from src/. Requires zig 0.17, Apple clang, dsymutil and
# Homebrew LLVM (llvm-strip, llvm-objcopy).
#
# bin/        what an agent analyzes: stripped executables, a raw firmware image and two library builds
# twins/      the same builds before stripping (symbols, and DWARF for ELF), the truth source; never given to an
#             agent. Stripping changes no code or data address; tools/agent-bench/v2/derive-truth.py checks that.
#
# Non-PIE (ET_EXEC) executables throughout, so every tool shows the same addresses; the shared libraries are
# asked about by exported name only.
set -euo pipefail
cd "$(dirname "$0")"
llvm=/opt/homebrew/opt/llvm/bin
mkdir -p bin twins
zig version
set -x
c=(-O1 -g -fno-omit-frame-pointer "-fdebug-prefix-map=$PWD=.")
# ld64 records object mtimes in the debug map that feeds the Mach-O UUID; zero them for reproducible output.
export ZERO_AR_DATE=1
macho() { # macho OUTPUT COMPILER SOURCE [FLAGS...]: compile to a kept object so dsymutil finds its DWARF
  local output=$1 compiler=$2 source=$3
  shift 3
  "$compiler" -arch arm64 "${c[@]}" "$@" -c -o "$output.o" "$source"
  "$compiler" -arch arm64 -o "twins/$output.macho" "$output.o"
}

# Stripped C++ with RTTI, x86-64 Linux, static: hierarchy and virtual-call tasks.
zig c++ -target x86_64-linux-musl "${c[@]}" -o twins/widgets-x64.elf src/widgets.cpp
# Stripped C++ with RTTI, arm64 macOS: field-layout task. dsymutil keeps the DWARF beside the twin.
macho packet-arm64 clang++ src/packet.cpp
# Vtable-only classes (-fno-rtti), arm64 macOS: vtable-slot task.
macho codec-arm64 clang++ src/codec.cpp -fno-rtti
# Typing: pointer chain (aarch64 Linux, static) and record table (x86-64 Linux, static).
zig cc -target aarch64-linux-musl "${c[@]}" -o twins/session-arm64.elf src/session.c
zig cc -target x86_64-linux-musl "${c[@]}" -o twins/services-x64.elf src/services.c
# Investigation: key derivation (arm64 macOS), option bit (x86-64 Linux), call chain without tail calls (aarch64
# Linux, dynamic), CRC parameters (big-endian MIPS32 Linux, dynamic).
macho vault-arm64 clang src/vault.c
zig cc -target x86_64-linux-musl "${c[@]}" -o twins/backup-x64.elf src/backup.c
zig cc -target aarch64-linux-gnu "${c[@]}" -fno-optimize-sibling-calls -o twins/beacon-arm64.elf src/beacon.c
zig cc -target mips-linux-gnueabihf "${c[@]}" -o twins/checksum-mips.elf src/checksum.c
# Firmware: Cortex-M3 ELF twin, shipped as a raw image of its flash contents from 0x0.
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 -O1 -g -ffreestanding -nostdlib \
  -fno-unwind-tables -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,--nmagic \
  -Wl,-e,reset_handler -Wl,-T,src/blinky.ld -o twins/blinky-cm3.elf src/blinky.c
# Diffing: two builds of one shared library.
zig cc -target x86_64-linux-gnu "${c[@]}" -fPIC -shared -o twins/libcalc-v1-x64.so src/libcalc.c
zig cc -target x86_64-linux-gnu "${c[@]}" -fPIC -shared -DCALC_V2 -o twins/libcalc-v2-x64.so src/libcalc.c

for name in packet-arm64 codec-arm64 vault-arm64; do
  rm -rf "twins/$name.macho.dSYM"
  dsymutil "twins/$name.macho"
  strip -S "twins/$name.macho"
  strip -o "bin/$name.macho" "twins/$name.macho"
done
for name in widgets-x64 session-arm64 services-x64 backup-x64 beacon-arm64 checksum-mips libcalc-v1-x64 \
  libcalc-v2-x64; do
  case "$name" in libcalc*) extension=so ;; *) extension=elf ;; esac
  "$llvm/llvm-strip" --strip-all -o "bin/$name.$extension" "twins/$name.$extension"
done
"$llvm/llvm-objcopy" -O binary --only-section=.text twins/blinky-cm3.elf bin/blinky-cm3.bin
# Only the hierarchy (widgets) and pointer-chain (session) truths read ELF DWARF; the other twins keep their
# symbol tables and drop the statically linked libc's debug info, which is most of their size.
for twin in services-x64.elf backup-x64.elf beacon-arm64.elf checksum-mips.elf libcalc-v1-x64.so \
  libcalc-v2-x64.so blinky-cm3.elf; do
  "$llvm/llvm-strip" --strip-debug "twins/$twin"
done
rm -f *.o
shasum -a 256 bin/*
