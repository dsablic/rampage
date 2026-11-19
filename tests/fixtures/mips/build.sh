#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuilds the MIPS fixtures from router.c (Linux userland) and boot.c (a bare-metal boot ROM). Each userland build
# has a stripped twin (the analysis target) and a -sym copy that keeps the symbol table (the truth); the twins share
# every loaded byte (llvm-strip removes only unloaded sections; `rampage-eval truth --stripped` checks it). Requires
# the zig pinned in crates/rampage-signatures/data/zig-version (set ZIG to it), llvm-strip and llvm-objcopy.
#   router-mips.elf / router-mipsel.elf   o32 PIC, dynamic glibc, -O2 (big- and little-endian)
#   router-mipsel-O0.elf                  o32 PIC, dynamic glibc, -O0
#   router-mips-static.elf                o32, static musl, -O2
#   router-mips64.elf                     n64 PIC, dynamic glibc, -O2
#   boot-mips.bin / boot-mips.elf         MIPS32 big-endian boot ROM at 0xbfc00000, non-PIC (the .elf is truth)
set -euo pipefail
cd "$(dirname "$0")"
repo=$(cd ../../.. && pwd -P)
. ../zig-env.sh
trap 'zig_cleanup' EXIT
zcc() {
  "$zig" cc "-ffile-prefix-map=$PWD=." "$@"
}
userland() {
  local name=$1
  shift
  zcc "$@" -g0 -o "$name-sym.elf" router.c
  llvm-strip --strip-debug --remove-section=.comment --remove-section=.pdr "$name-sym.elf"
  scrub "$name-sym.elf"
  llvm-strip --strip-all -o "$name.elf" "$name-sym.elf"
}
userland router-mips -target mips-linux-gnueabihf -O2
userland router-mipsel -target mipsel-linux-gnueabihf -O2
userland router-mipsel-O0 -target mipsel-linux-gnueabihf -O0 -fno-sanitize=all
userland router-mips-static -target mips-linux-musleabi -O2 -static
userland router-mips64 -target mips64-linux-gnuabi64 -O2
zcc -target mips-freestanding-none -mcpu=mips32r2 -O1 -g0 -ffreestanding -nostdlib -fno-pic -mno-abicalls \
  -fno-unwind-tables -fno-asynchronous-unwind-tables -Wl,-T,boot.ld -Wl,--build-id=none -Wl,-e,_reset \
  -o boot-mips.elf boot.c
scrub boot-mips.elf
llvm-objcopy -O binary -j .text boot-mips.elf boot-mips.bin
chmod -x boot-mips.bin
