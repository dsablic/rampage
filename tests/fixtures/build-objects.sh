#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuilds the relocatable-object and static-library fixtures in objects/ from src/objects.c and
# src/objects-helper.c: one object per architecture (non-PIC, plus PIC builds that reach data and calls through a
# GOT), a GNU-format library with two members that share a name, and a BSD-format one. The tests assert what the
# loader makes of them (call targets, data references, Thumb mode, MIPS HI16/LO16 pairs, member selection), not
# their exact bytes, so another zig release that emits other code still passes them.
set -euo pipefail
cd "$(dirname "$0")"
repo=$(cd ../.. && pwd)
zig=${ZIG:-zig}
"$zig" version
out=objects
mkdir -p "$out"
flags=(-O1 -g0 -fno-inline -fcommon -ffile-prefix-map="$PWD"=. -c)
object() { # target, output, extra flags...
    local target=$1 output=$2
    shift 2
    "$zig" cc -target "$target" "${flags[@]}" "$@" -o "$out/$output" src/objects.c
}
set -x
object x86_64-linux-musl objects-x86_64.o -fno-pic
object x86_64-linux-musl objects-x86_64-pic.o -fPIC
object x86-linux-musl objects-x86.o -fno-pic
object aarch64-linux-musl objects-aarch64.o -fno-pic
object aarch64-linux-musl objects-aarch64-pic.o -fPIC
object arm-linux-musleabihf objects-arm.o -fno-pic -marm
object thumb-freestanding-eabi objects-thumb.o -mcpu=cortex_m3
object mipsel-linux-musleabi objects-mipsel.o -fno-pic
object mipsel-linux-musleabi objects-mipsel-pic.o -fPIC
object riscv64-linux-musl objects-riscv64.o -fno-pic
object riscv64-linux-musl objects-riscv64-pic.o -fPIC

# Archives: objects.o and helper.o, then a second, different objects.o (the PIC build) under the same name.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/pic"
cp "$out/objects-x86_64.o" "$work/objects.o"
cp "$out/objects-x86_64-pic.o" "$work/pic/objects.o"
"$zig" cc -target x86_64-linux-musl "${flags[@]}" -fno-pic -o "$work/helper.o" src/objects-helper.c
rm -f "$out/libobjects-gnu.a" "$out/libobjects-bsd.a"
(cd "$work" && "$zig" ar --format=gnu rcs libobjects-gnu.a objects.o helper.o && "$zig" ar --format=gnu q libobjects-gnu.a pic/objects.o \
    && "$zig" ar --format=gnu s libobjects-gnu.a)
(cd "$work" && "$zig" ar --format=bsd rcs libobjects-bsd.a objects.o helper.o)
cp "$work/libobjects-gnu.a" "$work/libobjects-bsd.a" "$out/"
set +x
python3 -I "$repo/tests/fixtures/scrub-paths.py" --check "$out"/*
