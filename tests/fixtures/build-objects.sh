#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuilds the relocatable-object and static-library fixtures in objects/ from src/objects.c and
# src/objects-helper.c: one object per architecture (non-PIC, plus PIC builds that reach data and calls through a
# GOT), a GNU-format library with two members that share a name, and a BSD-format one. COFF objects (src/objects-
# coff.c, x64/x86/ARM64/Thumb, one rewritten as a big object), an MSVC-style .lib of them and an import library
# (llvm-lib, llvm-dlltool); Mach-O objects (src/objects-macho.c, Apple clang) and a universal library of them
# (libtool, lipo). The tests assert what the
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
"$zig" cc -target x86_64-linux-musl "${flags[@]}" -fno-pic -o "$out/objects-tls-x86_64.o" src/objects-tls.c
# Hand-written: a conditional jump to an extern (a conditional sibling call), and an AArch64 call to an extern
# followed by a `cbz` that has no relocation of its own.
"$zig" cc -target x86_64-linux-musl -g0 -ffile-prefix-map="$PWD"=. -c -o "$out/objects-sibcall-x86_64.o" src/objects-sibcall-x86_64.s
"$zig" cc -target arm-linux-musleabihf -g0 -ffile-prefix-map="$PWD"=. -c -o "$out/objects-sibcall-arm.o" src/objects-sibcall-arm.s
"$zig" cc -target aarch64-linux-musl -g0 -ffile-prefix-map="$PWD"=. -c -o "$out/objects-call-cbz-aarch64.o" src/objects-call-cbz-aarch64.s

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

# A MIPS library and a stripped program statically linked against it (no C library: src/objects-link-stubs.c),
# for signatures built from the library: its `%hi`/`%lo` pairs differ between the objects and the program.
mkdir "$work/mips"
cp "$out/objects-mipsel.o" "$work/mips/objects.o"
"$zig" cc -target mipsel-linux-musleabi "${flags[@]}" -fno-pic -o "$work/mips/helper.o" src/objects-helper.c
rm -f "$out/libobjects-mipsel.a"
(cd "$work/mips" && "$zig" ar rcs libobjects-mipsel.a objects.o helper.o)
cp "$work/mips/libobjects-mipsel.a" "$out/"
"$zig" cc -target mipsel-linux-musleabi -O1 -g0 -fno-inline -fno-pic -no-pie -static -nostdlib -Wl,-e,_start -s \
    -ffile-prefix-map="$PWD"=. -o "$out/linked-mipsel" src/objects-link-stubs.c "$out/libobjects-mipsel.a"

# COFF: the objects, a big-object copy, a .lib holding the x64 object and the helper, and an import library.
llvm=${LLVM:-/opt/homebrew/opt/llvm/bin}
coff() { # target, output
    "$zig" cc -target "$1" "${flags[@]}" -o "$out/$2" src/objects-coff.c
}
coff x86_64-windows-msvc objects-coff-x86_64.obj
coff x86-windows-msvc objects-coff-x86.obj
coff aarch64-windows-msvc objects-coff-aarch64.obj
coff thumb-windows-msvc objects-coff-thumb.obj
# The CodeView object name in `.debug$S` is zig's temporary output path; blank its cache directory.
zig_cache=$("$zig" env | sed -n 's/.*\.global_cache_dir = "\(.*\)",/\1/p')
python3 -I "$repo/tests/fixtures/scrub-paths.py" --root "$zig_cache" "$out"/objects-coff-*.obj
python3 -I coff-bigobj.py "$out/objects-coff-x86_64.obj" "$out/objects-coff-bigobj.obj"
mkdir "$work/coff"
cp "$out/objects-coff-x86_64.obj" "$work/coff/objects.obj"
"$zig" cc -target x86_64-windows-msvc "${flags[@]}" -o "$work/coff/helper.obj" src/objects-helper.c
python3 -I "$repo/tests/fixtures/scrub-paths.py" --root "$zig_cache" "$work/coff/helper.obj"
rm -f "$out/libobjects-coff.lib" "$out/imports-coff.lib"
(cd "$work/coff" && "$llvm/llvm-lib" /out:libobjects-coff.lib objects.obj helper.obj)
cp "$work/coff/libobjects-coff.lib" "$out/"
"$llvm/llvm-dlltool" -m i386:x86-64 -d src/objects-imports.def -l "$out/imports-coff.lib"

# Mach-O: the objects, and a universal library of one member per architecture (libtool's `__.SYMDEF SORTED`).
for arch in x86_64 arm64; do
    clang -arch "$arch" -O1 -g0 -fno-inline -fno-common -ffile-prefix-map="$PWD"=. -c \
        -o "$out/objects-macho-$arch.o" src/objects-macho.c
    mkdir -p "$work/macho-$arch"
    cp "$out/objects-macho-$arch.o" "$work/macho-$arch/objects.o"
    (cd "$work/macho-$arch" && ZERO_AR_DATE=1 libtool -static -o "lib-$arch.a" objects.o)
done
rm -f "$out/libobjects-macho.a"
lipo -create -output "$out/libobjects-macho.a" "$work/macho-x86_64/lib-x86_64.a" "$work/macho-arm64/lib-arm64.a"
set +x
python3 -I "$repo/tests/fixtures/scrub-paths.py" --check "$out"/*
