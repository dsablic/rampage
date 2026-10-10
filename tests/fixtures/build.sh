#!/usr/bin/env bash
# Rebuilds the committed fixture binaries. Requires zig, Apple clang and llvm-strip.
set -euo pipefail
cd "$(dirname "$0")"
src=src/hello.c
zig cc -target x86_64-linux-musl -O1 -g0 -o bin/hello-x64.elf "$src"
zig cc -target x86_64-linux-gnu -O1 -g0 -o bin/hello-x64-dyn.elf "$src"
zig cc -target aarch64-linux-gnu -O1 -g0 -o bin/hello-arm64.elf "$src"
# Other architectures, decoded through Capstone.
zig cc -target arm-linux-gnueabihf -O1 -g0 -o bin/hello-arm.elf "$src"
zig cc -target thumb-linux-musleabihf -O1 -g0 -o bin/hello-thumb.elf "$src"
zig cc -target mips-linux-gnueabihf -O1 -g0 -o bin/hello-mips.elf "$src"
zig cc -target mipsel-linux-gnueabihf -O1 -g0 -o bin/hello-mipsel.elf "$src"
zig cc -target powerpc-linux-musleabi -O1 -g0 -o bin/hello-ppc.elf "$src"
zig cc -target powerpc64le-linux-gnu -O1 -g0 -o bin/hello-ppc64le.elf "$src"
zig cc -target riscv64-linux-gnu -O1 -g0 -o bin/hello-riscv64.elf "$src"
zig cc -target s390x-linux-gnu -O1 -g0 -o bin/hello-s390x.elf "$src"
llvm-strip --strip-debug bin/hello-x64-dyn.elf bin/hello-arm64.elf bin/hello-{arm,thumb,mips,mipsel,ppc,ppc64le,riscv64,s390x}.elf
zig cc -target x86_64-linux-gnu -O1 -g0 -fPIC -shared -o bin/libhelper-x64.so src/helper.c
llvm-strip --strip-debug bin/libhelper-x64.so
zig cc -target x86_64-windows-gnu -O1 -g0 -o bin/hello-x64.exe "$src"
rm -f bin/*.pdb
clang -arch x86_64 -O1 -o bin/hello-x64.macho "$src"
clang -arch arm64 -O1 -o bin/hello-arm64.macho "$src"
lipo -create bin/hello-x64.macho bin/hello-arm64.macho -output bin/hello-universal.macho
clang -arch x86_64 -O1 -dynamiclib -o bin/hello-x64.dylib "$src"
strip -o bin/hello-x64-stripped.macho bin/hello-x64.macho
clang -arch x86_64 -O1 -c -o bin/hello-x64.o "$src"
zig cc -target x86_64-linux-gnu -O1 -g0 -c -o bin/hello-x64-elf.o "$src"
python3 craft.py malformed
