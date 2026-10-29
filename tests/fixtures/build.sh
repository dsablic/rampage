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
llvm-strip --strip-debug bin/hello-x64-dyn.elf bin/hello-arm64.elf \
  bin/hello-{arm,thumb,mips,mipsel,ppc,ppc64le,riscv64,s390x}.elf
zig cc -target x86_64-linux-gnu -O1 -g0 -fPIC -shared -o bin/libhelper-x64.so src/helper.c
llvm-strip --strip-debug bin/libhelper-x64.so
zig cc -target x86_64-windows-gnu -O1 -g0 -o bin/hello-x64.exe "$src"
# A PE with a TLS callback: the callback is an entry point reached before main, recovered as a function start.
zig cc -target x86_64-windows-gnu -O1 -g0 -o bin/tls-x64.exe src/tls.c
rm -f bin/*.pdb
clang -arch x86_64 -O1 -o bin/hello-x64.macho "$src"
clang -arch arm64 -O1 -o bin/hello-arm64.macho "$src"
lipo -create bin/hello-x64.macho bin/hello-arm64.macho -output bin/hello-universal.macho
clang -arch x86_64 -O1 -dynamiclib -o bin/hello-x64.dylib "$src"
strip -o bin/hello-x64-stripped.macho bin/hello-x64.macho
# Stripped C++ fixture for RTTI class recovery: classic rebase (-no_fixup_chains) keeps on-disk pointers real.
clang++ -arch arm64 -O1 -Wl,-no_fixup_chains -o bin/classes-arm64.macho src/classes.cpp
strip bin/classes-arm64.macho
# Objective-C metadata: arm64 and arm64e use chained fixups (arm64e pointers are authenticated) and relative
# method lists, with category merging off so a category on a local class survives; x86_64 targets 10.14 for
# classic rebase/bind info and absolute method lists. The stripped copies keep only the runtime metadata.
objc=(-O1 -fobjc-arc -framework Foundation)
clang -arch arm64 "${objc[@]}" -Wl,-no_objc_category_merging -o bin/objc-arm64.macho src/objc.m
clang -arch arm64e "${objc[@]}" -Wl,-no_objc_category_merging -o objc-arm64e.tmp src/objc.m
clang -arch x86_64 "${objc[@]}" -mmacosx-version-min=10.14 -o objc-x64.tmp src/objc.m
strip -o bin/objc-arm64-stripped.macho bin/objc-arm64.macho
strip -o bin/objc-arm64e-stripped.macho objc-arm64e.tmp
strip -o bin/objc-x64-stripped.macho objc-x64.tmp
rm objc-arm64e.tmp objc-x64.tmp
clang -arch x86_64 -O1 -c -o bin/hello-x64.o "$src"
zig cc -target x86_64-linux-gnu -O1 -g0 -c -o bin/hello-x64-elf.o "$src"
# Stripped Go binaries keep their gopclntab, from which function names are recovered. Needs the Go toolchain.
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/hello-go-x64.elf src/hello.go
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/hello-go-arm64.elf src/hello.go
python3 craft.py malformed
# Go build info and cargo-auditable `.dep-v0` fixtures.
./build-buildinfo.sh
# WebAssembly and PyInstaller fixtures.
./build-formats.sh
# PE resource and load-config fixtures.
./build-pe-metadata.sh
