#!/usr/bin/env bash
# Rebuilds the committed fixture binaries. Requires the zig pinned in crates/rampage-signatures/data/zig-version (set
# ZIG to it when the one on PATH is another release), Apple clang, llvm-strip and Go. Zig's own start files and
# compiler_rt name local directories in their debug info whatever the prefix map says: scrub (zig-env.sh) blanks
# them in every zig output and fails if any local path is left.
set -euo pipefail
cd "$(dirname "$0")"
repo=$(cd ../.. && pwd -P)
. ./zig-env.sh
trap 'zig_cleanup' EXIT
zcc() {
  "$zig" cc "-ffile-prefix-map=$PWD=." "$@"
}
src=src/hello.c
zcc -target x86_64-linux-musl -O1 -g0 -o bin/hello-x64.elf "$src"
zcc -target x86_64-linux-gnu -O1 -g0 -o bin/hello-x64-dyn.elf "$src"
zcc -target aarch64-linux-gnu -O1 -g0 -o bin/hello-arm64.elf "$src"
# Other architectures, decoded through Capstone.
zcc -target arm-linux-gnueabihf -O1 -g0 -o bin/hello-arm.elf "$src"
zcc -target thumb-linux-musleabihf -O1 -g0 -o bin/hello-thumb.elf "$src"
zcc -target mips-linux-gnueabihf -O1 -g0 -o bin/hello-mips.elf "$src"
zcc -target mipsel-linux-gnueabihf -O1 -g0 -o bin/hello-mipsel.elf "$src"
zcc -target powerpc-linux-musleabi -O1 -g0 -o bin/hello-ppc.elf "$src"
zcc -target powerpc64le-linux-gnu -O1 -g0 -o bin/hello-ppc64le.elf "$src"
zcc -target riscv64-linux-gnu -O1 -g0 -o bin/hello-riscv64.elf "$src"
zcc -target s390x-linux-gnu -O1 -g0 -o bin/hello-s390x.elf "$src"
llvm-strip --strip-debug bin/hello-x64-dyn.elf bin/hello-arm64.elf \
  bin/hello-{arm,thumb,mips,mipsel,ppc,ppc64le,riscv64,s390x}.elf
zcc -target x86_64-linux-gnu -O1 -g0 -fPIC -shared -o bin/libhelper-x64.so src/helper.c
llvm-strip --strip-debug bin/libhelper-x64.so
# The same on 32-bit x86, whose PIC PLT stubs jump through `[ebx+disp]` rather than an absolute slot.
zcc -target x86-linux-gnu -march=i686 -O1 -g0 -fPIC -shared -o bin/libhelper-x86.so src/helper.c
llvm-strip --strip-debug bin/libhelper-x86.so
zcc -target x86_64-windows-gnu -O1 -g0 -o bin/hello-x64.exe "$src"
# A PE with a TLS callback: the callback is an entry point reached before main, recovered as a function start.
zcc -target x86_64-windows-gnu -O1 -g0 -o bin/tls-x64.exe src/tls.c
rm -f bin/*.pdb
scrub bin/hello-{x64,x64-dyn,arm64,arm,thumb,mips,mipsel,ppc,ppc64le,riscv64,s390x}.elf bin/libhelper-{x64,x86}.so \
  bin/hello-x64.exe bin/tls-x64.exe
clang -arch x86_64 -O1 -o bin/hello-x64.macho "$src"
clang -arch arm64 -O1 -o bin/hello-arm64.macho "$src"
lipo -create bin/hello-x64.macho bin/hello-arm64.macho -output bin/hello-universal.macho
clang -arch x86_64 -O1 -dynamiclib -o bin/hello-x64.dylib "$src"
strip -o bin/hello-x64-stripped.macho bin/hello-x64.macho
# Stripped C++ fixture for RTTI class recovery: classic rebase (-no_fixup_chains) keeps on-disk pointers real.
clang++ -arch arm64 -O1 -Wl,-no_fixup_chains -o bin/classes-arm64.macho src/classes.cpp
strip bin/classes-arm64.macho
# The same source with the linker's default chained fixups: typeinfo pointers on disk are chain encodings.
clang++ -arch arm64 -O1 -o bin/classes-chained-arm64.macho src/classes.cpp
strip bin/classes-chained-arm64.macho
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
zcc -target x86_64-linux-gnu -O1 -g0 -c -o bin/hello-x64-elf.o "$src"
scrub bin/hello-x64-elf.o
# Stripped Go binaries keep their gopclntab, from which function names are recovered. go1.27.2, fetched by
# GOTOOLCHAIN; -trimpath keeps the source and GOROOT directories out of the file table.
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOTOOLCHAIN=go1.27.2 go build -trimpath -ldflags "-s -w" \
  -o bin/hello-go-x64.elf src/hello.go
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOTOOLCHAIN=go1.27.2 go build -trimpath -ldflags "-s -w" \
  -o bin/hello-go-arm64.elf src/hello.go
for file in bin/hello-go-x64.elf bin/hello-go-arm64.elf; do
  if [ "$(grep -c -a -e /Users/ -e /home/ "$file")" != 0 ]; then
    echo "$file holds a local path" >&2
    exit 1
  fi
done
python3 craft.py malformed
# Go build info and cargo-auditable `.dep-v0` fixtures.
./build-buildinfo.sh
# WebAssembly and PyInstaller fixtures.
./build-formats.sh
# PE resource and load-config fixtures.
./build-pe-metadata.sh
