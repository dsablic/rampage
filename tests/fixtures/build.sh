#!/usr/bin/env bash
# Rebuilds the committed fixture binaries. Requires zig and Apple clang.
set -euo pipefail
cd "$(dirname "$0")"
src=src/hello.c
zig cc -target x86_64-linux-musl -O1 -g0 -o bin/hello-x64.elf "$src"
zig cc -target x86_64-windows-gnu -O1 -g0 -o bin/hello-x64.exe "$src"
rm -f bin/*.pdb
clang -arch x86_64 -O1 -o bin/hello-x64.macho "$src"
clang -arch arm64 -O1 -o bin/hello-arm64.macho "$src"
lipo -create bin/hello-x64.macho bin/hello-arm64.macho -output bin/hello-universal.macho
clang -arch x86_64 -O1 -dynamiclib -o bin/hello-x64.dylib "$src"
strip -o bin/hello-x64-stripped.macho bin/hello-x64.macho
