#!/bin/sh
# Rebuilds the workflow test fixtures. Requires the zig recorded in crates/rampage-signatures/data/zig-version,
# the toolchain the other generated fixtures are built with: another zig can emit different code.
set -eu
cd "$(dirname "$0")"
expected=$(cat ../../../rampage-signatures/data/zig-version)
actual=$(zig version)
if [ "$actual" != "$expected" ]; then
    echo "zig $expected required (crates/rampage-signatures/data/zig-version), found $actual" >&2
    exit 1
fi
zig cc -target x86_64-linux-gnu -O1 -g0 -o net-client-x64.elf net-client.c
zig cc -target x86_64-linux-gnu -O1 -g0 -s -o net-client-x64-stripped.elf net-client.c
zig cc -target x86_64-linux-gnu -O1 -g0 -o persist-x64.elf persist.c
zig cc -target x86_64-windows-gnu -O1 -g0 -s -o persist-x64.exe persist.c -ladvapi32
zig cc -target x86_64-linux-gnu -O1 -g0 -o decode-x64.elf decode.c
zig cc -target aarch64-linux-gnu -O1 -g0 -o decode-arm64.elf decode.c
zig cc -target x86_64-linux-gnu -O1 -g0 -o decode-alloc-x64.elf decode-alloc.c
zig cc -target aarch64-linux-gnu -O1 -g0 -o decode-alloc-arm64.elf decode-alloc.c
rm -f *.pdb
