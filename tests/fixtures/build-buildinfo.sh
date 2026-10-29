#!/usr/bin/env bash
# Rebuilds the build-info fixtures. Go: src/gobuildinfo, one module with a locally replaced dependency, for ELF,
# Mach-O and PE (needs only the Go toolchain; VCS stamping is off so rebuilds do not depend on the checkout).
# Rust: cargo-auditable is not required; src/auditable.c carries src/auditable.json zlib-compressed in a `.dep-v0`
# section the way cargo-auditable lays it out (needs python3, zig and Apple clang).
set -euo pipefail
cd "$(dirname "$0")"
out=$PWD/bin

header=$(mktemp -d)
trap 'rm -rf "$header"' EXIT
python3 -I -c '
import sys, zlib
data = zlib.compress(open(sys.argv[1], "rb").read().rstrip(b"\n"), 9)
print("#define AUDITABLE_DATA " + ", ".join(str(byte) for byte in data))
' src/auditable.json >"$header/auditable-data.h"
zig cc -target x86_64-linux-musl -O1 -g0 -s -I"$header" -o "$out/auditable-x64.elf" src/auditable.c
zig cc -target x86_64-windows-gnu -O1 -g0 -s -I"$header" -o "$out/auditable-x64.exe" src/auditable.c
clang -arch arm64 -O1 -I"$header" -o "$out/auditable-arm64.macho" src/auditable.c
strip "$out/auditable-arm64.macho"
rm -f "$out"/auditable-x64.pdb

cd src/gobuildinfo
export GOTOOLCHAIN=local GOPROXY=off GOWORK=off
flags=(-trimpath -buildvcs=false -ldflags "-s -w")
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build "${flags[@]}" -o "$out/buildinfo-go-x64.elf" .
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build "${flags[@]}" -o "$out/buildinfo-go-arm64.macho" .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build "${flags[@]}" -o "$out/buildinfo-go-x64.exe" .
