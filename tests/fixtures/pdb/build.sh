#!/usr/bin/env bash
set -euo pipefail

source_dir="$(cd "$(dirname "$0")" && pwd)"
clang="${CLANG:-clang}"
linker="${LLD_LINK:-lld-link}"
linker="$(command -v "$linker")"
work="$(mktemp -d "${TMPDIR:-/tmp}/rampage-pdb.XXXXXX")"
trap 'rm -f "$work/fixture.obj" "$work/fixture.exe" "$work/fixture.pdb" "$work/lld-link"; rmdir "$work"' EXIT

cd "$work"
ln -s "$linker" lld-link
"$clang" --target=x86_64-pc-windows-msvc -c "$source_dir/fixture.c" -o fixture.obj \
    -O0 -g -gcodeview -gno-codeview-command-line -ffreestanding -fno-stack-protector \
    -Xclang -object-file-name=/rampage/pdb/fixture.obj \
    -fdebug-compilation-dir=/rampage/pdb -ffile-prefix-map="$source_dir"=/rampage/pdb \
    -ffile-prefix-map="$work"=/rampage/pdb
./lld-link fixture.obj /out:fixture.exe /pdb:fixture.pdb /pdbaltpath:fixture.pdb /pdbsourcepath:/rampage/pdb \
    /debug:full /nodefaultlib /entry:pdb_entry /subsystem:console \
    /opt:noicf /opt:noref /base:0x140000000 /fixed /Brepro /timestamp:0 /noimplib
cp fixture.exe fixture.pdb "$source_dir/"
