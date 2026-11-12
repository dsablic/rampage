#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the suite-v3 symbol-rich C fixture: the SQLite shell (public domain) from the pinned 3.46.1 amalgamation,
# checked against its SHA-256, compiled as an optimized release build that keeps its symbol table and DWARF, into
# target/bench/v3/sqlite/. Nothing here is committed. Requires zig 0.17, curl and unzip.
#
#   sqlite3-x64.elf   x86-64 Linux, static (musl), non-PIE, -O2 -g: what the agent analyzes, and (through LLVM's
#                     tools) the truth source. The questions are about its own symbols and debug info.
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
out="$root/target/bench/v3/sqlite"
name=sqlite-amalgamation-3460100
url="https://www.sqlite.org/2024/$name.zip"
digest=77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784
mkdir -p "$out"
cd "$out"
[ -f "$name.zip" ] || curl -sSfL -o "$name.zip" "$url"
echo "$digest  $name.zip" | shasum -a 256 -c -
rm -rf "$name"
unzip -q "$name.zip"
zig version
cd "$name"
# The relative source paths and the prefix map keep the build directory out of the debug info.
zig cc -target x86_64-linux-musl -O2 -g -fno-omit-frame-pointer "-fdebug-prefix-map=$PWD=." \
  -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -DNDEBUG \
  -o "$out/sqlite3-x64.elf" shell.c sqlite3.c
ls -l "$out/sqlite3-x64.elf"
shasum -a 256 "$out/sqlite3-x64.elf"
