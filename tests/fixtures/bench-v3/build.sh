#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the owned suite-v3 head-to-head benchmark fixtures from src/. Requires zig 0.17 and Homebrew LLVM
# (llvm-strip).
#
# bin/        what an agent analyzes: stripped executables and shared libraries
# twins/      the same builds before stripping (symbol tables, and DWARF where a truth reads it), the truth
#             source; never given to an agent. Stripping changes no loaded byte or address;
#             tools/agent-bench/v3/derive-truth.py checks that.
#
# Executables are non-PIE (ET_EXEC, or a PE at its preferred base), so every tool shows the same addresses; the
# shared libraries are asked about by exported name only.
#
# The other suite-v3 fixtures are built into target/bench/v3/ and not committed:
#   tools/agent-bench/v3/build-sqlite.sh   pinned SQLite amalgamation (symbols and DWARF kept)
#   tools/agent-bench/v3/build-go.sh       pinned restic with its release Go toolchain
#   tools/agent-bench/v3/build-msvc.sh     src/engine.cpp for the MSVC ABI (needs a local MSVC CRT and SDK)
set -euo pipefail
cd "$(dirname "$0")"
# The helper scripts; override when building a copy of this directory elsewhere (to check reproducibility).
tools="${BENCH_V3_TOOLS:-../../../tools/agent-bench/v3}"
llvm=/opt/homebrew/opt/llvm/bin
mkdir -p bin twins
zig version
set -x
c=(-g -fno-omit-frame-pointer "-fdebug-prefix-map=$PWD=.")

# Decompiler-heavy semantics on 32-bit targets: i686 (no SSE, so 64-bit values live in register pairs) and
# ARMv7-A in ARM mode.
zig cc -target x86-linux-musl -march=i686 -O2 "${c[@]}" -o twins/semantics-x86.elf src/semantics.c
zig cc -target arm-linux-musleabihf -marm -O2 "${c[@]}" -o twins/semantics-arm32.elf src/semantics.c
# Type propagation: a struct pointer through several functions (x86-64 and aarch64 Linux, static).
zig cc -target x86_64-linux-musl -O1 "${c[@]}" -o twins/jobs-x64.elf src/jobs.c
zig cc -target aarch64-linux-musl -O1 "${c[@]}" -o twins/stream-arm64.elf src/stream.c
# Switch tables: absolute table in a non-PIC executable, relative tables in PIC shared libraries.
zig cc -target x86_64-linux-musl -O2 "${c[@]}" -fno-pic -fno-pie -no-pie -DVARIANT=1 \
  -o twins/opcodes-x64.elf src/opcodes.c
zig cc -target x86_64-linux-gnu -O2 "${c[@]}" -fPIC -shared -DOPCODES_SHARED -DVARIANT=2 \
  -o twins/libopcodes-x64.so src/opcodes.c
zig cc -target x86-linux-gnu -march=i686 -O2 "${c[@]}" -fPIC -shared -DOPCODES_SHARED -DVARIANT=3 \
  -o twins/libopcodes-x86.so src/opcodes.c
# 32-bit x86 Windows (MinGW ABI): cdecl, stdcall, fastcall and thiscall.
zig c++ -target x86-windows-gnu -march=i686 -O1 "${c[@]}" -fno-exceptions -fno-rtti \
  -o twins/conv-x86.exe src/conv.cpp
# The PE's timestamps and PDB GUID depend on the build paths recorded in its PDB: zero them. The PDB itself holds
# build-machine paths, so only the public symbols the truth reads are kept (twins/conv-x86.publics.txt).
python3 -I "$tools/pe-normalize.py" twins/conv-x86.exe
"$llvm/llvm-pdbutil" dump --publics twins/conv-x86.pdb |
  grep -A1 -E '`(_blend_three|_clamp_three@12|@pack_three@12|_weigh_four|_select_four@16|@rotate_four@16|@record_five@20|_record_three@12|_submit|__ZN5Mixer5blendEiii|__ZNK5Mixer5levelEv)`$' |
  grep -v '^--$' | sed -E 's/^ *[0-9]+ \| //; s/^ +//' > twins/conv-x86.publics.txt
rm -f twins/conv-x86.pdb

for name in semantics-x86.elf semantics-arm32.elf jobs-x64.elf stream-arm64.elf opcodes-x64.elf \
  libopcodes-x64.so libopcodes-x86.so conv-x86.exe; do
  "$llvm/llvm-strip" --strip-all -o "bin/$name" "twins/$name"
done
# The structure layouts the typing truths read, from the twins' DWARF; then every twin keeps its symbol table and
# drops its debug info (mostly the C library's, which records build-machine paths).
python3 -I "$tools/dwarf-extract.py" twins/jobs-x64.layout.json twins/jobs-x64.elf job
python3 -I "$tools/dwarf-extract.py" twins/stream-arm64.layout.json twins/stream-arm64.elf stream stream_ops
for name in semantics-x86.elf semantics-arm32.elf jobs-x64.elf stream-arm64.elf opcodes-x64.elf \
  libopcodes-x64.so libopcodes-x86.so; do
  "$llvm/llvm-strip" --strip-debug "twins/$name"
done
shasum -a 256 bin/*
