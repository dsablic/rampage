#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuilds the MIPS16e fixtures, the way OpenWrt builds most of its packages (`-mips16`): router16.c as programs
# whose functions are MIPS16e except the `nomips16` ones, and libmips16.c as a shared library without section
# headers. Same toolchain as build-gnu.sh: Debian bookworm's MIPS cross GCC 12.2.0 (12.2.0-14cross5), binutils 2.40
# and glibc 2.36, installed at pinned versions into the gcc:13 image pinned by digest; no debug info. Each -sym copy
# keeps its symbol table (and section headers) as the truth. The programs' stripped twins come from llvm-strip,
# which leaves the loaded bytes alone; the library's from ../strip-sections.py, which removes the section headers
# as OpenWrt's sstrip does. The outputs link GCC's crtbegin/crtend (GPL-3.0 with the GCC Runtime Library Exception)
# and glibc 2.36's crt1/crti/crtn (LGPL-2.1 with its linking exception); see CONTRIBUTING.md and
# crates/rampage-signatures/data/notices/index.json.
#   router16-gnu-mips.elf     big-endian PIE, -O2: the global pointer comes from a PC-relative sequence
#   router16-gnu-mipsel.elf   little-endian, non-PIC (-fno-pic -no-pie), -O2: literal pools, jal and jalx
#   libmips16-gnu-mipsel.so   little-endian shared library, -O2 -fPIC, section headers removed
set -euo pipefail
cd "$(dirname "$0")"
docker=${DOCKER:-docker}
image=gcc:13@sha256:8c0fe724784c6d617cb582f79ddaf5dd2233aaba2fb7a14e0b9d03348fea8088
"$docker" run --rm -v "$PWD":/w -w /w "$image" bash -c '
  set -e
  apt-get update -qq >/dev/null
  packages=""
  for arch in mips mipsel; do
    packages="$packages gcc-12-$arch-linux-gnu=12.2.0-14cross5 cpp-12-$arch-linux-gnu=12.2.0-14cross5"
    packages="$packages libgcc-12-dev-$arch-cross=12.2.0-14cross5 libc6-dev-$arch-cross=2.36-8cross2"
    packages="$packages binutils-$arch-linux-gnu=2.40-2cross2"
  done
  apt-get install -y -qq --no-install-recommends $packages >/dev/null 2>&1
  mips-linux-gnu-gcc-12 -O2 -g0 -mips16 -o router16-gnu-mips-sym.elf router16.c
  mipsel-linux-gnu-gcc-12 -O2 -g0 -mips16 -fno-pic -no-pie -o router16-gnu-mipsel-sym.elf router16.c
  mipsel-linux-gnu-gcc-12 -O2 -g0 -mips16 -fPIC -shared -o libmips16-gnu-mipsel-sym.so libmips16.c
  chown "$(stat -c %u:%g router16.c)" router16-gnu-mips-sym.elf router16-gnu-mipsel-sym.elf libmips16-gnu-mipsel-sym.so'
for name in router16-gnu-mips router16-gnu-mipsel; do
  llvm-strip --strip-all -o "$name.elf" "$name-sym.elf"
done
python3 -I ../strip-sections.py libmips16-gnu-mipsel-sym.so libmips16-gnu-mipsel.so
python3 -I ../scrub-paths.py --check router16-gnu-mips{,el}{,-sym}.elf libmips16-gnu-mipsel{,-sym}.so
