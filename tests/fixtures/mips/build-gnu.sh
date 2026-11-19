#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuilds the GNU-toolchain MIPS fixtures from router.c, the way most router and camera userlands are built: GCC
# and GNU ld, o32 PIC, a PIE whose imports are called through lazy-binding `.MIPS.stubs` (the GOT holds each
# stub's address until the import is bound) and whose functions restore `$gp` from the stack after each call.
# Zig's lld makes neither. The compilers are Debian bookworm's MIPS cross GCC 12.2.0 (package 12.2.0-14cross5),
# installed at pinned versions into the gcc:13 image pinned by digest (the image's own GCC 13 is not used); no debug
# info. Each -sym copy keeps its symbol table as the truth and its twin has it stripped (llvm-strip, which leaves
# the loaded bytes alone). The binaries link GCC's crtbegin/crtend (GPL-3.0 with the GCC Runtime Library
# Exception) and glibc 2.36's crt1/crti/crtn (LGPL-2.1 with its linking exception); see CONTRIBUTING.md and
# crates/rampage-signatures/data/notices/index.json. Should Debian retire these versions, take them from
# snapshot.debian.org.
#   router-gnu-mips.elf / router-gnu-mipsel.elf   GCC 12.2.0 -O2, big- and little-endian
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
  mips-linux-gnu-gcc-12 -O2 -g0 -o router-gnu-mips-sym.elf router.c
  mipsel-linux-gnu-gcc-12 -O2 -g0 -o router-gnu-mipsel-sym.elf router.c
  chown "$(stat -c %u:%g router.c)" router-gnu-mips-sym.elf router-gnu-mipsel-sym.elf'
for name in router-gnu-mips router-gnu-mipsel; do
  llvm-strip --strip-all -o "$name.elf" "$name-sym.elf"
done
python3 -I ../scrub-paths.py --check router-gnu-mips{,el}{,-sym}.elf
