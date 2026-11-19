#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuilds the GNU-toolchain MIPS fixtures from router.c, the way most router and camera userlands are built: GCC
# and GNU ld, o32 PIC, a PIE whose imports are called through lazy-binding `.MIPS.stubs` (the GOT holds each
# stub's address until the import is bound) and whose functions restore `$gp` from the stack after each call.
# Zig's lld makes neither. Runs Debian's cross compilers in the gcc:13 image (Docker), without debug info; each
# -sym copy keeps its symbol table as the truth and its twin has it stripped (llvm-strip, which leaves the loaded
# bytes alone).
#   router-gnu-mips.elf / router-gnu-mipsel.elf   GCC 12, -O2, big- and little-endian
set -euo pipefail
cd "$(dirname "$0")"
docker=${DOCKER:-docker}
"$docker" run --rm -v "$PWD":/w -w /w gcc:13 bash -c '
  set -e
  apt-get update -qq >/dev/null
  apt-get install -y -qq gcc-mips-linux-gnu gcc-mipsel-linux-gnu >/dev/null 2>&1
  mips-linux-gnu-gcc -O2 -g0 -o router-gnu-mips-sym.elf router.c
  mipsel-linux-gnu-gcc -O2 -g0 -o router-gnu-mipsel-sym.elf router.c
  chown "$(stat -c %u:%g router.c)" router-gnu-mips-sym.elf router-gnu-mipsel-sym.elf'
for name in router-gnu-mips router-gnu-mipsel; do
  llvm-strip --strip-all -o "$name.elf" "$name-sym.elf"
done
python3 -I ../scrub-paths.py --check router-gnu-mips{,el}{,-sym}.elf
