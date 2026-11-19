#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the lock-mechanism fixtures from the sources in this directory:
#   ../raw-cortex-m-locks.bin  flash image of firmware.c (Cortex-M3, base 0x08000000, vector table at offset 0)
#   ../raw-cortex-m-locks.elf  the same with symbols, the test truth for addresses
#   ../locks-x64.elf           host.c for x86-64 Linux, dynamically linked, stripped
#   ../locks-x64-sym.elf       the same with symbols, the test truth for addresses
#   ../locks-x64-O0.elf        host.c unoptimized, stripped (../locks-x64-O0-sym.elf keeps the symbols)
#   ../locks-x64-noplt.elf     host.c calling imports through GOT slots (-fno-plt), stripped (-sym keeps them)
#   ../locks-negative-x64.elf  negative.c, stripped (-sym keeps the symbols): crypto that decides nothing
# The crypto is checked first by a native self-test (selftest.c) against standard vectors and the synthetic
# signatures in test_keys.c. Needs the zig pinned in crates/rampage-signatures/data/zig-version (set ZIG to it when
# the one on PATH is another release) and llvm-objcopy. Zig's own start files name local directories in their debug
# info whatever the prefix map says: scrub (../../zig-env.sh) blanks them in the -sym builds and fails if any local
# path is left.
set -euo pipefail
cd "$(dirname "$0")"
repo=$(cd ../../../.. && pwd -P)
. ../../zig-env.sh
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"; zig_cleanup' EXIT
zig() {
  "$zig" "$@"
}
set -x
zig cc -O2 -Wall -Wextra -Werror -o "$scratch/selftest" selftest.c hash.c pk.c test_keys.c
"$scratch/selftest"
common=("-ffile-prefix-map=$PWD=." -O2 -g0 -Wall -Wextra -Werror -ffunction-sections -fdata-sections -fno-unwind-tables
  -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,--gc-sections)
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 "${common[@]}" -ffreestanding -nostdlib -fno-builtin \
  -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,firmware.ld -o ../raw-cortex-m-locks.elf \
  firmware.c hash.c pk.c test_keys.c runtime.c
llvm-objcopy -O binary -j .text -j .rodata ../raw-cortex-m-locks.elf ../raw-cortex-m-locks.bin
zig cc -target x86_64-linux-gnu.2.28 "${common[@]}" -o ../locks-x64-sym.elf host.c hash.c pk.c test_keys.c
llvm-objcopy --strip-all ../locks-x64-sym.elf ../locks-x64.elf
host=("-ffile-prefix-map=$PWD=." -target x86_64-linux-gnu.2.28 -g0 -fno-sanitize=all -Wall -Wextra -Werror -fno-unwind-tables -fno-asynchronous-unwind-tables
  -Wl,--build-id=none)
zig cc "${host[@]}" -O0 -o ../locks-x64-O0-sym.elf host.c hash.c pk.c test_keys.c
zig cc "${host[@]}" -O2 -fno-plt -o ../locks-x64-noplt-sym.elf host.c hash.c pk.c test_keys.c
zig cc "${host[@]}" -O2 -o ../locks-negative-x64-sym.elf negative.c hash.c pk.c
scrub ../raw-cortex-m-locks.elf ../locks-x64-sym.elf ../locks-x64-O0-sym.elf ../locks-x64-noplt-sym.elf \
  ../locks-negative-x64-sym.elf
for name in locks-x64-O0 locks-x64-noplt locks-negative-x64; do
  llvm-objcopy --strip-all "../$name-sym.elf" "../$name.elf"
done
chmod -x ../raw-cortex-m-locks.bin
