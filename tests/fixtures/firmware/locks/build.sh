#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the lock-mechanism fixtures from the sources in this directory:
#   ../raw-cortex-m-locks.bin  flash image of firmware.c (Cortex-M3, base 0x08000000, vector table at offset 0)
#   ../raw-cortex-m-locks.elf  the same with symbols, the test truth for addresses
#   ../locks-x64.elf           host.c for x86-64 Linux, dynamically linked, stripped
#   ../locks-x64-sym.elf       the same with symbols, the test truth for addresses
# The crypto is checked first by a native self-test (selftest.c) against standard vectors and the synthetic
# signatures in test_keys.c. Needs zig and llvm-objcopy.
set -euo pipefail
cd "$(dirname "$0")"
zig version
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
set -x
zig cc -O2 -Wall -Wextra -Werror -o "$scratch/selftest" selftest.c hash.c pk.c test_keys.c
"$scratch/selftest"
common=(-O2 -g0 -Wall -Wextra -Werror -ffunction-sections -fdata-sections -fno-unwind-tables
  -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,--gc-sections)
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 "${common[@]}" -ffreestanding -nostdlib -fno-builtin \
  -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,firmware.ld -o ../raw-cortex-m-locks.elf \
  firmware.c hash.c pk.c test_keys.c runtime.c
llvm-objcopy -O binary -j .text -j .rodata ../raw-cortex-m-locks.elf ../raw-cortex-m-locks.bin
zig cc -target x86_64-linux-gnu.2.28 "${common[@]}" -o ../locks-x64-sym.elf host.c hash.c pk.c test_keys.c
llvm-objcopy --strip-all ../locks-x64-sym.elf ../locks-x64.elf
chmod -x ../raw-cortex-m-locks.bin
