#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the bare-metal Cortex-M3 firmware fixture for live QEMU (lm3s6965evb) debugger tests.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
zig cc -target thumb-freestanding-eabi -mcpu=cortex_m3 -O1 -g0 -ffreestanding -nostdlib \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Wl,--build-id=none -Wl,--nmagic -Wl,-e,reset_handler -Wl,-T,cortex-m3.ld -Wl,-s -o cortex-m3.elf cortex-m3.c
