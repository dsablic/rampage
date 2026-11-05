#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the debug correlation fixture: a freestanding x86-64 PIE with a GNU build ID and symbols.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
zig cc -target x86_64-linux-none -O1 -g0 -ffreestanding -nostdlib -fPIE -pie \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Wl,--build-id=sha1 -Wl,-e,_start -o correlation-x64.elf correlation-a.c correlation-b.c
