#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild only the freestanding compiler-generated switch acceptance fixtures.
set -euo pipefail
cd "$(dirname "$0")"
zig version
zig cc --version -o /dev/null
set -x
zig cc -target x86-linux-musl -O2 -g0 -fPIC -ffreestanding -nostdlib -shared \
  -Wl,--build-id=none -o bin/switch-pic-i386.so src/switch_pic.c
# AArch64's higher default threshold would turn this compact eight-case fixture into a branch tree.
zig cc -target aarch64-linux-musl -O2 -g0 -fPIC -ffreestanding -nostdlib -shared \
  -mllvm -aarch64-min-jump-table-entries=4 -DSCHEDULED_GUARD \
  -Wl,--build-id=none -o bin/switch-scheduled-arm64.so src/switch_pic.c
zig cc -target aarch64-linux-musl -O2 -g0 -fPIC -ffreestanding -nostdlib -shared \
  -mllvm -aarch64-min-jump-table-entries=4 -DINVERSE_GUARD \
  -Wl,--build-id=none -o bin/switch-inverse-arm64.so src/switch_pic.c
