#!/bin/sh
# Rebuilds the workflow test fixtures. Requires zig.
set -eu
cd "$(dirname "$0")"
zig cc -target x86_64-linux-gnu -O1 -g0 -o net-client-x64.elf net-client.c
zig cc -target x86_64-linux-gnu -O1 -g0 -s -o net-client-x64-stripped.elf net-client.c
