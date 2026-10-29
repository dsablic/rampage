#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild only the pe_resources/pe_load_config fixtures: a Windows program with a VERSIONINFO block, a manifest, a
# string table and a named custom resource (zig's built-in resource compiler), and a hand-written load config that
# the linker publishes from `_load_config_used`. zig's linker cannot emit the CET debug entry; unit tests cover it.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
zig cc -target x86_64-windows-gnu -O1 -g0 -o bin/pe-metadata-x64.exe src/pe-load-config.c src/pe-resources.rc
zig cc -target x86-windows-gnu -O1 -g0 -o bin/pe-metadata-x86.exe src/pe-load-config.c src/pe-resources.rc
rm -f bin/pe-metadata-x64.pdb bin/pe-metadata-x86.pdb
