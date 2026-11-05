#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the Windows debug fixtures with zig (its MinGW-w64 target, which links with LLD): pe-loop-x64.exe and
# pe-loop-x86.exe, small console programs without a C runtime. Each is ASLR-enabled (DYNAMIC_BASE, a .reloc
# section, with base relocations in .text and .data) and carries a CodeView (RSDS) debug record naming its PDB,
# which LLD writes with -g. The PDBs are not kept: the RSDS GUID and age are what binding compares.
set -euo pipefail
cd "$(dirname "$0")"
zig version
set -x
common=(-O1 -g -nostdlib -Wl,--subsystem,console -Wl,--dynamicbase -lkernel32)
zig cc -target x86_64-windows-gnu "${common[@]}" -Wl,--entry=start -Wl,--high-entropy-va -o pe-loop-x64.exe pe-loop.c
zig cc -target x86-windows-gnu "${common[@]}" -Wl,--entry=start -o pe-loop-x86.exe pe-loop.c
rm -f pe-loop-x64.pdb pe-loop-x86.pdb pe-loop-x64.lib pe-loop-x86.lib pe-loop.lib
