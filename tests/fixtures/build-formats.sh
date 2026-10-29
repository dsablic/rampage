#!/usr/bin/env bash
# Rebuilds the WebAssembly and PyInstaller fixtures for wasm_module and pyinstaller_archive. Requires zig and python3.
set -euo pipefail
cd "$(dirname "$0")"
zig version
# -g0 keeps DWARF (and the build path) out; the linker still writes the name section (the module name is the output
# file name) and clang the producers section, which names the clang zig embeds (Homebrew's zig reports "Homebrew
# clang"). Rebuilding with the same zig reproduces bin/module.wasm byte for byte.
zig cc -target wasm32-freestanding -O1 -g0 -nostdlib -Wl,--no-entry -Wl,--export-memory \
  -o bin/module.wasm src/wasm-module.c
python3 craft_formats.py bin
