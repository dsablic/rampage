#!/bin/bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$root"
output="${1:-target/phase2-3-first/corpus}"
clang="${FUZZY_CLANG:-/opt/homebrew/opt/llvm@22/bin/clang}"
linker="${FUZZY_LLD:-/opt/homebrew/opt/lld@22/bin/ld.lld}"
strip="${FUZZY_STRIP:-/opt/homebrew/opt/llvm@22/bin/llvm-strip}"
source="tests/fixtures/src/signature-fuzzy-corpus.c"
if [[ -e "$output/build-manifest.txt" || -e "$output/reference.elf" ]]; then
    printf '%s\n' 'Refusing to overwrite an existing corpus attempt; use a fresh output directory.' >&2
    exit 1
fi
mkdir -p "$output"
flags=(--target=x86_64-unknown-linux-gnu "-fuse-ld=$linker" -std=c11 -nostdlib -fno-builtin
    -fno-stack-protector -fno-pie -no-pie -Wl,--build-id=none -Wl,-e,_start -Wl,-Ttext=0x401000)
"$clang" --version > "$output/compiler-version.txt"
"$linker" --version > "$output/linker-version.txt"
"$strip" --version > "$output/strip-version.txt"
{
    printf 'source=%s\n' "$source"
    printf 'compiler=%s\nlinker=%s\nstrip=%s\n' "$clang" "$linker" "$strip"
    printf 'reference_command: '; printf '%q ' "$clang" "${flags[@]}" -O2 -DREFERENCE_ONLY=1 "$source"
    printf '\ncalibration_command: '; printf '%q ' "$clang" "${flags[@]}" -O1 "$source"
    printf '\nheldout_command: '; printf '%q ' "$clang" "${flags[@]}" -Os "$source"
    printf '\nNative ELF code is never executed.\n'
    shasum -a 256 "$source" "$clang" "$linker" "$strip"
} > "$output/build-manifest.txt"
"$clang" "${flags[@]}" -O2 -DREFERENCE_ONLY=1 "$source" -o "$output/reference.elf" \
    > "$output/reference.compiler.log" 2>&1
"$clang" "${flags[@]}" -O1 "$source" -o "$output/calibration.elf" \
    > "$output/calibration.compiler.log" 2>&1
"$clang" "${flags[@]}" -Os "$source" -o "$output/heldout.elf" \
    > "$output/heldout.compiler.log" 2>&1
"$strip" --strip-all -o "$output/calibration.stripped.elf" "$output/calibration.elf"
"$strip" --strip-all -o "$output/heldout.stripped.elf" "$output/heldout.elf"
shasum -a 256 "$output/"*.elf >> "$output/build-manifest.txt"
