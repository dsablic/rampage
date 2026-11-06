#!/usr/bin/env bash
# Builds the flywheel's synthetic version-split fixtures (crates/rampage-mcp/tests/flywheel.rs): minilib v1 (the
# training version) and v2 (held out) linked into programs A and B, and a negative program, for x86-64 ELF,
# freestanding and unstripped-then-stripped with rampage-eval. Requires zig 0.17.x and a rampage-eval build.
# Usage: tests/fixtures/flywheel/build.sh [RAMPAGE_EVAL]
set -euo pipefail
cd "$(dirname "$0")"
eval_bin=${1:-../../../target/release/rampage-eval}
flags=(-target x86_64-linux-musl -O2 -g0 -ffreestanding -fno-stack-protector -fno-builtin)
link=(-nostdlib -static -Wl,-e,main)
for version in 1 2; do
    define=()
    [[ $version == 2 ]] && define=(-DMINILIB_V2)
    zig cc "${flags[@]}" "${define[@]}" -c minilib.c -o "minilib-v$version.o"
    for program in a b; do
        zig cc "${flags[@]}" -c "prog-$program.c" -o "prog-$program.o"
        zig cc "${flags[@]}" "${link[@]}" -g "prog-$program.o" "minilib-v$version.o" -o "v$version-$program.linked"
        "$eval_bin" strip --keep-symbols "v$version-$program.linked" "v$version-$program.twin.elf"
        "$eval_bin" strip "v$version-$program.linked" "v$version-$program.elf"
        rm "v$version-$program.linked"
    done
done
zig cc "${flags[@]}" -c negative.c -o negative.o
zig cc "${flags[@]}" "${link[@]}" -g negative.o -o negative.linked
"$eval_bin" strip --keep-symbols negative.linked negative.twin.elf
"$eval_bin" strip negative.linked negative.elf
rm negative.linked
ls -l *.elf *.o
