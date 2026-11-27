#!/usr/bin/env bash
# Rebuilds the parameter-type dev set (docs/plans/2026-11-27-parameter-types.md): LZ4 1.10.0 and cJSON 1.7.18,
# static against Zig's musl, `zig cc -g`, x86-64 and AArch64 at O0 and O2. For each build it writes
#   NAME.debug.elf   with DWARF (the truth source)
#   NAME.elf         the stripped twin (what is decompiled)
#   NAME.truth.json  `rampage-eval type-truth`, restricted to the functions the library's own objects define
# Usage: tools/types-dev/build.sh SOURCES_DIR OUT_DIR [RAMPAGE_EVAL]
#   SOURCES_DIR holds lz4-1.10.0-lz4-1.10.0.tar.gz and cjson-1.7.18-v1.7.18.tar.gz (target/flywheel/sources, or the
#   upstream release tarballs saved under those names). Needs zig 0.17.x, nm, python3.
set -euo pipefail
sources=$(cd "$1" && pwd)
out=$2
eval_bin=${3:-target/release/rampage-eval}
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$sources/lz4-1.10.0-lz4-1.10.0.tar.gz" -C "$work"
tar -xzf "$sources/cjson-1.7.18-v1.7.18.tar.gz" -C "$work"
printf 'int main(void){return 0;}\n' > "$work/main.c"

build() { # NAME DIR INCLUDE SOURCES...
    local name=$1 dir=$2 inc=$3; shift 3
    local arch opt triple
    for arch in x86_64 aarch64; do
        triple=$arch-linux-musl
        for opt in O0 O2; do
            local base=$out/$name-$arch-$opt objs=() names=""
            for src in "$@"; do
                local obj=$work/$name-$arch-$opt-$(basename "$src").o
                (cd "$work/$dir" && zig cc -target "$triple" "-$opt" -g -I"$inc" -c "$src" -o "$obj")
                objs+=("$obj")
                names+=$'\n'$(nm --defined-only "$obj" | awk '$2 ~ /^[Tt]$/ {print $3}')
            done
            zig cc -target "$triple" -static -g -Wl,--no-gc-sections "${objs[@]}" "$work/main.c" -o "$base.debug.elf"
            "$eval_bin" strip "$base.debug.elf" "$base.elf"
            "$eval_bin" type-truth "$base.debug.elf" --stripped "$base.elf" > "$work/full.json"
            printf '%s\n' "$names" | python3 -I -c '
import json, sys
keep = {line.lstrip("_") for line in sys.stdin.read().split() if line}
truth = json.load(open(sys.argv[1]))
kept = {a: f for a, f in truth.items() if f["name"] in keep}
json.dump(kept, open(sys.argv[2], "w"), indent=0, sort_keys=True)
' "$work/full.json" "$base.truth.json"
            echo "$base: $(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$base.truth.json") functions"
        done
    done
}
build lz4 lz4-1.10.0 lib lib/lz4.c lib/lz4hc.c lib/lz4frame.c lib/xxhash.c
build cjson cJSON-1.7.18 . cJSON.c
