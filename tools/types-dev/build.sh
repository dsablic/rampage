#!/usr/bin/env bash
# Rebuilds the parameter-type dev set (docs/plans/2026-11-27-parameter-types.md): LZ4 1.10.0 and cJSON 1.7.18,
# static against Zig's musl, `zig cc -g`, x86-64 and AArch64 at O0 and O2. SET `acceptance` builds the plan's
# acceptance input instead, never tuned on: zstd 1.5.5 (lib/common, lib/compress, lib/decompress, ZSTD_DISABLE_ASM),
# inih r58 and tinyexpr 1.1.1, at O2 only. For each build it writes
#   NAME.debug.elf   with DWARF (the truth source)
#   NAME.elf         the stripped twin (what is decompiled)
#   NAME.truth.json  `rampage-eval type-truth`, restricted to the functions the library's own objects define
# Usage: tools/types-dev/build.sh SOURCES_DIR OUT_DIR [RAMPAGE_EVAL] [dev|acceptance]
#   SOURCES_DIR holds the release tarballs under the names target/flywheel/sources uses:
#   lz4-1.10.0-lz4-1.10.0.tar.gz, cjson-1.7.18-v1.7.18.tar.gz (dev); zstd-1.5.5-zstd-1.5.5.tar.gz,
#   inih-r58-r58.tar.gz, tinyexpr-1.1.1-v1.1.1.tar.gz (acceptance). Needs zig 0.17.x, nm, python3.
set -euo pipefail
export LC_ALL=C # globs and sort order, so the zstd source list is the same everywhere
sources=$(cd "$1" && pwd)
out=$2
eval_bin=${3:-target/release/rampage-eval}
set_name=${4:-dev}
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf 'int main(void){return 0;}\n' > "$work/main.c"

build() { # NAME DIR "OPT..." "CFLAG..." SOURCES...
    local name=$1 dir=$2 opts=$3 cflags=$4; shift 4
    local arch opt triple
    for arch in x86_64 aarch64; do
        triple=$arch-linux-musl
        for opt in $opts; do
            local base=$out/$name-$arch-$opt objs=() names=""
            for src in "$@"; do
                local obj=$work/$name-$arch-$opt-$(basename "$src").o
                # shellcheck disable=SC2086 # cflags is a word list
                (cd "$work/$dir" && zig cc -target "$triple" "-$opt" -g $cflags -c "$src" -o "$obj")
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
case $set_name in
dev)
    tar -xzf "$sources/lz4-1.10.0-lz4-1.10.0.tar.gz" -C "$work"
    tar -xzf "$sources/cjson-1.7.18-v1.7.18.tar.gz" -C "$work"
    build lz4 lz4-1.10.0 "O0 O2" "-Ilib" lib/lz4.c lib/lz4hc.c lib/lz4frame.c lib/xxhash.c
    build cjson cJSON-1.7.18 "O0 O2" "-I." cJSON.c
    ;;
acceptance)
    tar -xzf "$sources/zstd-1.5.5-zstd-1.5.5.tar.gz" -C "$work"
    tar -xzf "$sources/inih-r58-r58.tar.gz" -C "$work"
    tar -xzf "$sources/tinyexpr-1.1.1-v1.1.1.tar.gz" -C "$work"
    zstd_sources=()
    for src in "$work"/zstd-1.5.5/lib/{common,compress,decompress}/*.c; do
        zstd_sources+=("${src#"$work/zstd-1.5.5/"}")
    done
    build zstd zstd-1.5.5 O2 "-Ilib -DZSTD_DISABLE_ASM" "${zstd_sources[@]}"
    build inih inih-r58 O2 "-I." ini.c
    build tinyexpr tinyexpr-1.1.1 O2 "-I." tinyexpr.c
    ;;
*)
    echo "unknown set $set_name: dev or acceptance" >&2
    exit 2
    ;;
esac
