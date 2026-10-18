#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
fi

root=$(cd "$(dirname "$0")/../../.." && pwd)
zig=${ZIG:-zig}
evaluator=${RAMPAGE_EVAL:-"$root/target/debug/rampage-eval"}
if [[ "$("$zig" version)" != 0.17.0 ]]; then
    echo "this owned fixture requires Zig 0.17.0" >&2
    exit 2
fi
if [[ ! -x "$evaluator" ]]; then
    echo "build rampage-eval or set RAMPAGE_EVAL" >&2
    exit 2
fi
mkdir -p "$1"
output=$(cd "$1" && pwd)
if [[ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "output directory must be empty" >&2
    exit 2
fi

export SOURCE_DATE_EPOCH=0
export ZIG_GLOBAL_CACHE_DIR="$output/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$output/zig-local-cache"
source="$root/tests/fixtures/src/arm-exidx-starts.c"
for policy in distinct coalesced; do
    flags=()
    if [[ "$policy" == distinct ]]; then flags+=(-DRAMPAGE_DISTINCT_UNWIND); fi
    "$zig" cc -target thumb-linux-musleabi -O1 -g0 -fno-lto -funwind-tables -fno-omit-frame-pointer \
        -static -no-pie -Wl,--no-gc-sections "${flags[@]}" "-ffile-prefix-map=$root=." \
        "$source" -o "$output/arm-exidx-$policy.elf"
    "$evaluator" strip "$output/arm-exidx-$policy.elf" "$output/arm-exidx-$policy.stripped.elf"
done
