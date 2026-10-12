#!/usr/bin/env bash
# Builds the strip-and-compare corpus for rampage-eval: library identification (libid) and function discovery.
#
# Per architecture it emits, into OUT_DIR:
#   ref-<arch>/*.elf               symbolized reference programs (the signature database is built from these)
#   program-<arch>/*.o             each program's own object, naming the functions that are not library code
#   twin-<arch>.elf                the corpus reference itself, stripped: the best case, identical layout
#   target-<arch>.elf              a different program linking the same static libc, stripped
#   target-<arch>.symbolized.elf   its symbolized twin, the truth source
#   truth-twin-<arch>.json         every sized function symbol of the twin (libid-twin and discovery truth)
#   truth-cross-<arch>.json        the cross-program target's identifiable functions (libid-cross truth)
#   zig-version                    the toolchain that produced them; a different zig can change code and hashes
#   manifest.json                  every slice, for: rampage-eval run --manifest OUT_DIR/manifest.json
#
# Slices per arch:
#   libid-twin-<arch>    reference DB vs the reference's own stripped twin. Every byte matches, so misses are
#                        hash collisions; an upper bound, not what users see.
#   libid-cross-<arch>   reference DB vs a different program. Its copies of the same libc functions sit at other
#                        addresses, so whatever the hash fails to mask (absolute addresses) shows up as misses.
#   discovery-<arch>     discovered function starts of the stripped twin vs its sized function symbols.
#
# A libid truth holds only identifiable code. The twin is a reference, so all of it is (its `main` included).
# The cross truth keeps the target's functions whose name a reference also defines, minus the programs' own
# functions (`rampage-eval truth --library --program`): a name match alone would keep `main`, which every
# program defines but no library signature can describe.
#
# A stripped binary is its symbolized twin with symbols and debug sections removed in place by
# `rampage-eval strip` (relinking with --strip-all is not equivalent: zig then builds libc differently and code
# shifts). `rampage-eval truth --stripped` re-checks that every truth function's bytes are identical in both.
#
# With --fixtures it also refreshes the committed fixtures used by `cargo test -p rampage-eval`, from the corpus
# reference alone (the committed references keep their symbols but drop debug sections, so they stay small):
#   tests/fixtures/bin/eval-{ref,twin,target,target-sym}-<arch>.elf, eval-program-{corpus,target}-<arch>.o
#   tests/fixtures/data/eval-truth-{twin,cross}-<arch>.json
#
# Requires: zig (0.17.x) and a build of rampage-eval (cargo build -p rampage-eval, or point RAMPAGE_EVAL at
# another build).
# Usage: tools/eval-corpus.sh OUT_DIR [--fixtures]
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 OUT_DIR [--fixtures]" >&2
    exit 2
fi
out=$(mkdir -p "$1" && cd "$1" && pwd)
fixtures=false
[[ "${2:-}" == "--fixtures" ]] && fixtures=true

cd "$(dirname "$0")"
repo=$(cd .. && pwd)
eval_bin=${RAMPAGE_EVAL:-"$repo/target/debug/rampage-eval"}
if [[ ! -x "$eval_bin" ]]; then
    echo "rampage-eval not found at $eval_bin; run: cargo build -p rampage-eval" >&2
    exit 1
fi

zig version >"$out/zig-version"
echo "zig $(cat "$out/zig-version")"

# Every reference links the same static musl as the target; the target is not among them, so a cross match is
# cross-binary rather than self-identity.
references=(signatures-corpus.c "$repo/tests/fixtures/src/hello.c")
target=signatures-target.c
flags=(-O1 -static)

# (zig target triple, rampage arch tag)
targets=(
    "x86_64-linux-musl x86_64"
    "aarch64-linux-musl aarch64"
)

count() {
    local n
    n=$(grep -c '"0x' "$1" || true)
    if [[ "$n" -eq 0 ]]; then
        echo "$1 is empty" >&2
        exit 1
    fi
    echo "$n"
}

slices=()
for entry in "${targets[@]}"; do
    read -r triple tag <<<"$entry"
    mkdir -p "$out/ref-$tag" "$out/program-$tag"
    programs=()
    for source in "${references[@]}" "$target"; do
        name=$(basename "$source" .c)
        # Only the function names matter, so no debug info.
        zig cc -target "$triple" -O1 -g0 -c -o "$out/program-$tag/$name.o" "$source"
        programs+=(--program "$out/program-$tag/$name.o")
    done
    for source in "${references[@]}"; do
        name=$(basename "$source" .c)
        zig cc -target "$triple" "${flags[@]}" -o "$out/ref-$tag/$name.elf" "$source"
    done
    library=()
    for reference in "$out/ref-$tag"/*.elf; do
        library+=(--library "$reference")
    done

    "$eval_bin" strip "$out/ref-$tag/signatures-corpus.elf" "$out/twin-$tag.elf"
    "$eval_bin" truth "$out/ref-$tag/signatures-corpus.elf" --stripped "$out/twin-$tag.elf" >"$out/truth-twin-$tag.json"

    zig cc -target "$triple" "${flags[@]}" -o "$out/target-$tag.symbolized.elf" "$target"
    "$eval_bin" strip "$out/target-$tag.symbolized.elf" "$out/target-$tag.elf"
    "$eval_bin" truth "$out/target-$tag.symbolized.elf" --stripped "$out/target-$tag.elf" \
        "${library[@]}" "${programs[@]}" >"$out/truth-cross-$tag.json"

    echo "  -> $tag: twin $(count "$out/truth-twin-$tag.json") functions," \
        "cross $(count "$out/truth-cross-$tag.json") identifiable"

    refs=$(cd "$out" && printf '"%s", ' ref-"$tag"/*.elf)
    refs="[${refs%, }]"
    slice() { # name, extra fields, target, truth
        slices+=("\"$1-$tag\": {$2\"target\": \"$3-$tag.elf\", \"truth\": \"truth-$4-$tag.json\"}")
    }
    slice libid-twin "\"refs\": $refs, " twin twin
    slice libid-cross "\"refs\": $refs, " target cross
    slice discovery '"family": "discovery", ' twin twin

    if $fixtures; then
        bin="$repo/tests/fixtures/bin"
        data="$repo/tests/fixtures/data"
        mkdir -p "$bin" "$data"
        "$eval_bin" strip --keep-symbols "$out/ref-$tag/signatures-corpus.elf" "$bin/eval-ref-$tag.elf"
        "$eval_bin" strip "$bin/eval-ref-$tag.elf" "$bin/eval-twin-$tag.elf"
        cp "$out/target-$tag.elf" "$bin/eval-target-$tag.elf"
        "$eval_bin" strip --keep-symbols "$out/target-$tag.symbolized.elf" "$bin/eval-target-sym-$tag.elf"
        cp "$out/program-$tag/signatures-corpus.o" "$bin/eval-program-corpus-$tag.o"
        cp "$out/program-$tag/signatures-target.o" "$bin/eval-program-target-$tag.o"
        # The committed slices build their database from the corpus reference only.
        fixture_truth=(--library "$bin/eval-ref-$tag.elf"
            --program "$bin/eval-program-corpus-$tag.o" --program "$bin/eval-program-target-$tag.o")
        "$eval_bin" truth "$bin/eval-ref-$tag.elf" --stripped "$bin/eval-twin-$tag.elf" \
            >"$data/eval-truth-twin-$tag.json"
        "$eval_bin" truth "$bin/eval-target-sym-$tag.elf" --stripped "$bin/eval-target-$tag.elf" \
            "${fixture_truth[@]}" >"$data/eval-truth-cross-$tag.json"
        echo "  -> fixtures: eval-{ref,twin,target,target-sym}-$tag.elf, eval-program-*-$tag.o," \
            "eval-truth-{twin,cross}-$tag.json"
    fi
done

{
    echo '{"slices": {'
    (IFS=$'\n'; echo "${slices[*]}") | sed '$!s/$/,/'
    echo '}}'
} >"$out/manifest.json"
echo "  -> manifest.json"
