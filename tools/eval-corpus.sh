#!/usr/bin/env bash
# Builds the strip-and-compare corpus for rampage-eval: library identification (libid), function discovery and
# type (signature) recovery.
#
# Per architecture it emits, into OUT_DIR:
#   ref-<arch>/*.elf               symbolized reference programs (the signature database is built from these)
#   program-<arch>/*.o             each program's own object, naming the functions that are not library code
#   twin-<arch>.elf                the corpus reference itself, stripped: the best case, identical layout
#   target-<arch>.elf              a different program linking the same static libc, stripped
#   target-<arch>.symbolized.elf   its symbolized twin, the truth source
#   truth-twin-<arch>.json         every sized function symbol of the twin (libid-twin and discovery truth)
#   truth-cross-<arch>.json        the cross-program target's identifiable functions (libid-cross truth)
#   types-<arch>.debug.elf         types-corpus.c built with -g, freestanding: DWARF is the signature truth
#   types-<arch>.elf               its stripped twin
#   truth-types-<arch>.json        each function's return and parameter type classes, from the DWARF
#   zig-version                    the toolchain that produced them; a different zig can change code and hashes
#   manifest.json                  every slice, for: rampage-eval run --manifest OUT_DIR/manifest.json
#
# The generated manifest has no min_recall or min_precision, so its gate only rejects wrong (and, for libid,
# spurious) answers; it is for measuring. The committed tests/fixtures/data/eval-manifest.json, which holds the
# baselines, is never rewritten by this script, not even with --fixtures: after re-measuring, ratchet its floors
# by hand.
#
# Slices per arch:
#   libid-twin-<arch>    reference DB vs the reference's own stripped twin. Every byte matches, so misses are
#                        hash collisions; an upper bound, not what users see.
#   libid-cross-<arch>   reference DB vs a different program. Its copies of the same libc functions sit at other
#                        addresses, so whatever the hash fails to mask (absolute addresses) shows up as misses.
#   discovery-<arch>     discovered function starts of the stripped twin vs its sized function symbols.
#   types-{params,return,classes}-<arch>
#                        signatures the decompiler infers for the stripped types corpus vs its DWARF: parameter
#                        counts, void-versus-value returns, and each parameter's type class.
#
# The types corpus links no libc (-nostdlib, entry main; it is never run), so the truth is the program's own
# functions rather than hundreds of libc ones, and the fixtures stay small. -fdebug-prefix-map keeps the
# checkout's path out of the DWARF so the build is reproducible.
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
#   tests/fixtures/bin/eval-types-{sym,}-<arch>.elf, tests/fixtures/data/eval-truth-types-<arch>.json
#
# Requires: zig (0.17.x) and a build of rampage-eval (cargo build -p rampage-eval, or point RAMPAGE_EVAL at
# another build).
# Usage: tools/eval-corpus.sh OUT_DIR [--fixtures]
set -euo pipefail

usage() {
    echo "usage: $0 OUT_DIR [--fixtures]" >&2
    exit 2
}
fixtures=false
if [[ $# -lt 1 || $# -gt 2 || "$1" == -* ]]; then
    usage
fi
if [[ $# -eq 2 ]]; then
    [[ "$2" == "--fixtures" ]] || usage
    fixtures=true
fi
out=$(mkdir -p "$1" && cd "$1" && pwd)
eval_bin=${RAMPAGE_EVAL:-}
# A relative RAMPAGE_EVAL names a path from the caller's directory, which the cd below leaves.
[[ -z "$eval_bin" || "$eval_bin" == /* ]] || eval_bin="$PWD/$eval_bin"

cd "$(dirname "$0")"
repo=$(cd .. && pwd)
eval_bin=${eval_bin:-"$repo/target/debug/rampage-eval"}
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

# A JSON string literal holding $1.
json_string() {
    local text=${1//\\/\\\\}
    printf '"%s"' "${text//\"/\\\"}"
}

slices=()
# Appends one manifest slice: name, extra JSON fields (each followed by ", "), target file, truth file.
add_slice() {
    slices+=("$(json_string "$1"): {$2\"target\": $(json_string "$3"), \"truth\": $(json_string "$4")}")
}
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

    # Assigned first: an exit inside a command substitution only leaves the subshell, and set -e then stops on
    # the failed assignment.
    twin_count=$(count "$out/truth-twin-$tag.json")
    cross_count=$(count "$out/truth-cross-$tag.json")
    echo "  -> $tag: twin $twin_count functions, cross $cross_count identifiable"

    refs=""
    for reference in "$out/ref-$tag"/*.elf; do
        refs+="$(json_string "ref-$tag/$(basename "$reference")"), "
    done
    refs="[${refs%, }]"
    add_slice "libid-twin-$tag" "\"refs\": $refs, " "twin-$tag.elf" "truth-twin-$tag.json"
    add_slice "libid-cross-$tag" "\"refs\": $refs, " "target-$tag.elf" "truth-cross-$tag.json"
    add_slice "discovery-$tag" '"family": "discovery", ' "twin-$tag.elf" "truth-twin-$tag.json"

    zig cc -target "$triple" -O1 -g -nostdlib -ffreestanding -static -Wl,-e,main -fdebug-prefix-map="$repo"=. \
        -o "$out/types-$tag.debug.elf" types-corpus.c
    "$eval_bin" strip "$out/types-$tag.debug.elf" "$out/types-$tag.elf"
    "$eval_bin" type-truth "$out/types-$tag.debug.elf" --stripped "$out/types-$tag.elf" >"$out/truth-types-$tag.json"
    types_count=$(count "$out/truth-types-$tag.json")
    echo "  -> $tag: types $types_count functions"
    for metric in params return classes; do
        add_slice "types-$metric-$tag" "\"family\": \"types\", \"metric\": \"$metric\", " "types-$tag.elf" \
            "truth-types-$tag.json"
    done

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
        cp "$out/types-$tag.debug.elf" "$bin/eval-types-sym-$tag.elf"
        cp "$out/types-$tag.elf" "$bin/eval-types-$tag.elf"
        "$eval_bin" type-truth "$bin/eval-types-sym-$tag.elf" --stripped "$bin/eval-types-$tag.elf" \
            >"$data/eval-truth-types-$tag.json"
        echo "  -> fixtures: eval-{ref,twin,target,target-sym,types,types-sym}-$tag.elf, eval-program-*-$tag.o," \
            "eval-truth-{twin,cross,types}-$tag.json"
    fi
done

{
    echo '{"slices": {'
    (IFS=$'\n'; echo "${slices[*]}") | sed '$!s/$/,/'
    echo '}}'
} >"$out/manifest.json"
echo "  -> manifest.json"
