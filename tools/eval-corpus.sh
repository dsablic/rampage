#!/usr/bin/env bash
# Builds the strip-and-compare matched-pair corpus for rampage-eval's library-identification evaluation.
#
# Per architecture it emits, into OUT_DIR:
#   ref-<arch>/*.elf     symbolized reference programs (the signature database is built from these)
#   target-<arch>.elf    a different program, stripped (what gets identified)
#   truth-<arch>.json    {"0x<address>": "<name>"} from the target's symbolized twin (sized function symbols)
#   zig-version          the toolchain that produced them; a different zig can change code and hashes
#
# The stripped target is the symbolized twin with its symbols and debug sections removed in place by
# `rampage-eval strip` (relinking with --strip-all is not equivalent: zig then builds libc differently and code
# shifts). `rampage-eval truth --stripped` re-checks that every truth function's bytes are identical in both, so
# the truth addresses provably describe the stripped binary.
#
# With --fixtures it also refreshes the small committed fixture pair used by `cargo test -p rampage-eval`:
#   tests/fixtures/bin/eval-{ref,target}-<arch>.elf and tests/fixtures/data/eval-truth-<arch>.json
# The committed reference keeps its symbols but drops its debug sections, so it stays small.
#
# Requires: zig (0.17.x) and a build of rampage-eval (cargo build -p rampage-eval --release, or point
# RAMPAGE_EVAL at another build).
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
eval_bin=${RAMPAGE_EVAL:-"$repo/target/release/rampage-eval"}
if [[ ! -x "$eval_bin" ]]; then
    echo "rampage-eval not found at $eval_bin; run: cargo build -p rampage-eval --release" >&2
    exit 1
fi

zig version >"$out/zig-version"
echo "zig $(cat "$out/zig-version")"

# Every reference links the same static musl as the target; the target is not among them, so a match is
# cross-binary rather than self-identity.
references=(signatures-corpus.c "$repo/tests/fixtures/src/hello.c")
target=signatures-target.c
flags=(-O1 -static)

# (zig target triple, rampage arch tag)
targets=(
    "x86_64-linux-musl x86_64"
    "aarch64-linux-musl aarch64"
)

for entry in "${targets[@]}"; do
    read -r triple tag <<<"$entry"
    mkdir -p "$out/ref-$tag"
    for source in "${references[@]}"; do
        name=$(basename "$source" .c)
        zig cc -target "$triple" "${flags[@]}" -o "$out/ref-$tag/$name.elf" "$source"
    done
    zig cc -target "$triple" "${flags[@]}" -o "$out/target-$tag.symbolized.elf" "$target"
    "$eval_bin" strip "$out/target-$tag.symbolized.elf" "$out/target-$tag.elf"
    "$eval_bin" truth "$out/target-$tag.symbolized.elf" --stripped "$out/target-$tag.elf" >"$out/truth-$tag.json"
    count=$(grep -c '"0x' "$out/truth-$tag.json" || true)
    if [[ "$count" -eq 0 ]]; then
        echo "truth-$tag.json is empty" >&2
        exit 1
    fi
    echo "  -> ref-$tag/, target-$tag.elf, truth-$tag.json ($count functions)"

    if $fixtures; then
        mkdir -p "$repo/tests/fixtures/bin" "$repo/tests/fixtures/data"
        "$eval_bin" strip --keep-symbols "$out/ref-$tag/signatures-corpus.elf" \
            "$repo/tests/fixtures/bin/eval-ref-$tag.elf"
        cp "$out/target-$tag.elf" "$repo/tests/fixtures/bin/eval-target-$tag.elf"
        cp "$out/truth-$tag.json" "$repo/tests/fixtures/data/eval-truth-$tag.json"
        echo "  -> fixtures: eval-ref-$tag.elf, eval-target-$tag.elf, eval-truth-$tag.json"
    fi
done
