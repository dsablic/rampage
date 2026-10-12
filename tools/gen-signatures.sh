#!/usr/bin/env bash
# Regenerates the bundled starter signature databases and their test fixtures.
#
# Each database names common C runtime (musl libc) functions so `rampage identify` labels library code out of
# the box. A database is specific to the exact library build it was made from, so this pins the toolchain (zig,
# which ships musl) and records the version below; rebuilding with a different zig can change the hashes.
#
# Requires: zig (0.17.x) and a release build of the rampage CLI (cargo build -p rampage-cli --release).
set -euo pipefail
cd "$(dirname "$0")"
repo=..
zig_version=$(zig version)
echo "zig ${zig_version}"

rampage=${RAMPAGE:-"$repo/target/release/rampage"}
if [[ ! -x "$rampage" ]]; then
    echo "rampage CLI not found at $rampage; run: cargo build -p rampage-cli --release" >&2
    exit 1
fi

data=$repo/crates/rampage-signatures/data
fixtures=$repo/tests/fixtures/bin
mkdir -p "$data" "$fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# (zig target triple, rampage arch tag)
targets=(
    "x86_64-linux-musl x86_64"
    "aarch64-linux-musl aarch64"
)

for entry in "${targets[@]}"; do
    read -r triple tag <<<"$entry"
    # The reference is linked with symbols so the database records real function names; the fixture is a
    # different program, stripped, so the identify test proves cross-binary matching rather than self-identity.
    zig cc -target "$triple" -O1 -static -o "$work/corpus-$tag" signatures-corpus.c
    zig cc -target "$triple" -O1 -static -Wl,--strip-all -o "$fixtures/musl-static-$tag.elf" signatures-target.c
    "$rampage" signatures "$work/corpus-$tag" --output "$data/musl-$tag.json"
    echo "  -> data/musl-$tag.json, fixtures/bin/musl-static-$tag.elf"
done
