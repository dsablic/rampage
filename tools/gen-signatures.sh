#!/usr/bin/env bash
# Regenerates the bundled starter signature databases and their test fixtures.
#
# Each database names common C runtime (musl libc) functions so `rampage identify` labels library code out of
# the box. A database is specific to the exact library build it was made from, so this pins the toolchain (zig,
# which ships musl) and writes its version to crates/rampage-signatures/data/zig-version; rebuilding with a
# different zig can change the hashes.
#
# Overwrites crates/rampage-signatures/data/musl-<arch>.json and the committed identify fixtures
# tests/fixtures/bin/musl-static-<arch>.elf.
#
# Requires: zig (0.17.x) and a build of the rampage CLI: target/release/rampage by default, or any other build
# (such as target/debug/rampage from `cargo build -p rampage-cli`) through RAMPAGE.
set -euo pipefail
rampage=${RAMPAGE:-}
# A relative RAMPAGE names a path from the caller's directory, which the cd below leaves.
[[ -z "$rampage" || "$rampage" == /* ]] || rampage="$PWD/$rampage"
cd "$(dirname "$0")"
repo=..

rampage=${rampage:-"$repo/target/release/rampage"}
if [[ ! -x "$rampage" ]]; then
    echo "rampage CLI not found at $rampage; run: cargo build -p rampage-cli --release," \
        "or point RAMPAGE at another build (e.g. RAMPAGE=target/debug/rampage)" >&2
    exit 1
fi

data=$repo/crates/rampage-signatures/data
fixtures=$repo/tests/fixtures/bin
mkdir -p "$data" "$fixtures"
zig version >"$data/zig-version"
echo "zig $(cat "$data/zig-version")"
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
