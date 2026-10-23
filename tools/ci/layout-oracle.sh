#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-${RUNNER_TEMP:-/tmp}}/rampage-layout-oracle.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

compiler=${CC_LAYOUT_ORACLE:-clang}
objcopy=${RAMPAGE_OBJCOPY:-objcopy}
fixtures="$root/crates/rampage-decompiler/tests/fixtures"

"$compiler" --version
"$objcopy" --version
for fixture in layout_constants layout_use; do
  "$compiler" --target=x86_64-linux-gnu -ffreestanding -std=c11 -O2 \
    -fno-stack-protector -fno-asynchronous-unwind-tables \
    -c "$fixtures/$fixture.c" -o "$scratch/$fixture.o"
done
"$objcopy" --only-section=.rampage_layout -O binary \
  "$scratch/layout_constants.o" "$scratch/layout_constants.bin"
"$objcopy" --only-section=.text -O binary "$scratch/layout_use.o" "$scratch/layout_use.text"

export RAMPAGE_LAYOUT_CONSTANTS="$scratch/layout_constants.bin"
export RAMPAGE_LAYOUT_TEXT="$scratch/layout_use.text"
cargo test --locked --manifest-path "$root/Cargo.toml" -p rampage-decompiler --test integration -- layout:: --ignored
