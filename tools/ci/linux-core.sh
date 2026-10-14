#!/usr/bin/env bash
set -euo pipefail

packages=(
  -p rampage-arch
  -p rampage-loaders
  -p rampage-analysis
  -p rampage-signatures
  -p rampage-capabilities
  -p rampage-detect
  -p rampage-constants
  -p rampage-decompiler
  -p armgen
)

time cargo clippy --locked "${packages[@]}" --all-targets -- -D warnings
time cargo test --locked "${packages[@]}"
time bash tools/ci/layout-oracle.sh
