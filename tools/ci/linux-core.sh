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
export RUST_SYSROOT="$(rustc --print sysroot)"
export RUST_HOST="$(rustc --version --verbose | sed -n 's/^host: //p')"
DEBUG_LAYOUT_CPP=1 OBJCOPY=objcopy bash tools/ci/debug-layout-oracle.sh --check \
  cargo test --locked -p rampage-loaders --test integration -- debug_layouts:: --include-ignored
OBJCOPY=objcopy bash tools/ci/debug-cpp-layout-oracle.sh --check \
  cargo test --locked -p rampage-loaders --test integration -- debug_cpp_layouts:: --include-ignored
