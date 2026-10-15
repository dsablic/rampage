#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
if [[ $# == 0 ]]; then
    exec bash "$root/tools/ci/debug-cpp-virtual-oracle.sh" --check \
        bash "$root/tools/ci/debug-cpp-virtual-acceptance.sh" --fixtures-ready
fi
if [[ $# != 1 || $1 != --fixtures-ready ]]; then
    echo "usage: bash tools/ci/debug-cpp-virtual-acceptance.sh" >&2
    exit 2
fi
: "${RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES:?owned fixture recipe must provide the inputs}"
: "${RAMPAGE_DEBUG_CPP_VIRTUAL_ORACLE:?owned fixture recipe must provide the independent oracle}"
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
export RUST_TEST_THREADS=${RUST_TEST_THREADS:-1}
cd "$root"
cargo test --locked -p rampage-loaders --test debug_cpp_virtuals -- --include-ignored
cargo test --locked -p rampage-api --lib virtual -- --include-ignored
cargo test --locked -p rampage-worker --test debug_cpp_virtuals -- --include-ignored
cargo test --locked -p rampage-ui --test debug_cpp_virtuals virtual_review_navigation -- --include-ignored
