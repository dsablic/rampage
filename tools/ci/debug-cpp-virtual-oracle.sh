#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
exec bash "$root/tests/fixtures/debug-cpp-virtuals/build.sh" "$@"
