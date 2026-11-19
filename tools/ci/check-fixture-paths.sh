#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fails if any tracked file names a build machine's local directory: /Users/<name>, /home/<name>/ (the generic
# /home/user/ is allowed), /var/folders/ or /private/tmp/ (macOS temporary directories) or C:\Users\. Debug info,
# Go file tables, PDB source paths and debug maps all pick these up unless a build remaps them. The definition is
# tests/fixtures/scrub-paths.py --check, which the fixture build scripts also run on their own outputs.
#
# Allowed: the files below, each of which holds a deliberate made-up path (documentation examples, test data for
# path handling) or the patterns themselves. Add a file only for such a path, never for a leaked one.
set -euo pipefail
cd "$(dirname "$0")/../.."
allowed=(
  README.md                                               # install example: /Users/you/.local/bin
  crates/rampage-api/src/workflows/persistence_surface.rs # test data: /home/u/.config/systemd unit paths
  crates/rampage-api/tests/debug_debugserver.rs           # test data: /Users/op/debug-macho module path
  crates/rampage-debug/src/fake.rs                        # fake debugger's module path, /Users/op/...
  crates/rampage-detect/src/matcher.rs                    # test data: /home/me/zig-0.17.0 debug path
  plugins/triage-report/src/lib.rs                        # test data: /Users/builder/source.cc
  tests/fixtures/scrub-paths.py                           # the patterns
  tools/agent-bench/test_claude_runner.py                 # test data: /home/u home directory
  tools/ci/check-fixture-paths.sh                         # this file
)
excluded=()
for file in "${allowed[@]}"; do
  excluded+=(":!:$file")
done
if git ls-files -z -- . "${excluded[@]}" | python3 -I tests/fixtures/scrub-paths.py --check --files-from -; then
  echo "no tracked file holds a local path"
else
  echo "rebuild the files above with the prefix maps their build scripts use (see tests/fixtures/zig-env.sh)" >&2
  exit 1
fi
