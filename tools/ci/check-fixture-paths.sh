#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fails if a committed fixture names a build machine's local directory: /Users/..., /home/<name>/... (the generic
# /home/user/ is allowed, as invented test data) or a macOS temporary directory (/var/folders/...). Debug info,
# Go file tables, PDB source paths and debug maps all pick these up unless a build remaps them; the build scripts
# remap and check their own outputs (tests/fixtures/zig-env.sh), and this catches whatever slips past.
#
# Checks every tracked file under tests/fixtures, crates/*/tests/fixtures and tools/*-fixture. Build and generator
# scripts (*.sh, *.py) are allowed: they name these patterns to check for them.
set -euo pipefail
cd "$(dirname "$0")/../.."
git ls-files -z -- tests/fixtures 'crates/*/tests/fixtures/*' 'tools/*-fixture/*' | python3 -I -c '
import re
import sys

LOCAL = re.compile(rb"/Users/[^/\0\s]|/home/(?!user/)[a-z][a-z0-9_.-]*/|/var/folders/")
ALLOWED = (".sh", ".py")
found = 0
for name in sys.stdin.buffer.read().split(b"\0"):
    if not name or name.endswith(tuple(suffix.encode() for suffix in ALLOWED)):
        continue
    with open(name, "rb") as handle:
        data = handle.read()
    for match in LOCAL.finditer(data):
        end = min(len(data), match.start() + 80)
        text = data[match.start():end].split(b"\0")[0].decode("utf-8", "replace")
        print(f"{name.decode()}: offset {match.start():#x}: {text}", file=sys.stderr)
        found += 1
        break
if found:
    print(f"{found} committed fixture(s) hold a local path; rebuild them with the prefix maps their build script "
          "uses (see tests/fixtures/zig-env.sh)", file=sys.stderr)
    sys.exit(1)
print("no committed fixture holds a local path")
'
