#!/usr/bin/env bash
# Rebuilds the packed fixtures: UPX (5.3.0, `brew install upx`) output of the repository's own fixtures, for the
# encrypted-or-packed code tests. Kept out of bin/ so the fixture-wide checks that expect ordinary code skip them.
set -euo pipefail
cd "$(dirname "$0")"
upx -q -f -o upx-musl-static-x86_64.elf ../bin/musl-static-x86_64.elf
upx -q -f -o upx-hello-x64.exe ../bin/hello-x64.exe
