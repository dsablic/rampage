#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the suite-v3 Go fixture: restic (BSD-2-Clause) at a pinned module version, compiled from the Go module
# proxy's checksummed source with the Go toolchain upstream released it with (go1.23.3, read from the official
# v0.17.3 linux-amd64 binary with `go version`), into target/bench/v3/go/. Nothing here is committed.
# Ghidra 12.2's Go support covers Go 1.15-1.26, so its Go analyzers apply to this build.
#
#   restic-x64.elf           unstripped twin (symbol table and DWARF): the truth source, never given to an agent
#   restic-x64-stripped.elf  `-s -w` build of the same source: what the agent analyzes (pclntab and runtime
#                            type data stay, as in any Go binary)
#
# Module integrity comes from go.sum plus the public checksum database (GONOSUMDB unset, GOFLAGS=-mod=readonly).
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
out="$root/target/bench/v3/go"
work="$out/work"
module=github.com/restic/restic
version=v0.17.3
mkdir -p "$work"
export GOPATH="$work/gopath" GOMODCACHE="$work/gopath/pkg/mod" GOFLAGS="-modcacherw -trimpath" GOTOOLCHAIN=go1.23.3
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
go version
go version | grep -q "go1.23.3 " || { echo "expected go1.23.3" >&2; exit 1; }
go mod download -json "$module@$version" > "$work/module.json"
src="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["Dir"])' "$work/module.json")"
cd "$src"
go build -mod=readonly -buildvcs=false -o "$out/restic-x64.elf" ./cmd/restic
go build -mod=readonly -buildvcs=false -ldflags "-s -w" -o "$out/restic-x64-stripped.elf" ./cmd/restic
ls -l "$out"/restic-x64*.elf
shasum -a 256 "$out"/restic-x64*.elf
