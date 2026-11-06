#!/usr/bin/env bash
# Build the suite-v2 scale fixture: Hugo (Apache-2.0) at a pinned module version, compiled from the Go module
# proxy's checksummed source with the Go toolchain upstream released it with (go1.23.4, read from the official
# v0.140.0 linux-amd64 binary with `go version`), into target/bench/v2/scale/. Nothing here is committed.
# Ghidra 12.2's Go support covers Go 1.15-1.26; a newer host toolchain would leave it unable to name anything.
#
#   hugo-x64.elf           unstripped twin (symbol table and DWARF): the truth source, never given to an agent
#   hugo-x64-stripped.elf  `-s -w` build of the same source: what the agent analyzes (pclntab stays, as in any
#                          Go binary)
#
# Module integrity comes from go.sum plus the public checksum database (GONOSUMDB unset, GOFLAGS=-mod=readonly).
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
out="$root/target/bench/v2/scale"
work="$out/work"
module=github.com/gohugoio/hugo
version=v0.140.0
mkdir -p "$work"
export GOPATH="$work/gopath" GOMODCACHE="$work/gopath/pkg/mod" GOFLAGS="-modcacherw -trimpath" GOTOOLCHAIN=go1.23.4
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
go version
go version | grep -q "go1.23.4 " || { echo "expected go1.23.4" >&2; exit 1; }
go mod download -json "$module@$version" > "$work/module.json"
src="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["Dir"])' "$work/module.json")"
cd "$src"
go build -mod=readonly -buildvcs=false -o "$out/hugo-x64.elf" .
go build -mod=readonly -buildvcs=false -ldflags "-s -w" -o "$out/hugo-x64-stripped.elf" .
ls -l "$out"/hugo-x64*.elf
shasum -a 256 "$out"/hugo-x64*.elf
