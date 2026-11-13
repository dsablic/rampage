#!/usr/bin/env bash
# Rebuilds the Go runtime type metadata fixtures from src/gotypes, one per moduledata/type layout era:
#   go1.16 x86   - pre-go1.17 name encoding, pre-go1.19 offsetEmbed fields, go1.16 moduledata, 32-bit
#   go1.20 x64   - go1.20 moduledata (typelinks), hashmap map descriptors
#   go1.26 x86   - go1.26 moduledata (epclntab), swiss map descriptors
#   go1.27 s390x - go1.27 moduledata (typedesclen, no typelinks), big-endian
# Every toolchain is pinned to its exact point release. go1.26.2 and go1.27.3 are fetched by GOTOOLCHAIN; releases
# before go1.21 have no toolchain module, so go1.16.15 and go1.20.14 run through their golang.org/dl wrappers
# (which download them once on first use). All are stripped (-s -w).
set -euo pipefail
cd "$(dirname "$0")/src/gotypes"
out=$(cd ../../bin && pwd)
export GOWORK=off CGO_ENABLED=0 GOOS=linux
flags=(-trimpath -ldflags "-s -w")
legacy() {
    local version=$1 wrapper
    shift
    # The wrapper is a host program: build it without the target GOOS/GOARCH.
    env -u GOOS -u GOARCH GOTOOLCHAIN=local go install "golang.org/dl/$version@latest"
    wrapper="$(env -u GOOS -u GOARCH go env GOPATH)/bin/$version"
    "$wrapper" download >/dev/null 2>&1 || true
    "$wrapper" "$@"
}
GOARCH=386 legacy go1.16.15 build "${flags[@]}" -o "$out/gotypes-go1.16-x86.elf" .
GOARCH=amd64 legacy go1.20.14 build -buildvcs=false "${flags[@]}" -o "$out/gotypes-go1.20-x64.elf" .
GOARCH=386 GOTOOLCHAIN=go1.26.2 go build -buildvcs=false "${flags[@]}" -o "$out/gotypes-go1.26-x86.elf" .
GOARCH=s390x GOTOOLCHAIN=go1.27.3 go build -buildvcs=false "${flags[@]}" -o "$out/gotypes-go1.27-s390x.elf" .
