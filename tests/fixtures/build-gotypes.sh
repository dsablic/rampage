#!/usr/bin/env bash
# Rebuilds the Go runtime type metadata fixtures from src/gotypes, one per moduledata/type layout era:
#   go1.16 x86   - pre-go1.17 name encoding, pre-go1.19 offsetEmbed fields, go1.16 moduledata, 32-bit
#   go1.20 x64   - go1.20 moduledata (typelinks), hashmap map descriptors
#   go1.26 x86   - go1.26 moduledata (epclntab), swiss map descriptors
#   go1.27 s390x - go1.27 moduledata (typedesclen, no typelinks), big-endian
# go1.16 and go1.20 come from golang.org/dl (`go run golang.org/dl/go1.16.15@latest download`); go1.26 from
# GOTOOLCHAIN; go1.27 is the local toolchain. All are stripped (-s -w).
set -euo pipefail
cd "$(dirname "$0")/src/gotypes"
out=$(cd ../../bin && pwd)
export GOWORK=off CGO_ENABLED=0 GOOS=linux
flags=(-trimpath -ldflags "-s -w")
GOARCH=386 GOTOOLCHAIN=local "$HOME/sdk/go1.16.15/bin/go" build "${flags[@]}" -o "$out/gotypes-go1.16-x86.elf" .
GOARCH=amd64 GOTOOLCHAIN=local "$HOME/sdk/go1.20.14/bin/go" build -buildvcs=false "${flags[@]}" -o "$out/gotypes-go1.20-x64.elf" .
GOARCH=386 GOTOOLCHAIN=go1.26.2 go build -buildvcs=false "${flags[@]}" -o "$out/gotypes-go1.26-x86.elf" .
GOARCH=s390x GOTOOLCHAIN=local go build -buildvcs=false "${flags[@]}" -o "$out/gotypes-go1.27-s390x.elf" .
