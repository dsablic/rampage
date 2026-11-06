#!/usr/bin/env bash
# Install a checksum-pinned cargo-nextest release binary into ~/.cargo/bin (Linux x86-64, Linux ARM64 or macOS).
set -euo pipefail

version=0.9.150
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)
        platform=x86_64-unknown-linux-gnu
        checksum=b0959bc64232974224cf9fb22c915845398c0e8668fa7831eb5b43fb1eef781f
        ;;
    Linux-aarch64)
        platform=aarch64-unknown-linux-gnu
        checksum=9164568e9840c6509177086828ac7d3178c2d8feb0658b4d2bff62fa620e98c8
        ;;
    Darwin-*)
        platform=universal-apple-darwin
        checksum=82a759b4d218d38359424196ab244c470e8f7c7d149c814fbbeef4d67c3c301a
        ;;
    *)
        echo "No pinned cargo-nextest for $(uname -s)-$(uname -m)" >&2
        exit 1
        ;;
esac
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rampage-nextest.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
archive=cargo-nextest-$version-$platform.tar.gz
curl --fail --silent --show-error --location --retry 2 --max-time 120 \
    "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$version/$archive" \
    --output "$scratch/$archive"
if sha256sum --version 2> /dev/null | grep GNU > /dev/null; then
    printf '%s  %s\n' "$checksum" "$scratch/$archive" | sha256sum --check --strict
else
    printf '%s  %s\n' "$checksum" "$scratch/$archive" | shasum -a 256 --check
fi
# Cargo finds subcommands in $CARGO_HOME/bin even when it is not on PATH. The macOS runner image does not create it.
destination="${CARGO_HOME:-$HOME/.cargo}/bin"
mkdir -p "$destination"
tar -xzf "$scratch/$archive" -C "$destination" cargo-nextest
cargo nextest --version
