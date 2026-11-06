#!/usr/bin/env bash
# Install Ubuntu packages, refreshing the package index only when the runner image's index is not enough.
set -euo pipefail

if ! sudo apt-get install --yes --no-install-recommends "$@"; then
    sudo apt-get update
    sudo apt-get install --yes --no-install-recommends "$@"
fi
