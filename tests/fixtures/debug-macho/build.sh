#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the debugserver fixture: a small arm64 macOS executable with symbols, ad-hoc signed with the
# com.apple.security.get-task-allow entitlement so debugserver may attach to it (or launch it) on a Mac with
# developer mode enabled.
set -euo pipefail
cd "$(dirname "$0")"
clang --version | head -1
set -x
clang -arch arm64 -mmacosx-version-min=13.0 -O1 -g0 -fno-stack-protector -o macho-loop macho-loop.c
strip -x macho-loop
codesign --force --sign - --entitlements macho-loop.entitlements macho-loop
codesign --display --entitlements - macho-loop
