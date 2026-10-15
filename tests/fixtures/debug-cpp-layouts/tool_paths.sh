#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

resolve_tool() {
  local value=$1
  local directory
  if [[ $value != */* ]]; then
    if ! value=$(command -v -- "$value"); then
      printf 'Cannot resolve executable: %s\n' "$1" >&2
      return 1
    fi
  fi
  directory=$(CDPATH= cd -- "$(dirname "$value")" && pwd -P) || return 1
  value="$directory/${value##*/}"
  if [[ ! -f $value || ! -x $value ]]; then
    printf 'Expected an executable file: %s\n' "$value" >&2
    return 1
  fi
  printf '%s\n' "$value"
}

resolve_fixture_tools() {
  local tool_bin
  rust_sysroot=
  compiler=${CLANG:-clang}
  linker=${LD:-ld.lld}
  objcopy=${OBJCOPY:-llvm-objcopy}
  python=${PYTHON:-python3}
  if [[ -n ${RUST_SYSROOT:-} ]]; then
    rust_sysroot=$(CDPATH= cd -- "$RUST_SYSROOT" && pwd -P) || return 1
    tool_bin="$rust_sysroot/lib/rustlib/${RUST_HOST:?Set RUST_HOST with RUST_SYSROOT}/bin"
    linker=${LD:-$tool_bin/rust-lld}
    objcopy=${OBJCOPY:-$tool_bin/rust-objcopy}
  fi
  compiler=$(resolve_tool "$compiler") || return 1
  linker=$(resolve_tool "$linker") || return 1
  objcopy=$(resolve_tool "$objcopy") || return 1
  python=$(resolve_tool "$python") || return 1
}
