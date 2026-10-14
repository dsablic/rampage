#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

fixtures=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$fixtures/../../.." && pwd)
compiler=${CLANG:-clang}
linker=${LD:-ld.lld}
objcopy=${OBJCOPY:-llvm-objcopy}
python=${PYTHON:-python3}
include_cpp=${DEBUG_LAYOUT_CPP:-0}

if [[ -n ${RUST_SYSROOT:-} ]]; then
  tool_bin="$RUST_SYSROOT/lib/rustlib/${RUST_HOST:?Set RUST_HOST with RUST_SYSROOT}/bin"
  linker=${LD:-$tool_bin/rust-lld}
  objcopy=${OBJCOPY:-$tool_bin/rust-objcopy}
fi

if [[ $include_cpp != 0 && $include_cpp != 1 ]]; then
  printf '%s\n' 'DEBUG_LAYOUT_CPP must be 0 or 1' >&2
  exit 2
fi
if [[ $# -gt 0 ]]; then
  if [[ $1 != --check || $# -lt 2 ]]; then
    printf '%s\n' 'Usage: bash build.sh [--check command [arguments...]]' >&2
    exit 2
  fi
  shift
fi

"$python" -B "$fixtures/test_verify_oracle.py"

temporary_parent=$(cd "${TMPDIR:-${RUNNER_TEMP:-/tmp}}" && pwd -P)
scratch=$(mktemp -d "$temporary_parent/rampage-debug-layouts.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

normalize() {
  local value=$1
  value=${value//"$scratch"/\/rampage-build}
  value=${value//"$root"/\/rampage}
  if [[ -n ${RUST_SYSROOT:-} ]]; then
    value=${value//"$RUST_SYSROOT"/\/rust-toolchain}
  fi
  printf '%s' "$value"
}

record_command() {
  local argument
  printf 'command:' >> "$scratch/provenance.txt"
  for argument in "$@"; do
    printf ' %q' "$(normalize "$argument")" >> "$scratch/provenance.txt"
  done
  printf '\n' >> "$scratch/provenance.txt"
}

run_objcopy() {
  record_command "$objcopy" "$@"
  if [[ $(uname -s) == Darwin && -n ${RUST_SYSROOT:-} ]]; then
    DYLD_LIBRARY_PATH="$RUST_SYSROOT/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" "$objcopy" "$@"
  else
    "$objcopy" "$@"
  fi
}

run_linker() {
  if [[ $(uname -s) == Darwin && -n ${RUST_SYSROOT:-} ]]; then
    DYLD_LIBRARY_PATH="$RUST_SYSROOT/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" "$linker" "$@"
  else
    "$linker" "$@"
  fi
}

linker_flags=(-m elf_x86_64 -e entry --image-base=0x400000 -z max-page-size=4096 --build-id=sha1)
if [[ ${linker##*/} == rust-lld ]]; then
  linker_flags=(-flavor gnu "${linker_flags[@]}")
fi
compiler_version=$("$compiler" --version)
if [[ ${linker##*/} == rust-lld ]]; then
  linker_version=$(run_linker -flavor gnu --version)
else
  linker_version=$(run_linker --version)
fi
objcopy_version=$(run_objcopy --version)
{
  printf 'license: Apache-2.0; workspace-owned generic inputs\n'
  printf 'target: x86_64-linux-gnu; ELF64; little endian; LP64\n'
  printf 'link: fixed-address ET_EXEC; base 0x400000; no target execution; no system libraries\n'
  printf 'compiler: %s\n' "$(normalize "${compiler_version%%$'\n'*}")"
  printf 'linker: %s\n' "$(normalize "${linker_version%%$'\n'*}")"
  printf 'objcopy: %s\n' "$(normalize "${objcopy_version%%$'\n'*}")"
  printf 'cpp-negative: %s\n' "$include_cpp"
} >> "$scratch/provenance.txt"

common_flags=(
  --target=x86_64-linux-gnu -ffreestanding -g -fno-stack-protector
  -fno-asynchronous-unwind-tables -fno-ident -ffile-prefix-map="$root"=/rampage
  -ffile-prefix-map="$scratch"=/rampage-build -fdebug-prefix-map="$root"=/rampage
  -fdebug-prefix-map="$scratch"=/rampage-build -fdebug-compilation-dir=/rampage-build
)

cd "$scratch"
for configuration in dwarf4-o1 dwarf5-o2; do
  case "$configuration" in
    dwarf4-o1) variant_flags=(-gdwarf-4 -O1) ;;
    dwarf5-o2) variant_flags=(-gdwarf-5 -O2) ;;
  esac
  mkdir "$configuration"
  sources=(entry flat_constants flat_use identity_a identity_b identity_incompatible collisions refusals)
  for source in "${sources[@]}"; do
    command=(
      "$compiler" "${common_flags[@]}" "${variant_flags[@]}" -std=c11 -fdollars-in-identifiers
      -c "$fixtures/$source.c" -o "$configuration/$source.o"
    )
    record_command "${command[@]}"
    "${command[@]}"
  done
  groups=(flat identity-compatible identity-incompatible collisions refusals)
  if [[ $include_cpp == 1 ]]; then
    command=(
      "$compiler" "${common_flags[@]}" "${variant_flags[@]}" -std=c++17 -fno-exceptions -fno-rtti
      -c "$fixtures/inheritance.cpp" -o "$configuration/inheritance.o"
    )
    record_command "${command[@]}"
    "${command[@]}"
    groups+=(inheritance)
  fi
  for group in "${groups[@]}"; do
    case "$group" in
      flat) inputs=(flat_use) ;;
      identity-compatible) inputs=(identity_a identity_b) ;;
      identity-incompatible) inputs=(identity_a identity_b identity_incompatible) ;;
      collisions) inputs=(collisions) ;;
      refusals) inputs=(refusals) ;;
      inheritance) inputs=(inheritance) ;;
    esac
    objects=("$configuration/entry.o" "$configuration/flat_constants.o")
    for source in "${inputs[@]}"; do
      objects+=("$configuration/$source.o")
    done
    binary="$configuration/$group.debug.elf"
    command=("$linker" "${linker_flags[@]}" -o "$binary" "${objects[@]}")
    record_command "${command[@]}"
    run_linker "${command[@]:1}"
    run_objcopy --only-section=.rampage_debug_layout -O binary "$binary" "$configuration/$group.constants.bin"
    run_objcopy --strip-debug "$binary" "$configuration/$group.symbols.elf"
  done
  run_objcopy --only-section=.text -O binary "$configuration/flat_use.o" "$configuration/flat_use.text"
done

"$python" -B "$fixtures/verify_oracle.py" "$scratch" "$fixtures/oracle.json" "$include_cpp"

if command -v sha256sum >/dev/null 2>&1; then
  hash=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash=(shasum -a 256)
else
  printf '%s\n' 'A SHA-256 tool (sha256sum or shasum) is required' >&2
  exit 2
fi
for source in "$fixtures"/*; do
  [[ -f $source ]] || continue
  digest=$("${hash[@]}" "$source")
  printf '%s  sources/%s\n' "${digest%% *}" "${source##*/}" >> source-sha256.txt
done
digest=$("${hash[@]}" "$root/tools/ci/debug-layout-oracle.sh")
printf '%s  recipes/tools/ci/debug-layout-oracle.sh\n' "${digest%% *}" >> source-sha256.txt
for artifact in provenance.txt source-sha256.txt dwarf*-o*/*; do
  [[ -f $artifact ]] || continue
  "${hash[@]}" "$artifact" >> artifact-sha256.txt
done
cat provenance.txt source-sha256.txt artifact-sha256.txt

export RAMPAGE_DEBUG_LAYOUT_FIXTURES="$scratch"
export RAMPAGE_DEBUG_LAYOUT_ORACLE="$fixtures/oracle.json"
if [[ $# -gt 0 ]]; then
  cd "$root"
  "$@"
fi
