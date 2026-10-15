#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

fixtures=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$fixtures/../../.." && pwd)
source "$fixtures/tool_paths.sh"

if [[ $# -gt 0 ]]; then
  if [[ $1 != --check || $# -lt 2 ]]; then
    printf '%s\n' 'Usage: bash build.sh [--check command [arguments...]]' >&2
    exit 2
  fi
  shift
fi

resolve_fixture_tools

temporary_parent=$(CDPATH= cd -- "${TMPDIR:-${RUNNER_TEMP:-/tmp}}" && pwd -P)
scratch=$(mktemp -d "$temporary_parent/rampage-debug-cpp-layouts.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

TMPDIR="$scratch" "$python" -B "$fixtures/test_recipe_paths.py"
"$python" -B "$fixtures/test_verify_cpp_oracle.py"

normalize() {
  local value=$1
  value=${value//"$scratch"/\/rampage-build}
  if [[ -n $rust_sysroot ]]; then
    value=${value//"$rust_sysroot"/\/rust-toolchain}
  fi
  value=${value//"$root"/\/rampage}
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
  if [[ $(uname -s) == Darwin && -n $rust_sysroot ]]; then
    DYLD_LIBRARY_PATH="$rust_sysroot/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" "$objcopy" "$@"
  else
    "$objcopy" "$@"
  fi
}

run_linker() {
  if [[ $(uname -s) == Darwin && -n $rust_sysroot ]]; then
    DYLD_LIBRARY_PATH="$rust_sysroot/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" "$linker" "$@"
  else
    "$linker" "$@"
  fi
}

linker_flags=(-m elf_x86_64 -e entry --image-base=0x400000 -z max-page-size=4096 --build-id=sha1)
if [[ ${linker##*/} == rust-lld ]]; then
  linker_flags=(-flavor gnu "${linker_flags[@]}")
fi
compiler_version=$("$compiler" --version)
python_version=$("$python" --version)
if [[ ${linker##*/} == rust-lld ]]; then
  linker_version=$(run_linker -flavor gnu --version)
else
  linker_version=$(run_linker --version)
fi
objcopy_version=$(run_objcopy --version)
{
  printf 'license: Apache-2.0; workspace-owned generic C++ inputs\n'
  printf 'target: x86_64-linux-gnu; ELF64; little endian; LP64; Itanium C++ linkage\n'
  printf 'scope: non-polymorphic base-free records; mutable explicit-this methods only\n'
  printf 'link: fixed-address ET_EXEC; base 0x400000; no target execution; no system libraries\n'
  printf 'compiler: %s\n' "$(normalize "${compiler_version%%$'\n'*}")"
  printf 'linker: %s\n' "$(normalize "${linker_version%%$'\n'*}")"
  printf 'objcopy: %s\n' "$(normalize "${objcopy_version%%$'\n'*}")"
  printf 'python: %s\n' "$(normalize "${python_version%%$'\n'*}")"
} >> "$scratch/provenance.txt"

common_flags=(
  --target=x86_64-linux-gnu -ffreestanding -g -fno-stack-protector
  -fno-asynchronous-unwind-tables -fno-ident -ffile-prefix-map="$root"=/rampage
  -ffile-prefix-map="$scratch"=/rampage-build -fdebug-prefix-map="$root"=/rampage
  -fdebug-prefix-map="$scratch"=/rampage-build -fdebug-compilation-dir=/rampage-build
)
cpp_flags=(-std=c++17 -fno-exceptions -fno-rtti -fstandalone-debug)
groups=(records unaligned const-method reference-argument byvalue virtual inherited static-method overloads)

cd "$scratch"
for configuration in dwarf4-o1 dwarf5-o2; do
  case "$configuration" in
    dwarf4-o1) variant_flags=(-gdwarf-4 -O1) ;;
    dwarf5-o2) variant_flags=(-gdwarf-5 -O2) ;;
  esac
  mkdir "$configuration"
  command=(
    "$compiler" "${common_flags[@]}" "${variant_flags[@]}" -std=c11
    -c "$fixtures/entry.c" -o "$configuration/entry.o"
  )
  record_command "${command[@]}"
  "${command[@]}"
  sources=(constants records unaligned const_method reference_argument byvalue virtual_record inherited_record)
  sources+=(static_method overloads)
  for source in "${sources[@]}"; do
    command=(
      "$compiler" "${common_flags[@]}" "${variant_flags[@]}" "${cpp_flags[@]}"
      -c "$fixtures/$source.cpp" -o "$configuration/$source.o"
    )
    record_command "${command[@]}"
    "${command[@]}"
  done
  for group in "${groups[@]}"; do
    case "$group" in
      records) source=records ;;
      unaligned) source=unaligned ;;
      const-method) source=const_method ;;
      reference-argument) source=reference_argument ;;
      byvalue) source=byvalue ;;
      virtual) source=virtual_record ;;
      inherited) source=inherited_record ;;
      static-method) source=static_method ;;
      overloads) source=overloads ;;
    esac
    binary="$configuration/$group.debug.elf"
    command=(
      "$linker" "${linker_flags[@]}" -o "$binary"
      "$configuration/entry.o" "$configuration/constants.o" "$configuration/$source.o"
    )
    record_command "${command[@]}"
    run_linker "${command[@]:1}"
    for record in checked companion; do
      run_objcopy --only-section=".rampage_cpp_$record" -O binary \
        "$binary" "$configuration/$group.$record.constants.bin"
    done
    if [[ $group == unaligned ]]; then
      run_objcopy --only-section=.rampage_cpp_unaligned -O binary \
        "$binary" "$configuration/$group.unaligned.constants.bin"
    fi
    run_objcopy --strip-debug "$binary" "$configuration/$group.symbols.elf"
  done
done

record_command "$python" -B "$fixtures/verify_cpp_oracle.py" "$scratch" "$fixtures/oracle.json"
"$python" -B "$fixtures/verify_cpp_oracle.py" "$scratch" "$fixtures/oracle.json"

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
for source in tests/fixtures/debug-layouts/verify_oracle.py tools/ci/debug-cpp-layout-oracle.sh; do
  digest=$("${hash[@]}" "$root/$source")
  printf '%s  dependencies/%s\n' "${digest%% *}" "$source" >> source-sha256.txt
done
for artifact in provenance.txt source-sha256.txt dwarf*-o*/*; do
  [[ -f $artifact ]] || continue
  "${hash[@]}" "$artifact" >> artifact-sha256.txt
done
cat provenance.txt source-sha256.txt artifact-sha256.txt

export RAMPAGE_DEBUG_CPP_LAYOUT_FIXTURES="$scratch"
export RAMPAGE_DEBUG_CPP_LAYOUT_ORACLE="$fixtures/oracle.json"
if [[ $# -gt 0 ]]; then
  cd "$root"
  "$@"
fi
