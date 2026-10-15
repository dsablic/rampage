#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

fixtures=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$fixtures/../../.." && pwd)
source "$fixtures/../debug-cpp-layouts/tool_paths.sh"

if [[ $# -gt 0 ]]; then
  if [[ $1 != --check || $# -lt 2 ]]; then
    printf '%s\n' 'Usage: bash build.sh [--check command [arguments...]]' >&2
    exit 2
  fi
  shift
fi

resolve_fixture_tools
temporary_parent=$(CDPATH= cd -- "${TMPDIR:-${RUNNER_TEMP:-/tmp}}" && pwd -P)
scratch=$(mktemp -d "$temporary_parent/rampage-debug-cpp-virtuals.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
export TMPDIR="$scratch"

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
  printf 'license: Apache-2.0; workspace-owned generic C++ virtual inputs\n'
  printf 'target: x86_64-linux-gnu; ELF64; little endian; LP64; GCC-compatible Itanium ABI consumer\n'
  printf 'scope: base-free mutable virtual slots; separate unsupported compiler-emitted controls\n'
  printf 'link: fixed-address ET_EXEC; base 0x400000; no target execution; no system libraries\n'
  printf 'offsetof: Clang non-standard-layout extension; data fields only, never artificial vptr\n'
  printf 'vptr: AST offset + IRgen pointer storage + source sizeof(void*); mandatory compiler dump\n'
  printf 'prefix: two raw zero words under -fno-rtti remain UnverifiedPrefix; no RTTI/offset-to-top proof\n'
  printf 'compiler: %s\n' "$(normalize "${compiler_version%%$'\n'*}")"
  printf 'linker: %s\n' "$(normalize "${linker_version%%$'\n'*}")"
  printf 'objcopy: %s\n' "$(normalize "${objcopy_version%%$'\n'*}")"
  printf 'python: %s\n' "$(normalize "${python_version%%$'\n'*}")"
} >> "$scratch/provenance.txt"

record_command "$python" -B "$fixtures/../debug-cpp-layouts/test_recipe_paths.py"
"$python" -B "$fixtures/../debug-cpp-layouts/test_recipe_paths.py"
record_command "$python" -B "$fixtures/test_verify_virtual_oracle.py"
"$python" -B "$fixtures/test_verify_virtual_oracle.py"

common_flags=(
  --target=x86_64-linux-gnu -ffreestanding -g -fno-pic -fno-pie -fno-stack-protector
  -fno-asynchronous-unwind-tables -fno-ident -ffile-prefix-map="$root"=/rampage
  -ffile-prefix-map="$scratch"=/rampage-build -fdebug-prefix-map="$root"=/rampage
  -fdebug-prefix-map="$scratch"=/rampage-build -fdebug-compilation-dir=/rampage-build
)
cpp_flags=(
  -std=c++17 -fno-exceptions -fno-rtti -fstandalone-debug -Wno-invalid-offsetof
  -Xclang -fdump-record-layouts -Xclang -fdump-vtable-layouts
)
groups=(records missing-alignment lookalikes inherited signatures)

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
  for group in "${groups[@]}"; do
    case "$group" in
      records) source=records; keys=(checked peer) ;;
      missing-alignment) source=missing_alignment; keys=(noalign) ;;
      lookalikes) source=lookalikes; keys=(callback chain) ;;
      inherited) source=inherited; keys=(inherited) ;;
      signatures) source=signatures; keys=(constant reference value destructor) ;;
    esac
    command=(
      "$compiler" "${common_flags[@]}" "${variant_flags[@]}" "${cpp_flags[@]}"
      -c "$fixtures/$source.cpp" -o "$configuration/$group.o"
    )
    record_command "${command[@]}"
    printf 'compiler-output: %s/%s.layouts.txt\n' "$configuration" "$group" >> provenance.txt
    if ! "${command[@]}" > "$configuration/$group.layouts.txt" 2>&1; then
      cat "$configuration/$group.layouts.txt" >&2
      exit 1
    fi
    binary="$configuration/$group.debug.elf"
    command=(
      "$linker" "${linker_flags[@]}" -o "$binary" "$configuration/entry.o" "$configuration/$group.o"
    )
    record_command "${command[@]}"
    run_linker "${command[@]:1}"
    for key in "${keys[@]}"; do
      run_objcopy --only-section=".rampage_virtual_$key" -O binary \
        "$binary" "$configuration/$group.$key.constants.bin"
    done
    run_objcopy --strip-debug "$binary" "$configuration/$group.symbols.elf"
  done
done

record_command "$python" -B "$fixtures/verify_virtual_oracle.py" "$scratch" "$fixtures/oracle.json"
"$python" -B "$fixtures/verify_virtual_oracle.py" "$scratch" "$fixtures/oracle.json"

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
dependencies=(
  tests/fixtures/debug-layouts/verify_oracle.py
  tests/fixtures/debug-cpp-layouts/verify_cpp_oracle.py
  tests/fixtures/debug-cpp-layouts/tool_paths.sh
  tests/fixtures/debug-cpp-layouts/test_recipe_paths.py
  tools/ci/debug-cpp-virtual-oracle.sh
)
for source in "${dependencies[@]}"; do
  digest=$("${hash[@]}" "$root/$source")
  printf '%s  dependencies/%s\n' "${digest%% *}" "$source" >> source-sha256.txt
done
for artifact in provenance.txt source-sha256.txt dwarf*-o*/*; do
  [[ -f $artifact ]] || continue
  "${hash[@]}" "$artifact" >> artifact-sha256.txt
done
cat provenance.txt source-sha256.txt artifact-sha256.txt

if [[ $# -gt 0 ]]; then
  export RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES="$scratch"
  export RAMPAGE_DEBUG_CPP_VIRTUAL_ORACLE="$fixtures/oracle.json"
  cd "$root"
  "$@"
fi
