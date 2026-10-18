#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/../../.." && pwd)
output=$1
clang=${CLANG:-clang}
clangxx=${CLANGXX:-clang++}
clangcl=${CLANG_CL:-clang-cl}
link=${LLD_LINK:-lld-link}

for tool in "$clang" "$clangxx" "$clangcl" "$link"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required build tool unavailable: $tool" >&2
    exit 2
  fi
done

mkdir -p "$output"
output=$(cd "$output" && pwd)
cd "$root"

"$clangcl" --target=x86_64-pc-windows-msvc /c /Z7 /Od /GS- "/Fo$output/debug-types.obj" \
  tests/fixtures/src/debug-types.c
"$link" /debug:full "/pdb:$output/debug-types.pdb" /pdbaltpath:debug-types.pdb \
  "/out:$output/debug-types.exe" /entry:debug_types_main /subsystem:console /nodefaultlib \
  /machine:x64 /Brepro /incremental:no "$output/debug-types.obj"

"$clangcl" --target=x86_64-pc-windows-msvc /c /Z7 /Od /GS- /GR- "/Fo$output/debug-types-cpp.obj" \
  tests/fixtures/src/debug-types-pdb.cpp
"$link" /debug:full "/pdb:$output/debug-types-cpp.pdb" /pdbaltpath:debug-types-cpp.pdb \
  "/out:$output/debug-types-cpp.exe" /entry:debug_types_main /subsystem:console /nodefaultlib \
  /machine:x64 /Brepro /incremental:no "$output/debug-types-cpp.obj"

"$clangcl" --target=x86_64-pc-windows-msvc /c /Z7 /Od /GS- /GR- "/Fo$output/debug-cpp.obj" \
  tests/fixtures/src/debug-types.cpp
"$link" /debug:full "/pdb:$output/debug-cpp.pdb" /pdbaltpath:debug-cpp.pdb \
  "/out:$output/debug-cpp.exe" /entry:debug_cpp_main /subsystem:console /nodefaultlib \
  /machine:x64 /Brepro /incremental:no "$output/debug-cpp.obj"

for target in x86_64-unknown-linux-gnu aarch64-none-elf; do
  case "$target" in
    x86_64-unknown-linux-gnu) suffix=x64 ;;
    aarch64-none-elf) suffix=arm64 ;;
  esac
  "$clang" --target="$target" -fuse-ld=lld -O0 -g -gdwarf-4 -ffreestanding -fno-builtin \
    -fno-stack-protector -nostdlib -static -Wl,-e,debug_types_main -Wl,--build-id=none \
    tests/fixtures/src/debug-types.c -o "$output/debug-types-$suffix.elf"
  "$clangxx" --target="$target" -fuse-ld=lld -O0 -g -gdwarf-4 -ffreestanding -fno-exceptions \
    -fno-rtti -fno-stack-protector -nostdlib -static -Wl,-e,debug_cpp_main -Wl,--build-id=none \
    tests/fixtures/src/debug-types.cpp -o "$output/debug-cpp-$suffix.elf"
done
