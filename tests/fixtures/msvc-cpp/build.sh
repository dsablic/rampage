#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuild the owned MSVC-ABI C++ fixtures with clang-cl and lld-link: msvc-cpp-x64.exe and msvc-cpp-x86.exe, each
# with its PDB and a truth listing dumped from that PDB by llvm-pdbutil.
#
# Licence: nothing from the Microsoft CRT or Windows SDK goes in. shapes.cpp includes no header, the link uses
# /nodefaultlib with its own entry point, and the only runtime references are imports by name from
# VCRUNTIME140.dll through an import library generated here from runtime-*.def. The committed PEs therefore hold
# only code compiled from shapes.cpp; no xwin sysroot is needed to rebuild them.
set -euo pipefail

source_dir="$(cd "$(dirname "$0")" && pwd)"
clang_cl="${CLANG_CL:-clang-cl}"
linker="$(command -v "${LLD_LINK:-lld-link}")"
dlltool="${LLVM_DLLTOOL:-llvm-dlltool}"
pdbutil="${LLVM_PDBUTIL:-llvm-pdbutil}"
work="$(mktemp -d "${TMPDIR:-/tmp}/rampage-msvc-cpp.XXXXXX")"
trap 'rm -rf "$work"' EXIT

cd "$work"
ln -s "$linker" lld-link
cp "$source_dir/shapes.cpp" "$source_dir"/runtime-*.def .

build() {
    local arch="$1" triple="$2" dll_machine="$3" machine="$4" base="$5"
    "$dlltool" -m "$dll_machine" -k -d "runtime-$arch.def" -l "runtime-$arch.lib"
    "$clang_cl" --target="$triple" /c /O2 /GS- /GR /EHsc /Z7 /std:c++17 /Zl /Gy \
        -fdebug-compilation-dir=/rampage/msvc-cpp \
        -Xclang -object-file-name=/rampage/msvc-cpp/shapes-"$arch".obj -gno-codeview-command-line \
        "/Fo:shapes-$arch.obj" shapes.cpp
    ./lld-link "shapes-$arch.obj" "runtime-$arch.lib" "/out:msvc-cpp-$arch.exe" "/pdb:msvc-cpp-$arch.pdb" \
        "/pdbaltpath:msvc-cpp-$arch.pdb" /pdbsourcepath:/rampage/msvc-cpp /debug:full /nodefaultlib /entry:entry \
        /subsystem:console "/machine:$machine" "/base:$base" /opt:ref /opt:noicf /safeseh:no /Brepro /timestamp:0 \
        /noimplib
    {
        echo "# Truth for msvc-cpp-$arch.exe, dumped from its PDB by build.sh. Columns: kind section:offset name."
        "$pdbutil" dump --symbols "msvc-cpp-$arch.pdb" |
            awk '/S_[GL]PROC32|S_THUNK32/ { kind = ($3 == "S_THUNK32") ? "thunk" : "function"; name = $0;
                     sub(/^[^`]*`/, "", name); sub(/`$/, "", name); want = 1; next }
                 want && match($0, /addr = [0-9]+:[0-9]+/) {
                     print kind, substr($0, RSTART + 7, RLENGTH - 7), name; want = 0 }' | sort -u
        "$pdbutil" dump --publics "msvc-cpp-$arch.pdb" |
            awk '/S_PUB32/ { name = $0; sub(/^[^`]*`/, "", name); sub(/`$/, "", name); want = 1; next }
                 want && match($0, /addr = [0-9]+:[0-9]+/) {
                     kind = ($0 ~ /flags = function/) ? "public-function" : "public-data";
                     print kind, substr($0, RSTART + 7, RLENGTH - 7), name; want = 0 }' | sort -u
    } > "truth-$arch.txt"
    cp "msvc-cpp-$arch.exe" "msvc-cpp-$arch.pdb" "truth-$arch.txt" "$source_dir/"
}

build x64 x86_64-pc-windows-msvc i386:x86-64 x64 0x140000000
build x86 i686-pc-windows-msvc i386 x86 0x400000

# Identical-code folding: icf.cpp's byte-identical function pairs fold under /OPT:ICF, so its PDB names one address
# with several procedure and public records.
"$clang_cl" --target=x86_64-pc-windows-msvc /c /O2 /GS- /Z7 /Zl /Gy -fdebug-compilation-dir=/rampage/msvc-cpp \
    -Xclang -object-file-name=/rampage/msvc-cpp/icf.obj -gno-codeview-command-line /Fo:icf.obj \
    -- "$source_dir/icf.cpp"
./lld-link icf.obj /out:msvc-icf-x64.exe /pdb:msvc-icf-x64.pdb /pdbaltpath:msvc-icf-x64.pdb \
    /pdbsourcepath:/rampage/msvc-cpp /debug:full /nodefaultlib /entry:icf_entry /subsystem:console /machine:x64 \
    /base:0x140000000 /opt:ref /opt:icf /Brepro /timestamp:0 /noimplib
cp msvc-icf-x64.exe msvc-icf-x64.pdb "$source_dir/"

# A C operations table called through a struct beside one polymorphic class (x86): a double-load indirect call
# that virtual call resolution must leave alone.
"$clang_cl" --target=i686-pc-windows-msvc /c /O2 /GS- /GR /Z7 /Zl /Gy -fdebug-compilation-dir=/rampage/msvc-cpp \
    -Xclang -object-file-name=/rampage/msvc-cpp/ops.obj -gno-codeview-command-line /Fo:ops.obj \
    -- "$source_dir/ops.cpp"
./lld-link ops.obj /out:msvc-ops-x86.exe /pdb:msvc-ops-x86.pdb /pdbaltpath:msvc-ops-x86.pdb \
    /pdbsourcepath:/rampage/msvc-cpp /debug:full /nodefaultlib /entry:ops_entry /subsystem:console /machine:x86 \
    /base:0x400000 /opt:ref /opt:noicf /safeseh:no /Brepro /timestamp:0 /noimplib
cp msvc-ops-x86.exe msvc-ops-x86.pdb "$source_dir/"
