#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the suite-v3 MSVC-ABI C++ fixture from tests/fixtures/bench-v3/src/engine.cpp into target/bench/v3/msvc/
# (or $MSVC_OUT). Nothing here is committed: the executable links Microsoft's static C runtime (/MT), whose code
# may not be redistributed in this repository, so the fixture is reproduced locally instead.
#
# Compiler and linker: Homebrew LLVM's clang-cl and lld-link (the MSVC ABI: Microsoft RTTI, vtable layout and
# __CxxFrameHandler3 exception tables; not Microsoft's cl.exe). Headers and libraries: the MSVC CRT and Windows
# SDK that `xwin --accept-license --arch x86,x86_64 splat --output ~/.cache/rampage-xwin/splat` unpacks; override
# the location with XWIN_SPLAT. The manifests' digests come from MSVC CRT 14.44.17.14 and Windows SDK 10.0.26100
# (xwin's downloads Microsoft.VC.14.44.17.14.CRT.* and Win11SDK_10.0.26100_*). Another CRT or SDK changes the
# embedded runtime: rerun tools/agent-bench/v3/derive-truth.py --update after building against one and review
# the diff.
#
# The build is path-independent: it runs inside the output directory on a copy of the source, reaches the
# sysroot through a relative symbolic link, keeps the compiler command line out of the debug info, and has
# lld-link resolve every relative path against the fixed /pdbsourcepath. The same CRT and SDK give the same bytes
# from any checkout or user.
#
#   engine-x64.exe   x86-64 PE, /O2, RTTI and C++ exceptions on: what the agent analyzes (without the PDB)
#   engine-x64.pdb   the truth source (public symbols and type records); never given to an agent
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
out="${MSVC_OUT:-$root/target/bench/v3/msvc}"
splat="${XWIN_SPLAT:-$HOME/.cache/rampage-xwin/splat}"
llvm=/opt/homebrew/opt/llvm/bin
for directory in crt/include crt/lib/x86_64 sdk/include/ucrt sdk/lib/ucrt/x86_64 sdk/lib/um/x86_64; do
  [ -d "$splat/$directory" ] || { echo "missing $splat/$directory: run xwin first" >&2; exit 1; }
done
ls "$splat/sdk/lib" | grep -qx 10.0.26100 || echo "warning: not Windows SDK 10.0.26100; digests will differ" >&2
mkdir -p "$out"
cp "$root/tests/fixtures/bench-v3/src/engine.cpp" "$out/engine.cpp"
cd "$out"
ln -sfn "$splat" xwin
"$llvm/clang-cl" --version | head -1
lld-link --version
"$llvm/clang-cl" --target=x86_64-pc-windows-msvc /nologo /O2 /MT /EHsc /GR /Z7 /Brepro /c \
  -gno-codeview-command-line -fdebug-compilation-dir=. -Wno-unused-command-line-argument \
  /imsvc xwin/crt/include /imsvc xwin/sdk/include/ucrt /imsvc xwin/sdk/include/um /imsvc xwin/sdk/include/shared \
  /Foengine.obj engine.cpp
lld-link /nologo /out:engine-x64.exe /debug /pdb:engine-x64.pdb /pdbaltpath:engine-x64.pdb /pdbsourcepath:/build \
  /Brepro /ignore:4099 /opt:ref /opt:noicf /fixed /dynamicbase:no /subsystem:console /machine:x64 \
  /libpath:xwin/crt/lib/x86_64 /libpath:xwin/sdk/lib/ucrt/x86_64 /libpath:xwin/sdk/lib/um/x86_64 engine.obj
rm -f engine.obj engine.cpp xwin
ls -l engine-x64.*
shasum -a 256 engine-x64.*
