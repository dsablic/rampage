#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${1:-} != --check || $# -lt 2 ]]; then
  echo 'usage: bash tools/ci/module-linkage-oracle.sh --check command [arguments...]' >&2
  exit 2
fi
shift
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rampage-module-linkage.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
sysroot=${RUST_SYSROOT:-$(rustc --print sysroot)}
host=${RUST_HOST:-$(rustc --version --verbose | sed -n 's/^host: //p')}
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"
test -x "$lld"

cat > "$scratch/provider.c" <<'EOF'
__declspec(dllexport) int add(int left, int right) { return left + right; }
EOF
cat > "$scratch/consumer.c" <<'EOF'
__declspec(dllimport) int add(int left, int right);
int entry(void) { return add(2, 3); }
EOF

clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -O1 \
  -c "$scratch/provider.c" -o "$scratch/provider.obj"
clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -O1 \
  -c "$scratch/consumer.c" -o "$scratch/consumer.obj"
env DYLD_LIBRARY_PATH="$sysroot/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
  "$lld" -flavor link /dll /noentry /nodefaultlib /machine:x64 /timestamp:0 \
  "/out:$scratch/owned-provider.dll" "/implib:$scratch/provider.lib" "$scratch/provider.obj"
env DYLD_LIBRARY_PATH="$sysroot/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
  "$lld" -flavor link /nodefaultlib /machine:x64 /subsystem:console /entry:entry /timestamp:0 \
  "/out:$scratch/consumer.exe" "$scratch/consumer.obj" "$scratch/provider.lib"
mv "$scratch/owned-provider.dll" "$scratch/renamed-provider.bin"
export RAMPAGE_MODULE_LINKAGE_FIXTURES="$scratch"
"$@"
