#!/bin/sh
# Rebuilds the Android fixtures in android/. No Java toolchain is needed: recorder.dex and recorder.apk are
# written by rampage-dex's test-side writers (crate feature `testkit`), and only the JNI library is compiled.
#
# android/libnative-arm64.so: jni.c as an aarch64 ELF shared library, built without the C runtime (-nostdlib), so
# no start files and no local paths enter it. Requires the zig in crates/rampage-signatures/data/zig-version.
# Afterwards `grep -c -a -e /Users/ -e /home/ android/*` must print 0 for every file.
#
# android/recorder.dex and android/recorder.apk: regenerated from libnative-arm64.so by
#   RAMPAGE_WRITE_ANDROID_FIXTURES=1 cargo nextest run -p rampage-dex -E 'test(committed_fixtures)'
# which otherwise checks that the committed files match what the writers produce.
set -eu
cd "$(dirname "$0")"
expected=$(cat ../../crates/rampage-signatures/data/zig-version)
actual=$(zig version)
case "$actual" in
    "$expected"*) ;;
    *) echo "zig $expected required, found $actual" >&2; exit 1 ;;
esac
zig cc -target aarch64-linux-gnu -O1 -g0 -shared -fPIC -nostdlib -Wl,-soname,libnative.so -Wl,--build-id=none \
    -o android/libnative-arm64.so android/jni.c
