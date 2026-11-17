#!/bin/sh
# Rebuilds the Android fixtures in android/. No Java toolchain is needed: recorder.dex and recorder.apk are
# written by rampage-dex's test-side writers (crate feature `testkit`), and only the JNI library is compiled.
#
# android/libnative-arm64.so: jni.c as an aarch64 ELF shared library, built without the C runtime (-nostdlib), so
# no start files and no local paths enter it, stripped (--strip-all keeps the dynamic exports) with -fno-ident, and
# the linker's .comment banner blanked in place, so nothing names the toolchain. Requires zig 0.17.x (crates/rampage-signatures/data/zig-version pins
# the patch release the other fixtures use; any 0.17 release builds this library the same). Afterwards
# `grep -c -a -e /Users/ -e /home/ android/*` must print 0 for every file.
#
# android/recorder.dex and android/recorder.apk: regenerated from libnative-arm64.so by
#   RAMPAGE_WRITE_ANDROID_FIXTURES=1 cargo nextest run -p rampage-dex -E 'test(committed_fixtures)'
# which otherwise checks that the committed files match what the writers produce.
set -eu
cd "$(dirname "$0")"
pinned=$(cat ../../crates/rampage-signatures/data/zig-version)
actual=$(zig version)
case "$actual" in
    "${pinned%.*}".*) ;;
    *) echo "zig ${pinned%.*}.x required (pinned $pinned), found $actual" >&2; exit 1 ;;
esac
zig cc -target aarch64-linux-gnu -O1 -g0 -fno-ident -shared -fPIC -nostdlib -Wl,-soname,libnative.so \
    -Wl,--build-id=none -Wl,--strip-all -o android/libnative-arm64.so android/jni.c
# The linker still writes its banner into .comment: blank it in place (same length, so no offset moves).
python3 -I - android/libnative-arm64.so <<'PY'
import re, sys
data = open(sys.argv[1], "rb").read()
data = re.sub(rb"Linker: [^\0]*", lambda match: b"\0" * len(match.group(0)), data)
open(sys.argv[1], "wb").write(data)
PY
if strings android/libnative-arm64.so | grep -q -i -e clang -e 'Linker:'; then
    echo "android/libnative-arm64.so names its toolchain" >&2
    exit 1
fi
for file in android/*; do
    if [ "$(grep -c -a -e /Users/ -e /home/ "$file")" != 0 ]; then
        echo "$file holds a local path" >&2
        exit 1
    fi
done
