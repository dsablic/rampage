#!/bin/sh
# Rebuilds the workflow test fixtures. Requires the zig recorded in crates/rampage-signatures/data/zig-version,
# the toolchain the other generated fixtures are built with: another zig can emit different code.
set -eu
cd "$(dirname "$0")"
expected=$(cat ../../../rampage-signatures/data/zig-version)
actual=$(zig version)
if [ "$actual" != "$expected" ]; then
    echo "zig $expected required (crates/rampage-signatures/data/zig-version), found $actual" >&2
    exit 1
fi
zig cc -target x86_64-linux-gnu -O1 -g0 -o net-client-x64.elf net-client.c
zig cc -target x86_64-linux-gnu -O1 -g0 -s -o net-client-x64-stripped.elf net-client.c
zig cc -target x86_64-linux-gnu -O1 -g0 -o persist-x64.elf persist.c
zig cc -target x86_64-windows-gnu -O1 -g0 -s -o persist-x64.exe persist.c -ladvapi32
zig cc -target x86_64-linux-gnu -O1 -g0 -o decode-x64.elf decode.c
zig cc -target aarch64-linux-gnu -O1 -g0 -o decode-arm64.elf decode.c
zig cc -target x86_64-linux-gnu -O1 -g0 -o decode-alloc-x64.elf decode-alloc.c
zig cc -target aarch64-linux-gnu -O1 -g0 -o decode-alloc-arm64.elf decode-alloc.c
# endpoints.c embeds a self-signed certificate for an invented name, generated once with OpenSSL and pasted in as
# PEM and DER (the pin is the base64 SHA-256 of its public key):
#   openssl ecparam -name prime256v1 -genkey -noout -out key.pem
#   openssl req -x509 -new -key key.pem -sha256 -subj "/O=Invented Device Maker/CN=device-ca.vendor-cloud.example" \
#     -addext "subjectAltName=DNS:telemetry.vendor-cloud.example,DNS:*.vendor-cloud.example" -set_serial 0x5a5a01 \
#     -not_before 20260101000000Z -not_after 20360101000000Z -out cert.pem
#
# endpoints-*.elf are built with the official zig release tarball for this host (zig-aarch64-macos-$expected.tar.xz
# from ziglang.org, checked against the SHA-256 in https://ziglang.org/download/index.json), unpacked anywhere: set
# ZIG_RELEASE to the unpacked zig-aarch64-macos-$expected directory. Zig compiles its C runtime start files itself,
# without the caller's -ffile-prefix-map, so their debug info names the unpack directory and this one as the
# compilation directory. After linking, both are overwritten in place with a same-length no-op run: the unpack
# directory (everything before /zig-aarch64-macos-...) with `/./.`, so the paths read
# /./././zig-aarch64-macos-$expected/lib/libc/..., and this directory with `./.` (that is, `.`). No local path is
# left, and same length keeps every DWARF string offset valid. Zig caches those start files with the directory of
# the build that first compiled them, so point ZIG_GLOBAL_CACHE_DIR at a fresh directory when building from
# somewhere else; afterwards `grep -c -a -e /Users/ -e /home/` on each output must print 0.
if [ -n "${ZIG_RELEASE:-}" ]; then
    release=$(cd "$ZIG_RELEASE" && pwd -P)
    if [ "$("$release/zig" version)" != "$expected" ]; then
        echo "ZIG_RELEASE must be zig $expected" >&2
        exit 1
    fi
    # privacy-*.elf import the capture and network libraries from stub shared libraries (privacy-stubs.c) built
    # with the real sonames into a temporary directory, so the calls are real imports; only the programs are kept.
    stubs=$(mktemp -d)
    trap 'rm -rf "$stubs"' EXIT
    for target in x86_64:x64 aarch64:arm64; do
        triple="${target%%:*}-linux-gnu"
        "$release/zig" cc -target "$triple" -O1 -g0 -o "endpoints-${target##*:}.elf" endpoints.c
        libraries=""
        for library in ASOUND:libasound.so.2 TINYALSA:libtinyalsa.so PULSE_SIMPLE:libpulse-simple.so.0 \
            CURL:libcurl.so.4 MOSQUITTO:libmosquitto.so.1; do
            out="$stubs/${target##*:}-${library#*:}"
            "$release/zig" cc -target "$triple" -O1 -g0 -shared -fPIC "-DLIB_${library%%:*}" \
                "-Wl,-soname,${library#*:}" -o "$out" privacy-stubs.c
            libraries="$libraries $out"
        done
        # shellcheck disable=SC2086
        "$release/zig" cc -target "$triple" -O1 -g0 -o "privacy-${target##*:}.elf" privacy.c $libraries -lpthread
    done
    python3 -I - "$(dirname "$release")" "$(pwd -P)" endpoints-x64.elf endpoints-arm64.elf privacy-x64.elf \
        privacy-arm64.elf <<'PY'
import sys
unpack, here = sys.argv[1].encode(), sys.argv[2].encode()
# /./. (absolute, the root) for the unpack directory; ./. (relative, `.`) for the compilation directory.
root = (b"/." * (len(unpack) // 2)) if len(unpack) % 2 == 0 else b"//" + b"./" * ((len(unpack) - 3) // 2) + b"."
dot = (b"./" * (len(here) // 2)) if len(here) % 2 == 0 else b"./" * (len(here) // 2) + b"."
assert len(root) == len(unpack) and len(dot) == len(here)
for name in sys.argv[3:]:
    data = open(name, "rb").read()
    data = data.replace(unpack + b"/zig-", root + b"/zig-").replace(here + b"\0", dot + b"\0").replace(here + b"/", dot + b"/")
    open(name, "wb").write(data)
PY
else
    echo "ZIG_RELEASE is not set: endpoints-*.elf and privacy-*.elf were not rebuilt" >&2
fi
rm -f *.pdb
