#!/bin/sh
# Rebuilds the workflow test fixtures. Requires the zig recorded in crates/rampage-signatures/data/zig-version,
# the toolchain the other generated fixtures are built with: another zig can emit different code. Set ZIG to that
# zig when the one on PATH is another release (or ZIG_RELEASE, below, which also rebuilds endpoints-* and privacy-*).
# Zig compiles its C runtime start files itself, without the caller's -ffile-prefix-map, so their debug info names
# the zig installation and this directory as the compilation directory: scrub (tests/fixtures/zig-env.sh) overwrites
# both in place with same-length no-op runs, keeping every DWARF string offset valid, and fails if any output still
# holds a local path.
set -eu
if [ -n "${ZIG_RELEASE:-}" ]; then
    # Resolved before the cd below, so a relative ZIG_RELEASE names what the caller meant.
    ZIG_RELEASE=$(cd "$ZIG_RELEASE" && pwd -P)
    ZIG="$ZIG_RELEASE/zig"
fi
cd "$(dirname "$0")"
repo=$(cd ../../../.. && pwd -P)
# shellcheck source=../../../../tests/fixtures/zig-env.sh
. "$repo/tests/fixtures/zig-env.sh"
trap 'zig_cleanup' EXIT
cc() {
    "$zig" cc "-ffile-prefix-map=$(pwd)=." "$@"
}
cc -target x86_64-linux-gnu -O1 -g0 -o net-client-x64.elf net-client.c
cc -target x86_64-linux-gnu -O1 -g0 -s -o net-client-x64-stripped.elf net-client.c
cc -target x86_64-linux-gnu -O1 -g0 -o persist-x64.elf persist.c
cc -target x86_64-windows-gnu -O1 -g0 -s -o persist-x64.exe persist.c -ladvapi32
cc -target x86_64-linux-gnu -O1 -g0 -o decode-x64.elf decode.c
cc -target aarch64-linux-gnu -O1 -g0 -o decode-arm64.elf decode.c
cc -target x86_64-linux-gnu -O1 -g0 -o decode-alloc-x64.elf decode-alloc.c
cc -target aarch64-linux-gnu -O1 -g0 -o decode-alloc-arm64.elf decode-alloc.c
# evaluate_function: floats per ABI (SSE, x87 on i686 without SSE, ARM hard and soft float, AArch64), SSE/AVX2
# vector code, and the imports it models. operator new/delete come from a stub libstdc++ built into a temporary
# directory, so they are real imports; only the program is kept. evaluate-variadic places variadic arguments on
# the stack: an even word pair on 32-bit ARM, every one on Apple arm64.
cc -target x86_64-linux-gnu -O1 -g0 -o evaluate-float-x64.elf evaluate-float.c
cc -target x86-linux-gnu -march=i686 -O1 -g0 -o evaluate-float-x86.elf evaluate-float.c
cc -target arm-linux-gnueabihf -marm -O1 -g0 -o evaluate-float-armhf.elf evaluate-float.c
cc -target arm-linux-gnueabi -marm -O1 -g0 -o evaluate-float-armel.elf evaluate-float.c
cc -target aarch64-linux-gnu -O1 -g0 -o evaluate-float-arm64.elf evaluate-float.c
cc -target x86_64-linux-gnu -O1 -g0 -o evaluate-simd-x64.elf evaluate-simd.c
models=$(mktemp -d)
printf '%s\n' 'void *_Znwm(unsigned long s){(void)s;return 0;}' 'void *_Znam(unsigned long s){(void)s;return 0;}' \
    'void _ZdlPv(void *p){(void)p;}' 'void _ZdaPv(void *p){(void)p;}' >"$models/stdcxx.c"
cc -target x86_64-linux-gnu -O1 -g0 -shared -fPIC -Wl,-soname,libstdc++.so.6 -o "$models/libstdc++.so.6" \
    "$models/stdcxx.c"
cc -target x86_64-linux-gnu -O1 -g0 -o evaluate-models-x64.elf evaluate-models.c "$models/libstdc++.so.6"
cc -target arm-linux-gnueabihf -marm -O1 -g0 -o evaluate-variadic-armhf.elf evaluate-variadic.c
cc -target aarch64-macos -O1 -g0 -o evaluate-variadic-arm64.macho evaluate-variadic.c
rm -rf "$models"
rm -f ./*.pdb
scrub net-client-x64.elf net-client-x64-stripped.elf persist-x64.elf persist-x64.exe decode-x64.elf decode-arm64.elf \
    decode-alloc-x64.elf decode-alloc-arm64.elf evaluate-float-x64.elf evaluate-float-x86.elf \
    evaluate-float-armhf.elf evaluate-float-armel.elf evaluate-float-arm64.elf evaluate-simd-x64.elf \
    evaluate-models-x64.elf evaluate-variadic-armhf.elf
# They keep their symbol tables, not the runtime's debug info (llvm-strip from Homebrew LLVM, or $LLVM).
for name in evaluate-float-x64.elf evaluate-float-x86.elf evaluate-float-armhf.elf evaluate-float-armel.elf \
    evaluate-float-arm64.elf evaluate-simd-x64.elf evaluate-models-x64.elf evaluate-variadic-armhf.elf; do
    "${LLVM:-/opt/homebrew/opt/llvm/bin}/llvm-strip" --strip-debug "$name"
done
check_paths evaluate-*.elf evaluate-variadic-arm64.macho
# endpoints.c embeds a self-signed certificate for an invented name, generated once with OpenSSL and pasted in as
# PEM and DER (the pin is the base64 SHA-256 of its public key):
#   openssl ecparam -name prime256v1 -genkey -noout -out key.pem
#   openssl req -x509 -new -key key.pem -sha256 -subj "/O=Invented Device Maker/CN=device-ca.vendor-cloud.example" \
#     -addext "subjectAltName=DNS:telemetry.vendor-cloud.example,DNS:*.vendor-cloud.example" -set_serial 0x5a5a01 \
#     -not_before 20260101000000Z -not_after 20360101000000Z -out cert.pem
#
# endpoints-*.elf and privacy-*.elf are built with the official zig release tarball for this host
# (zig-aarch64-macos-<version>.tar.xz from ziglang.org, checked against the SHA-256 in
# https://ziglang.org/download/index.json), unpacked anywhere: set ZIG_RELEASE to the unpacked
# zig-aarch64-macos-<version> directory. scrub blanks everything before /zig-aarch64-macos-..., so their libc
# paths read /./././zig-aarch64-macos-<version>/lib/libc/..., and this directory to `./.` (that is, `.`).
if [ -n "${ZIG_RELEASE:-}" ]; then
    # privacy-*.elf import the capture and network libraries from stub shared libraries (privacy-stubs.c) built
    # with the real sonames into a temporary directory, so the calls are real imports; only the programs are kept.
    stubs=$(mktemp -d)
    trap 'rm -rf "$stubs"; zig_cleanup' EXIT
    for target in x86_64:x64 aarch64:arm64; do
        triple="${target%%:*}-linux-gnu"
        cc -target "$triple" -O1 -g0 -o "endpoints-${target##*:}.elf" endpoints.c
        libraries=""
        for library in ASOUND:libasound.so.2 TINYALSA:libtinyalsa.so PULSE_SIMPLE:libpulse-simple.so.0 \
            CURL:libcurl.so.4 MOSQUITTO:libmosquitto.so.1; do
            out="$stubs/${target##*:}-${library#*:}"
            cc -target "$triple" -O1 -g0 -shared -fPIC "-DLIB_${library%%:*}" \
                "-Wl,-soname,${library#*:}" -o "$out" privacy-stubs.c
            libraries="$libraries $out"
        done
        # shellcheck disable=SC2086
        cc -target "$triple" -O1 -g0 -o "privacy-${target##*:}.elf" privacy.c $libraries -lpthread
    done
    scrub endpoints-x64.elf endpoints-arm64.elf privacy-x64.elf privacy-arm64.elf
else
    echo "ZIG_RELEASE is not set: endpoints-*.elf and privacy-*.elf were not rebuilt" >&2
fi
