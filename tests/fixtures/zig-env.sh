# shellcheck shell=sh
# SPDX-License-Identifier: Apache-2.0
# Sourced by the fixture build scripts that use zig, after they set `repo` to the repository root and cd to the
# directory they build in. Provides:
#   $zig        the zig to run: $ZIG if set (an official release tarball's zig, for one), else zig on PATH; it must
#               be the release pinned in crates/rampage-signatures/data/zig-version, as another can emit other code
#   a fresh, private ZIG_GLOBAL_CACHE_DIR, because zig caches its start files and compiler_rt with the directory of
#               the build that first compiled them; zig_cleanup removes it (call it from the script's EXIT trap)
#   scrub FILE...  blanks the local directories zig writes into its own start files' and compiler_rt's debug info,
#               which ignore -ffile-prefix-map (the working directory, the zig installation and the cache), with a
#               same-length no-op so no offset moves, then fails if any file still names /Users/ or /home/<name>/.
#               Compile with "-ffile-prefix-map=$PWD=." as well, so the fixture's own debug info is relative.
: "${repo:?set repo to the repository root before sourcing zig-env.sh}"
zig=${ZIG:-zig}
zig_pinned=$(cat "$repo/crates/rampage-signatures/data/zig-version")
if [ "$("$zig" version)" != "$zig_pinned" ]; then
    echo "zig $zig_pinned required (crates/rampage-signatures/data/zig-version), found $("$zig" version);" \
        "set ZIG to that release's zig" >&2
    exit 1
fi
# The directory holding the zig installation: /./././zig-aarch64-macos-0.17.0/lib/libc/... for a release tarball.
zig_exe=$("$zig" env | sed -n 's/^ *\.zig_exe = "\(.*\)",$/\1/p')
if [ -z "$zig_exe" ]; then
    echo "could not read zig_exe from \`$zig env\`" >&2
    exit 1
fi
zig_home=$(dirname "$(dirname "$zig_exe")")
# Zig records the cache directory normalized, so no doubled slash from a TMPDIR that ends in one.
zig_cache=$(mktemp -d "${TMPDIR:-/tmp}/rampage-zig-cache.XXXXXX")
zig_cache=$(cd "$zig_cache" && pwd)
ZIG_GLOBAL_CACHE_DIR=$zig_cache
export ZIG_GLOBAL_CACHE_DIR
zig_cleanup() {
    rm -rf "$zig_cache"
}
scrub() {
    python3 -I "$repo/tests/fixtures/scrub-paths.py" --here "$(pwd)" --here "$(pwd -P)" \
        --root "$zig_home" --root "$(cd "$zig_home" && pwd -P)" \
        --root "$zig_cache" --root "$(cd "$zig_cache" && pwd -P)" "$@"
}
