#!/usr/bin/env bash
# Verify a release archive: checksum, layout, and that the unpacked binaries run.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo 'Usage: tools/ci/check-release-archive.sh ARCHIVE.tar.gz' >&2
    exit 2
fi
archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
name="$(basename "$archive" .tar.gz)"

(
    cd "$(dirname "$archive")"
    if command -v sha256sum > /dev/null; then
        sha256sum --check --strict "$name.tar.gz.sha256"
    else
        shasum -a 256 --check "$name.tar.gz.sha256"
    fi
)

scratch="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rampage-unpack.XXXXXXXX")"
trap 'rm -rf "$scratch"' EXIT
tar -xzf "$archive" -C "$scratch"
root="$scratch/$name"
for file in LICENSE NOTICE THIRD-PARTY-NOTICES README.md; do
    test -s "$root/$file" || { echo "Missing $file" >&2; exit 1; }
done
for binary in rampage rampage-worker; do
    test -x "$root/bin/$binary" || { echo "Missing executable bin/$binary" >&2; exit 1; }
done
unexpected="$(cd "$root" && find . -mindepth 1 | sort | grep -v -x -E '\./(bin|bin/rampage|bin/rampage-worker|bin/rampage-ui|LICENSE|NOTICE|THIRD-PARTY-NOTICES|README\.md)' || true)"
if [ -n "$unexpected" ]; then
    printf 'Unexpected archive entries:\n%s\n' "$unexpected" >&2
    exit 1
fi

reported="$("$root/bin/rampage" --version)"
echo "$reported"
case "$name-" in
    "rampage-${reported#rampage }-"*) ;;
    *) echo "Version '$reported' does not match archive $name" >&2; exit 1 ;;
esac
"$root/bin/rampage" server serve --help > /dev/null
if [ -x "$root/bin/rampage-ui" ]; then
    "$root/bin/rampage-ui" --version
fi
if command -v ldd > /dev/null; then
    ldd "$root/bin/rampage" "$root/bin/rampage-worker"
elif command -v otool > /dev/null; then
    otool -L "$root/bin/rampage" "$root/bin/rampage-worker"
fi
echo "Archive $name verified"
