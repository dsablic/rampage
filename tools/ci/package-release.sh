#!/usr/bin/env bash
# Package release binaries as rampage-VERSION-TARGET.tar.gz plus a .sha256 file.
#
# The archive holds one top-level directory with the layout tools/install.sh publishes to: bin/ with rampage and its
# sibling rampage-worker (the CLI finds the worker next to itself), plus rampage-ui when built, and the license files.
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo 'Usage: tools/ci/package-release.sh TARGET VERSION BINARY_DIR OUT_DIR' >&2
    exit 2
fi
target=$1
version=$2
binaries=$3
out=$4
repository="$(cd "$(dirname "$0")/../.." && pwd)"
name="rampage-$version-$target"

mkdir -p "$out"
stage="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rampage-package.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name/bin"
for binary in rampage rampage-worker; do
    install -m 0755 "$binaries/$binary" "$stage/$name/bin/$binary"
done
if [ -f "$binaries/rampage-ui" ]; then
    install -m 0755 "$binaries/rampage-ui" "$stage/$name/bin/rampage-ui"
fi
for file in LICENSE NOTICE THIRD-PARTY-NOTICES; do
    install -m 0644 "$repository/$file" "$stage/$name/$file"
done
cat > "$stage/$name/README.md" <<EOF
# rampage $version ($target)

rampage is an AI-first reverse-engineering toolkit. Its main interface is an MCP server for AI agents.

## Install

Copy everything in \`bin/\` into one directory on your \`PATH\`, for example \`~/.local/bin\`:

\`\`\`sh
mkdir -p ~/.local/bin
cp bin/* ~/.local/bin/
\`\`\`

\`rampage\` starts \`rampage-worker\` from its own directory for supervised decompilation, so keep the two side by
side. \`rampage-ui\` is the desktop UI; it is tested on macOS only.

## Run

\`\`\`sh
rampage --version
rampage server serve --help   # MCP server over stdin/stdout
\`\`\`

Documentation: https://github.com/dsablic/rampage

Licensed under Apache-2.0; see LICENSE and NOTICE. Bundled third-party components are listed in
THIRD-PARTY-NOTICES.
EOF

# Reproducible-ish archive: sorted entries, no owner names.
archive="$out/$name.tar.gz"
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner -czf "$archive" "$name"
else
    # bsdtar on macOS would otherwise add AppleDouble ._* entries for extended attributes.
    COPYFILE_DISABLE=1 tar -C "$stage" --no-mac-metadata --uid 0 --gid 0 -czf "$archive" "$name"
fi
(
    cd "$out"
    if sha256sum --version 2> /dev/null | grep GNU > /dev/null; then
        sha256sum "$name.tar.gz" > "$name.tar.gz.sha256"
    else
        shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256"
    fi
    cat "$name.tar.gz.sha256"
)
ls -l "$out"
