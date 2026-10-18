#!/usr/bin/env bash
# Regenerates the bundled starter signature databases and their test fixtures.
#
# Each database names common C runtime (musl libc) functions so `rampage identify` labels library code out of
# the box. A database is specific to the exact library build it was made from, so this pins the toolchain (zig,
# which ships musl) and writes its version to crates/rampage-signatures/data/zig-version; rebuilding with a
# different zig can change the hashes.
#
# Overwrites crates/rampage-signatures/data/musl-<arch>.{json,json.gz,counts} and the committed identify fixtures
# tests/fixtures/bin/musl-static-<arch>.elf.
#
# Requires: Python 3.10+; zig (0.17.x); a build of the rampage CLI: target/release/rampage by default, or another build
# (such as target/debug/rampage from `cargo build -p rampage-cli`) through RAMPAGE; and a build of rampage-eval,
# target/debug/rampage-eval by default or RAMPAGE_EVAL.
set -euo pipefail
if [[ $# -gt 0 ]]; then
    exec python3 "$(dirname "$0")/signature-corpus.py" "$@"
fi
rampage=${RAMPAGE:-}
eval_bin=${RAMPAGE_EVAL:-}
# A relative RAMPAGE names a path from the caller's directory, which the cd below leaves.
[[ -z "$rampage" || "$rampage" == /* ]] || rampage="$PWD/$rampage"
[[ -z "$eval_bin" || "$eval_bin" == /* ]] || eval_bin="$PWD/$eval_bin"
cd "$(dirname "$0")"
repo=..

rampage=${rampage:-"$repo/target/release/rampage"}
if [[ ! -x "$rampage" ]]; then
    echo "rampage CLI not found at $rampage; run: cargo build -p rampage-cli --release," \
        "or point RAMPAGE at another build (e.g. RAMPAGE=target/debug/rampage)" >&2
    exit 1
fi
eval_bin=${eval_bin:-"$repo/target/debug/rampage-eval"}
if [[ ! -x "$eval_bin" ]]; then
    echo "rampage-eval not found at $eval_bin; run: cargo build -p rampage-eval, or point RAMPAGE_EVAL at it" >&2
    exit 1
fi

data=$repo/crates/rampage-signatures/data
fixtures=$repo/tests/fixtures/bin
mkdir -p "$data" "$fixtures"
zig version >"$data/zig-version"
echo "zig $(cat "$data/zig-version")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# (zig target triple, rampage arch tag)
targets=(
    "x86_64-linux-musl x86_64"
    "aarch64-linux-musl aarch64"
)

for entry in "${targets[@]}"; do
    read -r triple tag <<<"$entry"
    # The reference is linked with symbols so the database records real function names; the fixture is a
    # different program, stripped, so the identify test proves cross-binary matching rather than self-identity.
    # It is stripped in place rather than linked with --strip-all, with which zig builds its libc differently from
    # the reference's.
    zig cc -target "$triple" -O1 -static -o "$work/corpus-$tag" signatures-corpus.c
    zig cc -target "$triple" -O1 -static -o "$work/target-$tag" signatures-target.c
    "$eval_bin" strip "$work/target-$tag" "$fixtures/musl-static-$tag.elf"
    "$rampage" signatures "$work/corpus-$tag" --output "$data/musl-$tag.json"
    python3 - "$data/musl-$tag.json" "$tag" <<'PY'
import gzip
import io
import json
import os
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
expected_arch = sys.argv[2]
raw = path.read_bytes()
database = json.loads(raw)
if not isinstance(database, dict):
    raise ValueError(f"{path}: expected a signature database object")
if expected_arch not in ("x86_64", "aarch64") or database.get("arch") != expected_arch:
    raise ValueError(f"{path}: starter database architecture mismatch")
if type(database.get("scheme")) is not int or database["scheme"] != 2:
    raise ValueError(f"{path}: starter database requires signature scheme 2")
entries = database.get("entries")
exact = database.get("exact", {})
calls = database.get("calls", {})
if not all(isinstance(table, dict) for table in (entries, exact, calls)):
    raise ValueError(f"{path}: entries, exact and calls must be maps")
buffer = io.BytesIO()
with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as stream:
    stream.write(raw)
compressed = buffer.getvalue()
counts = f"{len(entries) + len(exact)} {len(calls)}\n".encode("ascii")
outputs = ((path.with_suffix(".json.gz"), compressed), (path.with_suffix(".counts"), counts))
pending: list[tuple[Path, Path]] = []
try:
    for destination, payload in outputs:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{destination.name}.", delete=False) as staged:
            temporary = Path(staged.name)
            pending.append((temporary, destination))
            os.fchmod(staged.fileno(), 0o644)
            staged.write(payload)
    for temporary, destination in pending:
        os.replace(temporary, destination)
finally:
    for temporary, _ in pending:
        temporary.unlink(missing_ok=True)
PY
    echo "  -> data/musl-$tag.{json,json.gz,counts}, fixtures/bin/musl-static-$tag.elf"
done
