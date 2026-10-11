#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo 'Usage: tools/decompile-benchmark.sh RAMPAGE GHIDRA IMAGE FUNCTION' >&2
    exit 2
fi
rampage="$1"
ghidra="$2"
image="$3"
function="$4"
scripts="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
version=$(sed -n 's/^application.version=//p' "$ghidra/Ghidra/application.properties")
test -n "$version"
export JAVA_HOME="${JAVA_HOME:-$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home}"
if ! "$ghidra/support/analyzeHeadless" "$work" differential -import "$image" -scriptPath "$scripts" \
    -postScript ghidra_decompile.java "$work/reference.c" "$function" -deleteProject >"$work/ghidra.log" 2>&1; then
    cat "$work/ghidra.log" >&2
    exit 1
fi
if [ ! -s "$work/reference.c" ]; then
    cat "$work/ghidra.log" >&2
    echo 'Ghidra did not produce a decompiled function' >&2
    exit 1
fi
"$rampage" --json decompile "$image" --at "$function" >"$work/rampage.json"
python3 - "$work/reference.c" "$work/rampage.json" "$version" "$image" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

reference, result, version, image = sys.argv[1:]
expected = Path(reference).read_text()
actual = json.loads(Path(result).read_text())
def normalize(text: str) -> str:
    return re.sub(r'\s+', ' ', text).strip()

print(json.dumps({
    'schema': 'rampage-decompile-comparison-v1',
    'image_sha256': hashlib.sha256(Path(image).read_bytes()).hexdigest(),
    'reference_version': version,
    'language_id': actual['language_id'],
    'function': actual['name'],
    'normalized_text_equal': normalize(expected) == normalize(actual['code']),
    'reference_bytes': len(expected.encode()),
    'rampage_bytes': len(actual['code'].encode()),
    'reference_warning_lines': sum('WARNING:' in line for line in expected.splitlines()),
    'rampage_warning_lines': sum('WARNING:' in line for line in actual['code'].splitlines()),
    'limitations': ['Analysis mappings, types and options are not yet matched; text equality is diagnostic, not parity.']
}, indent=2))
PY
