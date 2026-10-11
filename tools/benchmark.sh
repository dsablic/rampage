#!/usr/bin/env bash
# Compares rampage's function discovery against Ghidra's on one or more binaries, using `rampage compare`.
#
# For each binary it runs Ghidra headless to list function starts, builds a reference JSON in rampage's format
# (matching the image SHA-256 and architecture), and prints the comparison. Ghidra's output is a reference, not
# ground truth: a matching function start does not establish a matching CFG, types or decompilation.
#
# Usage: tools/benchmark.sh <rampage-binary> <ghidra-install> [<fixture> <arch>]...
# Example:
#   tools/benchmark.sh target/debug/rampage "$(brew --prefix ghidra)/libexec" \
#     tests/fixtures/bin/hello-x64.elf x86_64 tests/fixtures/bin/hello-arm64.elf aarch64
set -euo pipefail

RAMPAGE="$1"; GHIDRA="$2"; shift 2
HEADLESS="$GHIDRA/support/analyzeHeadless"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export JAVA_HOME="${JAVA_HOME:-$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home}"

printf '%-34s %8s %8s %8s %8s\n' "binary" "ghidra" "rampage" "matched" "recall"
while [ "$#" -ge 2 ]; do
    fixture="$1"; arch="$2"; shift 2
    starts="$WORK/starts.txt"; ref="$WORK/ref.json"
    mkdir -p "$WORK/proj"
    "$HEADLESS" "$WORK/proj" bench -import "$fixture" -scriptPath "$SCRIPTS" \
        -postScript ghidra_function_starts.java "$starts" -deleteProject >/dev/null 2>&1
    sha=$(shasum -a 256 "$fixture" | cut -d' ' -f1)
    python3 - "$starts" "$ref" "$sha" "$arch" <<'PY'
import json, sys
starts, ref, sha, arch = sys.argv[1:5]
funcs = [l.strip() for l in open(starts) if l.strip()]
json.dump({"tool": "ghidra", "version": "12.1.4", "image_sha256": sha, "arch": arch, "functions": funcs},
          open(ref, "w"))
PY
    result=$("$RAMPAGE" compare "$fixture" --reference "$ref" --json)
    python3 - "$fixture" "$result" <<'PY'
import json, os, sys
fixture, result = sys.argv[1], sys.argv[2]
c = json.loads(result)
ref, ram, matched = c["reference_functions"], c["rampage_functions"], c["matched"]
recall = matched / ref if ref else 0.0
print(f'{os.path.basename(fixture):<34} {ref:>8} {ram:>8} {matched:>8} {recall:>7.1%}')
PY
done
