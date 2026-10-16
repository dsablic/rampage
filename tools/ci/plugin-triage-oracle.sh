#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${1:-} != --check || $# -lt 2 ]]; then
  echo 'usage: bash tools/ci/plugin-triage-oracle.sh --check command [arguments...]' >&2
  exit 2
fi
shift
root=$(cd "$(dirname "$0")/../.." && pwd)
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rampage-component.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
export CARGO_BUILD_JOBS=2
sysroot=$(rustc --print sysroot)

build_guest() {
  local name=$1
  local manifest=$2
  env DYLD_LIBRARY_PATH="$sysroot/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
    cargo build --locked --manifest-path "$manifest" \
    --target wasm32-unknown-unknown --release --target-dir "$root/target" \
    --message-format=json > "$scratch/$name-build.jsonl"
  local core
  core=$(python3 -B - "$scratch/$name-build.jsonl" <<'PY'
import json
import sys

artifacts = []
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        record = json.loads(line)
        if record.get("reason") == "compiler-artifact":
            artifacts.extend(name for name in record["filenames"] if name.endswith(".wasm"))
if len(artifacts) != 1:
    raise SystemExit("expected exactly one owned guest core-Wasm artifact")
print(artifacts[0])
PY
  )
  "$root/target/debug/rampage-componentize" "$core" "$scratch/$name.component.wasm"
}

cargo build --locked --manifest-path "$root/Cargo.toml" -p rampage-componentize -p rampage-plugin-worker
build_guest triage "$root/plugins/triage-report/Cargo.toml"
build_guest probe "$root/plugins/runtime-probe/Cargo.toml"
export RAMPAGE_TRIAGE_COMPONENT="$scratch/triage.component.wasm"
export RAMPAGE_RUNTIME_PROBE_COMPONENT="$scratch/probe.component.wasm"
export RAMPAGE_PLUGIN_WORKER="$root/target/debug/rampage-plugin-worker"
"$@"
