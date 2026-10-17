#!/usr/bin/env bash
# Recipe plumbing only; the proxy must never execute, including its version probe.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$repo/target/parity"
scratch=$(mktemp -d "$repo/target/parity/proxy-check.XXXXXX")
trap 'rm -r -- "$scratch"' EXIT
cat >"$scratch/rustup" <<'SH'
#!/usr/bin/env bash
echo 'ERROR: recipe executed a proxy' >&2
exit 99
SH
chmod u+x "$scratch/rustup"
ln "$scratch/rustup" "$scratch/rustc"
result=0
RUSTC="$scratch/rustc" bash "$repo/tools/parity-corpus.sh" "$scratch/output" \
    --only parity-rust-a64-macho-o1 >"$scratch/result.log" 2>&1 || result=$?
[[ "$result" == 1 ]]
jq -e '.entries[] | select(.id=="parity-rust-a64-macho-o1") |
    .status=="unavailable" and (.reason|contains("proxy refused")) and
    (.stages["compiler-version"]==null)' "$scratch/output/corpus.json" >/dev/null
! grep -q 'recipe executed a proxy' "$scratch/result.log"
echo 'Corpus recipe check passed: explicit sibling rustup proxy refused before invocation.'
