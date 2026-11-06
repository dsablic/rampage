#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 || ! -x $1 ]]; then
  echo 'usage: bash tools/ci/scan-secrets.sh /absolute/path/to/gitleaks' >&2
  exit 2
fi
scanner=$1
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rampage-secret-head.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$scratch/head/tree"
git archive HEAD | tar -x -C "$scratch/head/tree"
# Gitleaks also auto-loads source-root ignore files, regardless of the explicit ignore path.
git clone --quiet --mirror --shared . "$scratch/history.git"
printf '[extend]\nuseDefault = true\n' > "$scratch/builtin.toml"
: > "$scratch/empty.ignore"
policy=(
  --config "$scratch/builtin.toml"
  --gitleaks-ignore-path "$scratch/empty.ignore"
  --redact=100 --no-banner --log-level warn --ignore-gitleaks-allow
)
reviewed="$(cd "$(dirname "$0")" && pwd)/secret-scan-reviewed.txt"

# Exit status 1 means findings. It becomes 0 only when the scanner wrote a report, the report is non-empty, and every
# finding's fingerprint is listed in the reviewed file. Anything else (another status, no or unreadable report, any
# unlisted finding) keeps the scanner's status, so the exception fails closed.
accept_reviewed() {
  local status=$1 report=$2 prefix=$3
  if [[ $status != 1 || ! -s $report ]]; then
    return "$status"
  fi
  python3 -I - "$report" "$reviewed" "$prefix" <<'PY' || return "$status"
import json
import os
import sys

report, reviewed, prefix = sys.argv[1:]
listed = set()
with open(reviewed, encoding="utf-8") as stream:
    for line in stream:
        line = line.split("#", 1)[0].strip()
        if line:
            listed.add(line)
with open(report, encoding="utf-8") as stream:
    findings = json.load(stream) or []
unlisted = 0
for finding in findings:
    fingerprint = finding["Fingerprint"]
    if prefix:
        path, rule, line = fingerprint.rsplit(":", 2)
        relative = os.path.relpath(os.path.realpath(path), os.path.realpath(prefix))
        fingerprint = f"HEAD:{relative}:{rule}:{line}"
    if fingerprint in listed:
        print(f"Reviewed false positive: {fingerprint}")
    else:
        unlisted += 1
if not findings or unlisted:
    sys.exit(1)
PY
}

status=0
scan=0
"$scanner" dir "$scratch/head" "${policy[@]}" --report-format json --report-path "$scratch/head.json" || scan=$?
accept_reviewed "$scan" "$scratch/head.json" "$scratch/head/tree/" || status=$?
scan=0
"$scanner" git "$scratch/history.git" --log-opts='--all --full-history -m' "${policy[@]}" \
  --report-format json --report-path "$scratch/history.json" || scan=$?
accept_reviewed "$scan" "$scratch/history.json" "" || status=$?
exit "$status"
