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
status=0
"$scanner" dir "$scratch/head" "${policy[@]}" || status=$?
"$scanner" git "$scratch/history.git" --log-opts='--all --full-history -m' "${policy[@]}" || status=$?
exit "$status"
