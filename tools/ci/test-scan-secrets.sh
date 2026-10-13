#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -gt 1 || ( $# = 1 && ! -x $1 ) ]]; then
  echo 'usage: bash tools/ci/test-scan-secrets.sh [/absolute/path/to/gitleaks]' >&2
  exit 2
fi
scanner=${1:-}
helper=$(cd "$(dirname "$0")" && pwd)/scan-secrets.sh
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rampage-secret-regression.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_DATE='2026-01-01T00:00:00Z' GIT_COMMITTER_DATE='2026-01-01T00:00:00Z'

repo=$scratch/repo
git init --quiet --initial-branch=main "$repo"
git -C "$repo" config user.name 'CI Regression'
git -C "$repo" config user.email 'ci@example.invalid'
printf 'benign\n' > "$repo/fixture.txt"
git -C "$repo" add fixture.txt
git -C "$repo" commit --quiet --no-gpg-sign -m base
git -C "$repo" checkout --quiet -b feature
printf 'feature\n' > "$repo/feature.txt"
git -C "$repo" add feature.txt
git -C "$repo" commit --quiet --no-gpg-sign -m feature
git -C "$repo" checkout --quiet main
printf 'main\n' > "$repo/fixture.txt"
git -C "$repo" add fixture.txt
git -C "$repo" commit --quiet --no-gpg-sign -m main
git -C "$repo" merge --quiet --no-ff --no-commit feature
# Deliberately synthetic, never an issued credential; its addition exists only in the merge commit.
printf 'value = "ghp_%s" # gitleaks:allow\n' '0123456789abcdefghijABCDEFGHIJklmnop' >> "$repo/fixture.txt"
git -C "$repo" add fixture.txt
git -C "$repo" commit --quiet --no-gpg-sign -m 'merge-only synthetic credential'
merge_commit=$(git -C "$repo" rev-parse HEAD)
printf 'clean\n' > "$repo/fixture.txt"
printf '[extend]\nuseDefault = true\n[allowlist]\nregexes = [".*"]\n' > "$repo/.gitleaks.toml"
printf '%s:fixture.txt:github-pat:2\n' "$merge_commit" > "$repo/.gitleaksignore"
git -C "$repo" add fixture.txt .gitleaks.toml .gitleaksignore
git -C "$repo" commit --quiet --no-gpg-sign -m 'remove credential and add bypass attempts'

if git -C "$repo" log --all --full-history -p --format= -- fixture.txt | grep '^+value = ' > /dev/null; then
  echo 'Fixture unexpectedly exposes the merge credential without merge diffs' >&2
  exit 1
fi

cat > "$scratch/fake-scanner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
trap 'exit 97' ERR
mode=$1
source=$2
shift 2
printf '%s\n' "$mode" >> "$CI_SCAN_LOG"
config=
ignore=
log_options=
redacted=0
ignore_inline=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) config=$2; shift 2 ;;
    --gitleaks-ignore-path) ignore=$2; shift 2 ;;
    --log-opts=*) log_options=${1#*=}; shift ;;
    --redact=100) redacted=1; shift ;;
    --ignore-gitleaks-allow) ignore_inline=1; shift ;;
    *) shift ;;
  esac
done
test "$redacted" = 1
test "$ignore_inline" = 1
test -f "$config"
test "$(cat "$config")" = $'[extend]\nuseDefault = true'
test -f "$ignore"
test ! -s "$ignore"
test ! -e "$source/.gitleaksignore"
case "$mode" in
  dir)
    test "$(cat "$source/tree/fixture.txt")" = clean
    exit "${CI_HEAD_STATUS:-0}"
    ;;
  git)
    test "$(git -C "$source" rev-parse --is-bare-repository)" = true
    test "$log_options" = '--all --full-history -m'
    git -C "$source" log --all --full-history -m -p --format= -- fixture.txt | grep '^+value = ' > /dev/null
    exit "${CI_HISTORY_STATUS:-1}"
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$scratch/fake-scanner"

run_helper() {
  local status=0
  (cd "$repo" && RUNNER_TEMP="$scratch" bash "$helper" "$1") || status=$?
  if [[ $status != $2 ]]; then
    echo "Secret-scan regression: expected status $2, got $status" >&2
    exit 1
  fi
}

export CI_SCAN_LOG=$scratch/scan.log
run_helper "$scratch/fake-scanner" 1
printf 'dir\ngit\n' > "$scratch/expected.log"
cmp "$scratch/expected.log" "$CI_SCAN_LOG"
: > "$CI_SCAN_LOG"
export CI_HEAD_STATUS=7 CI_HISTORY_STATUS=0
run_helper "$scratch/fake-scanner" 7
cmp "$scratch/expected.log" "$CI_SCAN_LOG"
unset CI_HEAD_STATUS CI_HISTORY_STATUS

if [[ -n $scanner ]]; then
  git clone --quiet --mirror --shared "$repo" "$scratch/control.git"
  printf '[extend]\nuseDefault = true\n' > "$scratch/control.toml"
  : > "$scratch/control.ignore"
  "$scanner" git "$scratch/control.git" --log-opts='--all --full-history' \
    --config "$scratch/control.toml" --gitleaks-ignore-path "$scratch/control.ignore" \
    --redact=100 --no-banner --log-level warn --ignore-gitleaks-allow
  cat > "$scratch/report-scanner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec "$CI_REAL_SCANNER" "$@" --report-format json --report-path "$CI_REPORT_DIR/$1.json"
EOF
  chmod +x "$scratch/report-scanner"
  export CI_REAL_SCANNER=$scanner CI_REPORT_DIR=$scratch
  run_helper "$scratch/report-scanner" 1
  python3 - "$scratch/dir.json" "$scratch/git.json" "$merge_commit" <<'PY'
import json
import sys
from pathlib import Path

head = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
history = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
assert head is None or head == [], "Synthetic HEAD must be clean"
assert any(
    finding["RuleID"] == "github-pat" and finding["Commit"] == sys.argv[3]
    for finding in history
), "Missing synthetic merge-only credential finding"
assert all(finding["Secret"] == "REDACTED" for finding in history), "Finding reports must be redacted"
PY
  echo 'Actual Gitleaks detected the merge-only credential despite repository bypass attempts.'
else
  echo 'Fake-scanner merge and policy regressions passed; actual Gitleaks was not supplied.'
fi

if find "$scratch" -maxdepth 1 -name 'rampage-secret-head.*' | grep . > /dev/null; then
  echo 'Secret-scan helper left temporary scan directories behind' >&2
  exit 1
fi
