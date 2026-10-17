#!/usr/bin/env bash
# Scripted recipe checks only: fake compiler/evaluator output is never an accuracy measurement.
set -euo pipefail
[[ $# == 1 ]] || { echo "usage: $0 VERIFIED_LUA_5_4_8_ARCHIVE" >&2; exit 2; }
repo=$(cd "$(dirname "$0")/../.." && pwd)
archive=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
mkdir -p "$repo/target/parity"
scratch=$(mktemp -d "$repo/target/parity/recipe-check.XXXXXX")
trap 'rm -r -- "$scratch"' EXIT
cat >"$scratch/zig" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == version ]]; then echo scripted-compiler; exit 0; fi
while [[ $# -gt 0 ]]; do
    if [[ "$1" == -o ]]; then : >"$2"; exit 0; fi
    shift
done
exit 2
SH
cat >"$scratch/eval" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
    strip) cp "$2" "$3" ;;
    artifact-info)
        arch=aarch64
        symbols=0
        [[ "$MODE" != header ]] || arch=x86_64
        [[ "$MODE" != metadata ]] || symbols=1
        printf '{"format":"elf","arch":"%s","endianness":"little",' "$arch"
        printf '"static_function_symbols":%s,"debug_sections":[]}\n' "$symbols"
        ;;
    truth)
        if [[ "$MODE" == emptytruth ]]; then echo '{}'; else echo '{"0x1000":"owned"}'; fi
        ;;
    *) exit 2 ;;
esac
SH
chmod u+x "$scratch/zig" "$scratch/eval"
cd "$repo"
for mode in success header metadata emptytruth; do
    result=0
    MODE=$mode ZIG="${scratch#"$repo/"}/zig" RAMPAGE_EVAL="$scratch/eval" \
        bash tools/parity-lua.sh "$scratch/$mode" "$archive" >"$scratch/$mode.log" 2>&1 || result=$?
    if [[ "$mode" == success ]]; then
        [[ "$result" == 0 ]]
        jq -e '.status=="available"' "$scratch/$mode/corpus.json" >/dev/null
        [[ -f "$scratch/$mode/manifest.json" ]]
    else
        [[ "$result" != 0 ]]
        jq -e '.status=="failed" and any(.stages[]; .exit_code!=0)' "$scratch/$mode/corpus.json" >/dev/null
        [[ ! -f "$scratch/$mode/manifest.json" ]]
    fi
done
echo 'Lua recipe checks passed: relative driver, header/metadata/truth refusal with failed evidence.'
