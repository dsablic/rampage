#!/usr/bin/env bash
# Build the pinned MIT Lua interpreter as a static AArch64 corpus; never execute it or fetch sources.
set -euo pipefail
export LC_ALL=C
export SOURCE_DATE_EPOCH=0

[[ $# == 2 ]] || { echo "usage: $0 OUT_DIR LUA_5_4_8_ARCHIVE" >&2; exit 2; }
repo=$(cd "$(dirname "$0")/.." && pwd)
archive=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
expected=4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae
hash() { shasum -a 256 "$1" | awk '{print $1}'; }
[[ $(hash "$archive") == "$expected" ]] || { echo "Lua archive digest differs from pinned source" >&2; exit 2; }
case "$1" in target/parity/*|*/target/parity/*) ;; *) echo "OUT_DIR must be under target/parity" >&2; exit 2 ;; esac
mkdir -p "$1"
out=$(cd "$1" && pwd -P)
case "$out" in */target/parity/*) ;; *) echo "OUT_DIR resolves outside target/parity" >&2; exit 2 ;; esac
[[ -z $(find "$out" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
    echo "OUT_DIR must be empty; choose a new run directory" >&2; exit 2;
}
zig=$(command -v "${ZIG:-zig}")
[[ "$zig" == /* ]] || zig="$PWD/$zig"
eval_bin=${RAMPAGE_EVAL:-"$repo/target/debug/rampage-eval"}
[[ "$eval_bin" == /* ]] || eval_bin="$PWD/$eval_bin"
export ZIG_GLOBAL_CACHE_DIR="$out/.zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$out/.zig-local-cache"
mkdir "$out/source"
tar -xzf "$archive" -C "$out/source"
cd "$out/source/lua-5.4.8/src"
sources=()
for source in *.c; do
    [[ "$source" == luac.c ]] || sources+=("$source")
done
command=("$zig" cc -target aarch64-linux-musl -O2 -g -gdwarf-4 -static -Wl,--build-id=none
    "-fdebug-prefix-map=$out/source=." "-ffile-prefix-map=$out/source=." "${sources[@]}" -lm -o "$out/symbolized.elf")
"$zig" version >"$out/compiler-version.txt"
jq -n --arg archive_sha256 "$expected" --arg script_sha256 "$(hash "$repo/tools/parity-lua.sh")" \
    --arg evaluator_sha256 "$(hash "$eval_bin")" --arg compiler "$(cat "$out/compiler-version.txt")" \
    --argjson argv "$(jq -cn --args '$ARGS.positional' -- "${command[@]}")" \
    '{schema_version:1, kind:"parity_realistic_lua", name:"Lua", version:"5.4.8", license:"MIT",
      source_url:"https://www.lua.org/ftp/lua-5.4.8.tar.gz", checksum_url:"https://www.lua.org/ftp/",
      archive_sha256:$archive_sha256, script_sha256:$script_sha256, evaluator_sha256:$evaluator_sha256,
      compiler_version:$compiler, argv:$argv, build_cwd:"source/lua-5.4.8/src", target_executed:false,
      status:"building",
      limits:"Matched-twin naming is a best-case baseline, not cross-build recognition."}' >"$out/corpus.json"
stage() {
    local name=$1 code
    shift
    if "$@" >"$out/$name.json" 2>"$out/$name.log"; then code=0; else code=$?; fi
    jq --arg name "$name" --argjson code "$code" \
        --argjson argv "$(jq -cn --args '$ARGS.positional' -- "$@")" \
        '.stages[$name]={argv:$argv,exit_code:$code} | .status=(if $code==0 then .status else "failed" end)' \
        "$out/corpus.json" >"$out/corpus.next.json"
    mv "$out/corpus.next.json" "$out/corpus.json"
    [[ "$code" == 0 ]]
}
stage build "${command[@]}"
stage strip "$eval_bin" strip "$out/symbolized.elf" "$out/stripped.elf"
stage symbolized-info "$eval_bin" artifact-info "$out/symbolized.elf"
stage stripped-info "$eval_bin" artifact-info "$out/stripped.elf"
for role in symbolized stripped; do
    stage "$role-validation" jq -e '.format=="elf" and .arch=="aarch64" and .endianness=="little"' \
        "$out/$role-info.json"
done
stage stripped-metadata-validation jq -e '.static_function_symbols==0 and (.debug_sections|length==0)' \
    "$out/stripped-info.json"
stage truth "$eval_bin" truth "$out/symbolized.elf" --stripped "$out/stripped.elf"
stage nonempty-truth-validation jq -e 'length>0' "$out/truth.json"
jq --arg symbolized_sha256 "$(hash "$out/symbolized.elf")" --arg stripped_sha256 "$(hash "$out/stripped.elf")" \
    --argjson functions "$(jq length "$out/truth.json")" \
    '.status="available" | .symbolized_sha256=$symbolized_sha256 | .stripped_sha256=$stripped_sha256 |
     .truth_functions=$functions | .twin_check="truth_function_bytes_identical"' \
    "$out/corpus.json" >"$out/corpus.next.json"
mv "$out/corpus.next.json" "$out/corpus.json"
cat >"$out/manifest.json" <<'JSON'
{"slices":{
  "discovery-lua-aarch64":{"family":"discovery","target":"stripped.elf","truth":"truth.json"},
  "libid-twin-lua-aarch64":{"refs":["symbolized.elf"],"target":"stripped.elf","truth":"truth.json"}
}}
JSON
echo "Verified Lua corpus: $out/manifest.json (target not executed)" >&2
