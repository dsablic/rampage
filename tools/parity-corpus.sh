#!/usr/bin/env bash
# Owned Phase 0 pilot; extends eval-corpus.sh's compile-once/strip/check convention.
# Usage: bash tools/parity-corpus.sh --list
#        bash tools/parity-corpus.sh target/parity/RUN --only ID [--only ID ...]
#        bash tools/parity-corpus.sh target/parity/RUN --all
# Requires jq, a SHA-256 tool and an existing rampage-eval; never builds the evaluator or runs target binaries.
# GCC, CLANG, CXX, ZIG, GO, RUSTC, LLVM_STRIP, LLVM_OBJCOPY and RAMPAGE_EVAL name single executables.
# GCC defaults to each recipe's compiler_driver; its -dumpmachine must exactly match the requested target.
# LLVM_OBJCOPY explicitly selects objcopy instead of llvm-strip for non-ELF outputs; no automatic fallback.
# Requires rampage-eval artifact-info; headers and removed metadata are checked before emitting slices.
# corpus.json inventories requested/observed metadata and command outcomes; manifest.json holds verified slices.
# Run separately: rampage-eval run --manifest target/parity/RUN/manifest.json > score.json
set -euo pipefail
export LC_ALL=C
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}

usage() {
    echo "usage: $0 --list | OUT_DIR (--only ID [--only ID ...] | --all)" >&2
    exit 2
}

repo=$(cd "$(dirname "$0")/.." && pwd)
script="$repo/tools/parity-corpus.sh"
recipes="$repo/tests/fixtures/corpus/manifest.json"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
if [[ $# -eq 1 && "$1" == --list ]]; then
    jq -r '.entries[] | [.id, .compiler, .target, .source] | @tsv' "$recipes"
    exit 0
fi
[[ $# -ge 2 && "$1" != -* ]] || usage
output=$1
shift
selected=()
selection_count=0
all=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --only)
            [[ $# -ge 2 && "$all" == false ]] || usage
            jq -e --arg id "$2" '.entries | any(.id == $id)' "$recipes" >/dev/null || usage
            selected+=("$2")
            selection_count=$((selection_count + 1))
            shift 2
            ;;
        --all)
            [[ "$selection_count" -eq 0 && "$all" == false ]] || usage
            all=true
            shift
            ;;
        *) usage ;;
    esac
done
[[ "$all" == true || "$selection_count" -gt 0 ]] || usage
case "$SOURCE_DATE_EPOCH" in *[!0-9]*|'') echo "SOURCE_DATE_EPOCH must be an integer" >&2; exit 2 ;; esac

if command -v sha256sum >/dev/null; then
    hash_command=(sha256sum)
elif command -v shasum >/dev/null; then
    hash_command=(shasum -a 256)
else
    echo "sha256sum or shasum is required" >&2
    exit 2
fi
sha256() { "${hash_command[@]}" "$1" | awk '{print $1}'; }
json_argv() { jq -cn --args '$ARGS.positional' -- "$@"; }

eval_bin=${RAMPAGE_EVAL:-"$repo/target/debug/rampage-eval"}
[[ "$eval_bin" == /* ]] || eval_bin="$PWD/$eval_bin"
# Resolve caller paths before moving into the checkout; no output may land in fixture directories.
case "$output" in
    target/parity|target/parity/*|*/target/parity|*/target/parity/*) ;;
    *) echo "OUT_DIR must be under a caller-selected target/parity directory" >&2; exit 2 ;;
esac
mkdir -p "$output"
out=$(cd "$output" && pwd -P)
case "$out" in
    */target/parity|*/target/parity/*) ;;
    *) echo "OUT_DIR must be under a caller-selected target/parity directory" >&2; exit 2 ;;
esac
if [[ -n "$(find "$out" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "OUT_DIR must be empty (use a new run directory); existing artifacts are never overwritten" >&2
    exit 2
fi
cd "$repo"
export ZIG_GLOBAL_CACHE_DIR="$out/.zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$out/.zig-local-cache"
revision=$(git rev-parse HEAD)
cp "$recipes" "$out/recipes.json"
jq -n --slurpfile recipe "$recipes" --arg revision "$revision" --arg epoch "$SOURCE_DATE_EPOCH" \
    --arg recipe_sha256 "$(sha256 "$recipes")" --arg script_sha256 "$(sha256 "$script")" \
    '{schema_version: 1, kind: "parity_pilot_inventory", repository_revision: $revision,
      recipe_sha256: $recipe_sha256, script_sha256: $script_sha256, source_date_epoch: $epoch,
      missing_coverage: $recipe[0].missing_coverage,
      entries: [$recipe[0].entries[] | . + {status: "not_selected",
        requested: {arch: .arch, format: .format, endianness: .endianness, target: .target}}]}' >"$out/corpus.json"
printf '{"slices":{}}\n' >"$out/manifest.json"
if [[ -x "$eval_bin" ]]; then
    jq --arg path "$eval_bin" --arg sha256 "$(sha256 "$eval_bin")" \
        '.evaluator = {path: $path, sha256: $sha256}' "$out/corpus.json" >"$out/corpus.next.json"
    mv "$out/corpus.next.json" "$out/corpus.json"
fi

# jq performs data updates only; manifest strings are never interpreted by the shell.
update_entry() {
    local patch=$1
    jq --arg id "$id" --argjson patch "$patch" \
        '(.entries[] | select(.id == $id)) |= . * $patch' "$out/corpus.json" >"$out/corpus.next.json"
    mv "$out/corpus.next.json" "$out/corpus.json"
}
record_status() {
    update_entry "$(jq -cn --arg status "$1" --arg reason "$2" '{status: $status, reason: $reason}')"
    echo "$id: $1: $2" >&2
}
run_stage() {
    local stage=$1 stdout=$2 stderr=$3 code
    shift 3
    if "$@" >"$out/$stdout" 2>"$out/$stderr"; then
        code=0
    else
        code=$?
    fi
    update_entry "$(jq -cn --arg stage "$stage" --arg stdout "$stdout" --arg stderr "$stderr" \
        --argjson argv "$(json_argv "$@")" --argjson code "$code" \
        '{stages: {($stage): {argv: $argv, stdout: $stdout, stderr: $stderr, exit_code: $code,
          status: (if $code == 0 then "succeeded" else "failed" end)}}}')"
    return "$code"
}
inspect_artifact() {
    local role=$1 path=$2
    local metadata="$id/$role-info.json" log="$id/$role-info.log"
    if run_stage "artifact-info-$role" "$metadata" "$log" "$eval_bin" artifact-info "$out/$path"; then
        :
    else
        record_status failed "$role artifact-info command failed; see $role-info.log and stages exit_code"
        return 1
    fi
    if ! jq -e '
        def count: type == "number" and . >= 0 and floor == .;
        type == "object" and
        (.format | type == "string") and (.arch | type == "string") and
        (.endianness | type == "string") and
        (.static_function_symbols | count) and (.dynamic_function_symbols | count) and
        (.thumb_ranges | count) and (.debug_sections | type == "array" and all(.[]; type == "string"))
        ' "$out/$metadata" >/dev/null; then
        record_status failed "$role artifact-info returned invalid metadata; see $role-info.json"
        return 1
    fi
    update_entry "$(jq -cn --arg role "$role" --slurpfile observed "$out/$metadata" \
        '{observed: {($role): $observed[0]}}')"
    if ! jq -e --argjson requested "$entry" --arg role "$role" '
        .format == $requested.format and .endianness == $requested.endianness and
        (if $requested.arch == "thumb" then
            .arch == "arm" and (if $role == "symbolized" then .thumb_ranges > 0 else true end)
         else .arch == $requested.arch end)
        ' "$out/$metadata" >/dev/null; then
        record_status failed "$role observed header or Thumb evidence does not match requested metadata"
        return 1
    fi
    if [[ "$role" == stripped ]] && ! jq -e \
        '.static_function_symbols == 0 and (.debug_sections | length == 0)' "$out/$metadata" >/dev/null; then
        record_status failed "stripped output retains static function symbols or debug sections"
        return 1
    fi
    update_entry "$(jq -cn --arg role "$role" '{artifact_validation: {($role): "passed"}}')"
}
add_slice() {
    local name=$1 slice=$2
    jq --arg name "$name" --argjson slice "$slice" '.slices[$name] = $slice' \
        "$out/manifest.json" >"$out/manifest.next.json"
    mv "$out/manifest.next.json" "$out/manifest.json"
}
is_selected() {
    [[ "$all" != true ]] || return 0
    local requested
    for requested in "${selected[@]}"; do
        [[ "$requested" != "$id" ]] || return 0
    done
    return 1
}

incomplete=0
while IFS= read -r entry; do
    id=$(jq -r '.id' <<<"$entry")
    is_selected || continue
    dir="$out/$id"
    mkdir "$dir"
    source=$(jq -r '.source' <<<"$entry")
    format=$(jq -r '.format' <<<"$entry")
    extension=$(jq -r '.extension' <<<"$entry")
    compiler=$(jq -r '.compiler' <<<"$entry")
    arch=$(jq -r '.arch' <<<"$entry")
    target=$(jq -r '.target' <<<"$entry")
    case "$arch" in
        x86_64|aarch64|thumb|mips) ;;
        *) record_status failed "unknown architecture recipe: $arch"; incomplete=1; continue ;;
    esac
    build_env=("LC_ALL=$LC_ALL" "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH")
    case "$compiler" in
        gcc) driver=${GCC:-$(jq -r '.compiler_driver' <<<"$entry")} ;;
        clang) driver=${CLANG:-clang} ;;
        clang++) driver=${CXX:-clang++} ;;
        zig) driver=${ZIG:-zig} ;;
        go)
            driver=${GO:-go}
            case "$target/$arch/$format/$(jq -r '.endianness' <<<"$entry")" in
                linux/amd64/x86_64/elf/little) goos=linux; goarch=amd64 ;;
                darwin/arm64/aarch64/macho/little) goos=darwin; goarch=arm64 ;;
                *) record_status failed "unsupported Go target/header recipe"; incomplete=1; continue ;;
            esac
            build_env+=("GOOS=$goos" "GOARCH=$goarch" "CGO_ENABLED=0" "GO111MODULE=off"
                "GOTOOLCHAIN=local" "GOPROXY=off" "GOSUMDB=off" "GOENV=off" "GOWORK=off"
                "GOFLAGS=" "GOEXPERIMENT=" "GOROOT=" "GOTELEMETRY=off" "GOAMD64=v1" "GOARM64=v8.0"
                "GOCACHE=$out/.go-cache" "GOPATH=$out/.go-path" "GOTMPDIR=$out/.go-tmp")
            mkdir -p "$out/.go-tmp"
            ;;
        rustc)
            driver=${RUSTC:-rustc}
            build_env+=("RUSTUP_AUTO_INSTALL=0")
            if [[ "$target/$arch/$format/$(jq -r '.endianness' <<<"$entry")" != \
                aarch64-apple-darwin/aarch64/macho/little ]]; then
                record_status failed "unsupported Rust target/header recipe"; incomplete=1; continue
            fi
            ;;
        *) record_status failed "unknown compiler recipe"; incomplete=1; continue ;;
    esac
    symbolized="$id/symbolized.$extension"
    stripped="$id/stripped.$extension"
    truth="$id/truth.json"
    update_entry "$(jq -cn --arg source_sha256 "$(sha256 "$source")" --arg symbolized "$symbolized" \
        --arg stripped "$stripped" --arg truth "$truth" \
        '{source_sha256: $source_sha256, pair: {symbolized: $symbolized, stripped: $stripped,
          truth: $truth, verification: "not_checked"}, build_status: "not_attempted"}')"
    if [[ ! -x "$eval_bin" ]]; then
        record_status unavailable "rampage-eval missing: set RAMPAGE_EVAL to an existing build"
        incomplete=1
        continue
    fi
    if ! driver_path=$(command -v "$driver"); then
        record_status unavailable "compiler not found: $driver"
        incomplete=1
        continue
    fi
    if [[ "$compiler" == rustc ]]; then
        sibling_rustup="$(dirname "$driver_path")/rustup"
        rustup_path=$(command -v rustup || true)
        if [[ "$driver_path" -ef "$sibling_rustup" ||
            ( -n "$rustup_path" && "$driver_path" -ef "$rustup_path" ) ]]; then
            record_status unavailable "direct rustc required: set RUSTC or PATH; rustup proxy refused"
            incomplete=1
            continue
        fi
    fi
    version_arg=$(jq -r '.version_arg' <<<"$entry")
    if run_stage compiler-version "$id/compiler-version.txt" "$id/compiler-version.log" \
        env "${build_env[@]}" "$driver_path" "$version_arg"; then
        :
    else
        record_status failed "compiler version probe failed; see compiler-version.log and stages exit_code"
        incomplete=1
        continue
    fi
    update_entry "$(jq -cn --arg path "$driver_path" --rawfile version "$dir/compiler-version.txt" \
        '{compiler_path: $path, compiler_version: $version}')"
    if [[ "$compiler" == gcc ]]; then
        if run_stage compiler-target "$id/compiler-target.txt" "$id/compiler-target.log" \
            "$driver_path" -dumpmachine; then
            machine=$(cat "$dir/compiler-target.txt")
        else
            record_status failed "GCC target probe failed; see compiler-target.log and stages exit_code"
            incomplete=1
            continue
        fi
        update_entry "$(jq -cn --arg machine "$machine" '{compiler_machine: $machine}')"
        if ! grep -Fq 'Free Software Foundation' "$dir/compiler-version.txt" ||
            grep -Eiq 'clang' "$dir/compiler-version.txt"; then
            record_status unavailable "genuine GNU GCC required (Clang and Apple gcc aliases are not GCC)"
            incomplete=1
            continue
        fi
        if [[ "$target/$arch/$format/$(jq -r '.endianness' <<<"$entry")" != \
            x86_64-elf/x86_64/elf/little || "$machine" != "$target" ]]; then
            record_status unavailable "GCC -dumpmachine must match the explicit x86_64-elf freestanding recipe"
            incomplete=1
            continue
        fi
    fi
    flags=()
    while IFS= read -r flag; do flags+=("$flag"); done < <(jq -r '.flags[]' <<<"$entry")
    case "$compiler" in
        go) command_argv=("$driver_path" build "${flags[@]}" -o "$out/$symbolized" "$source") ;;
        rustc)
            command_argv=("$driver_path" "${flags[@]}" --remap-path-prefix "$repo=."
                -o "$out/$symbolized" "$source")
            ;;
        *)
            command_argv=("$driver_path" "${flags[@]}" "-fdebug-prefix-map=$repo=." "-ffile-prefix-map=$repo=."
                -o "$out/$symbolized" "$source")
            ;;
    esac
    command_argv=(env "${build_env[@]}" "${command_argv[@]}")
    update_entry "$(jq -cn --argjson argv "$(json_argv "${command_argv[@]}")" \
        --argjson environment "$(json_argv "${build_env[@]}")" \
        '{build_argv: $argv, build_environment_argv: $environment}')"
    if run_stage build "$id/build.stdout" "$id/build.log" "${command_argv[@]}"; then
        update_entry "$(jq -cn --arg hash "$(sha256 "$out/$symbolized")" \
            '{build_status: "built", build_exit_code: 0, pair: {symbolized_sha256: $hash}}')"
    else
        code=$?
        update_entry "$(jq -cn --argjson code "$code" '{build_status: "failed", build_exit_code: $code}')"
        record_status failed "build failed (exit $code); see build.log"
        incomplete=1
        continue
    fi
    if ! inspect_artifact symbolized "$symbolized"; then
        incomplete=1
        continue
    fi
    if [[ "$format" == elf ]]; then
        strip_argv=("$eval_bin" strip "$out/$symbolized" "$out/$stripped")
    else
        if [[ -n "${LLVM_OBJCOPY:-}" ]]; then
            strip_driver=$LLVM_OBJCOPY
            strip_kind=objcopy
        else
            strip_driver=${LLVM_STRIP:-llvm-strip}
            strip_kind=strip
        fi
        if ! strip_path=$(command -v "$strip_driver"); then
            record_status unavailable "symbolized build exists; missing $format strip tool: $strip_driver"
            incomplete=1
            continue
        fi
        if run_stage strip-version "$id/strip-version.txt" "$id/strip-version.log" "$strip_path" --version; then
            :
        else
            record_status failed "strip version probe failed; see strip-version.log and stages exit_code"
            incomplete=1
            continue
        fi
        if [[ "$strip_kind" == objcopy ]]; then
            strip_argv=("$strip_path" --strip-all "$out/$symbolized" "$out/$stripped")
        else
            strip_argv=("$strip_path" --strip-all -o "$out/$stripped" "$out/$symbolized")
        fi
    fi
    update_entry "$(jq -cn --argjson argv "$(json_argv "${strip_argv[@]}")" '{strip_argv: $argv}')"
    if run_stage strip "$id/strip.stdout" "$id/strip.log" "${strip_argv[@]}"; then
        :
    else
        record_status failed "strip command failed; see strip.log and stages exit_code"
        incomplete=1
        continue
    fi
    update_entry "$(jq -cn --arg hash "$(sha256 "$out/$stripped")" '{pair: {stripped_sha256: $hash}}')"
    if ! inspect_artifact stripped "$stripped"; then
        incomplete=1
        continue
    fi
    update_entry '{"pair":{"stripping_verification":"no_static_function_symbols_or_debug_sections"}}'
    truth_argv=("$eval_bin" truth "$out/$symbolized" --stripped "$out/$stripped")
    truth_source=$(jq -r '.truth_source // "sized_symbols"' <<<"$entry")
    case "$truth_source" in
        sized_symbols) ;;
        embedded_dwarf)
            if ! jq -e '.debug_sections | any(.==".debug_info" or .=="__debug_info" or
                .==".zdebug_info" or .=="__zdebug_info")' \
                "$dir/symbolized-info.json" >/dev/null; then
                record_status unavailable "explicit embedded DWARF truth requested, but no debug_info section"
                incomplete=1
                continue
            fi
            truth_argv+=(--dwarf)
            ;;
        uuid_matched_dsym)
            debug_file=$(jq -r '.dwarf_file // empty' <<<"$entry")
            if [[ -z "$debug_file" || ! -f "$out/$debug_file" ]]; then
                record_status unavailable "explicit standalone dSYM file is missing"
                incomplete=1
                continue
            fi
            truth_argv+=(--dwarf-file "$out/$debug_file")
            update_entry "$(jq -cn --arg path "$debug_file" --arg hash "$(sha256 "$out/$debug_file")" \
                '{debug_file: {path: $path, sha256: $hash}}')"
            ;;
        *) record_status failed "unsupported truth source: $truth_source"; incomplete=1; continue ;;
    esac
    update_entry "$(jq -cn --arg source "$truth_source" '{truth_source: $source}')"
    update_entry "$(jq -cn --argjson argv "$(json_argv "${truth_argv[@]}")" '{truth_argv: $argv}')"
    if run_stage truth "$truth" "$id/truth.log" "${truth_argv[@]}"; then
        :
    else
        record_status failed "truth extraction or twin byte-identity check failed; see truth.log and stages exit_code"
        incomplete=1
        continue
    fi
    if ! jq -e 'type == "object"' "$dir/truth.json" >/dev/null; then
        record_status failed "truth command returned invalid JSON; see truth.json"
        incomplete=1
        continue
    fi
    if ! jq -e 'length > 0' "$dir/truth.json" >/dev/null; then
        record_status unavailable "no sized function-symbol truth; build is not scored"
        incomplete=1
        continue
    fi
    update_entry "$(jq -cn --arg symbolized "$(sha256 "$out/$symbolized")" \
        --arg stripped "$(sha256 "$out/$stripped")" --arg truth "$(sha256 "$dir/truth.json")" \
        '{pair: {verification: "function_bytes_identical", symbolized_sha256: $symbolized,
          stripped_sha256: $stripped, truth_sha256: $truth}}')"
    if [[ $(jq -r '.type_truth' <<<"$entry") == true ]]; then
        type_argv=("$eval_bin" type-truth "$out/$symbolized" --stripped "$out/$stripped")
        update_entry "$(jq -cn --argjson argv "$(json_argv "${type_argv[@]}")" '{type_truth_argv: $argv}')"
        if run_stage type-truth "$id/types.json" "$id/types.log" "${type_argv[@]}"; then
            :
        else
            update_entry '{"type_status":"failed","type_reason":"DWARF truth command failed; see types.log"}'
            record_status failed "type-truth command failed; see types.log and stages exit_code"
            incomplete=1
            continue
        fi
        if ! jq -e 'type == "object"' "$dir/types.json" >/dev/null; then
            update_entry '{"type_status":"failed","type_reason":"Invalid type-truth JSON"}'
            record_status failed "type-truth command returned invalid JSON; see types.json"
            incomplete=1
            continue
        fi
        if ! jq -e 'length > 0' "$dir/types.json" >/dev/null; then
            update_entry '{"type_status":"unavailable","type_reason":"No applicable DWARF truth"}'
            record_status unavailable "successful type-truth extraction returned no applicable DWARF truth"
            incomplete=1
            continue
        fi
        update_entry "$(jq -cn --arg path "$id/types.json" --arg hash "$(sha256 "$dir/types.json")" \
            '{type_status: "available", type_truth_artifact: {path: $path, sha256: $hash}}')"
        for metric in params return classes; do
            add_slice "types-$metric-$id" "$(jq -cn --arg target "$stripped" --arg truth "$id/types.json" \
                --arg metric "$metric" '{family: "types", metric: $metric, target: $target, truth: $truth}')"
        done
    fi
    add_slice "discovery-$id" "$(jq -cn --arg target "$stripped" --arg truth "$truth" \
        '{family: "discovery", target: $target, truth: $truth}')"
    record_status available "verified headers, stripped metadata and function bytes; slices emitted without floors"
done < <(jq -c '.entries[]' "$recipes")

echo "Inventory: $out/corpus.json; verified evaluation slices: $out/manifest.json" >&2
echo "This is a pilot corpus, not the combined parity scorecard; unavailable or failed selections exit 1." >&2
exit "$incomplete"
