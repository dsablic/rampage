#!/usr/bin/env bash
# Builds the flywheel's library-identification corpus (see docs/flywheel.md) from the pinned sources in
# tools/flywheel/corpus.json.
#
# Each library version is compiled per architecture, compiler and optimisation level into a static archive, and
# each of its owned driver programs in tools/flywheel/drivers/ is linked against it with Zig's static musl. A
# target library is built twice: its older version for the training split and its current version, held out.
# Negative libraries and owned programs are built the same way; no target signature may ever match them.
#
# Each linked image yields a stripped binary (what is evaluated) and a symbolized twin with the same layout
# (where the truth comes from). The driver's own object is kept so the truth can leave the program's functions
# out; a relocatable link of the library's objects is kept so each truth function can be tagged with its library.
#
# Output: OUT/<version>/ with bin/, obj/, lib/ and manifest.json, where <version> is "libid-" and the first 12
# hex digits of a SHA-256 over this script, corpus.json, the driver sources and the toolchain versions (zig,
# clang, ld.lld). The same inputs give the same version.
#
# Reproducibility: tools/flywheel/expected-digests.json records the stripped binaries' SHA-256 of a reference
# build (`--record-digests` writes it). Every build compares against it and reports each binary that differs.
# It is not part of the version, so recording it does not change the corpus it describes.
#
# Downloaded sources and built binaries live under target/ and are never committed. A source archive whose
# SHA-256 differs from corpus.json stops the build.
#
# Requires: zig 0.17.x, a clang that targets ELF (default: Homebrew's), ld.lld, curl, python3, and a build of
# rampage-eval (for `strip` and `artifact-info`).
#
# Usage: tools/flywheel/build-corpus.sh [--out DIR] [--source-cache DIR] [--jobs N] [--rampage-eval PATH]
#                                       [--clang PATH] [--record-digests]
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out="$repo/target/flywheel/corpus"
cache="$repo/target/flywheel/sources"
jobs=3
record=false
eval_bin=${RAMPAGE_EVAL:-}
clang=${FLYWHEEL_CLANG:-/opt/homebrew/opt/llvm/bin/clang}

usage() {
    sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) out=$2; shift 2 ;;
        --source-cache) cache=$2; shift 2 ;;
        --jobs) jobs=$2; shift 2 ;;
        --rampage-eval) eval_bin=$2; shift 2 ;;
        --clang) clang=$2; shift 2 ;;
        --record-digests) record=true; shift ;;
        -h | --help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done
if [[ -z "$eval_bin" ]]; then
    for candidate in "$repo/target/release/rampage-eval" "$repo/target/debug/rampage-eval"; do
        if [[ -x "$candidate" ]]; then
            eval_bin=$candidate
            break
        fi
    done
fi
if [[ -z "$eval_bin" || ! -x "$eval_bin" ]]; then
    echo "rampage-eval not found; run: cargo build --release -p rampage-eval (or pass --rampage-eval)" >&2
    exit 1
fi
command -v zig >/dev/null || { echo "zig not found" >&2; exit 1; }
command -v ld.lld >/dev/null || { echo "ld.lld not found" >&2; exit 1; }
[[ -x "$clang" ]] || { echo "clang not found at $clang (pass --clang)" >&2; exit 1; }

recipe="$here/corpus.json"
expected="$here/expected-digests.json"
# One query of corpus.json: python3 prints the requested fields, separated by |, one record per line.
query() {
    python3 -I -c "
import json, sys
corpus = json.load(open(sys.argv[1]))
what = sys.argv[2]
if what == 'builds':
    for library in corpus['libraries']:
        for version in library['versions']:
            print('|'.join([library['name'], library['role'], version['split'], version['version'],
                            version.get('url', ''), version.get('sha256', ''), version.get('root', ''),
                            ' '.join(library['include']), ' '.join(library['defines']),
                            ' '.join(library['sources']), ' '.join(library['drivers'])]))
elif what == 'arches':
    for arch in corpus['arches']:
        print(arch['name'] + '|' + arch['triple'])
elif what == 'compilers':
    print('\n'.join(compiler['name'] for compiler in corpus['compilers']))
elif what == 'optimizations':
    print('\n'.join(corpus['optimizations']))
" "$recipe" "$1"
}

zig_version=$(zig version)
clang_version=$("$clang" --version | head -n 1)
lld_version=$(ld.lld --version | head -n 1)
zig_lib=$(zig env | python3 -I -c "import re, sys; print(re.search(r'\.lib_dir = \"([^\"]+)\"', sys.stdin.read()).group(1))")
clang_resource=$("$clang" -print-resource-dir)/include

version_input() {
    cat "$0" "$recipe"
    find "$here/drivers" -type f -name '*.c' | LC_ALL=C sort | while read -r file; do
        printf '%s\n' "${file#"$here"/}"
        cat "$file"
    done
    printf 'zig %s\nclang %s\nlld %s\n' "$zig_version" "$clang_version" "$lld_version"
}
version="libid-$(version_input | shasum -a 256 | cut -c1-12)"
root="$out/$version"
work="$root/.work"
if [[ -f "$root/manifest.json" ]]; then
    echo "corpus $version is already built: $root"
    exit 0
fi
rm -rf "$root"
mkdir -p "$root/bin" "$root/obj" "$root/lib" "$work/src" "$work/rows" "$cache"
echo "building corpus $version into $root (zig $zig_version; $clang_version; $lld_version; jobs $jobs)"

# Fetch and check every source archive, then extract it.
while IFS="|" read -r name _role _split library_version url sha256 source_root _rest; do
    [[ -n "$url" ]] || continue
    archive="$cache/$name-$library_version-$(basename "$url")"
    if [[ ! -f "$archive" ]]; then
        echo "fetching $url"
        curl -fsSL -o "$archive.partial" "$url"
        mv "$archive.partial" "$archive"
    fi
    actual=$(shasum -a 256 "$archive" | cut -d' ' -f1)
    if [[ "$actual" != "$sha256" ]]; then
        echo "$archive: SHA-256 $actual, but corpus.json pins $sha256" >&2
        exit 1
    fi
    tar -xzf "$archive" -C "$work/src"
    [[ -d "$work/src/$source_root" ]] || { echo "$archive has no $source_root/" >&2; exit 1; }
done < <(query builds)

# compile COMPILER TRIPLE OPT SOURCE OBJECT FLAGS...
compile() {
    local compiler=$1 triple=$2 opt=$3 source=$4 object=$5
    shift 5
    case "$compiler" in
        zig) zig cc -target "$triple" "-$opt" -g0 -c "$source" -o "$object" "$@" ;;
        clang)
            "$clang" --target="$triple" "-$opt" -g0 -nostdinc -isystem "$clang_resource" \
                -isystem "$zig_lib/libc/include/$triple" -isystem "$zig_lib/libc/include/generic-musl" \
                -isystem "$zig_lib/libc/include/any-linux-any" -c "$source" -o "$object" "$@"
            ;;
        *) echo "unknown compiler $compiler" >&2; return 1 ;;
    esac
}

# build_cell BUILD_RECORD ARCH TRIPLE COMPILER OPT: one library version in one configuration, and its drivers.
build_cell() {
    local name role split library_version url sha256 source_root include defines sources drivers
    IFS="|" read -r name role split library_version url sha256 source_root include defines sources drivers <<<"$1"
    local arch=$2 triple=$3 compiler=$4 opt=$5
    local cell="$arch-$compiler-$opt"
    local tag="$name-$library_version"
    local objects="$work/$tag-$cell"
    mkdir -p "$objects"
    local flags=()
    for directory in $include; do flags+=("-I$work/src/$source_root/$directory"); done
    for define in $defines; do flags+=("-D$define"); done
    local library_objects=()
    for source in $sources; do
        local object="$objects/$(basename "$source" .c).o"
        compile "$compiler" "$triple" "$opt" "$work/src/$source_root/$source" "$object" "${flags[@]}"
        library_objects+=("$object")
    done
    local link=()
    local library_object=""
    if [[ ${#library_objects[@]} -gt 0 ]]; then
        rm -f "$objects/lib.a"
        zig ar rcs "$objects/lib.a" "${library_objects[@]}"
        link=("$objects/lib.a")
        # The library's functions, for tagging truth functions with their library.
        library_object="lib/$tag-$cell.o"
        ld.lld -r -o "$root/$library_object" "${library_objects[@]}"
    fi
    for driver in $drivers; do
        local program
        program=$(basename "$driver" .c)
        local id="$tag-$program-$cell"
        compile "$compiler" "$triple" "$opt" "$here/drivers/$driver" "$root/obj/$id.o" "${flags[@]}"
        # -g keeps the symbol table, which zig strips at -Os; the strips below remove the debug sections.
        zig cc -target "$triple" "-$opt" -g -static "$root/obj/$id.o" "${link[@]}" -o "$objects/$id.linked"
        "$eval_bin" strip --keep-symbols "$objects/$id.linked" "$root/bin/$id.twin.elf"
        "$eval_bin" strip "$objects/$id.linked" "$root/bin/$id.elf"
        # A twin without function symbols has no truth: refuse it rather than measure nothing.
        if "$eval_bin" artifact-info "$root/bin/$id.twin.elf" | grep -q '"static_function_symbols":0[,}]'; then
            echo "$id: the symbolized twin has no function symbols" >&2
            return 1
        fi
        printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$id" "$name/$program" "$name" "$library_version" "$role" \
            "$split" "$arch" "$compiler" "$opt" "$library_object" >"$work/rows/$id.row"
    done
    echo "  built $tag $cell"
}

# The matrix is read up front: a `wait` must only ever see the build jobs, never a query's process.
mapfile -t arches < <(query arches)
mapfile -t compilers < <(query compilers)
mapfile -t optimizations < <(query optimizations)
mapfile -t builds < <(query builds)
pids=()
for arch_record in "${arches[@]}"; do
    IFS="|" read -r arch triple <<<"$arch_record"
    for compiler in "${compilers[@]}"; do
        for opt in "${optimizations[@]}"; do
            for build in "${builds[@]}"; do
                while [[ $(jobs -rp | wc -l) -ge $jobs ]]; do
                    sleep 0.2
                done
                build_cell "$build" "$arch" "$triple" "$compiler" "$opt" </dev/null &
                pids+=("$!")
            done
        done
    done
done
# Every cell must succeed before the manifest is written.
failed=0
for pid in "${pids[@]}"; do
    wait "$pid" || failed=$((failed + 1))
done
if [[ $failed -gt 0 ]]; then
    echo "$failed library builds failed; no manifest written" >&2
    exit 1
fi
built=$(find "$work/rows" -name '*.row' | wc -l | tr -d ' ')
echo "$built binaries built in ${SECONDS}s"

python3 -I - "$root" "$version" "$recipe" "$zig_version" "$clang_version" "$lld_version" "$expected" "$record" <<'PYTHON'
import hashlib, json, pathlib, sys

root, version, recipe_path, zig_version, clang_version, lld_version, expected_path, record = sys.argv[1:]
root = pathlib.Path(root)
recipe = json.loads(pathlib.Path(recipe_path).read_text())

def digest(path):
    return hashlib.sha256((root / path).read_bytes()).hexdigest()

binaries = []
for row in sorted((root / ".work" / "rows").glob("*.row")):
    fields = row.read_text().rstrip("\n").split("|")
    identifier, program, library, library_version, role, split, arch, compiler, opt, library_object = fields
    entry = {
        "id": identifier,
        "program": program,
        "library": library,
        "library_version": library_version,
        "split": split,
        "arch": arch,
        "compiler": compiler,
        "opt": opt,
        "stripped": f"bin/{identifier}.elf",
        "twin": f"bin/{identifier}.twin.elf",
        "program_object": f"obj/{identifier}.o",
    }
    if library_object:
        entry["library_object"] = library_object
    for key in ("stripped", "twin", "program_object", "library_object"):
        if key in entry:
            entry[key + "_sha256"] = digest(entry[key])
    binaries.append(entry)
manifest = {
    "schema_version": 2,
    "family": recipe["family"],
    "name": recipe["name"],
    "version": version,
    "toolchains": {"zig": zig_version, "clang": clang_version, "lld": lld_version},
    "libraries": [
        {"name": library["name"], "license": library["license"], "role": library["role"],
         "versions": [{key: value for key, value in entry.items() if key != "root"} for entry in library["versions"]]}
        for library in recipe["libraries"]
    ],
    "split": recipe["split"],
    "binaries": binaries,
}
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"{len(binaries)} binaries; manifest {root / 'manifest.json'}")

digests = {entry["id"]: entry["stripped_sha256"] for entry in binaries}
expected_path = pathlib.Path(expected_path)
if record == "true":
    expected_path.write_text(json.dumps({"corpus_version": version, "stripped_sha256": digests}, indent=1,
                                        sort_keys=True) + "\n")
    print(f"recorded {len(digests)} expected digests in {expected_path}")
elif expected_path.is_file():
    reference = json.loads(expected_path.read_text())
    wanted = reference.get("stripped_sha256", {})
    differing = sorted(key for key in digests if key in wanted and wanted[key] != digests[key])
    missing = sorted(set(wanted) - set(digests))
    if differing or missing:
        print(f"REPRODUCIBILITY: {len(differing)} binaries differ from {expected_path.name} "
              f"(recorded for {reference.get('corpus_version')}), {len(missing)} missing; first: "
              f"{(differing + missing)[:5]}", file=sys.stderr)
    else:
        print(f"reproducibility: all {len(wanted)} recorded digests match")
PYTHON
