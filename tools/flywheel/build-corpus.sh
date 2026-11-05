#!/usr/bin/env bash
# Builds the flywheel's library-identification corpus (see docs/flywheel.md) from the pinned sources in
# tools/flywheel/corpus.json.
#
# Each library is compiled per architecture, compiler and optimisation level into a static archive, and every
# owned driver program in tools/flywheel/drivers/<library>/ is linked against it with Zig's static musl. Each
# linked image yields two files: a stripped binary (what is evaluated) and a symbolized twin with the same layout
# (where the truth comes from). The driver's own object is kept so the truth can leave the program's functions
# out; a relocatable link of the library's objects is kept so each truth function can be tagged with its library.
#
# Output: OUT/<version>/ with bin/, obj/, lib/ and manifest.json, where <version> is "libid-" and the first 12
# hex digits of a SHA-256 over this script, corpus.json, the driver sources and the toolchain versions. The
# same inputs give the same version; anything that changes the binaries changes it, and with it the split.
#
# Downloaded sources and built binaries live under target/ and are never committed. A source archive whose
# SHA-256 differs from corpus.json stops the build.
#
# Requires: zig 0.17.x, a clang that targets ELF (default: Homebrew's), curl, python3, and a build of
# rampage-eval (for `strip`).
#
# Usage: tools/flywheel/build-corpus.sh [--out DIR] [--source-cache DIR] [--jobs N] [--rampage-eval PATH]
#                                       [--clang PATH]
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out="$repo/target/flywheel/corpus"
cache="$repo/target/flywheel/sources"
jobs=3
eval_bin=${RAMPAGE_EVAL:-}
clang=${FLYWHEEL_CLANG:-/opt/homebrew/opt/llvm/bin/clang}

usage() {
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) out=$2; shift 2 ;;
        --source-cache) cache=$2; shift 2 ;;
        --jobs) jobs=$2; shift 2 ;;
        --rampage-eval) eval_bin=$2; shift 2 ;;
        --clang) clang=$2; shift 2 ;;
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
[[ -x "$clang" ]] || { echo "clang not found at $clang (pass --clang)" >&2; exit 1; }

recipe="$here/corpus.json"
# One query of corpus.json: python3 prints the requested fields, separated by |, one record per line.
query() {
    python3 -I -c "
import json, sys
corpus = json.load(open(sys.argv[1]))
what = sys.argv[2]
if what == 'libraries':
    for library in corpus['libraries']:
        print('|'.join([library['name'], library['url'], library['sha256'], library['root'],
                         ' '.join(library['include']), ' '.join(library['defines']), ' '.join(library['sources']),
                         ' '.join(library['drivers'])]))
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
zig_lib=$(zig env | python3 -I -c "import re, sys; print(re.search(r'\.lib_dir = \"([^\"]+)\"', sys.stdin.read()).group(1))")
clang_resource=$("$clang" -print-resource-dir)/include

version_input() {
    cat "$0" "$recipe"
    find "$here/drivers" -type f -name '*.c' | LC_ALL=C sort | while read -r file; do
        printf '%s\n' "${file#"$here"/}"
        cat "$file"
    done
    printf 'zig %s\nclang %s\n' "$zig_version" "$clang_version"
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
echo "building corpus $version into $root (zig $zig_version; $clang_version; jobs $jobs)"

# Fetch and check every source archive, then extract it.
while IFS="|" read -r name url sha256 source_root _include _defines _sources _drivers; do
    archive="$cache/$(basename "$url")"
    if [[ "$(basename "$url")" == v*.tar.gz ]]; then
        archive="$cache/$name-$(basename "$url")"
    fi
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
done < <(query libraries)

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

# build_cell LIBRARY_RECORD ARCH TRIPLE COMPILER OPT: one library in one configuration, and its drivers.
build_cell() {
    local name url sha256 source_root include defines sources drivers
    IFS="|" read -r name url sha256 source_root include defines sources drivers <<<"$1"
    local arch=$2 triple=$3 compiler=$4 opt=$5
    local cell="$arch-$compiler-$opt"
    local objects="$work/$name-$cell"
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
    rm -f "$objects/lib.a"
    zig ar rcs "$objects/lib.a" "${library_objects[@]}"
    # The library's functions, for tagging truth functions with their library.
    ld.lld -r -o "$root/lib/$name-$cell.o" "${library_objects[@]}"
    for driver in $drivers; do
        local program
        program=$(basename "$driver" .c)
        local id="$name-$program-$cell"
        compile "$compiler" "$triple" "$opt" "$here/drivers/$driver" "$root/obj/$id.o" "${flags[@]}"
        # -g keeps the symbol table, which zig strips at -Os; the strips below remove the debug sections.
        zig cc -target "$triple" "-$opt" -g -static "$root/obj/$id.o" "$objects/lib.a" -o "$objects/$id.linked"
        "$eval_bin" strip --keep-symbols "$objects/$id.linked" "$root/bin/$id.twin.elf"
        "$eval_bin" strip "$objects/$id.linked" "$root/bin/$id.elf"
        # A twin without function symbols has no truth: refuse it rather than measure nothing.
        if "$eval_bin" artifact-info "$root/bin/$id.twin.elf" | grep -q '"static_function_symbols":0[,}]'; then
            echo "$id: the symbolized twin has no function symbols" >&2
            return 1
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$name/$program" "$name" "$arch" "$compiler" "$opt" \
            >"$work/rows/$id.tsv"
    done
    echo "  built $name $cell"
}

# The matrix is read up front: a `wait` must only ever see the build jobs, never a query's process.
mapfile -t arches < <(query arches)
mapfile -t compilers < <(query compilers)
mapfile -t optimizations < <(query optimizations)
mapfile -t libraries < <(query libraries)
pids=()
for arch_record in "${arches[@]}"; do
    IFS="|" read -r arch triple <<<"$arch_record"
    for compiler in "${compilers[@]}"; do
        for opt in "${optimizations[@]}"; do
            for library in "${libraries[@]}"; do
                while [[ $(jobs -rp | wc -l) -ge $jobs ]]; do
                    sleep 0.2
                done
                build_cell "$library" "$arch" "$triple" "$compiler" "$opt" </dev/null &
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
expected=$((${#arches[@]} * ${#compilers[@]} * ${#optimizations[@]}))
built=$(find "$work/rows" -name '*.tsv' | wc -l | tr -d ' ')
echo "$built binaries built over $expected configurations in ${SECONDS}s"

python3 -I - "$root" "$version" "$recipe" "$zig_version" "$clang_version" <<'PYTHON'
import hashlib, json, pathlib, sys

root, version, recipe_path, zig_version, clang_version = sys.argv[1:]
root = pathlib.Path(root)
recipe = json.loads(pathlib.Path(recipe_path).read_text())

def digest(path):
    return hashlib.sha256((root / path).read_bytes()).hexdigest()

binaries = []
for row in sorted((root / ".work" / "rows").glob("*.tsv")):
    identifier, program, library, arch, compiler, opt = row.read_text().rstrip("\n").split("\t")
    cell = f"{arch}-{compiler}-{opt}"
    entry = {
        "id": identifier,
        "program": program,
        "library": library,
        "arch": arch,
        "compiler": compiler,
        "opt": opt,
        "stripped": f"bin/{identifier}.elf",
        "twin": f"bin/{identifier}.twin.elf",
        "program_object": f"obj/{identifier}.o",
        "library_object": f"lib/{library}-{cell}.o",
    }
    for key in ("stripped", "twin", "program_object", "library_object"):
        entry[key + "_sha256"] = digest(entry[key])
    binaries.append(entry)
manifest = {
    "schema_version": 1,
    "family": recipe["family"],
    "name": recipe["name"],
    "version": version,
    "toolchains": {"zig": zig_version, "clang": clang_version},
    "libraries": [
        {key: library[key] for key in ("name", "version", "license", "url", "sha256")}
        for library in recipe["libraries"]
    ],
    "split": recipe["split"],
    "binaries": binaries,
}
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"{len(binaries)} binaries; manifest {root / 'manifest.json'}")
PYTHON
