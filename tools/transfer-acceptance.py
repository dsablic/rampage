#!/usr/bin/env python3
"""Phase 7 acceptance for `transfer_annotations`: zlib 1.2.13 -> 1.3, stripped, per architecture.

Downloads the two pinned upstream releases (SHA-256 checked; never committed), builds each with zig cc at -O2 as a
shared library (stripped of everything but its dynamic exports) and as a static executable (stripped of every
symbol), and keeps an unstripped twin with the same loaded bytes for the truth. Then, per architecture and shape:

1. names every function of the stripped old build by its symbol, through an annotation batch on its log;
2. runs `rampage annotation transfer NEW --from OLD` (matches page, then --apply);
3. scores against the twins' symbol tables:
   - unchanged functions: present once in both builds with an identical body after comments and whitespace are
     removed (zlib 1.3 rewrote K&R headers as prototypes, so headers are not compared);
   - matched correctly: the unchanged function's old address was matched to its new address;
   - false matches: matched pairs whose two symbols differ (pairs with a symbol on one side only are counted apart);
   - transferred correctly: the new build's annotation log names the unchanged function's new address correctly.

Usage: tools/transfer-acceptance.py --rampage target/debug/rampage [--work DIR] [--source-cache DIR]
       [--arch x86_64 --arch aarch64] [--json OUT]
Requires zig 0.17.x, llvm-strip (STRIP, PATH or Homebrew llvm) and python3.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

RELEASES = {
    "1.2.13": (
        "https://github.com/madler/zlib/releases/download/v1.2.13/zlib-1.2.13.tar.gz",
        "b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30",
    ),
    "1.3": (
        "https://github.com/madler/zlib/releases/download/v1.3/zlib-1.3.tar.gz",
        "ff0ba4c292013dbc27530b3a81e1f9a813cd39de01ca5e0f8bf355702efa593e",
    ),
}
SOURCES = [
    "adler32.c", "compress.c", "crc32.c", "deflate.c", "gzclose.c", "gzlib.c", "gzread.c", "gzwrite.c",
    "infback.c", "inffast.c", "inflate.c", "inftrees.c", "trees.c", "uncompr.c", "zutil.c",
]
DEFINES = ["-DHAVE_UNISTD_H", "-DHAVE_STDARG_H", "-D_LARGEFILE64_SOURCE=1"]
DRIVER = "int main(void) { return 0; }\n"


def fetch(version: str, cache: Path) -> Path:
    url, digest = RELEASES[version]
    archive = cache / f"zlib-{version}-{Path(url).name}"
    if not archive.exists():
        cache.mkdir(parents=True, exist_ok=True)
        partial = archive.with_suffix(".partial")
        with urllib.request.urlopen(url) as response, open(partial, "wb") as out:
            shutil.copyfileobj(response, out)
        partial.rename(archive)
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != digest:
        sys.exit(f"{archive}: SHA-256 {actual}, expected {digest}")
    return archive


def unpack(archive: Path, into: Path, version: str) -> Path:
    root = into / f"zlib-{version}"
    if not root.exists():
        into.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as tar:
            tar.extractall(into, filter="data")
    return root


def run(command: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run([str(part) for part in command], check=True, capture_output=True, text=True, **kwargs)


def build(root: Path, arch: str, shape: str, out: Path) -> tuple[Path, Path]:
    """The unstripped twin and the stripped build of zlib at `root`."""
    twin, stripped = out / f"{shape}.twin.elf", out / f"{shape}.elf"
    if twin.exists() and stripped.exists():
        return twin, stripped
    out.mkdir(parents=True, exist_ok=True)
    triple = f"{arch}-linux-musl"
    sources = [root / source for source in SOURCES]
    common = ["zig", "cc", "-target", triple, "-O2", "-g0", "-I", root, *DEFINES]
    if shape == "shared":
        link = [*common, "-fPIC", "-shared", *sources]
    else:
        driver = out / "driver.c"
        driver.write_text(DRIVER)
        link = [*common, "-static", "-Wl,--no-gc-sections", driver, *sources]
    run([*link, "-o", twin])
    run([strip_tool(), "--strip-all", twin, "-o", stripped])
    if loaded_bytes(twin) != loaded_bytes(stripped):
        sys.exit(f"{stripped}: its loaded segments differ from {twin}")
    return twin, stripped


def strip_tool() -> str:
    """llvm-strip: $STRIP, else on PATH, else Homebrew's."""
    for candidate in (os.environ.get("STRIP"), shutil.which("llvm-strip"), "/opt/homebrew/opt/llvm/bin/llvm-strip"):
        if candidate and Path(candidate).exists():
            return candidate
    sys.exit("llvm-strip not found; set STRIP")


def loaded_bytes(path: Path) -> list:
    """The file bytes of each PT_LOAD segment of an ELF64 little-endian file, with its address, header aside."""
    data = path.read_bytes()
    phoff, = struct.unpack_from("<Q", data, 0x20)
    # The ELF header (often inside the first segment) names the section headers, which stripping moves.
    data = bytes(64) + data[64:]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    segments = []
    for index in range(phnum):
        kind, _, offset, vaddr, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phentsize)
        if kind == 1:
            segments.append((vaddr, data[offset:offset + filesz]))
    return segments


def elf_functions(path: Path, table: int = 2) -> dict:
    """Address -> names of the defined FUNC symbols of an ELF64 little-endian file's .symtab (or .dynsym, 11)."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        sys.exit(f"{path}: not an ELF64 little-endian file")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize) for index in range(shnum)]
    functions = {}
    for section in sections:
        if section[1] != table:
            continue
        strings = sections[section[6]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, info, _, shndx, value, size = struct.unpack_from("<IBBHQQ", data, offset)
            if info & 0xF != 2 or shndx == 0 or size == 0:
                continue
            start = strings[4] + name
            text = data[start:data.index(b"\0", start)].decode()
            functions.setdefault(value, set()).add(text)
    return functions


def unique_names(functions: dict) -> dict:
    """Name -> address for names that occur once, at an address only that name has."""
    counts = {}
    for names in functions.values():
        for name in names:
            counts[name] = counts.get(name, 0) + 1
    return {
        next(iter(names)): address
        for address, names in functions.items()
        if len(names) == 1 and counts[next(iter(names))] == 1
    }


def strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/|//[^\n]*", " ", text, flags=re.S)


def function_bodies(source: str) -> dict:
    """Function name -> body without whitespace, for top-level C function definitions in `source`."""
    text = strip_comments(source)
    text = re.sub(r"^[ \t]*#(?:[^\n]*\\\n)*[^\n]*", "", text, flags=re.M)
    bodies, depth, header_start, index = {}, 0, 0, 0
    while index < len(text):
        char = text[index]
        if char in "\"'":
            end = index + 1
            while end < len(text) and text[end] != char:
                end += 2 if text[end] == "\\" else 1
            index = end + 1
            continue
        if char == "{":
            if depth == 0:
                header = text[header_start:index]
                open_at = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                match = re.search(r"([A-Za-z_]\w*)\s*\(", header)
                if match and "=" not in header.split("(")[0] and not re.search(r"\b(struct|union|enum)\s+\w*\s*$", header):
                    bodies[match.group(1)] = re.sub(r"\s+", "", text[open_at:index + 1])
                header_start = index + 1
        elif char == ";" and depth == 0 and (
            text[header_start:index].rstrip().endswith(")") or "=" in text[header_start:index]
        ):
            # A prototype or initialized declaration ends a header; a K&R parameter declaration (`int level;`) does not.
            header_start = index + 1
        index += 1
    return bodies


def unchanged_names(old_root: Path, new_root: Path) -> set:
    names = set()
    for source in SOURCES:
        old = function_bodies((old_root / source).read_text(errors="replace"))
        new = function_bodies((new_root / source).read_text(errors="replace"))
        names.update(name for name, body in old.items() if new.get(name) == body)
    return names


def rampage(binary: Path, *arguments) -> dict:
    result = run([binary, *arguments, "--json"])
    return json.loads(result.stdout)


def score(rampage_bin: Path, roots: dict, builds: dict, work: Path) -> dict:
    old_twin, old = builds["1.2.13"]
    new_twin, new = builds["1.3"]
    for log in (Path(f"{old}.rampage"), Path(f"{new}.rampage")):
        log.unlink(missing_ok=True)
    old_symbols, new_symbols = elf_functions(old_twin), elf_functions(new_twin)
    old_names, new_names = unique_names(old_symbols), unique_names(new_symbols)
    common = set(old_names) & set(new_names)
    unchanged = unchanged_names(roots["1.2.13"], roots["1.3"]) & common

    # Name every old function by its symbol, as an analyst's annotation log would.
    entries = [{"at": hex(address), "name": name} for name, address in sorted(old_names.items())]
    batch = work / "names.json"
    for start in range(0, len(entries), 1000):
        batch.write_text(json.dumps(entries[start:start + 1000]))
        run([rampage_bin, "annotation", "apply-batch", old, batch])

    matches, offset = [], 0
    while offset is not None:
        page = rampage(rampage_bin, "annotation", "transfer", new, "--from", old, "--list", "matches",
                       "--limit", "1000", "--offset", str(offset))
        matches += page["rows"]
        offset = page["next_offset"]
    applied = rampage(rampage_bin, "annotation", "transfer", new, "--from", old, "--apply", "--limit", "1")
    # What the new build now shows: its log's names over the exports its stripped file keeps.
    names = {address: next(iter(found)) for address, found in elf_functions(new, 11).items() if len(found) == 1}
    names.update(
        {int(row["address"], 16): row["text"] for row in rampage(rampage_bin, "annotation", "list", new)["names"]}
    )

    by_pair = {int(row["old"], 16): (int(row["new"], 16), row["method"]) for row in matches}
    false, unverifiable, per_method = [], 0, {}
    for row in matches:
        old_address, new_address = int(row["old"], 16), int(row["new"], 16)
        a, b = old_symbols.get(old_address), new_symbols.get(new_address)
        tally = per_method.setdefault(row["method"], {"matches": 0, "false": 0})
        tally["matches"] += 1
        if a is None or b is None:
            unverifiable += 1
        elif not a & b:
            tally["false"] += 1
            false.append({"old": sorted(a), "new": sorted(b), "method": row["method"]})
    matched = [name for name in unchanged if by_pair.get(old_names[name], (None,))[0] == new_names[name]]
    transferred = [name for name in unchanged if names.get(new_names[name]) == name]
    wrong_names = [
        (hex(address), name) for address, name in names.items()
        if address in new_symbols and name not in new_symbols[address]
    ]
    common_matched = [name for name in common if by_pair.get(old_names[name], (None,))[0] == new_names[name]]
    return {
        "functions": {"old_symbols": len(old_names), "new_symbols": len(new_names), "common": len(common),
                      "unchanged": len(unchanged)},
        "unchanged_matched": len(matched),
        "unchanged_matched_pct": round(100 * len(matched) / max(len(unchanged), 1), 1),
        "unchanged_transferred": len(transferred),
        "unchanged_transferred_pct": round(100 * len(transferred) / max(len(unchanged), 1), 1),
        "common_matched": len(common_matched),
        "common_matched_pct": round(100 * len(common_matched) / max(len(common), 1), 1),
        "matches": len(matches),
        "false_matches": len(false),
        "unverifiable_matches": unverifiable,
        "per_method": per_method,
        "wrong_names_written": len(wrong_names),
        "missed_unchanged": sorted(set(unchanged) - set(matched)),
        "false_examples": false[:10],
        "tool_summary": {"matching": applied["matching"], "annotations": applied["annotations"],
                         "applied": applied.get("applied")},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    repo = Path(__file__).resolve().parent.parent
    parser.add_argument("--rampage", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=repo / "target" / "transfer-acceptance")
    parser.add_argument("--source-cache", type=Path, default=repo / "target" / "transfer-acceptance" / "sources")
    parser.add_argument("--arch", action="append", choices=["x86_64", "aarch64"])
    parser.add_argument("--shape", action="append", choices=["shared", "static"])
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    work = args.work.resolve()
    rampage_bin = args.rampage.resolve()
    roots = {version: unpack(fetch(version, args.source_cache), work / "src", version) for version in RELEASES}
    results = {}
    for arch in args.arch or ["x86_64", "aarch64"]:
        for shape in args.shape or ["shared", "static"]:
            builds = {version: build(roots[version], arch, shape, work / arch / version) for version in RELEASES}
            result = score(rampage_bin, roots, builds, work / arch)
            results[f"{arch}-{shape}"] = result
            print(
                f"{arch} {shape}: unchanged {result['functions']['unchanged']}, matched "
                f"{result['unchanged_matched_pct']}%, transferred {result['unchanged_transferred_pct']}%, "
                f"false matches {result['false_matches']} of {result['matches']} "
                f"({result['unverifiable_matches']} unverifiable), wrong names {result['wrong_names_written']}, "
                f"all common names matched {result['common_matched_pct']}%"
            )
    if args.json:
        args.json.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
