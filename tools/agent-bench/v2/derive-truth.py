"""Derive every suite-v2 answer from sources, debug info, symbols and deterministic harness runs, then compare
with the task manifests. Neither benchmarked server is used: the tools are LLVM's (llvm-nm, llvm-objdump,
llvm-dwarfdump, llvm-readelf), Apple's dyld_info, the Go toolchain's objdump, and host programs the script
compiles and runs from the owned sources.

Usage: python3 -I tools/agent-bench/v2/derive-truth.py [--skip-scale] [--json OUT]
Exits non-zero when a derived truth disagrees with a manifest, a stripped fixture's loaded bytes differ from its
twin's, or a fixture digest differs from its manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
FIX = ROOT / "tests/fixtures/bench-v2"
TASKS = ROOT / "crates/rampage-eval/tasks/v2"
LLVM = Path("/opt/homebrew/opt/llvm/bin")
SCALE = ROOT / "target/bench/v2/scale"


def run(*command: str | Path, cwd: Path | None = None) -> str:
    return subprocess.run([str(part) for part in command], check=True, capture_output=True, text=True, cwd=cwd).stdout


def symbols(path: Path) -> dict[str, int]:
    table: dict[str, int] = {}
    for line in run(LLVM / "llvm-nm", "--defined-only", path).splitlines():
        parts = line.split()
        if len(parts) == 3:
            table.setdefault(parts[2].lstrip("_") if path.suffix == ".macho" else parts[2], int(parts[0], 16))
    return table


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------------------------------------------
# Loaded-image comparison: stripping must not move or change any loaded byte.


def elf_image(path: Path) -> list[tuple[int, bytes]]:
    data = path.read_bytes()
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    if is64:
        phoff, = struct.unpack_from(endian + "Q", data, 0x20)
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 0x36)
    else:
        phoff, = struct.unpack_from(endian + "I", data, 0x1C)
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 0x2A)
    segments = []
    for index in range(phnum):
        base = phoff + index * phentsize
        if is64:
            kind, _, offset, vaddr, _, filesz, _, _ = struct.unpack_from(endian + "IIQQQQQQ", data, base)
        else:
            kind, offset, vaddr, _, filesz, _, _, _ = struct.unpack_from(endian + "IIIIIIII", data, base)
        if kind == 1:
            segments.append((vaddr, data[offset : offset + filesz]))
    return segments


def macho_image(path: Path) -> list[tuple[str, int, bytes]]:
    data = path.read_bytes()
    ncmds, = struct.unpack_from("<I", data, 16)
    offset = 32
    segments = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, offset)
        if cmd == 0x19:
            name = data[offset + 8 : offset + 24].rstrip(b"\0").decode()
            vmaddr, _, fileoff, filesize = struct.unpack_from("<QQQQ", data, offset + 24)
            if name != "__LINKEDIT":
                segments.append((name, vmaddr, data[fileoff : fileoff + filesize]))
        offset += size
    return segments


def elf_sections(path: Path) -> list[tuple[int, bytes]]:
    """(address, bytes) of every allocated section with file contents; headers and symbol tables excluded."""
    data = path.read_bytes()
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    if is64:
        shoff, = struct.unpack_from(endian + "Q", data, 0x28)
        shentsize, shnum = struct.unpack_from(endian + "HH", data, 0x3A)
    else:
        shoff, = struct.unpack_from(endian + "I", data, 0x20)
        shentsize, shnum = struct.unpack_from(endian + "HH", data, 0x2E)
    sections = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if is64:
            _, kind, flags, addr, offset, size = struct.unpack_from(endian + "IIQQQQ", data, base)
        else:
            _, kind, flags, addr, offset, size = struct.unpack_from(endian + "IIIIII", data, base)
        if flags & 2 and kind != 8:
            sections.append((addr, data[offset : offset + size]))
    return sorted(sections)


def macho_sections(path: Path) -> list[tuple[int, bytes]]:
    data = path.read_bytes()
    ncmds, = struct.unpack_from("<I", data, 16)
    offset = 32
    sections = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, offset)
        if cmd == 0x19:
            nsects, = struct.unpack_from("<I", data, offset + 64)
            for index in range(nsects):
                base = offset + 72 + index * 80
                addr, length, fileoffset = struct.unpack_from("<QQI", data, base + 32)
                flags, = struct.unpack_from("<I", data, base + 64)
                zerofill = (flags & 0xFF) in (1, 12, 18)
                sections.append((addr, b"" if zerofill else data[fileoffset : fileoffset + length]))
        offset += size
    return sorted(sections)


def same_image(stripped: Path, twin: Path) -> bool:
    if stripped.suffix == ".macho":
        return macho_sections(stripped) == macho_sections(twin)
    return elf_sections(stripped) == elf_sections(twin)


# ---------------------------------------------------------------------------------------------------------------
# A small reader over `llvm-dwarfdump --debug-info` text: DIEs with offsets, tags, attributes and children.


class Die:
    def __init__(self, offset: int, tag: str, depth: int) -> None:
        self.offset, self.tag, self.depth = offset, tag, depth
        self.attrs: dict[str, str] = {}
        self.children: list[Die] = []


def dwarf(path: Path) -> dict[int, Die]:
    dies: dict[int, Die] = {}
    stack: list[Die] = []
    current: Die | None = None
    for line in run(LLVM / "llvm-dwarfdump", "--debug-info", path).splitlines():
        match = re.match(r"^0x([0-9a-f]+):( +)(DW_TAG_\w+|NULL)", line)
        if match:
            depth = len(match.group(2))
            if match.group(3) == "NULL":
                current = None
                continue
            current = Die(int(match.group(1), 16), match.group(3), depth)
            while stack and stack[-1].depth >= depth:
                stack.pop()
            if stack:
                stack[-1].children.append(current)
            stack.append(current)
            dies[current.offset] = current
            continue
        attr = re.match(r"^\s+(DW_AT_\w+)\s+\((.*)\)$", line)
        if attr and current is not None:
            current.attrs[attr.group(1)] = attr.group(2)
    return dies


def ref(value: str) -> int:
    return int(value.split()[0], 16)


def type_size(dies: dict[int, Die], offset: int) -> int:
    die = dies[offset]
    if "DW_AT_byte_size" in die.attrs:
        return int(die.attrs["DW_AT_byte_size"], 0)
    if die.tag == "DW_TAG_pointer_type":
        return 8
    return type_size(dies, ref(die.attrs["DW_AT_type"]))


def named(dies: dict[int, Die], tag: str, name: str) -> Die:
    found = [die for die in dies.values() if die.tag == tag and die.attrs.get("DW_AT_name") == f'"{name}"'
             and die.children]
    if not found:
        raise SystemExit(f"no DWARF {tag} {name}")
    return found[0]


def members(dies: dict[int, Die], die: Die) -> dict[str, tuple[int, int]]:
    result = {}
    for child in die.children:
        if child.tag == "DW_TAG_member" and "DW_AT_data_member_location" in child.attrs:
            name = child.attrs["DW_AT_name"].strip('"')
            result[name] = (int(child.attrs["DW_AT_data_member_location"], 0),
                            type_size(dies, ref(child.attrs["DW_AT_type"])))
    return result


def disassemble(path: Path, symbol: str) -> str:
    return run(LLVM / "llvm-objdump", "-d", "--no-show-raw-insn", f"--disassemble-symbols={symbol}", path)


# ---------------------------------------------------------------------------------------------------------------
# Per-task derivations. Each returns the answer object the manifest must hold.


def cpp_hierarchy() -> dict[str, Any]:
    twin = FIX / "twins/widgets-x64.elf"
    dies = dwarf(twin)
    edges = []
    classes = []
    for die in dies.values():
        if die.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and die.children and die.depth == 3:
            name = die.attrs.get("DW_AT_name", "").strip('"')
            if not name or not any(child.tag == "DW_TAG_member" and "_vptr" in child.attrs.get("DW_AT_name", "")
                                   for child in die.children) and not any(
                                       child.tag == "DW_TAG_inheritance" for child in die.children):
                continue
            classes.append(name)
            for child in die.children:
                if child.tag == "DW_TAG_inheritance":
                    base = dies[ref(child.attrs["DW_AT_type"])].attrs["DW_AT_name"].strip('"')
                    edges.append([base, name])
    # Cross-check: the global-namespace type_info names in the binary are exactly these classes.
    rtti = sorted(re.sub(r"^_ZTS\d+", "", name) for name in symbols(twin) if re.fullmatch(r"_ZTS\d+\w+", name))
    assert rtti == sorted(set(classes)), (rtti, classes)
    return {"edges": sorted(edges)}


def cpp_virtual_call() -> dict[str, Any]:
    twin = FIX / "twins/widgets-x64.elf"
    table = symbols(twin)
    text = disassemble(twin, "_Z4drawPK4Nodei")
    calls = re.findall(r"callq\s+\*0x([0-9a-f]+)\(%rax\)", text)
    assert len(calls) == 1, text
    slot = int(calls[0], 16)
    # The Slider vtable's address point is 16 bytes past _ZTV6Slider; read the slot's entry from the twin.
    image = dict(elf_image(twin))
    address = table["_ZTV6Slider"] + 16 + slot
    entry = None
    for vaddr, data in image.items():
        if vaddr <= address < vaddr + len(data):
            entry, = struct.unpack_from("<Q", data, address - vaddr)
    assert entry == table["_ZNK6Slider6renderEi"], (hex(entry or 0), hex(table["_ZNK6Slider6renderEi"]))
    return {"draw": table["_Z4drawPK4Nodei"], "target": entry}


def cpp_layout() -> dict[str, Any]:
    dies = dwarf(FIX / "twins/packet-arm64.macho.dSYM")
    fields = members(dies, named(dies, "DW_TAG_class_type", "Packet"))
    return {"fields": sorted([offset, size] for name, (offset, size) in fields.items() if not name.startswith("_vptr"))}


def cpp_vtable_slots() -> dict[str, Any]:
    twin = FIX / "twins/codec-arm64.macho"
    table = symbols(twin)
    order = ["ZN5Codec6encodeEPKhiPh", "ZN9FastCodec6decodeEPKhiPh", "ZN5Codec5resetEv", "ZN9FastCodec5flushEPh"]
    slots = [table[name] for name in order]
    # Cross-check against the rebase fixups dyld applies to FastCodec's vtable.
    vtable = table["ZTV9FastCodec"] + 16
    fixups = {}
    for line in run("dyld_info", "-fixups", twin).splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[3] == "rebase":
            fixups[int(parts[2], 16)] = int(parts[4], 16)
    assert [fixups[vtable + 8 * index] for index in range(4)] == slots
    assert vtable + 32 not in fixups or fixups.get(vtable + 32) is None
    return {"factory": table["Z10make_codeci"], "slots": slots}


def pointer_chain() -> dict[str, Any]:
    twin = FIX / "twins/session-arm64.elf"
    dies = dwarf(twin)
    session = members(dies, named(dies, "DW_TAG_structure_type", "session"))
    conn = members(dies, named(dies, "DW_TAG_structure_type", "conn"))
    stats = members(dies, named(dies, "DW_TAG_structure_type", "stats"))
    return {"function": symbols(twin)["session_read"],
            "offsets": [session["primary"][0], conn["stats"][0], stats["bytes"][0]], "size": stats["bytes"][1]}


def record_table() -> dict[str, Any]:
    source = (FIX / "src/services.c").read_text()
    records = re.findall(r'\{"([^"]+)", (\d+), (\d+), 0x[0-9a-f]+, (\d+)\}', source)
    match = [record for record in records if record[1] == "8443"]
    assert len(records) == 12 and len(match) == 1
    twin = FIX / "twins/services-x64.elf"
    # Harness run: compile the same source for the host and query it.
    output, _ = host_run(FIX / "src/services.c", ["8443"])
    assert output.startswith(f"{match[0][0]} ") and output.strip().endswith(f"timeout={match[0][3]}"), output
    return {"function": symbols(twin)["find_service"], "name": match[0][0], "timeout": int(match[0][3])}


def key_derivation() -> dict[str, Any]:
    twin = FIX / "twins/vault-arm64.macho"
    table = symbols(twin)
    source = (FIX / "src/vault.c").read_text()
    body = source[source.index("static void derive_key"):]
    constant = int(re.search(r"\^ (0x[0-9A-Fa-f]+)u;", body).group(1), 16)
    # The decoy keeps its own constant, so the two routines were not merged.
    text = disassemble(twin, "_derive_key") + disassemble(twin, "_derive_tag")
    assert "_derive_key" in text and "_derive_tag" in text
    return {"function": table["derive_key"], "xor_constant": constant}


def option_bit() -> dict[str, Any]:
    source = (FIX / "src/backup.c").read_text()
    options = dict((bit, name) for name, bit in re.findall(r'\{"(--[a-z-]+)", (0x[0-9a-f]+)\}', source))
    main = source[source.index("int main"):]
    bit = re.search(r"if \(flags & (0x[0-9a-f]+)\) \{\s+write_archive\(\);", main).group(1)
    assert 'fopen("backup.tar"' in source[source.index("write_archive(void)"):]
    output, created = host_run(FIX / "src/backup.c", [options[bit]])
    assert created == ["backup.tar"], (output, created)
    for name in options.values():
        if name != options[bit]:
            assert "backup.tar" not in host_run(FIX / "src/backup.c", [name])[1], name
    return {"option": options[bit]}


def call_chain() -> dict[str, Any]:
    twin = FIX / "twins/beacon-arm64.elf"
    table = symbols(twin)
    chain = ["main", "run", "send_beacon", "open_channel", "dial"]
    for caller, callee in zip(chain, chain[1:]):
        text = disassemble(twin, caller)
        assert re.search(rf"\bbl\s+0x{table[callee]:x} <{callee}>", text), (caller, callee)
    assert re.search(r"\bbl\s+0x[0-9a-f]+ <connect@plt>", disassemble(twin, "dial"))
    for other in set(name for name in ("log_line", "parse_port", "main", "run", "send_beacon", "open_channel")):
        assert "connect@plt" not in disassemble(twin, other), other
    return {"chain": [table[name] for name in chain]}


def crc_parameters() -> dict[str, Any]:
    source = (FIX / "src/checksum.c").read_text()
    init = int(re.search(r"uint32_t crc = (0x[0-9A-Fa-f]+)u;", source).group(1), 16)
    poly = int(re.search(r"\^ \((0x[0-9A-Fa-f]+)u &", source).group(1), 16)
    final = int(re.search(r"return crc \^ (0x[0-9A-Fa-f]+)u;", source).group(1), 16)

    def reference(data: bytes) -> int:
        crc = init
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (poly if crc & 1 else 0)
        return crc ^ final

    output, _ = host_run(FIX / "src/checksum.c", ["123456789"])
    assert int(output.split()[0], 16) == reference(b"123456789"), output
    return {"function": symbols(FIX / "twins/checksum-mips.elf")["frame_check"], "polynomial": poly, "init": init,
            "final_xor": final}


def firmware() -> dict[str, Any]:
    twin = FIX / "twins/blinky-cm3.elf"
    table = symbols(twin)
    reset = table["reset_handler"] & ~1
    image = (FIX / "bin/blinky-cm3.bin").read_bytes()
    vector, = struct.unpack_from("<I", image, 4)
    assert vector == reset | 1
    source = (FIX / "src/blinky.c").read_text()
    order = ["clock_enable", "gpio_setup"]
    writes = []
    for function in order:
        body = source[source.index(f"void {function}(void)"):]
        body = body[: body.index("\n}")]
        writes += [[int(a, 16), int(v, 16)] for a, v in re.findall(r"REG\((0x[0-9A-F]+)u\) = (0x[0-9A-F]+)u;", body)]
    reset_body = source[source.index("void reset_handler(void)"):]
    calls = re.findall(r"(clock_enable|gpio_setup|REG\(0x[0-9A-F]+u\))", reset_body)
    assert calls == ["clock_enable", "REG(0xE000E010u)", "gpio_setup"], calls
    writes = [write for write in writes if 0x40000000 <= write[0] <= 0x5FFFFFFF]
    # Each helper's stores happen in source order: one str per store in the twin's disassembly.
    for function in order:
        text = disassemble(twin, function)
        assert len(re.findall(r"\bstr\b", text)) == len(re.findall(r"REG\(", source[source.index(f"void {function}(void)"):].split("\n}")[0])), text
    return {"reset_handler": reset, "writes": writes}


def library_diff() -> dict[str, Any]:
    source = (FIX / "src/libcalc.c").read_text()
    changed = set()
    for match in re.finditer(r"EXPORT [^\n]*?(calc_\w+)\(", source):
        start = match.start()
        end = source.find("\nEXPORT", start)
        if "#ifdef CALC_V2" in source[start : end if end > 0 else len(source)]:
            changed.add(match.group(1))
    exports = set(re.findall(r"EXPORT [^\n]*?(calc_\w+)\(", source))
    # Cross-check: exactly the changed functions differ in instruction text once addresses are masked.
    def bodies(path: Path) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        current = None
        for line in run(LLVM / "llvm-objdump", "-d", "--no-show-raw-insn", "--no-leading-addr", path).splitlines():
            head = re.match(r"^(?:[0-9a-f]+ )?<(calc_\w+)>:$", line.strip())
            if head:
                current = head.group(1)
                result[current] = []
            elif current and line.strip() and not line.startswith("Disassembly"):
                result[current].append(re.sub(r"0x[0-9a-f]+|<[^>]+>", "#", line.strip()))
            elif not line.strip():
                current = None
        return result

    old, new = bodies(FIX / "twins/libcalc-v1-x64.so"), bodies(FIX / "twins/libcalc-v2-x64.so")
    assert set(old) == set(new) == exports, (set(old), exports)
    differing = {name for name in exports if old[name] != new[name]}
    assert differing == changed, (differing, changed)
    return {"changed": sorted(changed)}


# ---------------------------------------------------------------------------------------------------------------
# Scale: Hugo, from the unstripped twin's symbol table and Go's own disassembler (see go_graph.py).

SCALE_STRING = "cascade is only supported for branch nodes"
SCALE_CALLEE = "github.com/gohugoio/hugo/common/paths.AbsPathify"
SCALE_CALLER = "github.com/gohugoio/hugo/resources/images.DecodeImageConfig"


def scale_graph() -> dict[str, Any]:
    cached = SCALE / "graph.json"
    twin = SCALE / "hugo-x64.elf"
    if not cached.is_file() or cached.stat().st_mtime < twin.stat().st_mtime:
        sys.path.insert(0, str(Path(__file__).parent))
        import go_graph  # noqa: PLC0415

        cached.write_text(json.dumps(go_graph.graph(twin)))
    return json.loads(cached.read_text())


def same_text(twin: Path, stripped: Path) -> bool:
    def text(path: Path) -> bytes:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "text"
            run(LLVM / "llvm-objcopy", "-O", "binary", "--only-section=.text", path, out)
            return out.read_bytes()

    return text(twin) == text(stripped)


def scale_string_function() -> dict[str, Any]:
    twin = SCALE / "hugo-x64.elf"
    data = twin.read_bytes()
    needle = SCALE_STRING.encode()
    assert data.count(needle) == 1, "the string must occur once"
    address = next(vaddr + segment.find(needle) for vaddr, segment in elf_image(twin) if needle in segment)
    users = sorted(name for name, refs in scale_graph()["refs"].items() if address in refs)
    assert len(users) == 1, users
    return {"function": users[0]}


def scale_caller_count() -> dict[str, Any]:
    graph = scale_graph()
    callers = sorted(name for name, callees in graph["calls"].items() if SCALE_CALLEE in callees and name != SCALE_CALLEE)
    start = graph["functions"][SCALE_CALLEE][0]
    assert not any(start in refs for refs in graph["refs"].values()), "address taken"
    assert f"{SCALE_CALLEE}·f" not in symbols(SCALE / "hugo-x64.elf"), "function value exists"
    return {"callers": len(callers), "caller_names": callers}


def scale_callees() -> dict[str, Any]:
    callees = scale_graph()["calls"][SCALE_CALLER]
    return {"callees": sorted(callee for callee in callees if not callee.startswith("runtime."))}


# ---------------------------------------------------------------------------------------------------------------


def host_run(source: Path, arguments: list[str]) -> tuple[str, list[str]]:
    """Compile an owned source for the host and run it in an empty directory: (stdout, files it created)."""
    with tempfile.TemporaryDirectory() as directory:
        build = Path(directory) / "build"
        build.mkdir()
        work = Path(directory) / "work"
        work.mkdir()
        compiler = "clang++" if source.suffix == ".cpp" else "clang"
        run(compiler, "-O1", "-o", build / "program", source)
        output = subprocess.run([str(build / "program"), *arguments], capture_output=True, text=True, cwd=work,
                                check=False, timeout=30).stdout
        return output, sorted(path.name for path in work.iterdir())


DERIVATIONS = {
    "cpp-hierarchy-x64-elf": cpp_hierarchy,
    "cpp-virtual-call-x64-elf": cpp_virtual_call,
    "cpp-field-layout-arm64-macho": cpp_layout,
    "cpp-vtable-slots-norrti-arm64-macho": cpp_vtable_slots,
    "pointer-chain-arm64-elf": pointer_chain,
    "record-table-x64-elf": record_table,
    "key-derivation-arm64-macho": key_derivation,
    "option-bit-x64-elf": option_bit,
    "call-chain-arm64-elf": call_chain,
    "crc-parameters-mips-elf": crc_parameters,
    "firmware-reset-cm3-raw": firmware,
    "library-diff-x64-so": library_diff,
    "scale-string-function-x64-elf": scale_string_function,
    "scale-caller-count-x64-elf": scale_caller_count,
    "scale-callees-x64-elf": scale_callees,
}

PAIRS = [
    ("widgets-x64.elf",), ("packet-arm64.macho",), ("codec-arm64.macho",), ("session-arm64.elf",),
    ("services-x64.elf",), ("vault-arm64.macho",), ("backup-x64.elf",), ("beacon-arm64.elf",),
    ("checksum-mips.elf",), ("libcalc-v1-x64.so",), ("libcalc-v2-x64.so",),
]


def manifest(task: str) -> dict[str, Any]:
    return tomllib.loads((TASKS / f"{task}.toml").read_text())


def expected(task: str) -> dict[str, Any]:
    answer = manifest(task)["answer"]
    if answer["kind"] == "exact":
        return answer["fields"]
    return {answer["field"]: answer["values"]}


def agrees(task: str, derived: dict[str, Any]) -> bool:
    answer = manifest(task)["answer"]
    want = expected(task)
    if answer["kind"] == "exact":
        return all(derived.get(key) == value for key, value in want.items())
    key = answer["field"]
    return sorted(map(json.dumps, derived.get(key, []))) == sorted(map(json.dumps, want[key]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-scale", action="store_true")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--only")
    arguments = parser.parse_args()
    problems = []
    for (name,) in PAIRS:
        if not same_image(FIX / "bin" / name, FIX / "twins" / name):
            problems.append(f"{name}: stripped loaded image differs from its twin")
    derived: dict[str, Any] = {}
    for task, derive in DERIVATIONS.items():
        scale = task.startswith("scale-")
        if (arguments.only and task != arguments.only) or (scale and arguments.skip_scale):
            continue
        if scale and not same_text(SCALE / "hugo-x64.elf", SCALE / "hugo-x64-stripped.elf"):
            problems.append("hugo: stripped .text differs from its twin")
        derived[task] = derive()
        fixture = manifest(task)["fixture"]
        for path, digest in [(fixture["path"], fixture["sha256"])] + [
            (companion["path"], companion["sha256"]) for companion in fixture.get("companions", [])
        ]:
            if sha256(ROOT / path) != digest:
                problems.append(f"{task}: {path} differs from the manifest digest")
        if not agrees(task, derived[task]):
            problems.append(f"{task}: derived {derived[task]} but the manifest expects {expected(task)}")
    print(json.dumps(derived, indent=1))
    if arguments.json:
        arguments.json.write_text(json.dumps(derived, indent=1) + "\n")
    for line in problems:
        print("PROBLEM:", line, file=sys.stderr)
    print(f"{len(derived)} tasks derived, {len(problems)} problems", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
