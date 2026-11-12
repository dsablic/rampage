"""Derive every suite-v3 answer from sources, debug info, symbols and deterministic harness runs, then compare
with the task manifests. Neither benchmarked server is used: the tools are LLVM's (llvm-nm, llvm-objdump,
llvm-dwarfdump, llvm-pdbutil), the Go toolchain's objdump (through ../v2/go_graph.py), this script's own ELF and
PE readers, and host programs it compiles and runs from the owned sources.

Usage: python3 -I tools/agent-bench/v3/derive-truth.py [--only TASK] [--skip-local] [--update] [--json OUT]

--skip-local leaves out the tasks whose fixtures are built into target/bench/v3/ (SQLite, Go, MSVC ABI).
--update rewrites each derived task's fixture digest and [answer] block in its manifest from what was derived;
use it after rebuilding a fixture, never to make a run pass. The address checks below still apply.

Exits non-zero when a derived truth disagrees with a manifest, an address the question names differs from the
derived one, a stripped fixture's loaded bytes differ from its twin's, or a fixture digest differs from its
manifest.
"""

from __future__ import annotations

import argparse
import importlib.util
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
FIX = ROOT / "tests/fixtures/bench-v3"
TASKS = ROOT / "crates/rampage-eval/tasks/v3"
LLVM = Path("/opt/homebrew/opt/llvm/bin")
LOCAL = ROOT / "target/bench/v3"
SQLITE = LOCAL / "sqlite/sqlite3-x64.elf"
SQLITE_SOURCE = LOCAL / "sqlite/sqlite-amalgamation-3460100/sqlite3.c"
GO_TWIN = LOCAL / "go/restic-x64.elf"
GO_STRIPPED = LOCAL / "go/restic-x64-stripped.elf"
MSVC_EXE = LOCAL / "msvc/engine-x64.exe"
MSVC_PDB = LOCAL / "msvc/engine-x64.pdb"

# Suite v2's script holds the shared readers (ELF segments and sections, symbol tables, digests).
_spec = importlib.util.spec_from_file_location("v2_truth", Path(__file__).resolve().parents[1] / "v2/derive-truth.py")
assert _spec and _spec.loader
v2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v2)
run, symbols, sha256 = v2.run, v2.symbols, v2.sha256


class Truth:
    """A derived answer, plus the addresses the task's question must name."""

    def __init__(self, answer: dict[str, Any], mentions: list[int] | None = None) -> None:
        self.answer = answer
        self.mentions = mentions or []


def disassembly(path: Path) -> dict[str, list[str]]:
    """Instruction lines of every function, by symbol name."""
    functions: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in run(LLVM / "llvm-objdump", "-d", "--no-show-raw-insn", path).splitlines():
        head = re.match(r"^[0-9a-f]+ <(.+)>:$", line)
        if head:
            current = functions.setdefault(head.group(1), [])
        elif current is not None and re.match(r"^\s*[0-9a-f]+:\s", line):
            current.append(line.rstrip())
    return functions


def address_of(line: str) -> int:
    return int(line.split(":")[0], 16)


def read_virtual(path: Path, address: int, size: int) -> bytes:
    for vaddr, data in v2.elf_image(path):
        if vaddr <= address and address + size <= vaddr + len(data):
            return data[address - vaddr : address - vaddr + size]
    raise SystemExit(f"{path.name}: {address:#x} is not in a loaded segment")


def host_run(source: Path, arguments: list[str], flags: tuple[str, ...] = ()) -> str:
    """Compile an owned source for the host and run it in an empty directory; its standard output."""
    with tempfile.TemporaryDirectory() as directory:
        program = Path(directory) / "program"
        work = Path(directory) / "work"
        work.mkdir()
        compiler = "clang++" if source.suffix == ".cpp" else "clang"
        run(compiler, "-O1", "-w", *flags, "-o", program, source)
        return subprocess.run([str(program), *arguments], capture_output=True, text=True, cwd=work, check=True,
                              timeout=30).stdout


# ---------------------------------------------------------------------------------------------------------------
# PE and PDB readers.


class Pe:
    def __init__(self, path: Path) -> None:
        self.data = path.read_bytes()
        pe, = struct.unpack_from("<I", self.data, 0x3C)
        assert self.data[pe : pe + 4] == b"PE\0\0", path
        count, = struct.unpack_from("<H", self.data, pe + 6)
        optional_size, = struct.unpack_from("<H", self.data, pe + 20)
        optional = pe + 24
        self.pe32_plus = struct.unpack_from("<H", self.data, optional)[0] == 0x20B
        self.base = struct.unpack_from("<Q" if self.pe32_plus else "<I", self.data, optional + (24 if self.pe32_plus else 28))[0]
        directories = optional + (112 if self.pe32_plus else 96)
        self.exception_rva, self.exception_size = struct.unpack_from("<II", self.data, directories + 3 * 8)
        self.sections: list[tuple[str, int, int, int, int]] = []
        table = optional + optional_size
        for index in range(count):
            entry = table + index * 40
            name = self.data[entry : entry + 8].rstrip(b"\0").decode()
            virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", self.data, entry + 8)
            self.sections.append((name, rva, virtual_size, raw, raw_size))

    def read(self, rva: int, size: int) -> bytes:
        for _, start, _, raw, raw_size in self.sections:
            if start <= rva and rva + size <= start + raw_size:
                return self.data[raw + rva - start : raw + rva - start + size]
        raise SystemExit(f"rva {rva:#x} is not in a section's file data")

    def u32(self, rva: int) -> int:
        return struct.unpack("<I", self.read(rva, 4))[0]

    def segment(self, number: int, offset: int) -> int:
        """Address of a PDB segment:offset pair."""
        return self.base + self.sections[number - 1][1] + offset

    def loaded(self) -> list[tuple[str, int, bytes]]:
        """Every section an image loader maps, with its bytes; debug sections (names starting with `/`) excluded."""
        return [(name, rva, self.data[raw : raw + min(raw_size, virtual_size)])
                for name, rva, virtual_size, raw, raw_size in self.sections if not name.startswith("/")]


def pdb_publics(listing: str, image: Pe) -> dict[str, int]:
    """Public symbols from `llvm-pdbutil dump --publics` output (or a committed extract of it), by address."""
    names: dict[str, int] = {}
    pending = None
    for line in listing.splitlines():
        symbol = re.search(r"S_PUB32 \[size = \d+\] `(.+)`$", line)
        if symbol:
            pending = symbol.group(1)
            continue
        where = re.search(r"addr = (\d+):(\d+)$", line)
        if where and pending is not None:
            names[pending] = image.segment(int(where.group(1)), int(where.group(2)))
            pending = None
    return names


# ---------------------------------------------------------------------------------------------------------------
# Symbol-rich C release binary: SQLite, from its own symbol table and DWARF.

SQLITE_CALLEE = "ptrmapPut"
SQLITE_ACCESSOR = "sqlite3_total_changes64"
SQLITE_NESTED = ("sqlite3", "init", "busy")
_sqlite: dict[str, list[str]] = {}


def sqlite_functions() -> dict[str, list[str]]:
    if not _sqlite:
        _sqlite.update(disassembly(SQLITE))
    return _sqlite


def sqlite_callers() -> Truth:
    functions = sqlite_functions()
    target = f"<{SQLITE_CALLEE}>"
    callers = set()
    for name, lines in functions.items():
        for line in lines:
            if not line.endswith(target):
                continue
            mnemonic = line.split("\t")[1]
            assert mnemonic.startswith("call"), f"{SQLITE_CALLEE} is reached by {mnemonic} in {name}: not a call"
            callers.add(name)
    assert SQLITE_CALLEE not in callers and len(callers) >= 5, callers
    # Not address-taken: no instruction holds the entry address as an immediate or a RIP-relative target.
    entry = symbols(SQLITE)[SQLITE_CALLEE]
    for name, lines in functions.items():
        for line in lines:
            assert not re.search(rf"(\$0x{entry:x}\b|# 0x{entry:x}\b)", line) or line.endswith(target), (name, line)
    # Each name is one function: the symbol table has no second function of that name.
    listing = run(LLVM / "llvm-nm", "--defined-only", SQLITE).split("\n")
    for name in callers | {SQLITE_CALLEE}:
        assert sum(1 for line in listing if line.split()[1:] in (["t", name], ["T", name])) == 1, name
    return Truth({"callers": sorted(callers)})


def sqlite_field_use() -> Truth:
    lines = [line for line in sqlite_functions()[SQLITE_ACCESSOR] if "\tnop" not in line]
    loads = [re.search(r"movq\t0x([0-9a-f]+)\(%rdi\), %rax", line) for line in lines]
    offsets = [int(match.group(1), 16) for match in loads if match]
    assert len(offsets) == 1 and len(lines) == 5, lines
    # The parameter's type, from DWARF: a pointer to the structure named below.
    info = run(LLVM / "llvm-dwarfdump", f"--name={SQLITE_ACCESSOR}", "--show-children", SQLITE)
    parameter = re.search(r'DW_TAG_formal_parameter\n\s+DW_AT_type\s+\(0x[0-9a-f]+ "(\w+) \*"\)', info)
    assert parameter, info
    structure = parameter.group(1)
    layout = run(LLVM / "llvm-dwarfdump", f"--name={structure}", "--show-children", SQLITE)
    members = re.findall(
        r'DW_TAG_member\n\s+DW_AT_name\s+\("(\w+)"\)\n\s+DW_AT_type[^\n]+\n(?:\s+DW_AT_decl[^\n]+\n)*'
        r"\s+DW_AT_data_member_location\s+\((0x[0-9a-f]+|\d+)\)", layout)
    at = [name for name, offset in members if int(offset, 0) == offsets[0]]
    assert len(set(at)) == 1, (at, offsets)
    # The source agrees.
    source = SQLITE_SOURCE.read_text(errors="replace")
    body = source[source.index(f"sqlite3_int64 {SQLITE_ACCESSOR}(sqlite3 *db)"):][:400]
    assert f"return db->{at[0]};" in body, body
    return Truth({"structure": structure, "member": at[0], "offset": offsets[0]})


def dwarf_members(path: Path, structure: str) -> tuple[int, dict[str, tuple[int, str]]]:
    """A named structure's byte size and {member: (offset, type name)} from llvm-dwarfdump; bit-fields left out."""
    parts = run(LLVM / "llvm-dwarfdump", f"--name={structure}", "--show-children", path).split("\n\n")
    starts = [index for index, block in enumerate(parts)
              if "DW_TAG_structure_type" in block and "DW_AT_byte_size" in block]
    assert len(starts) == 1, (structure, len(starts))
    parts = parts[starts[0]:]
    size = int(re.search(r"DW_AT_byte_size\s+\((\w+)\)", parts[0]).group(1), 0)
    members = {}
    for block in parts[1:]:
        if "DW_TAG_member" not in block:
            break
        name = re.search(r'DW_AT_name\s+\("([^"]+)"\)', block)
        offset = re.search(r"DW_AT_data_member_location\s+\((\w+)\)", block)
        kind = re.search(r'DW_AT_type\s+\(0x[0-9a-f]+ "([^"]+)"\)', block)
        if name and offset and kind:
            members[name.group(1)] = (int(offset.group(1), 0), kind.group(1))
    assert members, structure
    return size, members


def sqlite_nested_member() -> Truth:
    outer, member, inner = SQLITE_NESTED
    _, fields = dwarf_members(SQLITE, outer)
    base, inner_type = fields[member]
    _, inner_fields = dwarf_members(SQLITE, inner_type)
    offset, kind = inner_fields[inner]
    sizes = {"u8": 1, "u16": 2, "u32": 4, "Pgno": 4}
    # The source agrees: the member is declared in the nested struct that struct sqlite3 holds as `init`.
    source = SQLITE_SOURCE.read_text(errors="replace")
    nested = source[source.index(f"struct {inner_type} {{"):]
    nested = nested[: nested.index(f"}} {member};")]
    assert re.search(rf"\b{kind} {inner};", nested), nested
    return Truth({"offset": base + offset, "size": sizes[kind]})


# ---------------------------------------------------------------------------------------------------------------
# Decompiler-heavy semantics: host runs of the owned source.

SEMANTICS = {
    "semantics-bits-x86-elf": ("semantics-x86.elf", "fold_bits", ["0x00F0A500", "3"]),
    "semantics-wide-x86-elf": ("semantics-x86.elf", "scale64", ["0x00012345", "0x0003000D"]),
    "semantics-wide-arm32-elf": ("semantics-arm32.elf", "mix64", ["0x0000000100000003", "4"]),
    "semantics-loop-arm32-elf": ("semantics-arm32.elf", "walk", ["7", "20"]),
}


def semantics(task: str) -> Truth:
    twin, function, arguments = SEMANTICS[task]
    result = int(host_run(FIX / "src/semantics.c", [function, *arguments]), 16)
    assert result < 1 << 63, "the manifest format holds signed 64-bit integers"
    # The same source at another optimization level returns the same value: nothing depends on undefined behaviour.
    assert result == int(host_run(FIX / "src/semantics.c", [function, *arguments], ("-O0",)), 16)
    return Truth({"result": result}, [symbols(FIX / "twins" / twin)[function]])


# ---------------------------------------------------------------------------------------------------------------
# Type propagation.

JOB_MEMBERS = ["kind", "flags", "retries", "state", "deadline", "tag", "budget", "input", "length", "checksum",
               "total", "priority", "owner", "errors"]


def layout(name: str) -> dict[str, Any]:
    """Structure layouts extracted from a twin's DWARF by build.sh (tools/agent-bench/v3/dwarf-extract.py)."""
    return json.loads((FIX / f"twins/{name}.layout.json").read_text())


def type_fields_written() -> Truth:
    source = (FIX / "src/jobs.c").read_text()
    code = source[source.index("NOINLINE int job_validate"): source.index("// Host harness")]
    written = set(re.findall(r"job->(\w+)(?:\[\d+\])?\s*(?:=(?!=)|\+=|\+\+)", code))
    assert written <= set(JOB_MEMBERS)
    # Harness runs over inputs that take every path, with two fill patterns: the members whose bytes changed.
    changed = set()
    for kind in ("1", "9"):
        for flags in ("0", "4"):
            for length in ("0", "8", "100"):
                for fill in ("0x00", "0x5A"):
                    output = host_run(FIX / "src/jobs.c", [kind, flags, length, fill]).split()
                    changed |= set(output[1:])
    assert changed == written, (changed, written)
    declared = re.findall(r"^\s+[\w ]+?[ *](\w+)(?:\[\d+\])?;$", source[source.index("struct job {"): source.index("};")],
                          re.M)
    assert declared == JOB_MEMBERS, declared
    twin = FIX / "twins/jobs-x64.elf"
    functions = disassembly(twin)
    for caller, callee in (("job_run", "job_validate"), ("job_run", "job_account"), ("job_run", "job_finish"),
                           ("job_account", "job_sum")):
        assert any(line.endswith(f"<{callee}>") for line in functions[caller]), (caller, callee)
    members = layout("jobs-x64")["job"]["members"]
    assert list(members) == JOB_MEMBERS
    return Truth({"fields": sorted(members[name] for name in written)}, [symbols(twin)["job_run"]])


def stream_call_checks() -> Truth:
    """The one ops call in the source, its host run and the twin's call tree (no task of its own)."""
    source = (FIX / "src/stream.c").read_text()
    call = re.findall(r"stream->ops->(\w+)\(stream, stream->(\w+), stream->(\w+)\)", source)
    assert len(call) == 1 and source.count("->ops->") == 1, call
    operation, first, second = call[0]
    assert host_run(FIX / "src/stream.c", ["1"]).split()[:3] == [operation, first, second]
    twin = FIX / "twins/stream-arm64.elf"
    functions = disassembly(twin)
    indirect = [name for name in ("stream_sync", "stream_step", "stream_emit")
                for line in functions[name] if re.search(r"\tblr?\tx\d+$|\tbr\tx\d+$", line)]
    assert indirect == ["stream_emit"], indirect
    assert any(line.endswith("<stream_step>") for line in functions["stream_sync"])
    assert any(line.endswith("<stream_emit>") for line in functions["stream_step"])
    return Truth({"operation": operation, "arguments": [first, second]}, [symbols(twin)["stream_sync"]])


def type_indirect_offsets() -> Truth:
    stream_call_checks()
    source = (FIX / "src/stream.c").read_text()
    (operation, first, second), = re.findall(r"stream->ops->(\w+)\(stream, stream->(\w+), stream->(\w+)\)", source)
    layouts = layout("stream-arm64")
    stream, ops = layouts["stream"]["members"], layouts["stream_ops"]["members"]
    twin = FIX / "twins/stream-arm64.elf"
    # The twin loads the table pointer and the slot at those offsets in the one function with the indirect call.
    text = "\n".join(disassembly(twin)["stream_emit"])
    assert re.search(rf"ldr\tx\d+, \[x0, #0x{stream['ops'][0]:x}\]", text), text
    assert re.search(rf"ldr\tx\d+, \[x\d+, #0x{ops[operation][0]:x}\]", text), text
    return Truth({"table_offset": stream["ops"][0], "slot_offset": ops[operation][0],
                  "argument_offsets": [stream[first][0], stream[second][0]]}, [symbols(twin)["stream_sync"]])


# ---------------------------------------------------------------------------------------------------------------
# Switch tables. The host run of the same source says which handler each opcode reaches; the twin's jump table,
# read here, must agree.

SWITCH_HANDLER = "op_jump"


def switch_values(variant: int) -> tuple[list[int], int]:
    """(opcodes that reach SWITCH_HANDLER, the lowest opcode with a case) from a host run."""
    reached = {}
    for line in host_run(FIX / "src/opcodes.c", ["0", "400"], (f"-DVARIANT={variant}",)).splitlines():
        opcode, handler = line.split()
        reached[int(opcode)] = handler
    cases = [opcode for opcode, handler in reached.items() if handler != "default"]
    assert len(cases) == 13 and max(cases) - min(cases) == 12, cases
    return [opcode for opcode in cases if reached[opcode] == SWITCH_HANDLER], min(cases)


def switch_block(lines: list[str], targets: list[int]) -> int:
    """The jump-table target that starts the block calling SWITCH_HANDLER."""
    calls = [address_of(line) for line in lines if re.search(rf"<{SWITCH_HANDLER}(@plt)?>$", line)]
    assert len(calls) == 1, calls
    block = max(target for target in targets if target <= calls[0])
    # Nothing else in the function branches into that block.
    assert not any(re.search(rf"\tj\w+\t0x{block:x} ", line) for line in lines)
    return block


def switch_check(targets: list[int], block: int, values: list[int], lowest: int) -> None:
    assert len(targets) == 13, targets
    assert [lowest + index for index, target in enumerate(targets) if target == block] == values, (targets, values)


def switch_nonpic() -> Truth:
    twin = FIX / "twins/opcodes-x64.elf"
    lines = disassembly(twin)["vm_dispatch"]
    values, lowest = switch_values(1)
    table = [re.search(r"jmpq\t\*0x([0-9a-f]+)\(,%r\w+,8\)", line) for line in lines]
    table = [int(match.group(1), 16) for match in table if match]
    assert len(table) == 1, lines
    targets = list(struct.unpack("<13Q", read_virtual(twin, table[0], 13 * 8)))
    block = switch_block(lines, targets)
    switch_check(targets, block, values, lowest)
    return Truth({"values": values}, [symbols(twin)["vm_dispatch"], block])


def switch_pic_x64() -> Truth:
    twin = FIX / "twins/libopcodes-x64.so"
    lines = disassembly(twin)["vm_dispatch"]
    values, lowest = switch_values(2)
    # The table base is the address the instruction before the table load computes.
    table = [re.search(r"leaq\t-?0x[0-9a-f]+\(%rip\), %r\w+\s+# 0x([0-9a-f]+)", lines[index - 1])
             for index, line in enumerate(lines) if re.search(r"movslq\t\(%r\w+,%r\w+,4\)", line)]
    table = [int(match.group(1), 16) for match in table if match]
    assert len(table) == 1, lines
    targets = [table[0] + offset for offset in struct.unpack("<13i", read_virtual(twin, table[0], 13 * 4))]
    switch_check(targets, switch_block(lines, targets), values, lowest)
    return Truth({"values": values})


def switch_pic_x86() -> Truth:
    twin = FIX / "twins/libopcodes-x86.so"
    lines = disassembly(twin)["vm_dispatch"]
    values, lowest = switch_values(3)
    # The GOT base: the address a call/pop pair loads, plus the constant added to it.
    base = None
    for index, line in enumerate(lines[:-2]):
        add = re.search(r"addl\t\$0x([0-9a-f]+), %ebx", lines[index + 2])
        if "calll" in line and "popl\t%ebx" in lines[index + 1] and add:
            base = address_of(lines[index + 1]) + int(add.group(1), 16)
    table = [re.search(r"movl\t-0x([0-9a-f]+)\(%ebx,%e\w+,4\), %e\w+", line) for line in lines]
    table = [int(match.group(1), 16) for match in table if match]
    assert base is not None and len(table) == 1, lines
    targets = [(base + offset) & 0xFFFFFFFF for offset in struct.unpack("<13i", read_virtual(twin, base - table[0], 13 * 4))]
    switch_check(targets, switch_block(lines, targets), values, lowest)
    return Truth({"values": values})


# ---------------------------------------------------------------------------------------------------------------
# 32-bit x86 calling conventions, from the twin's PDB public symbols (their decoration encodes the convention),
# the source and the twin's disassembly.

CONVENTIONS = {"CDECL": "cdecl", "STDCALL": "stdcall", "FASTCALL": "fastcall"}
CLASSIFIED = ["blend_three", "clamp_three", "pack_three", "weigh_four", "select_four", "rotate_four"]


def conv_publics() -> tuple[Pe, dict[str, int]]:
    image = Pe(FIX / "twins/conv-x86.exe")
    return image, pdb_publics((FIX / "twins/conv-x86.publics.txt").read_text(), image)


def decorated(publics: dict[str, int], name: str) -> tuple[str, int]:
    found = [(symbol, address) for symbol, address in publics.items()
             if re.fullmatch(rf"[_@]{name}(@\d+)?", symbol)]
    assert len(found) == 1, (name, found)
    return found[0]


def return_pop(image: Pe, address: int) -> int:
    """Bytes of stack arguments the function at `address` removes on return (0 for a plain ret)."""
    text = run(LLVM / "llvm-objdump", "-d", "--no-show-raw-insn", f"--start-address={address:#x}",
               f"--stop-address={address + 0x80:#x}", FIX / "twins/conv-x86.exe")
    returns = re.search(r"\tretl(?:\t\$0x([0-9a-f]+))?", text)
    assert returns, text
    return int(returns.group(1) or "0", 16)


def callconv_classify() -> Truth:
    image, publics = conv_publics()
    source = (FIX / "src/conv.cpp").read_text()
    pairs = []
    for name in CLASSIFIED:
        declared = re.search(rf"NOINLINE int (CDECL|STDCALL|FASTCALL) {name}\(([^)]*)\)", source)
        assert declared, name
        convention = CONVENTIONS[declared.group(1)]
        parameters = declared.group(2).count(",") + 1
        symbol, address = decorated(publics, name)
        expected = {"cdecl": f"_{name}", "stdcall": f"_{name}@{4 * parameters}",
                    "fastcall": f"@{name}@{4 * parameters}"}[convention]
        assert symbol == expected, (symbol, expected)
        popped = {"cdecl": 0, "stdcall": 4 * parameters, "fastcall": 4 * (parameters - 2)}[convention]
        assert return_pop(image, address) == popped, (name, popped)
        pairs.append([address, convention])
    return Truth({"conventions": sorted(pairs)}, [address for address, _ in pairs])


def callconv_arguments() -> Truth:
    _, publics = conv_publics()
    source = (FIX / "src/conv.cpp").read_text()
    call = re.search(r"record_five\((0x[^)]*)\)", source[source.index("NOINLINE int submit"):])
    assert call
    arguments = [int(value, 16) for value in call.group(1).split(", ")]
    printed = [line for line in host_run(FIX / "src/conv.cpp", []).splitlines() if line.startswith("record_five ")]
    assert len(printed) == 1 and [int(value) for value in printed[0].split()[1:]] == arguments, printed
    symbol, callee = decorated(publics, "record_five")
    assert symbol == "@record_five@20"
    return Truth({"arguments": arguments}, [decorated(publics, "submit")[1], callee])


def callconv_member() -> Truth:
    image, publics = conv_publics()
    symbol = "__ZN5Mixer5blendEiii"
    parameters = len(re.fullmatch(r"__ZN5Mixer5blendE(i+)", symbol).group(1))
    source = (FIX / "src/conv.cpp").read_text()
    declared = re.search(r"int Mixer::blend\(([^)]*)\)", source)
    assert declared and declared.group(1).count(",") + 1 == parameters
    # Callee cleanup of exactly the explicit parameters, with the object pointer in ecx: thiscall.
    address = publics[symbol]
    assert return_pop(image, address) == 4 * parameters
    text = run(LLVM / "llvm-objdump", "-d", "--no-show-raw-insn", f"--start-address={address:#x}",
               f"--stop-address={address + 0x20:#x}", FIX / "twins/conv-x86.exe")
    assert "(%ecx)" in text, text
    return Truth({"convention": "thiscall", "parameters": parameters}, [address])


# ---------------------------------------------------------------------------------------------------------------
# Go: restic, from the unstripped twin's symbol table, DWARF and Go's own disassembler.

GO_MODULE = "github.com/restic/restic/internal/"
GO_CALLEE = GO_MODULE + "crypto.(*Key).Open"
GO_STRUCT = GO_MODULE + "restic.Snapshot"
GO_NESTED = ("Summary", "DataAddedPacked")


def go_graph() -> dict[str, Any]:
    cached = LOCAL / "go/graph.json"
    if not cached.is_file() or cached.stat().st_mtime < GO_TWIN.stat().st_mtime:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "v2"))
        import go_graph as builder  # noqa: PLC0415

        cached.write_text(json.dumps(builder.graph(GO_TWIN)))
    return json.loads(cached.read_text())


def go_callers() -> Truth:
    graph = go_graph()
    callers = sorted(name for name, callees in graph["calls"].items() if GO_CALLEE in callees and name != GO_CALLEE)
    start = graph["functions"][GO_CALLEE][0]
    assert not any(start in refs for refs in graph["refs"].values()), "address taken"
    stripped = GO_STRIPPED.read_bytes()
    for name in [*callers, GO_CALLEE]:
        assert name.encode() + b"\0" in stripped, f"{name} is not in the stripped binary's function names"
    return Truth({"callers": callers})


def go_struct_layout() -> Truth:
    info = run(LLVM / "llvm-dwarfdump", f"--name={GO_STRUCT}", "--show-children", GO_TWIN)
    assert info.count("DW_TAG_structure_type") == 1, "one structure of that name"
    fields = [[name, int(offset, 0)] for name, offset in re.findall(
        r'DW_TAG_member\n\s+DW_AT_name\s+\("([^"]+)"\)\n\s+DW_AT_data_member_location\s+\((\w+)\)', info)]
    assert len(fields) == info.count("DW_TAG_member") >= 10, fields
    # The stripped binary keeps the type's runtime descriptor: its name and every field name are in its data.
    stripped = GO_STRIPPED.read_bytes()
    assert b"*restic.Snapshot" in stripped
    for name, _ in fields:
        assert name.encode() in stripped, name
    return Truth({"fields": sorted(fields)})


def go_nested_field() -> Truth:
    pointer_field, field = GO_NESTED
    _, fields = dwarf_members(GO_TWIN, GO_STRUCT)
    _, pointer = fields[pointer_field]
    assert pointer.endswith(" *"), pointer
    target = pointer[:-2]
    size, inner = dwarf_members(GO_TWIN, target)
    offset, kind = inner[field]
    # The stripped binary keeps the type's runtime descriptor: its short name and the field name.
    stripped = GO_STRIPPED.read_bytes()
    assert b"*" + target.rsplit("/", 1)[1].encode() in stripped and field.encode() in stripped
    return Truth({"type": target, "size": size, "offset": offset, "field_type": kind})


# ---------------------------------------------------------------------------------------------------------------
# MSVC-ABI C++: the PDB (type records and public symbols), the source, and the image's own tables.

MSVC_CLASS = "CubeTexture"
MSVC_TRY = "load_checked"


def msvc_image() -> tuple[Pe, dict[str, int]]:
    image = Pe(MSVC_EXE)
    return image, pdb_publics(run(LLVM / "llvm-pdbutil", "dump", "--publics", MSVC_PDB), image)


def msvc_hierarchy() -> Truth:
    records = re.split(r"\n(?=\s*0x[0-9A-F]+ \| )", run(LLVM / "llvm-pdbutil", "dump", "--types", MSVC_PDB))
    names: dict[int, str] = {}
    lists: dict[int, list[int]] = {}
    classes: dict[str, int] = {}
    for record in records:
        head = re.match(r"\s*0x([0-9A-F]+) \| (LF_\w+)", record)
        if not head:
            continue
        index = int(head.group(1), 16)
        if head.group(2) in ("LF_CLASS", "LF_STRUCTURE"):
            name = re.search(r"`(.*)`", record).group(1)
            names[index] = name
            fields = re.search(r"field list: 0x([0-9A-F]+)", record)
            if fields and "forward ref" not in record:
                classes[name] = int(fields.group(1), 16)
        elif head.group(2) == "LF_FIELDLIST":
            lists[index] = [int(base, 16) for base in re.findall(r"- LF_BCLASS\n\s+type = 0x([0-9A-F]+)", record)]
            assert "LF_VBCLASS" not in record and "LF_IVBCLASS" not in record or "engine::" not in record
    edges = []
    for name, fields in classes.items():
        if name.startswith("engine::") and "::" not in name[len("engine::"):]:
            for base in lists[fields]:
                assert names[base].startswith("engine::"), names[base]
                edges.append([names[base][len("engine::"):], name[len("engine::"):]])
    # The source declares the same edges, and the image carries an RTTI type descriptor for every class.
    source = (FIX / "src/engine.cpp").read_text()
    declared = []
    for derived, bases in re.findall(r"^class (\w+) : ([^{]+) \{", source, re.M):
        declared += [[base, derived] for base in re.findall(r"public (\w+)", bases)]
    assert sorted(declared) == sorted(edges), (declared, edges)
    image = MSVC_EXE.read_bytes()
    for name in {name for edge in edges for name in edge}:
        assert f".?AV{name}@engine@@".encode() in image, name
    return Truth({"edges": sorted(edges)})


def named_first(slots: list[int], functions: dict[int, str]) -> str:
    return functions.get(slots[0], "") if slots else ""


def msvc_vtable_slots() -> Truth:
    image, publics = msvc_image()
    functions = {address: name for name, address in publics.items() if not name.startswith("??_7")}
    vtable = publics[f"??_7{MSVC_CLASS}@engine@@6B@"]
    slots = []
    while True:
        entry, = struct.unpack("<Q", image.read(vtable - image.base + 8 * len(slots), 8))
        text = image.sections[0]
        if not (image.base + text[1] <= entry < image.base + text[1] + text[2]):
            break
        slots.append(entry)
    # Slot order per the source: the destructor, Asset's virtual functions, then Texture's; each slot holds the
    # most derived override.
    # Slot 0 is the deleting destructor: scalar (??_G) or vector (??_E), as the compiler chooses.
    expected = [("??_G" if named_first(slots, functions).startswith("??_G") else "??_E") + f"{MSVC_CLASS}@engine@@", f"?size@{MSVC_CLASS}@engine@@", f"?kind@{MSVC_CLASS}@engine@@",
                "?load@Texture@engine@@", f"?mip@{MSVC_CLASS}@engine@@", "?stride@Texture@engine@@"]
    named = [functions.get(slot, "") for slot in slots]
    assert len(slots) == len(expected) and all(name.startswith(prefix) for name, prefix in zip(named, expected)), named
    assert len(set(slots)) == len(slots)
    return Truth({"slots": slots})


def msvc_catch_types() -> Truth:
    image, publics = msvc_image()
    function = next(address for name, address in publics.items() if name.startswith(f"?{MSVC_TRY}@engine@@"))
    source = (FIX / "src/engine.cpp").read_text()
    body = source[source.index(f"int {MSVC_TRY}("):]
    body = body[: body.index("\n}\n")]
    caught = re.findall(r"catch \(const (\w+) &", body)
    assert len(caught) == 2 and body.count("catch") == 2
    # The image's own exception tables: .pdata -> unwind info -> __CxxFrameHandler3 FuncInfo -> handler types.
    handlers = None
    for offset in range(0, image.exception_size, 12):
        begin, _, unwind = struct.unpack("<III", image.read(image.exception_rva + offset, 12))
        if image.base + begin != function:
            continue
        version_flags, _, codes, _ = struct.unpack("<BBBB", image.read(unwind, 4))
        assert version_flags >> 3 & 1, "the function has an exception handler"
        language = unwind + 4 + 2 * ((codes + 1) & ~1)
        handler = image.base + image.u32(language)
        assert any(address == handler and "__CxxFrameHandler3" in name for name, address in publics.items())
        info = image.u32(language + 4)
        magic, _, _, tries, try_map = struct.unpack("<IIIII", image.read(info, 20))
        assert magic & 0x1FFFFFFF in (0x19930520, 0x19930521, 0x19930522) and tries == 1, hex(magic)
        _, _, _, count, array = struct.unpack("<IIIII", image.read(try_map, 20))
        handlers = []
        for index in range(count):
            _, descriptor, _, _, _ = struct.unpack("<IIIII", image.read(array + 20 * index, 20))
            name = image.read(descriptor + 16, 64).split(b"\0")[0].decode()
            handlers.append(re.fullmatch(r"\.\?AV(\w+)@engine@@", name).group(1))
    assert handlers == caught, (handlers, caught)
    return Truth({"caught": sorted(caught)}, [function])


# ---------------------------------------------------------------------------------------------------------------

DERIVATIONS = {
    "sqlite-callers-x64-elf": sqlite_callers,
    "sqlite-field-use-x64-elf": sqlite_field_use,
    "sqlite-nested-member-x64-elf": sqlite_nested_member,
    **{task: (lambda task=task: semantics(task)) for task in SEMANTICS},
    "type-fields-written-x64-elf": type_fields_written,
    "type-indirect-offsets-arm64-elf": type_indirect_offsets,
    "switch-nonpic-x64-elf": switch_nonpic,
    "switch-pic-x64-so": switch_pic_x64,
    "switch-pic-x86-so": switch_pic_x86,
    "callconv-classify-x86-pe": callconv_classify,
    "callconv-arguments-x86-pe": callconv_arguments,
    "callconv-member-x86-pe": callconv_member,
    "go-callers-x64-elf": go_callers,
    "go-struct-layout-x64-elf": go_struct_layout,
    "go-nested-field-x64-elf": go_nested_field,
    "msvc-rtti-hierarchy-x64-pe": msvc_hierarchy,
    "msvc-vtable-slots-x64-pe": msvc_vtable_slots,
    "msvc-catch-types-x64-pe": msvc_catch_types,
}

ELF_PAIRS = ["semantics-x86.elf", "semantics-arm32.elf", "jobs-x64.elf", "stream-arm64.elf", "opcodes-x64.elf",
             "libopcodes-x64.so", "libopcodes-x86.so"]


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
        return derived == want
    key = answer["field"]
    return list(derived) == [key] and sorted(map(json.dumps, derived[key])) == sorted(map(json.dumps, want[key]))


def toml_value(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    return json.dumps(value)


def update(task: str, derived: dict[str, Any]) -> None:
    """Rewrite the manifest's fixture digest and answer block from the derived truth."""
    path = TASKS / f"{task}.toml"
    text = path.read_text()
    fixture = manifest(task)["fixture"]
    text = text.replace(f'sha256 = "{fixture["sha256"]}"', f'sha256 = "{sha256(ROOT / fixture["path"])}"', 1)
    head, answer = text.split("[answer]\n", 1)
    kind = re.search(r'^kind = "(\w+)"$', answer, re.M).group(1)
    lines = [f'kind = "{kind}"']
    if "hex_integers = true" in answer:
        lines.append("hex_integers = true")
    if kind == "exact":
        lines.append("[answer.fields]")
        lines += [f"{key} = {toml_value(value)}" for key, value in derived.items()]
    else:
        (key, values), = derived.items()
        lines += [f'field = "{key}"', f"values = {toml_value(values)}"]
    path.write_text(head + "[answer]\n" + "\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-local", action="store_true")
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--only")
    arguments = parser.parse_args()
    problems = []
    for name in ELF_PAIRS:
        if not v2.same_image(FIX / "bin" / name, FIX / "twins" / name):
            problems.append(f"{name}: stripped loaded image differs from its twin")
    if Pe(FIX / "bin/conv-x86.exe").loaded() != Pe(FIX / "twins/conv-x86.exe").loaded():
        problems.append("conv-x86.exe: stripped loaded image differs from its twin")
    derived: dict[str, Any] = {}
    for task, derive in DERIVATIONS.items():
        local = manifest(task)["fixture"]["path"].startswith("target/")
        if (arguments.only and task != arguments.only) or (local and arguments.skip_local):
            continue
        truth = derive()
        derived[task] = truth.answer
        if arguments.update:
            update(task, truth.answer)
        entry = manifest(task)
        for address in truth.mentions:
            if not re.search(rf"\b0x{address:x}\b", entry["question"]):
                problems.append(f"{task}: the question does not name {address:#x}")
        if sha256(ROOT / entry["fixture"]["path"]) != entry["fixture"]["sha256"]:
            problems.append(f"{task}: {entry['fixture']['path']} differs from the manifest digest")
        if not agrees(task, truth.answer):
            problems.append(f"{task}: derived {truth.answer} but the manifest expects {expected(task)}")
    print(json.dumps(derived, indent=1))
    if arguments.json:
        arguments.json.write_text(json.dumps(derived, indent=1) + "\n")
    for line in problems:
        print("PROBLEM:", line, file=sys.stderr)
    print(f"{len(derived)} tasks derived, {len(problems)} problems", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
