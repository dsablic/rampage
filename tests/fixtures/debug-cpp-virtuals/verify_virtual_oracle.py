# SPDX-License-Identifier: Apache-2.0
"""Check source constants, compiler vptr dumps and raw ELF tables without parsing type DWARF."""

from __future__ import annotations

import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "debug-cpp-layouts"))
from verify_cpp_oracle import check_constant_symbols, check_cpp_debug

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "debug-layouts"))
from verify_oracle import (
    LoadSegment,
    Section,
    backs_range,
    check_constants,
    check_symbols,
    find_section,
    parse_elf,
    read_bytes,
    read_string,
    require,
    slice_bytes,
)


@dataclass(frozen=True)
class Symbol:
    name: str
    info: int
    visibility: int
    section: int
    address: int
    size: int


@dataclass(frozen=True)
class VptrLayout:
    offset: int
    width: int
    size: int
    alignment: int
    count_offset: int
    tail_offset: int


def layout_words(metadata: dict[str, Any], key: str) -> list[int]:
    encoding = metadata["constant_encoding"]
    layout = metadata["layouts"][metadata["records"][key]["layout"]]
    words = [
        int(encoding["magic"], 16),
        encoding["version"],
        metadata["target"]["address_size"],
        encoding["byte_order_tag"],
        layout["size"],
        layout["alignment"],
        len(layout["fields"]),
    ]
    for field in layout["fields"]:
        words.extend([field["offset"], field["size"], field["alignment"]])
    require(len(words) == 13 and len(words) * 8 == encoding["byte_size"], "Virtual layout word count mismatch")
    return words


def parse_vptr_dump(text: str, record: str, pointer_width: int) -> VptrLayout:
    require(pointer_width == 8, "Vptr dump requires independently measured LP64 pointer width")
    name = re.escape(record)
    ast_blocks = [
        block
        for block in text.split("*** Dumping AST Record Layout")[1:]
        if re.search(rf"^\s*0\s*\| (?:class|struct) {name}\s*$", block, re.MULTILINE)
    ]
    require(len(ast_blocks) == 1, f"{record}: expected one exact AST record layout")
    ast = ast_blocks[0].split("*** Dumping", 1)[0]
    vptrs = re.findall(rf"^\s*(\d+)\s*\|   \({name} vtable pointer\)\s*$", ast, re.MULTILINE)
    all_vptrs = re.findall(r"^.*vtable pointer.*$", ast, re.MULTILINE)
    require(len(vptrs) == 1 and len(all_vptrs) == 1, f"{record}: expected one compiler-generated vptr")
    fields = re.findall(r"^\s*(\d+)\s*\|   (int count|unsigned char tail)\s*$", ast, re.MULTILINE)
    field_offsets = {field: int(offset) for offset, field in fields}
    require(
        len(fields) == 2 and set(field_offsets) == {"int count", "unsigned char tail"},
        f"{record}: missing exact data-field dump facts",
    )
    summaries = re.findall(r"\[sizeof=(\d+),\s*dsize=\d+,\s*align=(\d+),", ast)
    require(len(summaries) == 1, f"{record}: missing AST size/alignment summary")
    ir_blocks = [
        block
        for block in text.split("*** Dumping IRgen Record Layout")[1:]
        if re.search(rf"^Record: .*\b(?:class|struct) {name} definition\s*$", block, re.MULTILINE)
    ]
    require(len(ir_blocks) == 1, f"{record}: expected one exact IRgen record layout")
    ir = ir_blocks[0].split("*** Dumping", 1)[0]
    llvm_types = re.findall(rf"^\s*LLVMType:%(?:class|struct)\.{name} = type (.+)$", ir, re.MULTILINE)
    require(len(llvm_types) == 1, f"{record}: missing exact LLVM record storage type")
    storage = re.sub(r"\s+", "", llvm_types[0])
    require(
        storage in {"{ptr,i32,i8}", "{ptr,i32,i8,[3xi8]}", "<{ptr,i32,i8,[3xi8]}>"},
        f"{record}: IRgen must independently identify a pointer as the first storage element",
    )
    size, alignment = (int(value) for value in summaries[0])
    measured = VptrLayout(
        int(vptrs[0]), pointer_width, size, alignment,
        field_offsets["int count"], field_offsets["unsigned char tail"],
    )
    require(measured == VptrLayout(0, 8, 16, 8, 8, 12), f"{record}: compiler vptr/data layout changed: {measured}")
    return measured


def read_symbols(data: bytes, sections: list[Section], maximum: int) -> list[Symbol]:
    table = find_section(sections, ".symtab")
    require(table.kind == 2 and table.entry_size == 24 and table.size % 24 == 0, "Invalid virtual symbol table")
    require(table.size // 24 <= maximum, "Virtual symbol count exceeds bound")
    require(0 <= table.link < len(sections), "Invalid virtual symbol string table")
    names = sections[table.link]
    require(names.kind == 3, "Virtual symbol names are not a string table")
    strings = slice_bytes(data, names.offset, names.size)
    symbols = []
    for offset in range(table.offset, table.offset + table.size, 24):
        name_offset, info, visibility, section, address, size = struct.unpack(
            "<IBBHQQ", slice_bytes(data, offset, 24)
        )
        symbols.append(Symbol(read_string(strings, name_offset), info, visibility, section, address, size))
    return symbols


def exact_symbol(symbols: list[Symbol], name: str) -> Symbol:
    matches = [symbol for symbol in symbols if symbol.name == name]
    require(len(matches) == 1, f"{name}: expected one exact symbol")
    return matches[0]


def overlaps(start: int, size: int, other_start: int, other_size: int) -> bool:
    return size > 0 and other_size > 0 and start < other_start + other_size and other_start < start + size


def check_readonly_range(
    data: bytes,
    sections: list[Section],
    loads: list[LoadSegment],
    section: Section,
    address: int,
    size: int,
    label: str,
) -> int:
    require(section.kind == 1 and section.flags == 2, f"{label}: expected allocated read-only data")
    relative = address - section.address
    require(0 <= relative <= section.size and 0 < size <= section.size - relative, f"{label}: outside section")
    offset = section.offset + relative
    slice_bytes(data, offset, size)
    mappings = [segment for segment in loads if overlaps(address, size, segment.address, segment.size)]
    require(
        len(mappings) == 1 and mappings[0].flags == 4 and backs_range(mappings[0], address, offset, size),
        f"{label}: expected one read-only nonexecutable file-backed mapping without VA aliases",
    )
    require(
        not any(
            overlaps(offset, size, segment.offset, segment.file_size)
            and (segment != mappings[0] or not backs_range(segment, address, offset, size))
            for segment in loads
        ),
        f"{label}: aliased file mapping",
    )
    require(
        not any(
            candidate.index != section.index
            and (
                (candidate.flags & 2 and overlaps(address, size, candidate.address, candidate.size))
                or (candidate.kind != 8 and overlaps(offset, size, candidate.offset, candidate.size))
            )
            for candidate in sections
        ),
        f"{label}: aliased section range",
    )
    require(
        not any(candidate.kind in (4, 9) and candidate.size for candidate in sections),
        f"{label}: linked fixture unexpectedly contains relocations",
    )
    return offset


def check_symbol_aliases(symbols: list[Symbol], symbol: Symbol) -> None:
    require(
        not any(
            candidate is not symbol
            and candidate.section == symbol.section
            and candidate.info & 15 in (0, 1, 2)
            and (
                symbol.address <= candidate.address < symbol.address + symbol.size
                or overlaps(symbol.address, symbol.size, candidate.address, candidate.size)
            )
            for candidate in symbols
        ),
        f"{symbol.name}: aliased or overlapping symbol",
    )


def check_nonalias_methods(symbols: list[Symbol], names: list[str]) -> None:
    for name in names:
        method = exact_symbol(symbols, name)
        require(method.info == 0x12 and method.size > 0, f"{name}: expected global method function")
        check_symbol_aliases(symbols, method)


def check_table(
    data: bytes,
    sections: list[Section],
    loads: list[LoadSegment],
    symbols: list[Symbol],
    table: dict[str, Any],
    maximum_method_bytes: int,
) -> None:
    symbol = exact_symbol(symbols, table["symbol"])
    require(symbol.info == 0x11 and symbol.visibility == 0, f"{symbol.name}: expected global vtable object")
    require(0 < symbol.section < len(sections), f"{symbol.name}: invalid section")
    expected = []
    for word in table["words"]:
        if isinstance(word, str):
            method = exact_symbol(symbols, word)
            require(
                method.info == 0x12 and 0 < method.size <= maximum_method_bytes,
                f"{word}: expected bounded method function",
            )
            text = find_section(sections, ".text")
            relative = method.address - text.address
            require(
                method.section == text.index and text.kind == 1 and text.flags == 6
                and 0 <= relative <= text.size and method.size <= text.size - relative
                and any(
                    segment.flags == 5
                    and backs_range(segment, method.address, text.offset + relative, method.size)
                    for segment in loads
                ),
                f"{word}: method lacks executable file-backed .text mapping",
            )
            expected.append(method.address)
        else:
            require(isinstance(word, int) and -(1 << 63) <= word < 1 << 64, "Invalid raw table word")
            expected.append(word & ((1 << 64) - 1))
    require(symbol.size == len(expected) * 8 and symbol.address % 8 == 0, f"{symbol.name}: wrong table extent")
    section = sections[symbol.section]
    require(section.alignment >= 8, f"{symbol.name}: insufficient table alignment")
    offset = check_readonly_range(data, sections, loads, section, symbol.address, symbol.size, symbol.name)
    check_symbol_aliases(symbols, symbol)
    measured = list(struct.unpack(f"<{len(expected)}Q", slice_bytes(data, offset, symbol.size)))
    require(measured == expected, f"{symbol.name}: raw vtable word order/values differ from exact method symbols")
    print(f"table {symbol.name}: address=0x{symbol.address:x} words={[hex(word) for word in measured]}")
    if "prefix_status" in table:
        require(
            table["prefix_status"] == "UnverifiedPrefix"
            and table["address_point_offset"] == 16
            and measured[:2] == [0, 0],
            "Positive raw prefix must remain UnverifiedPrefix",
        )
        print(f"prefix {symbol.name}: words=[0, 0] status=UnverifiedPrefix; no RTTI/offset-to-top proof")
        print(f"candidate_slot_base {symbol.name}: 0x{symbol.address + 16:x}; slots=0:readCount,1:writeCount")


def check_vtable_inventory(symbols: list[Symbol], tables: list[dict[str, Any]]) -> None:
    expected = {table["symbol"] for table in tables}
    require(len(expected) == len(tables), "Duplicate table metadata")
    measured = {symbol.name for symbol in symbols if symbol.name.startswith("_ZTV")}
    require(measured == expected, f"Unexpected/missing vtable symbols: {measured ^ expected}")
    require(not any(symbol.name.startswith(("_ZTI", "_ZTS")) for symbol in symbols), "Unexpected RTTI symbols")
    require(
        not any(symbol.section == 0 and symbol.name for symbol in symbols),
        "Fixture must not depend on undefined runtime symbols",
    )


def verify(directory: Path, metadata: dict[str, Any]) -> None:
    target = metadata["target"]
    require(
        target["max_binary_bytes"] <= 1048576
        and target["max_debug_info_bytes"] <= 131072
        and target["max_layout_dump_bytes"] <= 131072
        and target["max_sections"] <= 128
        and target["max_symbols"] <= 256
        and target["max_function_bytes"] <= 128,
        "Virtual fixture bounds exceed the reviewed limits",
    )
    for configuration, version in [("dwarf4-o1", 4), ("dwarf5-o2", 5)]:
        for group_name, group in metadata["groups"].items():
            prefix = directory / configuration / group_name
            dump_path = prefix.with_suffix(".layouts.txt")
            dump = read_bytes(dump_path, target["max_layout_dump_bytes"]).decode("utf-8")
            constants = []
            for key in group["records"]:
                words = layout_words(metadata, key)
                path = directory / configuration / f"{group_name}.{key}.constants.bin"
                measured = read_bytes(path, metadata["constant_encoding"]["byte_size"])
                require(measured == struct.pack("<13Q", *words), f"{path}: extracted source constants differ")
                constants.append({"symbol": f"debug_cpp_virtual_{key}_constants", "section": f".rampage_virtual_{key}"})
                decoded = struct.unpack("<13Q", measured)
                record = metadata["records"][key]["tag"]
                print(
                    f"source_layout {configuration}/{record}: size={decoded[4]} align={decoded[5]} "
                    f"count=offset:{decoded[7]},width:{decoded[8]} tail=offset:{decoded[10]},width:{decoded[11]}"
                )
                if key in group["vptr_dump_records"]:
                    facts = parse_vptr_dump(dump, record, decoded[2])
                    print(f"compiler_layout {configuration}/{record}: {facts}; width=IRgen ptr + source sizeof(void*)")
            for suffix, expected_version in [(".debug.elf", version), (".symbols.elf", None)]:
                path = prefix.with_suffix(suffix)
                print(f"verify {configuration}/{path.name}")
                data = read_bytes(path, target["max_binary_bytes"])
                sections, loads, entry = parse_elf(data, target)
                check_cpp_debug(data, sections, expected_version, target["max_debug_info_bytes"])
                symbols = read_symbols(data, sections, target["max_symbols"])
                for key, constant in zip(group["records"], constants, strict=True):
                    words = layout_words(metadata, key)
                    check_constants(data, sections, loads, constant["section"], words)
                    section = find_section(sections, constant["section"])
                    check_readonly_range(data, sections, loads, section, section.address, section.size, section.name)
                    check_symbol_aliases(symbols, exact_symbol(symbols, constant["symbol"]))
                check_constant_symbols(data, sections, constants, target["max_symbols"])
                check_symbols(data, sections, loads, group["functions"], target, entry)
                check_nonalias_methods(symbols, group.get("nonalias_methods", []))
                check_vtable_inventory(symbols, group["tables"])
                for table in group["tables"]:
                    check_table(data, sections, loads, symbols, table, target["max_function_bytes"])
    print("Source constants, compiler vptr dumps and exact ELF vtable words agree; no type-DWARF graph claims")


def main() -> None:
    require(len(sys.argv) == 3, "Usage: verify_virtual_oracle.py ARTIFACT_DIRECTORY ORACLE_JSON")
    path = Path(sys.argv[2])
    try:
        metadata = json.loads(read_bytes(path, 65536))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot decode virtual oracle metadata {path}") from error
    require(isinstance(metadata, dict), "Virtual oracle metadata must be an object")
    verify(Path(sys.argv[1]), metadata)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, UnicodeError, struct.error, KeyError, TypeError) as error:
        print(f"debug-cpp-virtual oracle failed: {error}", file=sys.stderr)
        sys.exit(1)
