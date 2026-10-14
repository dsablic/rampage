# SPDX-License-Identifier: Apache-2.0
"""Check compiler layout constants and bounded ELF facts without parsing type DWARF."""

from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class LoadSegment:
    flags: int
    address: int
    size: int
    offset: int
    file_size: int


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_bytes(path: Path, maximum: int) -> bytes:
    require(0 <= maximum <= 1024 * 1024, "Oracle input byte limit is unsupported")
    try:
        with path.open("rb") as source:
            data = source.read(maximum + 1)
        require(len(data) <= maximum, f"{path}: exceeds {maximum}-byte bound")
        return data
    except OSError as error:
        raise RuntimeError(f"Cannot read oracle input {path}") from error


def slice_bytes(data: bytes, offset: int, size: int) -> bytes:
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset, "ELF range is out of bounds")
    return data[offset : offset + size]


def read_string(strings: bytes, offset: int) -> str:
    require(0 <= offset < len(strings), "ELF string offset is out of bounds")
    end = strings.find(b"\0", offset)
    require(end >= offset and end - offset <= 256, "ELF name is unterminated or overlong")
    return strings[offset:end].decode("ascii")


def parse_elf(data: bytes, target: dict[str, Any]) -> tuple[list[Section], list[LoadSegment], int]:
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "Expected little-endian ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    (
        _,
        kind,
        machine,
        version,
        entry,
        program_offset,
        section_offset,
        _,
        header_size,
        program_size,
        program_count,
        section_size,
        section_count,
        names_index,
    ) = header
    require(kind == target["elf_type"] and machine == target["elf_machine"] and version == 1, "Wrong ELF target")
    require(header_size == 64 and section_size == 64, "Unexpected ELF header sizes")
    require(0 < section_count <= target["max_sections"], "Section count exceeds bound")
    require(0 <= names_index < section_count, "Invalid section name table")
    raw_sections = [
        struct.unpack("<IIQQQQIIQQ", slice_bytes(data, section_offset + index * 64, 64))
        for index in range(section_count)
    ]
    names_header = raw_sections[names_index]
    names = slice_bytes(data, names_header[4], names_header[5])
    sections = [Section(index, read_string(names, raw[0]), *raw[1:]) for index, raw in enumerate(raw_sections)]
    require(program_size == 56 and 0 < program_count <= 16, "Unexpected program header table")
    loads = []
    for index in range(program_count):
        program = struct.unpack("<IIQQQQQQ", slice_bytes(data, program_offset + index * 56, 56))
        program_kind, flags, offset, address, _, file_size, memory_size, _ = program
        require(file_size <= memory_size, "Segment file size exceeds memory size")
        slice_bytes(data, offset, file_size)
        if program_kind == 1:
            loads.append(LoadSegment(flags, address, memory_size, offset, file_size))
    require(bool(loads), "ELF has no loadable segments")
    return sections, loads, entry


def find_section(sections: list[Section], name: str) -> Section:
    matches = [section for section in sections if section.name == name]
    require(len(matches) == 1, f"Expected exactly one {name} section")
    return matches[0]


def backs_range(segment: LoadSegment, address: int, offset: int, size: int) -> bool:
    relative = address - segment.address
    return (
        0 <= relative <= segment.file_size
        and 0 <= size <= segment.file_size - relative
        and offset == segment.offset + relative
    )


def check_constants(
    data: bytes,
    sections: list[Section],
    loads: list[LoadSegment],
    name: str,
    expected: list[int],
) -> None:
    section = find_section(sections, name)
    require(section.kind == 1 and section.flags == 2, f"{name}: expected allocated read-only data")
    require(section.size == 8 * len(expected) and section.alignment == 8, f"{name}: wrong size or alignment")
    measured = struct.unpack(f"<{len(expected)}Q", slice_bytes(data, section.offset, section.size))
    require(list(measured) == expected, f"{name}: compiler facts {list(measured)} != source oracle {expected}")
    require(
        any(
            segment.flags & 4
            and not segment.flags & 3
            and backs_range(segment, section.address, section.offset, section.size)
            for segment in loads
        ),
        f"{name}: not covered by a read-only, nonexecutable load segment",
    )
    require(
        not any(
            segment.flags & 3
            and segment.address < section.address + section.size
            and section.address < segment.address + segment.size
            for segment in loads
        ),
        f"{name}: overlaps a writable or executable load segment",
    )
    require(
        not any(
            candidate.kind in (4, 9) and candidate.info == section.index and candidate.size for candidate in sections
        ),
        f"{name}: constants contain relocations",
    )


def check_symbols(
    data: bytes,
    sections: list[Section],
    loads: list[LoadSegment],
    functions: list[str],
    target: dict[str, Any],
    entry: int,
) -> None:
    symbols = find_section(sections, ".symtab")
    require(symbols.entry_size == 24 and symbols.size % 24 == 0, "Invalid symbol table entries")
    require(symbols.size // 24 <= target["max_symbols"], "Symbol count exceeds bound")
    require(0 <= symbols.link < len(sections), "Invalid symbol string table")
    names = sections[symbols.link]
    strings = slice_bytes(data, names.offset, names.size)
    text = find_section(sections, ".text")
    required = {*functions, "entry"}
    found: dict[str, tuple[int, int]] = {}
    for offset in range(symbols.offset, symbols.offset + symbols.size, 24):
        name_offset, info, _, section_index, address, size = struct.unpack("<IBBHQQ", slice_bytes(data, offset, 24))
        name = read_string(strings, name_offset)
        if name not in required:
            continue
        require(info == 0x12 and section_index == text.index, f"{name}: not a global .text function")
        require(0 < size <= target["max_function_bytes"], f"{name}: function size outside bound")
        require(text.address <= address and address + size <= text.address + text.size, f"{name}: outside .text")
        require(
            any(
                segment.flags & 1 and backs_range(segment, address, text.offset + address - text.address, size)
                for segment in loads
            ),
            f"{name}: not covered by executable load segment",
        )
        require(name not in found, f"Duplicate function symbol {name}")
        found[name] = (address, size)
    require(set(found) == required, f"Missing functions: {required - set(found)}")
    require(found["entry"][0] == entry, "ELF entry does not point to entry symbol")
    for name, (address, size) in sorted(found.items()):
        print(f"function {name}: address=0x{address:x} size={size}")


def check_debug(data: bytes, sections: list[Section], expected_version: int | None) -> None:
    debug = [section for section in sections if section.name.startswith(".debug_")]
    if expected_version is None:
        require(not debug, "Symbols-only control unexpectedly retains debug sections")
        return
    find_section(sections, ".debug_abbrev")
    information = find_section(sections, ".debug_info")
    units = slice_bytes(data, information.offset, information.size)
    offset = 0
    count = 0
    while offset < len(units):
        length, version = struct.unpack("<IH", slice_bytes(units, offset, 6))
        require(7 <= length < 0xFFFFFFF0, "Expected bounded DWARF32 compilation units")
        require(version == expected_version, f"Expected DWARF {expected_version}, got {version}")
        slice_bytes(units, offset + 4, length)
        offset += 4 + length
        count += 1
        require(count <= 64, "Compilation unit count exceeds bound")
    require(count > 0, "No DWARF compilation units")


def flat_words(metadata: dict[str, Any]) -> list[int]:
    section = metadata["constant_section"]
    flat = metadata["flat"]
    words = [
        int(section["magic"], 16),
        section["version"],
        metadata["target"]["address_size"],
        section["byte_order_tag"],
        flat["size"],
        flat["alignment"],
        len(flat["fields"]),
    ]
    for field in flat["fields"]:
        words.extend([field["offset"], field["size"], field["alignment"]])
    require(len(words) * 8 == section["byte_size"], "Oracle metadata word count mismatch")
    return words


def verify(directory: Path, metadata: dict[str, Any], include_cpp: bool) -> None:
    words = flat_words(metadata)
    target = metadata["target"]
    for configuration, version in [("dwarf4-o1", 4), ("dwarf5-o2", 5)]:
        for group_name, group in metadata["groups"].items():
            prefix = directory / configuration / group_name
            if group_name == "inheritance" and not include_cpp:
                continue
            constants = read_bytes(prefix.with_suffix(".constants.bin"), metadata["constant_section"]["byte_size"])
            require(constants == struct.pack("<25Q", *words), f"{prefix}: extracted constants mismatch")
            for suffix, expected_version in [(".debug.elf", version), (".symbols.elf", None)]:
                path = prefix.with_suffix(suffix)
                print(f"verify {configuration}/{path.name}")
                data = read_bytes(path, target["max_binary_bytes"])
                sections, loads, entry = parse_elf(data, target)
                check_constants(data, sections, loads, metadata["constant_section"]["name"], words)
                for section_name, expected in group["extra_constants"].items():
                    check_constants(data, sections, loads, section_name, expected)
                check_symbols(data, sections, loads, group["functions"], target, entry)
                check_debug(data, sections, expected_version)
    print("Source-static and compiler-measured layout oracles agree; ELF metadata bounds verified")


def main() -> None:
    require(len(sys.argv) == 4, "Usage: verify_oracle.py ARTIFACT_DIRECTORY ORACLE_JSON CPP_FLAG")
    require(sys.argv[3] in ("0", "1"), "CPP_FLAG must be 0 or 1")
    metadata_path = Path(sys.argv[2])
    try:
        metadata = json.loads(read_bytes(metadata_path, 65536))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot decode oracle metadata {metadata_path}") from error
    require(isinstance(metadata, dict), "Oracle metadata must be an object")
    verify(Path(sys.argv[1]), metadata, sys.argv[3] == "1")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, UnicodeError, struct.error) as error:
        print(f"debug-layout oracle failed: {error}", file=sys.stderr)
        sys.exit(1)
