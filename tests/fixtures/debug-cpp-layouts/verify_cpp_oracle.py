# SPDX-License-Identifier: Apache-2.0
"""Compare C++ constants and exact symbols using independent bounded ELF helpers."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "debug-layouts"))
from verify_oracle import (
    Section,
    check_constants,
    check_debug,
    check_symbols,
    find_section,
    parse_elf,
    read_bytes,
    read_string,
    require,
    slice_bytes,
)


def layout_words(metadata: dict[str, Any]) -> list[int]:
    encoding = metadata["constant_encoding"]
    layout = metadata["layout"]
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
    require(
        len(words) == 25 and len(words) * 8 == encoding["byte_size"],
        "C++ oracle word count mismatch",
    )
    return words


def check_constant_symbols(
    data: bytes,
    sections: list[Section],
    records: list[dict[str, str]],
    maximum_symbols: int,
) -> None:
    expected = {
        record["symbol"]: find_section(sections, record["section"])
        for record in records
    }
    require(len(expected) == len(records), "Duplicate C++ constant symbol in metadata")
    symbols = find_section(sections, ".symtab")
    require(
        symbols.kind == 2 and symbols.entry_size == 24 and symbols.size % 24 == 0,
        "Invalid C++ symbol table",
    )
    require(symbols.size // 24 <= maximum_symbols, "C++ symbol count exceeds bound")
    require(0 <= symbols.link < len(sections), "Invalid C++ symbol string table")
    names = sections[symbols.link]
    require(names.kind == 3, "C++ symbol names are not a string table")
    strings = slice_bytes(data, names.offset, names.size)
    found: set[str] = set()
    for offset in range(symbols.offset, symbols.offset + symbols.size, 24):
        name_offset, info, _, section_index, address, size = struct.unpack(
            "<IBBHQQ", slice_bytes(data, offset, 24)
        )
        name = read_string(strings, name_offset)
        if name not in expected:
            continue
        section = expected[name]
        require(info == 0x11, f"{name}: expected global C-linkage object symbol")
        require(section_index == section.index, f"{name}: wrong constant section")
        require(
            address == section.address and size == section.size,
            f"{name}: does not cover exact constant section",
        )
        require(name not in found, f"Duplicate C++ constant symbol {name}")
        found.add(name)
    require(
        found == set(expected), f"Missing C++ constant symbols: {set(expected) - found}"
    )


def check_cpp_debug(
    data: bytes, sections: list[Section], version: int | None, maximum_info: int
) -> None:
    for section in sections:
        require(
            not section.name.startswith(".zdebug_"),
            "Compressed C++ debug sections are unsupported",
        )
        if section.name.startswith(".debug_"):
            require(
                not section.flags & 0x800,
                "Compressed C++ debug sections are unsupported",
            )
    if version is not None:
        information = find_section(sections, ".debug_info")
        require(information.size <= maximum_info, "C++ .debug_info exceeds byte bound")
    check_debug(data, sections, version)


def verify(directory: Path, metadata: dict[str, Any]) -> None:
    target = metadata["target"]
    words = layout_words(metadata)
    encoded = struct.pack("<25Q", *words)
    for configuration, version in [("dwarf4-o1", 4), ("dwarf5-o2", 5)]:
        for group_name, group in metadata["groups"].items():
            records = [
                metadata["records"][key]
                for key in metadata["common_constants"] + group["extra_constants"]
            ]
            prefix = directory / configuration / group_name
            for key in metadata["common_constants"] + group["extra_constants"]:
                path = directory / configuration / f"{group_name}.{key}.constants.bin"
                extracted = read_bytes(path, metadata["constant_encoding"]["byte_size"])
                require(
                    extracted == encoded, f"{path}: extracted C++ constants mismatch"
                )
            for suffix, expected_version in [
                (".debug.elf", version),
                (".symbols.elf", None),
            ]:
                path = prefix.with_suffix(suffix)
                print(f"verify {configuration}/{path.name}")
                data = read_bytes(path, target["max_binary_bytes"])
                sections, loads, entry = parse_elf(data, target)
                for record in records:
                    check_constants(data, sections, loads, record["section"], words)
                check_constant_symbols(data, sections, records, target["max_symbols"])
                check_symbols(data, sections, loads, group["functions"], target, entry)
                check_cpp_debug(
                    data, sections, expected_version, target["max_debug_info_bytes"]
                )
                if expected_version is not None:
                    information = find_section(sections, ".debug_info")
                    print(
                        f"debug_info {configuration}/{group_name}: bytes={information.size} dwarf={expected_version}"
                    )
    print(
        "C++ source-static constants, exact linkage symbols and bounded ELF headers agree"
    )
    print(
        "Parent inspection must separately prove DWARF declarations, definitions and object-pointer relationships"
    )


def main() -> None:
    require(
        len(sys.argv) == 3, "Usage: verify_cpp_oracle.py ARTIFACT_DIRECTORY ORACLE_JSON"
    )
    path = Path(sys.argv[2])
    try:
        metadata = json.loads(read_bytes(path, 65536))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot decode C++ oracle metadata {path}") from error
    require(isinstance(metadata, dict), "C++ oracle metadata must be an object")
    verify(Path(sys.argv[1]), metadata)


if __name__ == "__main__":
    try:
        main()
    except (
        ValueError,
        RuntimeError,
        UnicodeError,
        struct.error,
        KeyError,
        TypeError,
    ) as error:
        print(f"debug-cpp-layout oracle failed: {error}", file=sys.stderr)
        sys.exit(1)
