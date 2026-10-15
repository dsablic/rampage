# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import struct
import unittest
from typing import Any

from verify_cpp_oracle import (
    Section,
    check_constant_symbols,
    check_cpp_debug,
    layout_words,
)


class ConstantSymbolTests(unittest.TestCase):
    def check_symbol(
        self,
        name: str = "debug_cpp_fixture_constants",
        info: int = 0x11,
        section_index: int = 1,
        address: int = 0x400000,
        size: int = 200,
        copies: int = 1,
    ) -> None:
        strings = b"\0" + name.encode("ascii") + b"\0"
        table = (
            struct.pack("<IBBHQQ", 1, info, 0, section_index, address, size) * copies
        )
        sections = [
            Section(0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0),
            Section(1, ".facts", 1, 2, 0x400000, 0, 200, 0, 0, 8, 0),
            Section(2, ".strtab", 3, 0, 0, len(table), len(strings), 0, 0, 1, 0),
            Section(3, ".symtab", 2, 0, 0, 0, len(table), 2, 0, 8, 24),
        ]
        records = [{"symbol": "debug_cpp_fixture_constants", "section": ".facts"}]
        check_constant_symbols(table + strings, sections, records, 256)

    def test_global_c_linkage_object_exactly_covering_section_is_accepted(self) -> None:
        self.check_symbol()

    def test_mangled_or_missing_constant_name_is_not_accepted_by_similar_spelling(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "Missing C\\+\\+ constant symbols"):
            self.check_symbol(name="_Z27debug_cpp_fixture_constants")

    def test_local_weak_and_function_symbols_are_not_global_c_objects(self) -> None:
        for info in [0x01, 0x21, 0x12]:
            with (
                self.subTest(info=info),
                self.assertRaisesRegex(ValueError, "global C-linkage object"),
            ):
                self.check_symbol(info=info)

    def test_wrong_section_or_partial_constant_symbol_extent_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "wrong constant section"):
            self.check_symbol(section_index=2)
        for address, size in [(0x400008, 200), (0x400000, 192), (0x400000, 208)]:
            with (
                self.subTest(address=address, size=size),
                self.assertRaisesRegex(ValueError, "exact constant section"),
            ):
                self.check_symbol(address=address, size=size)

    def test_duplicate_global_constant_symbols_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Duplicate C\\+\\+ constant symbol"):
            self.check_symbol(copies=2)


class DebugBoundTests(unittest.TestCase):
    def information(
        self, size: int, flags: int = 0, name: str = ".debug_info"
    ) -> Section:
        return Section(1, name, 1, flags, 0, 0, size, 0, 0, 1, 0)

    def test_oversized_information_is_rejected_before_reading_or_traversing_units(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds byte bound"):
            check_cpp_debug(b"", [self.information(131073)], 4, 131072)

    def test_compressed_debug_cannot_bypass_bounds_or_symbols_only_control(
        self,
    ) -> None:
        for section in [
            self.information(0, flags=0x800),
            self.information(0, name=".zdebug_info"),
        ]:
            for version in [None, 4]:
                with (
                    self.subTest(section=section.name, version=version),
                    self.assertRaisesRegex(ValueError, "Compressed C\\+\\+ debug"),
                ):
                    check_cpp_debug(b"", [section], version, 131072)

    def test_normal_debug_version_and_symbols_only_checks_remain_active(self) -> None:
        data = struct.pack("<IH", 7, 4) + bytes(5)
        sections = [
            self.information(len(data)),
            self.information(0, name=".debug_abbrev"),
        ]
        check_cpp_debug(data, sections, 4, 131072)
        with self.assertRaisesRegex(ValueError, "Expected DWARF 5"):
            check_cpp_debug(data, sections, 5, 131072)
        with self.assertRaisesRegex(ValueError, "unexpectedly retains debug"):
            check_cpp_debug(data, sections, None, 131072)


class WordEncodingTests(unittest.TestCase):
    def metadata(self) -> dict[str, Any]:
        return {
            "constant_encoding": {
                "magic": "0x1234",
                "version": 1,
                "byte_order_tag": 1,
                "byte_size": 200,
            },
            "target": {"address_size": 8},
            "layout": {
                "size": 40,
                "alignment": 8,
                "fields": [{"offset": 11, "size": 3, "alignment": 2}] * 6,
            },
        }

    def test_member_size_and_alignment_are_not_swapped_or_replaced_with_offset(
        self,
    ) -> None:
        self.assertEqual(layout_words(self.metadata())[7:10], [11, 3, 2])

    def test_wrong_declared_byte_count_or_field_count_is_rejected(self) -> None:
        metadata = self.metadata()
        metadata["constant_encoding"]["byte_size"] = 192
        with self.assertRaisesRegex(ValueError, "word count mismatch"):
            layout_words(metadata)
        metadata = self.metadata()
        metadata["layout"]["fields"].pop()
        with self.assertRaisesRegex(ValueError, "word count mismatch"):
            layout_words(metadata)


if __name__ == "__main__":
    unittest.main()
