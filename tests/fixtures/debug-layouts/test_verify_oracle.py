# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import struct
import unittest

from verify_oracle import LoadSegment, Section, backs_range, check_constants, parse_elf


class ConstantMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = 0x123456789ABCDEF0
        self.data = struct.pack("<Q", self.value)
        self.section = Section(1, ".facts", 1, 2, 0x1000, 0, 8, 0, 0, 8, 0)
        self.readonly = LoadSegment(4, 0x1000, 8, 0, 8)

    def check(self, segments: list[LoadSegment]) -> None:
        check_constants(self.data, [self.section], segments, ".facts", [self.value])

    def test_exact_readonly_file_mapping_is_accepted(self) -> None:
        self.check([self.readonly])

    def test_memory_coverage_without_complete_file_backing_is_rejected(self) -> None:
        for file_size in [0, 4, 7]:
            with self.subTest(file_size=file_size), self.assertRaisesRegex(ValueError, "not covered by a read-only"):
                self.check([LoadSegment(4, 0x1000, 8, 0, file_size)])

    def test_file_to_virtual_offset_must_match_the_verified_bytes(self) -> None:
        with self.assertRaisesRegex(ValueError, "not covered by a read-only"):
            self.check([LoadSegment(4, 0x1000, 8, 1, 8)])

    def test_writable_or_executable_aliases_invalidate_the_readonly_witness(self) -> None:
        for flags in [1, 2, 3, 5, 6, 7]:
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "overlaps a writable or executable"):
                self.check([self.readonly, LoadSegment(flags, 0x1004, 8, 0, 0)])

    def test_adjacent_writable_ranges_do_not_overlap_constants(self) -> None:
        self.check([self.readonly, LoadSegment(6, 0x0FF8, 8, 0, 0), LoadSegment(6, 0x1008, 8, 0, 0)])

    def test_backing_window_checks_both_ends_and_file_correspondence(self) -> None:
        segment = LoadSegment(5, 0x1000, 32, 16, 16)
        self.assertTrue(backs_range(segment, 0x1004, 20, 4))
        for address, offset, size in [(0x0FFF, 15, 1), (0x100F, 31, 2), (0x1010, 32, 1), (0x1004, 21, 4)]:
            with self.subTest(address=address, offset=offset, size=size):
                self.assertFalse(backs_range(segment, address, offset, size))

    def test_program_header_file_range_survives_elf_parsing(self) -> None:
        data = bytearray(520)
        identification = b"\x7fELF\x02\x01\x01" + bytes(9)
        struct.pack_into(
            "<16sHHIQQQIHHHHHH", data, 0, identification, 2, 62, 1, 0x400000, 64, 120, 0, 64, 56, 1, 64, 2, 1
        )
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 4, 512, 0x400000, 0, 8, 16, 8)
        names = b"\0.shstrtab\0"
        struct.pack_into("<IIQQQQIIQQ", data, 184, 1, 3, 0, 0, 248, len(names), 0, 0, 1, 0)
        data[248 : 248 + len(names)] = names
        _, segments, _ = parse_elf(bytes(data), {"elf_type": 2, "elf_machine": 62, "max_sections": 128})
        self.assertEqual(segments, [LoadSegment(4, 0x400000, 16, 512, 8)])


if __name__ == "__main__":
    unittest.main()
