# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

from verify_virtual_oracle import (
    LoadSegment,
    Section,
    Symbol,
    VptrLayout,
    check_cpp_debug,
    check_nonalias_methods,
    check_readonly_range,
    check_symbol_aliases,
    check_table,
    check_vtable_inventory,
    exact_symbol,
    parse_elf,
    parse_vptr_dump,
    read_bytes,
    read_symbols,
)


def compiler_dump(record: str = "VirtualRecord") -> str:
    return (
        "*** Dumping AST Record Layout\n"
        f"         0 | class {record}\n"
        f"         0 |   ({record} vtable pointer)\n"
        "         8 |   int count\n"
        "        12 |   unsigned char tail\n"
        "           | [sizeof=16, dsize=13, align=8,\n"
        "           |  nvsize=13, nvalign=8]\n"
        "*** Dumping IRgen Record Layout\n"
        f"Record: CXXRecordDecl 0x1234 <records.h:10:1> class {record} definition\n"
        "Layout: <CGRecordLayout\n"
        f"  LLVMType:%class.{record} = type <{{ ptr, i32, i8, [3 x i8] }}>\n"
        f"  NonVirtualBaseLLVMType:%class.{record}.base = type <{{ ptr, i32, i8 }}>\n"
        ">\n"
    )


class VptrDumpTests(unittest.TestCase):
    def test_ast_offset_and_ir_pointer_storage_are_both_required(self) -> None:
        self.assertEqual(parse_vptr_dump(compiler_dump(), "VirtualRecord", 8), VptrLayout(0, 8, 16, 8, 8, 12))
        variants = [
            compiler_dump().replace("(VirtualRecord vtable pointer)", "void *callback"),
            compiler_dump().replace("ptr, i32", "i64, i32"),
            compiler_dump().split("*** Dumping IRgen")[0],
            compiler_dump().replace("unsigned char tail", "int count"),
        ]
        for text in variants:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_vptr_dump(text, "VirtualRecord", 8)

    def test_ir_pointer_width_is_not_inferred_from_the_next_member_offset(self) -> None:
        with self.assertRaisesRegex(ValueError, "independently measured LP64"):
            parse_vptr_dump(compiler_dump(), "VirtualRecord", 4)
        with self.assertRaisesRegex(ValueError, "vptr/data layout changed"):
            parse_vptr_dump(compiler_dump().replace("8 |   int count", "4 |   int count"), "VirtualRecord", 8)

    def test_exact_record_boundaries_prevent_near_name_and_cross_record_joins(self) -> None:
        text = compiler_dump("VirtualRecordExtra") + compiler_dump("PeerRecord")
        with self.assertRaisesRegex(ValueError, "exact AST record"):
            parse_vptr_dump(text, "VirtualRecord", 8)
        text = compiler_dump().replace("class VirtualRecord definition", "class PeerRecord definition")
        with self.assertRaisesRegex(ValueError, "exact IRgen record"):
            parse_vptr_dump(text, "VirtualRecord", 8)

    def test_duplicate_ast_ir_and_secondary_vptr_dumps_are_rejected(self) -> None:
        ir = compiler_dump().split("*** Dumping IRgen Record Layout", 1)[1]
        variants = [
            compiler_dump() * 2,
            compiler_dump().replace(
                "8 |   int count", "8 |   (RightRecord vtable pointer)\n         8 |   int count"
            ),
            compiler_dump() + "*** Dumping IRgen Record Layout" + ir,
        ]
        for text in variants:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_vptr_dump(text, "VirtualRecord", 8)

    def test_changed_vptr_offset_size_alignment_or_tail_offset_is_rejected(self) -> None:
        for old, new in [
            ("0 |   (VirtualRecord", "8 |   (VirtualRecord"),
            ("sizeof=16", "sizeof=24"),
            ("align=8,", "align=4,"),
            ("12 |   unsigned char tail", "13 |   unsigned char tail"),
        ]:
            with self.subTest(change=old), self.assertRaisesRegex(ValueError, "vptr/data layout changed"):
                parse_vptr_dump(compiler_dump().replace(old, new), "VirtualRecord", 8)


class RawTableTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data: bytes = struct.pack("<4Q", 0, 0, 0x401000, 0x401004) + bytes(40)
        self.sections: list[Section] = [
            Section(0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0),
            Section(1, ".rodata", 1, 2, 0x400000, 0, 32, 0, 0, 8, 0),
            Section(2, ".text", 1, 6, 0x401000, 64, 8, 0, 0, 16, 0),
        ]
        self.loads: list[LoadSegment] = [LoadSegment(4, 0x400000, 32, 0, 32), LoadSegment(5, 0x401000, 8, 64, 8)]
        self.symbols: list[Symbol] = [
            Symbol("_ZTV13VirtualRecord", 0x11, 0, 1, 0x400000, 32),
            Symbol("read", 0x12, 0, 2, 0x401000, 4),
            Symbol("write", 0x12, 0, 2, 0x401004, 4),
        ]
        self.table: dict[str, Any] = {
            "symbol": "_ZTV13VirtualRecord",
            "words": [0, 0, "read", "write"],
            "address_point_offset": 16,
            "prefix_status": "UnverifiedPrefix",
        }

    def check(self) -> None:
        check_table(self.data, self.sections, self.loads, self.symbols, self.table, 128)

    def test_raw_slots_bind_exact_symbols_in_order_not_wrapper_argument_names(self) -> None:
        self.check()
        self.data = struct.pack("<4Q", 0, 0, 0x401004, 0x401000) + bytes(40)
        with self.assertRaisesRegex(ValueError, "word order/values"):
            self.check()

    def test_nonzero_prefix_and_promoted_rtti_status_are_not_accepted(self) -> None:
        self.data = struct.pack("<4Q", 0, 0x402000, 0x401000, 0x401004) + bytes(40)
        with self.assertRaisesRegex(ValueError, "word order/values"):
            self.check()
        self.data = struct.pack("<4Q", 0, 0, 0x401000, 0x401004) + bytes(40)
        self.table["prefix_status"] = "KnownRtti"
        with self.assertRaisesRegex(ValueError, "remain UnverifiedPrefix"):
            self.check()

    def test_duplicate_near_name_partial_and_weak_table_symbols_are_rejected(self) -> None:
        original = self.symbols[0]
        for symbol in [
            replace(original, name="_ZTV13VirtualRecordExtra"),
            replace(original, size=24),
            replace(original, info=0x21),
            replace(original, address=0x400008),
        ]:
            self.symbols[0] = symbol
            with self.subTest(symbol=symbol), self.assertRaises(ValueError):
                self.check()
        self.symbols[0] = original
        self.symbols.append(original)
        with self.assertRaisesRegex(ValueError, "one exact symbol"):
            self.check()

    def test_table_aliases_including_zero_extent_interior_labels_are_rejected(self) -> None:
        for info, address, size in [(0x11, 0x400000, 32), (0x10, 0x400010, 0), (0x21, 0x3FFFF8, 16)]:
            self.symbols.append(Symbol("alias", info, 0, 1, address, size))
            with self.subTest(info=info), self.assertRaisesRegex(ValueError, "aliased or overlapping"):
                self.check()
            self.symbols.pop()

    def test_selected_methods_and_source_constants_cannot_be_symbol_aliases(self) -> None:
        method = self.symbols[1]
        self.symbols.append(replace(method, name="other_record_read"))
        with self.assertRaisesRegex(ValueError, "aliased or overlapping"):
            check_nonalias_methods(self.symbols, ["read"])
        constant = Symbol("source_facts", 0x11, 0, 1, 0x400000, 32)
        with self.assertRaisesRegex(ValueError, "aliased or overlapping"):
            check_symbol_aliases([constant, replace(constant, name="alias")], constant)

    def test_out_of_bound_and_nonexecutable_method_targets_are_rejected(self) -> None:
        original = self.symbols[1]
        self.symbols[1] = replace(original, size=129)
        with self.assertRaisesRegex(ValueError, "bounded method"):
            self.check()
        self.symbols[1] = original
        self.loads[1] = replace(self.loads[1], flags=4)
        with self.assertRaisesRegex(ValueError, "executable file-backed"):
            self.check()

    def test_inventory_rejects_unexpected_tables_rtti_and_runtime_dependencies(self) -> None:
        check_vtable_inventory(self.symbols, [self.table])
        for symbol in [
            Symbol("_ZTV10PeerRecord", 0x11, 0, 1, 0x400020, 32),
            Symbol("_ZTI13VirtualRecord", 0x11, 0, 1, 0x400020, 16),
            Symbol("runtime_delete", 0x12, 0, 0, 0, 0),
        ]:
            with self.subTest(symbol=symbol), self.assertRaises(ValueError):
                check_vtable_inventory(self.symbols + [symbol], [self.table])


class MappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.section: Section = Section(1, ".facts", 1, 2, 0x400000, 0, 32, 0, 0, 8, 0)
        self.sections: list[Section] = [self.section]
        self.loads: list[LoadSegment] = [LoadSegment(4, 0x400000, 32, 0, 32)]

    def check(self) -> None:
        check_readonly_range(bytes(64), self.sections, self.loads, self.section, 0x400000, 32, "facts")

    def test_one_readonly_file_mapping_is_accepted(self) -> None:
        self.check()

    def test_writable_executable_bss_partial_and_wrong_file_offset_are_rejected(self) -> None:
        original = self.loads[0]
        for load in [
            replace(original, flags=6), replace(original, flags=5),
            replace(original, file_size=0), replace(original, file_size=31), replace(original, offset=8),
        ]:
            self.loads = [load]
            with self.subTest(load=load), self.assertRaisesRegex(ValueError, "file-backed mapping"):
                self.check()

    def test_va_and_file_alias_mappings_are_rejected_even_if_readonly(self) -> None:
        original = self.loads[0]
        for alias in [original, replace(original, flags=6), replace(original, address=0x500000)]:
            self.loads = [original, alias]
            with self.subTest(alias=alias), self.assertRaisesRegex(ValueError, "mapping"):
                self.check()

    def test_section_aliases_and_relocations_are_rejected(self) -> None:
        for alias in [
            replace(self.section, index=2, name=".alias"),
            replace(self.section, index=2, name=".alias", address=0x500000),
            Section(2, ".rela.facts", 4, 0, 0, 40, 24, 0, 1, 8, 24),
        ]:
            self.sections = [self.section, alias]
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                self.check()

    def test_readonly_section_flags_cannot_hide_executable_or_writable_storage(self) -> None:
        for flags in [0, 3, 6]:
            self.section = replace(self.section, flags=flags)
            self.sections = [self.section]
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "allocated read-only"):
                self.check()


class BoundTests(unittest.TestCase):
    def test_binary_and_dump_bounds_are_enforced_by_bounded_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rampage-virtual-bounds-") as temporary:
            path = Path(temporary) / "oversized"
            for maximum in [1048576, 131072]:
                path.write_bytes(bytes(maximum + 1))
                with self.subTest(maximum=maximum), self.assertRaisesRegex(ValueError, "exceeds .*byte bound"):
                    read_bytes(path, maximum)

    def test_oversized_debug_is_rejected_before_reading_or_traversing_units(self) -> None:
        information = Section(1, ".debug_info", 1, 0, 0, 0, 131073, 0, 0, 1, 0)
        with self.assertRaisesRegex(ValueError, "exceeds byte bound"):
            check_cpp_debug(b"", [information], 4, 131072)

    def test_section_bound_is_checked_before_section_table_reads(self) -> None:
        header = struct.pack(
            "<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01", 2, 62, 1,
            0, 0, 0, 0, 64, 56, 1, 64, 129, 0,
        )
        target = {"elf_type": 2, "elf_machine": 62, "max_sections": 128}
        with self.assertRaisesRegex(ValueError, "Section count exceeds bound"):
            parse_elf(header, target)

    def test_symbol_bound_precedes_string_and_symbol_reads(self) -> None:
        table = Section(0, ".symtab", 2, 0, 0, 0, 257 * 24, 0, 0, 8, 24)
        with self.assertRaisesRegex(ValueError, "symbol count exceeds bound"):
            read_symbols(b"", [table], 256)

    def test_duplicate_method_linkage_names_are_not_resolved_by_first_match(self) -> None:
        symbol = Symbol("readCount", 0x12, 0, 1, 0x401000, 4)
        with self.assertRaisesRegex(ValueError, "one exact symbol"):
            exact_symbol([symbol, replace(symbol, address=0x401004)], "readCount")


if __name__ == "__main__":
    unittest.main()
