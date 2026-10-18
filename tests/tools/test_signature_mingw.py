"""Finite runtime-unit admission tests; no target execution or SDK build."""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
import unittest
from pathlib import Path
from typing import Any

SPEC = importlib.util.spec_from_file_location(
    "signature_mingw", Path(__file__).resolve().parents[2] / "tools/signature_mingw.py"
)
assert SPEC is not None and SPEC.loader is not None
mingw = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mingw
SPEC.loader.exec_module(mingw)


def coff(names: list[str]) -> bytes:
    strings = bytearray(b"\0\0\0\0")
    symbols = bytearray()
    for name in names:
        encoded = name.encode()
        reference = b"\0\0\0\0" + struct.pack("<I", len(strings))
        strings.extend(encoded + b"\0")
        symbols.extend(reference + struct.pack("<IhHBB", 0, 1, 0x20, 2, 0))
    struct.pack_into("<I", strings, 0, len(strings))
    header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 60, len(names), 0, 0)
    section = bytearray(40)
    section[:5] = b".text"
    struct.pack_into("<I", section, 36, 0x60000020)
    return header + section + symbols + strings


def ar_entry(name: str, payload: bytes) -> bytes:
    header = f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(payload):<10}`\n".encode()
    return header + payload + (b"\n" if len(payload) & 1 else b"")


class MingwPesectTests(unittest.TestCase):
    def test_unique_member_uses_literal_archive_payload_and_ordinal(self) -> None:
        payload = coff(sorted(mingw.OWNED_NAMES))
        name = "zig-global-cache/o/" + "a" * 32 + "/pesect.obj"
        archive = b"!<arch>\n" + ar_entry("//", name.encode() + b"\0")
        archive += ar_entry("other.obj/", b"not owned") + ar_entry("/0", payload)
        selected, receipt = mingw.select_member(archive)
        self.assertEqual(selected, payload)
        self.assertEqual(receipt["ordinal"], 1)
        self.assertEqual(receipt["member"], name)
        self.assertEqual(receipt["sha256"], hashlib.sha256(payload).hexdigest())
        mingw.validate_object(selected)

    def test_duplicate_member_names_are_refused_even_for_identical_payload(
        self,
    ) -> None:
        name = "zig-global-cache/o/" + "b" * 32 + "/pesect.obj"
        payload = coff(sorted(mingw.OWNED_NAMES))
        archive = b"!<arch>\n" + ar_entry("//", name.encode() + b"\0")
        archive += ar_entry("/0", payload) * 2
        with self.assertRaisesRegex(mingw.core.CorpusError, "unique"):
            mingw.select_member(archive)

    def test_wrong_cache_name_thin_archive_and_truncated_member_are_refused(
        self,
    ) -> None:
        payload = coff(sorted(mingw.OWNED_NAMES))
        name = "../pesect.obj"
        wrong = (
            b"!<arch>\n"
            + ar_entry("//", name.encode() + b"\0")
            + ar_entry("/0", payload)
        )
        for archive in (
            wrong,
            b"!<thin>\n",
            b"!<arch>\n" + ar_entry("pesect.obj/", payload)[:-2],
        ):
            with (
                self.subTest(prefix=archive[:12]),
                self.assertRaises(mingw.core.CorpusError),
            ):
                mingw.select_member(archive)

    def test_source_unit_cannot_silently_expand_or_drop_external_function_names(
        self,
    ) -> None:
        names = sorted(mingw.OWNED_NAMES)
        for changed in (
            names[:-1],
            [*names, "unexpected_alias"],
            [*names[:-1], "replacement"],
        ):
            with (
                self.subTest(names=changed),
                self.assertRaisesRegex(mingw.core.CorpusError, "nine declared"),
            ):
                mingw.validate_object(coff(changed))

    def test_import_object_and_nonexecutable_function_definitions_are_refused(
        self,
    ) -> None:
        payload = bytearray(coff(sorted(mingw.OWNED_NAMES)))
        struct.pack_into("<I", payload, 20 + 36, 0x40000040)
        for changed in (b"\0\0\xff\xff" + b"\0" * 40, bytes(payload)):
            with (
                self.subTest(prefix=changed[:4]),
                self.assertRaises(mingw.core.CorpusError),
            ):
                mingw.validate_object(changed)

    def test_passing_eight_function_denominator_is_not_accepted(self) -> None:
        names = sorted(mingw.OWNED_NAMES)
        for changed in (names[:-1], [*names, "unowned_alias"]):
            report: dict[str, Any] = {
                "passed": True,
                "library_truth": {f"0x{i:x}": name for i, name in enumerate(changed)},
                "truth_functions": len(changed),
                "producer_range_source": "explicit_identity_matched_pdb_procedures",
                "ownership_scope_id": "public_strong",
            }
            with (
                self.subTest(names=changed),
                self.assertRaisesRegex(mingw.core.CorpusError, "all nine"),
            ):
                mingw.validate_truth(report)

    def test_forged_passing_nine_function_report_cannot_change_owned_object_identity(
        self,
    ) -> None:
        selected_sha = hashlib.sha256(coff(sorted(mingw.OWNED_NAMES))).hexdigest()
        report: dict[str, Any] = {
            "passed": True,
            "library_truth": {
                f"0x{i:x}": name for i, name in enumerate(sorted(mingw.OWNED_NAMES))
            },
            "truth_functions": 9,
            "producer_range_source": "explicit_identity_matched_pdb_procedures",
            "ownership_scope_id": "public_strong",
            "library_object_count": 1,
            "library_object_sha256": [selected_sha],
        }
        mingw.validate_truth(report)
        mingw.validate_ownership(report, selected_sha)
        invalid: tuple[dict[str, Any], ...] = (
            {"library_object_count": 0},
            {"library_object_count": 2},
            {"library_object_count": True},
            {"library_object_count": "1"},
            {"library_object_sha256": ["0" * 64]},
            {"library_object_sha256": []},
            {"library_object_sha256": [selected_sha, selected_sha]},
            {"library_object_sha256": selected_sha},
            {"library_object_sha256": (selected_sha,)},
        )
        for changes in invalid:
            forged = {**report, **changes}
            with self.subTest(changes=changes):
                mingw.validate_truth(forged)
                with self.assertRaisesRegex(
                    mingw.core.CorpusError, "exactly one object"
                ):
                    mingw.validate_ownership(forged, selected_sha)

    def test_public_names_without_global_procedure_provenance_are_not_truth(
        self,
    ) -> None:
        report: dict[str, Any] = {
            "library_truth": {
                f"0x{i:x}": name for i, name in enumerate(sorted(mingw.OWNED_NAMES))
            },
            "truth_functions": 9,
            "producer_range_source": "public_names_only",
            "ownership_scope_id": "public_strong",
        }
        with self.assertRaisesRegex(mingw.core.CorpusError, "GLOBAL procedure"):
            mingw.validate_truth(report)
        report["producer_range_source"] = "explicit_identity_matched_pdb_procedures"
        mingw.validate_truth(report)


if __name__ == "__main__":
    unittest.main()
