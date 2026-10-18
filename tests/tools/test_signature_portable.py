"""Hermetic admission/provenance tests; no compiler, network or target execution."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "signature_portable_test", ROOT / "tools/signature_portable.py"
)
assert SPEC is not None and SPEC.loader is not None
portable = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = portable
SPEC.loader.exec_module(portable)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tar_bytes(members: list[tuple[tarfile.TarInfo, bytes]], **kwargs: Any) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output, mode="w", format=tarfile.PAX_FORMAT, **kwargs
    ) as stream:
        for member, data in members:
            stream.addfile(member, io.BytesIO(data))
    return output.getvalue()


def member(name: str, data: bytes = b"source") -> tuple[tarfile.TarInfo, bytes]:
    information = tarfile.TarInfo(name)
    information.size = len(data)
    return information, data


def recipe() -> dict[str, Any]:
    return {
        "archive_root": "source",
        "selected_sha256": {"source/unit.c": digest(b"source")},
        "bounds": {
            "compressed_bytes": 128 * 1024,
            "physical_tar_bytes": 128 * 1024,
            "physical_headers": 20,
            "member_bytes": 32 * 1024,
            "metadata_bytes": 1024,
            "selected_bytes": 64,
        },
    }


class AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="signature-portable-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()

    def extract(
        self, data: bytes, declaration: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        archive = self.directory / "input.tar.gz"
        compressed = gzip.compress(data)
        archive.write_bytes(compressed)
        declaration = declaration or recipe()
        declaration["archive_sha256"] = digest(compressed)
        return portable.materialize(archive, self.directory / "selected", declaration)

    def test_materializes_only_selected_original_bytes(self) -> None:
        data = tar_bytes(
            [member("source/unit.c"), member("source/not-owned.c", b"not selected")]
        )
        evidence = self.extract(data)
        self.assertEqual(evidence["logical_members"], 2)
        self.assertEqual(
            (self.directory / "selected/source/unit.c").read_bytes(), b"source"
        )
        self.assertFalse((self.directory / "selected/source/not-owned.c").exists())

    def test_rejects_unsafe_unselected_names(self) -> None:
        for name in (
            "../escape",
            "source/../escape",
            "/absolute",
            "source//ambiguous",
            "source/./dot",
            "source\\back",
            "C:drive",
        ):
            with self.subTest(name=name), self.assertRaises(portable.PortableError):
                self.extract(tar_bytes([member("source/unit.c"), member(name)]))
            self.assertFalse((self.directory / "selected").exists())

    def test_duplicate_unselected_paths_are_not_ignored(self) -> None:
        with self.assertRaisesRegex(portable.PortableError, "duplicate"):
            self.extract(
                tar_bytes(
                    [
                        member("source/unit.c"),
                        member("source/other"),
                        member("source/other"),
                    ]
                )
            )

    def test_pax_effective_duplicate_and_outside_root_are_rejected(self) -> None:
        information, data = member("source/alias")
        information.pax_headers = {"path": "source/unit.c"}
        for members in (
            [member("source/unit.c"), (information, data)],
            [member("source/unit.c"), member("another-root/file")],
        ):
            with (
                self.subTest(members=members),
                self.assertRaises(portable.PortableError),
            ):
                self.extract(tar_bytes(members))

    def test_both_parser_passes_use_the_same_pinned_immutable_bytes(self) -> None:
        admission = portable.physical_admission

        def replace_disk_snapshot(
            stream: io.BufferedIOBase, bounds: dict[str, int]
        ) -> dict[str, int]:
            result = admission(stream, bounds)
            (self.directory / "input.tar.gz").write_bytes(
                gzip.compress(tar_bytes([member("../escape")]))
            )
            return result

        with patch.object(
            portable, "physical_admission", side_effect=replace_disk_snapshot
        ):
            self.extract(tar_bytes([member("source/unit.c")]))
        self.assertEqual(
            (self.directory / "selected/source/unit.c").read_bytes(), b"source"
        )

    def test_selected_symlink_is_never_followed(self) -> None:
        information = tarfile.TarInfo("source/unit.c")
        information.type = tarfile.SYMTYPE
        information.linkname = "outside"
        with self.assertRaisesRegex(portable.PortableError, "not an ordinary file"):
            self.extract(tar_bytes([(information, b"")]))

    def test_hardlink_and_corrupt_headers_fail_admission(self) -> None:
        information = tarfile.TarInfo("source/unit.c")
        information.type = tarfile.LNKTYPE
        information.linkname = "source/elsewhere"
        with self.assertRaises(portable.PortableError):
            self.extract(tar_bytes([(information, b"")]))
        corrupt = bytearray(tar_bytes([member("source/unit.c")]))
        corrupt[0] ^= 1
        with self.assertRaises(tarfile.TarError):
            self.extract(bytes(corrupt))

    def test_unselected_symlink_is_not_materialized(self) -> None:
        information = tarfile.TarInfo("source/unselected-link")
        information.type = tarfile.SYMTYPE
        information.linkname = "../../outside"
        self.extract(tar_bytes([member("source/unit.c"), (information, b"")]))
        self.assertFalse((self.directory / "selected/source/unselected-link").exists())

    def test_paths_under_archive_links_are_rejected(self) -> None:
        information = tarfile.TarInfo("source/link")
        information.type = tarfile.SYMTYPE
        information.linkname = "elsewhere"
        with self.assertRaisesRegex(portable.PortableError, "obstructed"):
            self.extract(
                tar_bytes(
                    [
                        member("source/unit.c"),
                        (information, b""),
                        member("source/link/child"),
                    ]
                )
            )

    def test_missing_or_changed_selected_source_rejects_before_materialization(
        self,
    ) -> None:
        for members in (
            [member("source/other")],
            [member("source/unit.c", b"changed")],
        ):
            with (
                self.subTest(members=members),
                self.assertRaises(portable.PortableError),
            ):
                self.extract(tar_bytes(members))
            self.assertFalse((self.directory / "selected").exists())

    def test_pax_override_path_gets_logical_validation(self) -> None:
        information, data = member("source/ordinary")
        information.pax_headers = {"path": "../escape"}
        with self.assertRaisesRegex(portable.PortableError, "unsafe"):
            self.extract(tar_bytes([member("source/unit.c"), (information, data)]))

    def test_global_and_per_file_pax_payloads_have_physical_budget(self) -> None:
        for global_header in (True, False):
            information, data = member("source/unit.c")
            kwargs = {"pax_headers": {"comment": "x" * 2048}} if global_header else {}
            if not global_header:
                information.pax_headers = {"comment": "x" * 2048}
            with (
                self.subTest(global_header=global_header),
                self.assertRaisesRegex(portable.PortableError, "metadata budget"),
            ):
                self.extract(tar_bytes([(information, data)], **kwargs))

    def test_total_physical_budget_cannot_be_hidden_by_pax_size(self) -> None:
        information, data = member("source/unit.c")
        information.pax_headers = {"size": "6"}
        declaration = recipe()
        declaration["bounds"]["physical_tar_bytes"] = 1024
        with self.assertRaisesRegex(portable.PortableError, "physical expanded"):
            self.extract(tar_bytes([(information, data)]), declaration)

    def test_header_member_and_selected_payload_budgets(self) -> None:
        for key, bound in (
            ("physical_headers", 1),
            ("member_bytes", 3),
            ("selected_bytes", 3),
        ):
            declaration = recipe()
            declaration["bounds"][key] = bound
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(portable.PortableError, "budget"),
            ):
                self.extract(
                    tar_bytes([member("source/unit.c"), member("source/other")]),
                    declaration,
                )

    def test_compressed_snapshot_budget_is_checked_before_expansion(self) -> None:
        declaration = recipe()
        declaration["bounds"]["compressed_bytes"] = 3
        with self.assertRaisesRegex(portable.PortableError, "compressed snapshot"):
            self.extract(tar_bytes([member("source/unit.c")]), declaration)

    def test_partial_payload_and_nonzero_trailing_tar_are_rejected(self) -> None:
        data = tar_bytes([member("source/unit.c")])
        for malformed in (data[:515], data + tar_bytes([member("source/trailing")])):
            with (
                self.subTest(size=len(malformed)),
                self.assertRaises(portable.PortableError),
            ):
                self.extract(malformed)

    def test_snapshot_rejects_bad_pin_symlink_fifo_and_over_budget(self) -> None:
        source = self.directory / "regular"
        source.write_bytes(b"input")
        link = self.directory / "link"
        link.symlink_to(source)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        for index, (path, maximum, expected) in enumerate(
            (
                (source, 10, digest(b"wrong")),
                (source, 2, digest(b"input")),
                (link, 10, digest(b"input")),
                (fifo, 10, digest(b"input")),
            )
        ):
            with (
                self.subTest(path=path, maximum=maximum),
                self.assertRaises(portable.PortableError),
            ):
                portable.snapshot(path, self.directory / str(index), maximum, expected)

    def test_snapshot_is_create_only_and_retains_admitted_bytes(self) -> None:
        source = self.directory / "original"
        source.write_bytes(b"input")
        destination = self.directory / "snapshot"
        portable.snapshot(source, destination, 10, digest(b"input"))
        source.write_bytes(b"later")
        self.assertEqual(destination.read_bytes(), b"input")
        with self.assertRaises(FileExistsError):
            portable.snapshot(source, destination, 10, digest(b"later"))

    def test_changed_consumed_input_blocks_publication(self) -> None:
        path = self.directory / "consumed"
        path.write_bytes(b"first")
        inventory = {str(path): digest(b"first")}
        portable.verify_inventory(inventory)
        path.write_bytes(b"later")
        with self.assertRaisesRegex(portable.PortableError, "changed consumed"):
            portable.verify_inventory(inventory)

    def test_output_refuses_existing_and_linked_roots(self) -> None:
        (self.directory / "target").mkdir()
        with patch.object(portable, "ROOT", self.directory):
            path = portable.fresh_directory(str(self.directory / "target/new"))
            with self.assertRaises(FileExistsError):
                portable.fresh_directory(str(path))
            (self.directory / "link").symlink_to(self.directory / "target")
            with self.assertRaises(portable.PortableError):
                portable.fresh_directory(str(self.directory / "link/other"))


class OwnershipTests(unittest.TestCase):
    def test_source_function_scope_rejects_weak_hidden_missing_and_extra_names(
        self,
    ) -> None:
        row = "1: 00000000 216 FUNC GLOBAL DEFAULT 3 __strverscmp\n"
        alias = "2: 00000000 216 FUNC WEAK DEFAULT 3 strverscmp\n"
        portable.validate_symbols(
            row + alias, {"__strverscmp"}, {"strverscmp": "__strverscmp"}
        )
        for altered in (
            row.replace("GLOBAL", "WEAK") + alias,
            row.replace("DEFAULT", "HIDDEN") + alias,
            alias,
            row + alias + "3: 00000100 10 FUNC GLOBAL DEFAULT 3 unexpected\n",
            row + alias.replace("00000000", "00000100"),
        ):
            with (
                self.subTest(altered=altered),
                self.assertRaises(portable.PortableError),
            ):
                portable.validate_symbols(
                    altered, {"__strverscmp"}, {"strverscmp": "__strverscmp"}
                )

    def test_report_binds_full_roster_objects_and_collector_binary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="portable-report-") as temporary:
            obj = Path(temporary) / "unit.o"
            obj.write_bytes(b"object")
            tool = Path(temporary) / "builder"
            tool.write_bytes(b"frozen host tool")
            metrics = {
                "correct": 1,
                "wrong": 0,
                "missed": 0,
                "spurious": 0,
                "precision": 1.0,
                "recall": 1.0,
            }
            report = {
                "schema_version": 1,
                "measurement": "phase2-1-library-signatures",
                "arch": "x86_64",
                "passed": True,
                "baseline_available": True,
                "target_executed": False,
                "load_image_equivalent_stripped_twin": True,
                "ownership_scope": "public strong",
                "ownership_scope_id": "public_strong",
                "library_truth": {"0x1000": "__strverscmp"},
                "truth_functions": 1,
                "baseline": dict(metrics),
                "after": dict(metrics),
                "matched_version_recall_gate": 0.8,
                "library_defined_names": 1,
                "library_object_count": 1,
                "library_object_sha256": [digest(b"object")],
                "evaluator_binary_sha256": digest(b"frozen host tool"),
            }
            artifacts = {"evaluator_binary_sha256": tool}
            declaration = {"profile": "glibc-strverscmp-portable"}
            portable.validate_report(report, declaration, [obj], artifacts, 0)
            for key, value in (
                ("library_truth", {"0x1000": "substituted"}),
                ("library_object_sha256", ["0" * 64]),
                ("evaluator_binary_sha256", "0" * 64),
            ):
                with (
                    self.subTest(key=key),
                    self.assertRaises(
                        (portable.PortableError, portable.core.CorpusError)
                    ),
                ):
                    portable.validate_report(
                        {**report, key: value}, declaration, [obj], artifacts, 0
                    )

    def test_recipe_fixture_pins_match_owned_harnesses_and_configuration(self) -> None:
        for fragment in portable.FRAGMENTS.values():
            declaration = json.loads(
                (ROOT / "tests/fixtures/signatures" / fragment).read_text()
            )
            for path, expected in declaration["fixture_sha256"].items():
                self.assertEqual(digest((ROOT / path).read_bytes()), expected)


if __name__ == "__main__":
    unittest.main()
