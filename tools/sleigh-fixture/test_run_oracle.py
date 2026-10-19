# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

SPEC = importlib.util.spec_from_file_location(
    "owned_sleigh_producer", Path(__file__).with_name("run_oracle.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned producer module unavailable")
producer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = producer
SPEC.loader.exec_module(producer)


class TestWorkspace(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="p2-tests-", dir=producer.RAW
        )
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def file(self, name: str, data: bytes) -> Path:
        path = self.directory / name
        path.write_bytes(data)
        return path


class BoundedInputTests(TestWorkspace):
    def test_oversized_file_refused_before_yield(self) -> None:
        path = self.file("oversized", b"x" * 9)
        with (
            self.assertRaisesRegex(ValueError, "pre-read cap"),
            producer.checked_file(path, 8),
        ):
            self.fail("oversized descriptor reached read body")

    def test_fixture_cap_is_128_bytes(self) -> None:
        path = self.file("fixture.bin", b"x" * 129)
        with self.assertRaisesRegex(ValueError, "pre-read cap"):
            producer.read_bounded(path, 128)

    def test_json_pre_read_cap_is_enforced(self) -> None:
        path = self.directory / "oracle.json"
        with path.open("wb") as output:
            output.truncate(producer.JSON_CAP + 1)
        with self.assertRaisesRegex(ValueError, "pre-read cap"):
            producer.read_bounded(path, producer.JSON_CAP)

    def test_symlink_and_fifo_are_not_read(self) -> None:
        target = self.file("target", b"owned")
        link = self.directory / "link"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            producer.read_bounded(link, 128)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            producer.read_bounded(fifo, 128)

    def test_missing_path_after_read_is_rejected(self) -> None:
        path = self.file("removed", b"owned")
        with (
            self.assertRaisesRegex(ValueError, "path missing"),
            producer.checked_file(path, 128) as source,
        ):
            self.assertEqual(source.read(129), b"owned")
            path.unlink()

    def test_replaced_path_after_read_is_rejected(self) -> None:
        path = self.file("replaced", b"owned")
        replacement = self.file("replacement", b"owned")
        with (
            self.assertRaisesRegex(ValueError, "identity changed"),
            producer.checked_file(path, 128) as source,
        ):
            self.assertEqual(source.read(129), b"owned")
            replacement.replace(path)

    def test_changed_descriptor_after_read_is_rejected(self) -> None:
        path = self.file("changed", b"owned")
        with (
            self.assertRaisesRegex(ValueError, "identity changed"),
            producer.checked_file(path, 128) as source,
        ):
            self.assertEqual(source.read(129), b"owned")
            with path.open("ab") as destination:
                destination.write(b"changed")

    def test_digest_is_streamed_and_bounded(self) -> None:
        path = self.file("digest", b"owned")
        result = producer.digest(path, cap=5)
        self.assertEqual(result["bytes"], 5)
        self.assertEqual(result["identity"]["inode"], path.stat().st_ino)
        with self.assertRaisesRegex(ValueError, "pre-read cap"):
            producer.digest(path, cap=4)

    def test_shared_snapshot_byte_and_file_caps(self) -> None:
        files = {
            "first": self.file("first", b"12345"),
            "second": self.file("second", b"12345"),
        }
        for budget in (producer.Budget(max_bytes=9), producer.Budget(max_files=1)):
            with (
                self.subTest(budget=budget),
                self.assertRaisesRegex(ValueError, "aggregate snapshot budget"),
            ):
                producer.snapshot(files, budget)

    def test_actual_repeat_reads_are_charged_to_shared_budget(self) -> None:
        path = self.file("repeat", b"owned")
        budget = producer.Budget(max_bytes=5)
        with (
            self.assertRaisesRegex(ValueError, "actual aggregate"),
            producer.checked_file(path, 5, budget) as source,
        ):
            self.assertEqual(source.read(5), b"owned")
            source.seek(0)
            source.read(1)

    def test_tool_sources_have_separate_small_cap(self) -> None:
        path = self.directory / "large.java"
        with path.open("wb") as output:
            output.truncate(producer.MIB + 1)
        with self.assertRaisesRegex(ValueError, "pre-read cap"):
            producer.snapshot({"source/large.java": path}, producer.Budget())

    def test_zip_member_cap_precedes_member_open(self) -> None:
        path = self.directory / "oversized.zip"
        with ZipFile(path, "w") as archive:
            archive.writestr("source.java", b"x" * 9)
        with (
            patch.object(producer, "SOURCE_MEMBER_CAP", 8),
            patch.object(ZipFile, "open") as opened,
        ):
            with self.assertRaisesRegex(ValueError, "pre-read cap"):
                producer.source_members(path, ["source.java"], producer.Budget())
            opened.assert_not_called()

    def test_zip_archive_file_cap_precedes_zip_parse(self) -> None:
        path = self.file("archive.zip", b"x" * 9)
        with (
            patch.object(producer, "FILE_CAP", 8),
            patch.object(producer, "ZipFile") as archive,
        ):
            with self.assertRaisesRegex(ValueError, "pre-read cap"):
                producer.source_members(path, ["source.java"], producer.Budget())
            archive.assert_not_called()

    def test_zip_duplicates_and_traversal_rejected(self) -> None:
        for unsafe in (
            "../escape.java",
            "/escape.java",
            "a/../escape.java",
            "a\\escape.java",
        ):
            with self.subTest(name=unsafe):
                path = self.directory / "unsafe.zip"
                with ZipFile(path, "w") as archive:
                    archive.writestr(unsafe, b"owned")
                with self.assertRaisesRegex(ValueError, "unsafe source archive member"):
                    producer.source_members(path, [unsafe], producer.Budget())
        duplicate = self.directory / "duplicate.zip"
        with ZipFile(duplicate, "w") as archive:
            archive.writestr("source.java", b"first")
            with self.assertWarns(UserWarning):
                archive.writestr("source.java", b"second")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            producer.source_members(duplicate, ["source.java"], producer.Budget())

    def test_zip_member_is_charged_to_shared_budget(self) -> None:
        path = self.directory / "source.zip"
        with ZipFile(path, "w") as archive:
            archive.writestr("source.java", b"owned")
        with self.assertRaisesRegex(ValueError, "aggregate snapshot budget"):
            producer.source_members(
                path,
                ["source.java"],
                producer.Budget(max_bytes=path.stat().st_size + 4),
            )


class ClassBindingTests(TestWorkspace):
    def test_nested_class_inventory_unchanged_then_changed(self) -> None:
        self.file("SleighOracle.class", b"owned-host-main")
        nested = self.file("SleighOracle$Fixture.class", b"owned-host-nested")
        before = producer.class_inventory(self.directory)
        self.assertEqual(
            set(before), {"SleighOracle.class", "SleighOracle$Fixture.class"}
        )
        self.assertEqual(producer.verify_classes(self.directory, before), before)
        nested.write_bytes(b"changed-host-nested")
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            producer.verify_classes(self.directory, before)

    def test_missing_post_execution_class_is_rejected(self) -> None:
        main = self.file("SleighOracle.class", b"owned-host-main")
        before = producer.class_inventory(self.directory)
        main.unlink()
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            producer.verify_classes(self.directory, before)

    def test_added_post_execution_class_is_rejected(self) -> None:
        self.file("SleighOracle.class", b"owned-host-main")
        before = producer.class_inventory(self.directory)
        self.file("SleighOracle$Added.class", b"added-host-class")
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            producer.verify_classes(self.directory, before)

    def test_class_file_size_and_total_count_are_bounded(self) -> None:
        path = self.directory / "SleighOracle.class"
        with path.open("wb") as output:
            output.truncate(producer.MIB + 1)
        with self.assertRaisesRegex(ValueError, "pre-read cap"):
            producer.class_inventory(self.directory)
        path.unlink()
        for index in range(33):
            self.file(f"Class{index}.class", b"owned-host-class")
        with self.assertRaisesRegex(ValueError, "inventory count"):
            producer.class_inventory(self.directory)

    def test_compiled_class_aggregate_size_is_bounded(self) -> None:
        for index in range(5):
            path = self.directory / f"Class{index}.class"
            with path.open("wb") as output:
                output.truncate(producer.MIB)
        with self.assertRaisesRegex(ValueError, "aggregate snapshot budget"):
            producer.class_inventory(self.directory)

    def test_nested_class_directories_are_inventoried(self) -> None:
        package = self.directory / "owned"
        package.mkdir()
        (package / "Nested.class").write_bytes(b"owned-host-package")
        self.assertEqual(
            set(producer.class_inventory(self.directory)), {"owned/Nested.class"}
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
