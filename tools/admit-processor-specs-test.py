"""Finite admission checks; no JVM, network, Cargo or target execution."""

from __future__ import annotations

import hashlib
import io
import json
import os
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

HELPER = runpy.run_path(str(Path(__file__).with_name("admit-processor-specs.py")))
BUNDLE = Path(__file__).resolve().parents[1] / "crates/rampage-decompiler/specs"
CANDIDATE = os.environ.get("PROCESSOR_ADMISSION_CANDIDATE")


class AdmissionTest(unittest.TestCase):
    def test_bundle_and_unknown_6502_c_abi(self) -> None:
        manifest = HELPER["verify"](BUNDLE, None)
        profile = next(p for p in manifest["profiles"] if p["family"] == "6502")
        self.assertIsNone(profile["c_integer_size_bytes"])
        self.assertIsNone(profile["c_pointer_size_bytes"])
        avr = next(p for p in manifest["profiles"] if p["family"] == "AVR8")
        code = next(s for s in avr["address_spaces"] if s["name"] == "code")
        self.assertEqual(code["word_size_bytes"], 2)
        self.assertIsNone(code["sla_runtime_confirmation"])

    def test_path_escapes_are_refused(self) -> None:
        for path in (
            "",
            "/etc/passwd",
            "../outside",
            "a/../b",
            "a//b",
            "a/./b",
            "a\\b",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                HELPER["relative_path"](path)

    def test_snapshot_rejects_symlink_and_fifo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            (root / "ordinary").write_bytes(b"data")
            (root / "link").symlink_to("ordinary")
            os.mkfifo(root / "fifo")
            for name in ("link", "fifo"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    HELPER["Snapshot"](root).read(name)

    def test_snapshot_bounds_and_consumed_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            path = root / "data"
            path.write_bytes(b"first")
            snapshot = HELPER["Snapshot"](root)
            original = snapshot.read("data")
            path.write_bytes(b"second")
            self.assertEqual(snapshot.read("data"), original)
            with (
                patch.dict(HELPER["Snapshot"].read.__globals__, MAX_BYTES=4),
                self.assertRaises(ValueError),
            ):
                HELPER["Snapshot"](root).read("data")

    def test_snapshot_aggregate_bound_and_cache_hits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            (root / "first").write_bytes(b"first")
            (root / "second").write_bytes(b"next")
            (root / "third").write_bytes(b"x")
            (root / "empty").write_bytes(b"")
            snapshot = HELPER["Snapshot"](root)

            class NoReadFile(io.FileIO):
                def read(self, size: int | None = -1, /) -> bytes:
                    raise AssertionError(
                        "Over-budget file must be rejected before reading"
                    )

            with patch.dict(HELPER["Snapshot"].read.__globals__, MAX_BYTES=9):
                first = snapshot.read("first")
                snapshot.read("second")
                for _ in range(3):
                    self.assertIs(snapshot.read("first"), first)
                    self.assertEqual(
                        snapshot.record("first")["sha256"],
                        hashlib.sha256(first).hexdigest(),
                    )
                snapshot.read("empty")
                self.assertEqual(snapshot.cached_bytes, 9)
                with (
                    patch(
                        "os.fdopen",
                        side_effect=lambda fd, mode, **_: NoReadFile(fd, mode),
                    ),
                    self.assertRaisesRegex(ValueError, "aggregate byte budget"),
                ):
                    snapshot.read("third")
            self.assertEqual(snapshot.cached_bytes, 9)
            self.assertNotIn("third", snapshot.cache)

    def test_growth_after_stat_is_bounded_by_remaining_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            (root / "prefix").write_bytes(b"12345678")
            growing = root / "growing"
            growing.write_bytes(b"x")
            snapshot = HELPER["Snapshot"](root)
            snapshot.read("prefix")
            requested = []

            class RecordingFile(io.FileIO):
                def read(self, size: int | None = -1, /) -> bytes:
                    requested.append(size)
                    data = super().read(size)
                    if data is None:
                        raise AssertionError(
                            "Regular file read unexpectedly would block"
                        )
                    return data

            def recording_open(
                descriptor: int, mode: str, *, buffering: int
            ) -> RecordingFile:
                self.assertEqual(buffering, 0)
                return RecordingFile(descriptor, mode)

            original_stat = os.fstat
            stat_calls = 0

            def grow_after_stat(descriptor: int) -> os.stat_result:
                nonlocal stat_calls
                metadata = original_stat(descriptor)
                stat_calls += 1
                if stat_calls == 1:
                    growing.write_bytes(b"longer than the entire test budget")
                return metadata

            with (
                patch.dict(HELPER["Snapshot"].read.__globals__, MAX_BYTES=10),
                patch("os.fdopen", side_effect=recording_open),
                patch("os.fstat", side_effect=grow_after_stat),
                self.assertRaisesRegex(ValueError, "aggregate byte budget"),
            ):
                snapshot.read("growing")
            self.assertEqual(requested, [3])
            self.assertEqual(snapshot.cached_bytes, 8)
            self.assertNotIn("growing", snapshot.cache)

    def test_one_aggregate_budget_across_snapshot_roots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            for name in ("first", "second"):
                (root / name).mkdir()
                (root / name / "data").write_bytes(b"12345")
            budget = HELPER["SnapshotBudget"]()
            first = HELPER["Snapshot"](root / "first", budget)
            second = HELPER["Snapshot"](root / "second", budget)
            with patch.dict(HELPER["Snapshot"].read.__globals__, MAX_BYTES=9):
                first.read("data")
                first.read("data")
                with self.assertRaisesRegex(ValueError, "aggregate byte budget"):
                    second.read("data")
            self.assertEqual(budget.cached_bytes, 5)
            self.assertEqual(budget.cached_files, 1)
            self.assertEqual(second.cached_bytes, 0)

    def test_file_count_budget_precedes_additional_open(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            (root / "first").write_bytes(b"one")
            (root / "second").write_bytes(b"two")
            snapshot = HELPER["Snapshot"](root)
            with patch.dict(HELPER["Snapshot"].read.__globals__, MAX_FILES=1):
                snapshot.read("first")
                snapshot.read("first")
                with (
                    patch(
                        "os.open",
                        side_effect=AssertionError("Must refuse before opening"),
                    ),
                    self.assertRaisesRegex(ValueError, "file-count budget"),
                ):
                    snapshot.read("second")

    def test_unknown_license_refuses_profile(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            (root / "LICENSE").write_bytes(
                (BUNDLE / "Ghidra/Processors/6502/LICENSE").read_bytes()
            )
            module = root / "Ghidra/Processors/8051"
            module.mkdir(parents=True)
            (module / "LICENSE.txt").write_bytes(b"Unreviewed custom terms")
            with self.assertRaisesRegex(
                ValueError, "8051 rejected: unreviewed module license"
            ):
                HELPER["review_legal"](
                    HELPER["Snapshot"](root), {"Ghidra/Processors/8051/LICENSE.txt"}
                )

    def test_staging_refuses_existing_or_in_source_attempt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            bundle = root / "bundle"
            sdk = root / "sdk"
            attempt = root / "attempt"
            attempt.mkdir()
            with self.assertRaisesRegex(
                ValueError, "Refusing to overwrite admission attempt"
            ):
                HELPER["stage_next"](bundle, sdk, attempt)
            with self.assertRaisesRegex(
                ValueError, "outside the original bundle and SDK"
            ):
                HELPER["stage_next"](bundle, sdk, bundle / "candidate")

    @unittest.skipUnless(
        CANDIDATE, "Set PROCESSOR_ADMISSION_CANDIDATE for staged bundle checks"
    )
    def test_candidate_preserves_pilot_and_does_not_admit_native_backends(self) -> None:
        if CANDIDATE is None:
            self.fail("Candidate path not supplied")
        root = Path(CANDIDATE)
        manifest = HELPER["verify"](root, None)
        original = json.loads((root.parent / "frozen-pilot-manifest.json").read_bytes())
        self.assertEqual(manifest["profiles"][:3], original["profiles"])
        self.assertTrue(all(item in manifest["files"] for item in original["files"]))
        additions = manifest["profiles"][3:]
        self.assertEqual(len(additions), 13)
        self.assertTrue(all(p["native_backend_accepted"] is False for p in additions))
        indexed = {profile["family"]: profile for profile in additions}
        self.assertEqual(indexed["CR16"]["c_pointer_shift"], 1)
        self.assertEqual(indexed["CR16"]["c_pointer_size_bytes"], 4)
        self.assertEqual(indexed["HCS12"]["c_pointer_size_bytes"], 2)
        self.assertEqual(
            next(s for s in indexed["HCS12"]["address_spaces"] if s["default"])[
                "address_size_bytes"
            ],
            3,
        )
        self.assertEqual(
            next(s for s in indexed["PIC"]["address_spaces"] if s["default"])[
                "word_size_bytes"
            ],
            2,
        )
        self.assertIsNone(indexed["Z80"]["c_integer_size_bytes"])
        for family in ("8051", "PIC", "V850", "6805"):
            self.assertIsNone(indexed[family]["c_integer_size_bytes"])
            self.assertIsNone(indexed[family]["c_pointer_size_bytes"])
            self.assertIn("decode_only_unknown", indexed[family]["abi_guard"])

    def test_syntax_closure_uses_one_aggregate_budget(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            source = b'@include "leaf.sinc"\n'
            leaf = b"leaf data"
            (root / "root.slaspec").write_bytes(source)
            (root / "leaf.sinc").write_bytes(leaf)
            for allowance in (len(source) + len(leaf), len(source) + len(leaf) - 1):
                with (
                    self.subTest(allowance=allowance),
                    patch.dict(
                        HELPER["Snapshot"].read.__globals__, MAX_BYTES=allowance
                    ),
                ):
                    snapshot = HELPER["Snapshot"](root)
                    if allowance == len(source) + len(leaf):
                        closure = HELPER["syntax_closure"](snapshot, {"root.slaspec"})
                        self.assertEqual(len(closure), 2)
                        self.assertEqual(snapshot.cached_bytes, allowance)
                    else:
                        with self.assertRaisesRegex(
                            ValueError, "aggregate byte budget"
                        ):
                            HELPER["syntax_closure"](snapshot, {"root.slaspec"})
                        self.assertEqual(snapshot.cached_bytes, len(source))

    def test_inventory_shares_budget_with_application_and_legal_data(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            base = "Ghidra/Processors/Pilot/data/languages"
            files = {
                "Ghidra/application.properties": b"application.version=12.1.4\n",
                "LICENSE": b"legal text",
                f"{base}/pilot.ldefs": (
                    b'<language_definitions><language id="pilot" slafile="pilot.sla"/></language_definitions>'
                ),
                f"{base}/pilot.sla": b"compiled data",
                f"{base}/pilot.slaspec": b"source data",
            }
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            total = sum(len(data) for data in files.values())
            for allowance in (total, total - 1):
                with (
                    self.subTest(allowance=allowance),
                    patch.dict(
                        HELPER["Snapshot"].read.__globals__,
                        MAX_BYTES=allowance,
                        FAMILIES={"Pilot": ["Pilot"]},
                    ),
                ):
                    snapshot = HELPER["Snapshot"](root)
                    snapshot.read("Ghidra/application.properties")
                    snapshot.read("LICENSE")
                    if allowance == total:
                        inventory = HELPER["inventory"](snapshot)
                        self.assertEqual(len(inventory[0]["languages"]), 1)
                        self.assertEqual(snapshot.cached_bytes, total)
                        self.assertEqual(HELPER["inventory"](snapshot), inventory)
                        self.assertEqual(snapshot.cached_bytes, total)
                    else:
                        with self.assertRaisesRegex(
                            ValueError, "aggregate byte budget"
                        ):
                            HELPER["inventory"](snapshot)
                        self.assertNotIn(f"{base}/pilot.slaspec", snapshot.cache)

    def test_include_traversal_and_xml_entities_are_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="processor-admission-") as directory:
            root = Path(directory)
            (root / "root.slaspec").write_text('@include "../escape.sinc"\n')
            with self.assertRaises(ValueError):
                HELPER["syntax_closure"](HELPER["Snapshot"](root), {"root.slaspec"})
        with self.assertRaises(ValueError):
            HELPER["xml"](b'<!DOCTYPE x [<!ENTITY y "expanded">]><x>&y;</x>')

    def copy_bundle(self, root: Path) -> dict[str, Any]:
        manifest = json.loads((BUNDLE / "processor-admission.json").read_text())
        for item in manifest["files"]:
            target = root / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(BUNDLE / item["path"], target)
        shutil.copyfile(
            BUNDLE / "processor-admission.json", root / "processor-admission.json"
        )
        return manifest

    def test_corruption_missing_dependency_and_extra_file_are_refused(self) -> None:
        for mode in ("corrupt", "missing", "extra", "symlink", "profile"):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory(prefix="processor-admission-") as directory,
            ):
                root = Path(directory)
                manifest = self.copy_bundle(root)
                target = root / manifest["profiles"][0]["sla_path"]
                if mode == "corrupt":
                    target.write_bytes(b"not the pinned SLA")
                elif mode == "missing":
                    target.unlink()
                elif mode == "extra":
                    target.with_name("unexpected.sla").write_bytes(b"extra")
                elif mode == "symlink":
                    target.unlink()
                    target.symlink_to("TI_MSP430.pspec")
                else:
                    manifest["profiles"][0]["c_pointer_size_bytes"] = 8
                    (root / "processor-admission.json").write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    HELPER["verify"](root, None)


if __name__ == "__main__":
    unittest.main()
