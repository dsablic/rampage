from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "signature_rust_component",
    Path(__file__).resolve().parents[2] / "tools/signature_rust_component.py",
)
assert SPEC is not None and SPEC.loader is not None
component = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(component)


class ComponentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.archive = self.base / "component.tar.xz"
        self.destination = self.base / "sysroot"
        self.target = "x86_64-unknown-linux-musl"
        self.root = f"rust-std-1.87.0-{self.target}"
        self.member = f"{self.root}/rust-std-{self.target}/lib/rustlib/{self.target}/lib/libstd-owned.rlib"

    def write_archive(
        self, extra: tuple[str, bytes] | None = None, symlink: bool = False
    ) -> str:
        with tarfile.open(self.archive, "w:xz") as output:
            entries = [
                (self.member, b"owned library data"),
                (f"{self.root}/install.sh", b"exit 1\n"),
            ]
            if extra is not None:
                entries.append(extra)
            for name, payload in entries:
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                output.addfile(info, io.BytesIO(payload))
            if symlink:
                info = tarfile.TarInfo(f"{self.root}/link")
                info.type = tarfile.SYMTYPE
                info.linkname = "install.sh"
                output.addfile(info)
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def materialize(self, digest: str) -> dict[str, Any]:
        return component.materialize_component(
            self.archive, digest, "1.87.0", self.target, self.destination
        )

    def test_selects_only_library_data_and_binds_receipt_to_materialized_bytes(
        self,
    ) -> None:
        receipt = self.materialize(self.write_archive())
        relative = f"lib/rustlib/{self.target}/lib/libstd-owned.rlib"
        library = self.destination / relative
        self.assertEqual(library.read_bytes(), b"owned library data")
        self.assertFalse((self.destination / "install.sh").exists())
        self.assertEqual(
            receipt["file_sha256"][relative],
            hashlib.sha256(library.read_bytes()).hexdigest(),
        )
        self.assertFalse(receipt["installer_executed"])
        self.assertEqual(
            json.loads((self.destination / "component-receipt.json").read_text()),
            receipt,
        )
        self.assertEqual(
            component.component_file_hashes(
                self.archive, receipt["archive_sha256"], "1.87.0", self.target
            ),
            receipt["file_sha256"],
        )
        library.write_bytes(b"forged component")
        receipt["file_sha256"][relative] = hashlib.sha256(
            library.read_bytes()
        ).hexdigest()
        self.assertNotEqual(
            component.component_file_hashes(
                self.archive, receipt["archive_sha256"], "1.87.0", self.target
            ),
            receipt["file_sha256"],
        )

    def test_fifo_is_admitted_nonblocking_then_rejected_as_nonregular(self) -> None:
        fifo = self.base / "pipe"
        os.mkfifo(fifo)
        original_open = os.open

        def require_nonblocking(path: Path, flags: int) -> int:
            self.assertTrue(flags & os.O_NONBLOCK)
            return original_open(path, flags)

        with (
            mock.patch.object(component.os, "open", side_effect=require_nonblocking),
            self.assertRaisesRegex(component.ComponentError, "regular file"),
        ):
            component.materialize_component(
                fifo, "a" * 64, "1.87.0", self.target, self.destination
            )
        self.assertFalse(self.destination.exists())

    def test_pax_metadata_is_charged_to_expanded_budget_before_tar_parsing(
        self,
    ) -> None:
        with tarfile.open(self.archive, "w:xz", format=tarfile.PAX_FORMAT) as output:
            info = tarfile.TarInfo(self.member)
            info.pax_headers = {"comment": "x" * 70000}
            info.size = 4
            output.addfile(info, io.BytesIO(b"data"))
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with (
            mock.patch.object(component, "MAX_EXPANDED_BYTES", 32768),
            self.assertRaisesRegex(component.ComponentError, "expanded byte budget"),
        ):
            self.materialize(digest)
        self.assertFalse(self.destination.exists())

    def test_changed_archive_is_rejected_before_materialization(self) -> None:
        digest = self.write_archive()
        self.write_archive((f"{self.root}/unverified", b"changed"))
        with self.assertRaisesRegex(component.ComponentError, "SHA-256 mismatch"):
            self.materialize(digest)
        self.assertFalse(self.destination.exists())

    def test_late_unsafe_paths_and_case_collisions_fail_before_any_write(self) -> None:
        for name in (
            f"{self.root}/../outside",
            self.member.replace("libstd-owned.rlib", "LIBSTD-OWNED.RLIB"),
        ):
            with self.subTest(name=name):
                digest = self.write_archive((name, b"bad"))
                with self.assertRaises(component.ComponentError):
                    self.materialize(digest)
                self.assertFalse(self.destination.exists())

    def test_links_are_rejected_and_existing_outputs_never_overwritten(self) -> None:
        digest = self.write_archive(symlink=True)
        with self.assertRaises(component.ComponentError):
            self.materialize(digest)
        self.destination.mkdir()
        marker = self.destination / "user-data"
        marker.write_bytes(b"preserved")
        with self.assertRaises(component.ComponentError):
            self.materialize(digest)
        self.assertEqual(marker.read_bytes(), b"preserved")
