"""Materialize pinned Rust target-library data without executing component installers."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

TARGETS = frozenset(
    (
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "i686-unknown-linux-musl",
        "x86_64-pc-windows-gnu",
    )
)
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_DECODER_MEMORY = 256 * 1024 * 1024


class ComponentError(Exception):
    """The requested pinned target component could not be materialized."""


def _component_snapshot(archive: Path, expected_sha256: str) -> bytes:
    descriptor = os.open(archive, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE_BYTES:
            raise ComponentError("component archive must be a bounded regular file")
        snapshot = stream.read(MAX_ARCHIVE_BYTES + 1)
    if (
        len(snapshot) != info.st_size
        or hashlib.sha256(snapshot).hexdigest() != expected_sha256
    ):
        raise ComponentError("component archive snapshot length or SHA-256 mismatch")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_DECODER_MEMORY)
    expanded = decoder.decompress(snapshot, max_length=MAX_EXPANDED_BYTES + 1)
    if len(expanded) > MAX_EXPANDED_BYTES or not decoder.eof or decoder.unused_data:
        raise ComponentError(
            "component compressed stream or expanded byte budget exceeded"
        )
    return expanded


def component_file_hashes(
    archive: Path, expected_sha256: str, version: str, target: str
) -> dict[str, str]:
    """Bind target-file hashes to the supplied archive snapshot, not to an editable receipt."""
    snapshot = _component_snapshot(archive, expected_sha256)
    with tarfile.open(fileobj=io.BytesIO(snapshot), mode="r:") as source:
        members = _selected_members(source, version, target)
        hashes = {}
        for member, relative in members:
            payload = source.extractfile(member)
            if payload is None:
                raise ComponentError("component member has no regular payload")
            digest = hashlib.sha256()
            with payload:
                while chunk := payload.read(1024 * 1024):
                    digest.update(chunk)
            hashes[str(relative)] = digest.hexdigest()
        return hashes


def _selected_members(
    source: tarfile.TarFile, version: str, target: str
) -> list[tuple[tarfile.TarInfo, Path]]:
    if target not in TARGETS or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ComponentError(
            "only explicit stable versions and native corpus targets are supported"
        )
    root = f"rust-std-{version}-{target}"
    prefix = PurePosixPath(root) / f"rust-std-{target}"
    selected = []
    seen: set[str] = set()
    expanded = 0
    for member in source:
        path = PurePosixPath(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "\\" in member.name
            or not path.parts
            or path.parts[0] != root
            or any(ord(char) < 32 for char in member.name)
        ):
            raise ComponentError("unsafe component archive path")
        folded = str(path).casefold()
        if folded in seen or len(seen) >= 10000:
            raise ComponentError(
                "duplicate/case-colliding component path or member count exceeded"
            )
        seen.add(folded)
        expanded += member.size
        if member.size < 0 or expanded > MAX_EXPANDED_BYTES:
            raise ComponentError("component expanded byte budget exceeded")
        if not (member.isdir() or member.isfile()):
            raise ComponentError(
                "component archive links and special entries are unsupported"
            )
        if member.isfile() and path.is_relative_to(prefix):
            relative = path.relative_to(prefix)
            if relative.parts[:3] == ("lib", "rustlib", target):
                selected.append((member, Path(*relative.parts)))
    if not selected or not any(path.name.startswith("libstd-") for _, path in selected):
        raise ComponentError("component has no target standard library data")
    return selected


def materialize_component(
    archive: Path,
    expected_sha256: str,
    version: str,
    target: str,
    destination: Path,
) -> dict[str, Any]:
    if target not in TARGETS or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ComponentError(
            "only explicit stable versions and native corpus targets are supported"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ComponentError("an exact component archive SHA-256 is required")
    if (
        destination.exists()
        or destination.is_symlink()
        or destination.resolve() != destination
    ):
        raise ComponentError("component destination must be a new canonical path")
    snapshot = _component_snapshot(archive, expected_sha256)
    with tarfile.open(fileobj=io.BytesIO(snapshot), mode="r:") as source:
        selected = _selected_members(source, version, target)
        hashes: dict[str, str] = {}
        destination.mkdir(parents=True)
        for member, relative in selected:
            output = destination / relative
            payload = source.extractfile(member)
            if payload is None:
                raise ComponentError("component member has no regular payload")
            digest = hashlib.sha256()
            output.parent.mkdir(parents=True, exist_ok=True)
            with payload, output.open("xb") as stream:
                remaining = member.size
                while remaining:
                    chunk = payload.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ComponentError("truncated component payload")
                    stream.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
            hashes[str(output.relative_to(destination))] = digest.hexdigest()
    receipt = {
        "schema_version": 1,
        "source_class": "hash-pinned-rust-target-component",
        "version": version,
        "target": target,
        "archive_sha256": expected_sha256,
        "archive_path": str(archive.resolve()),
        "sysroot": str(destination),
        "file_sha256": hashes,
        "installer_executed": False,
        "target_executed": False,
    }
    with (destination / "component-receipt.json").open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2, sort_keys=True)
        output.write("\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    destination = args.output_dir.absolute()
    root = Path(__file__).resolve().parents[1] / "target"
    if not destination.is_relative_to(root):
        parser.error(
            "component output must be beneath this repository's target directory"
        )
    try:
        receipt = materialize_component(
            args.archive, args.sha256, args.version, args.target, destination
        )
        print(
            f"materialized {len(receipt['file_sha256'])} target-library files; no installer execution"
        )
        return 0
    except (ComponentError, OSError, tarfile.TarError, lzma.LZMAError) as error:
        print(f"Rust target component: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
