#!/usr/bin/env python3
"""Build an offline, source-owned signature pilot without executing target code."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import math
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIGURED_SPEC = importlib.util.spec_from_file_location(
    "_signature_configured_driver", ROOT / "tools/signature_configured.py"
)
if CONFIGURED_SPEC is None or CONFIGURED_SPEC.loader is None:
    raise RuntimeError("cannot load the fixed configured-profile driver")
configured = importlib.util.module_from_spec(CONFIGURED_SPEC)
sys.modules[CONFIGURED_SPEC.name] = configured
CONFIGURED_SPEC.loader.exec_module(configured)
MANIFEST = ROOT / "tests/fixtures/signatures/recipes.json"
VERSIONS = {
    "zlib": "1.3.1",
    "lz4": "1.10.0",
    "lua": "5.4.7",
    "sqlite": "3.46.1",
    "zlib-1.2.13": "1.2.13",
    "lz4-1.9.4": "1.9.4",
    "lua-5.4.8": "5.4.8",
    "sqlite-3.45.3": "3.45.3",
    "zstd-1.5.6": "1.5.6",
    "mbedtls-2.28.9": "2.28.9",
    "libpng-1.6.44": "1.6.44",
    "openssl-3.0.15": "3.0.15",
    "curl-8.10.1": "8.10.1",
}
HARNESS_FAMILIES = frozenset(
    ("zlib", "lz4", "lua", "sqlite", "zstd", "mbedtls", "libpng", "openssl", "curl")
)
VERSIONED_FAMILIES = {
    "zlib-1.2.13": "zlib",
    "lz4-1.9.4": "lz4",
    "lua-5.4.8": "lua",
    "sqlite-3.45.3": "sqlite",
    "zstd-1.5.6": "zstd",
    "mbedtls-2.28.9": "mbedtls",
    "libpng-1.6.44": "libpng",
    "openssl-3.0.15": "openssl",
    "curl-8.10.1": "curl",
}
COMMAND_ENVIRONMENT = (
    "ZIG_GLOBAL_CACHE_DIR",
    "ZIG_LOCAL_CACHE_DIR",
    "SOURCE_DATE_EPOCH",
    "LC_ALL",
    "TMPDIR",
    "TZ",
    "CONFIG_SITE",
    "CC",
    "AR",
    "RANLIB",
    "CFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "LIBS",
    "MAKEFLAGS",
    "MFLAGS",
    "PKG_CONFIG",
    "PKG_CONFIG_LIBDIR",
    "PKG_CONFIG_PATH",
    "PERL",
    "CONFIG_SHELL",
)
PNG_HEADER_SOURCE = "scripts/pnglibconf.h.prebuilt"
PNG_HEADER_DESTINATION = "pnglibconf.h"
PNG_DEPENDENCY = "zlib-1.2.13"
PNG_SOURCES = (
    "png.c",
    "pngerror.c",
    "pngget.c",
    "pngmem.c",
    "pngpread.c",
    "pngread.c",
    "pngrio.c",
    "pngrtran.c",
    "pngrutil.c",
    "pngset.c",
    "pngtrans.c",
    "pngwio.c",
    "pngwrite.c",
    "pngwtran.c",
    "pngwutil.c",
)
PNG_SIMD_DEFINES = (
    "PNG_ARM_NEON_OPT=0",
    "PNG_INTEL_SSE_OPT=0",
    "PNG_MIPS_MSA_OPT=0",
    "PNG_MIPS_MMI_OPT=0",
    "PNG_POWERPC_VSX_OPT=0",
    "PNG_LOONGARCH_LSX_OPT=0",
)
TARGETS = (
    "x86_64-linux-musl",
    "aarch64-linux-musl",
    "x86-linux-musl",
    "thumb-linux-musleabi",
    "x86_64-windows-gnu",
)
ARCHES = dict(zip(TARGETS, ("x86_64", "aarch64", "x86", "arm", "x86_64")))


class CorpusError(Exception):
    """An explicit corpus input or producer failure."""


class UnsupportedProfile(CorpusError):
    """Installed producer cannot supply the evidence this exact profile requires."""


@dataclass(frozen=True)
class Selection:
    library: str
    target: str
    optimization: str

    @property
    def name(self) -> str:
        return f"{self.library}-{self.target}-{self.optimization}"


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or not value:
        raise CorpusError(f"unsafe relative recipe/archive path: {value!r}")
    return path


def harness_family(library: str, recipe: dict[str, Any]) -> str:
    family = recipe.get("harness", library)
    expected = VERSIONED_FAMILIES.get(library, library)
    if (
        library not in VERSIONS
        or not isinstance(family, str)
        or family not in HARNESS_FAMILIES
        or family != expected
    ):
        raise CorpusError(f"{library}: unallowlisted harness family {family!r}")
    return family


def archive_root(value: str) -> str:
    if len(relative_path(value).parts) != 1:
        raise CorpusError(
            f"archive root must be a single directory basename: {value!r}"
        )
    return value


def validate_extract_roots(roots: list[str]) -> None:
    if not isinstance(roots, list) or not roots:
        raise CorpusError("extract_roots must be a nonempty list of top-level entries")
    for entry in roots:
        if not isinstance(entry, str) or not entry.strip():
            raise CorpusError("extract_roots entries must be relative top-level names")
        path = relative_path(entry)
        if len(path.parts) != 1 or str(path) != entry:
            raise CorpusError(
                f"extract_roots entry must be a top-level basename: {entry!r}"
            )
    if len(roots) != len(set(roots)):
        raise CorpusError("extract_roots contains duplicate entries")


def recipe_extract_roots(library: str, recipe: dict[str, Any]) -> list[str] | None:
    if "extract_roots" not in recipe:
        return None
    if library != "zstd-1.5.6":
        raise CorpusError(f"{library}: extract_roots is supported only for zstd-1.5.6")
    roots = recipe["extract_roots"]
    validate_extract_roots(roots)
    for required in [recipe["include"], recipe["license_file"], *recipe["sources"]]:
        path = relative_path(required)
        if not path.parts or path.parts[0] not in roots:
            raise CorpusError(
                f"{library}: required recipe path outside extract_roots: {required}"
            )
    return roots


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["schema_version"] != 1 or data["zig_version"] != "0.17.0":
            raise CorpusError("recipe schema 1 and exact Zig 0.17.0 are required")
        if data["targets"] != list(TARGETS) or data["optimizations"] != ["O1", "O2"]:
            raise CorpusError("recipe target/optimization allowlist changed")
        libraries = data["libraries"]
        if set(libraries) != set(VERSIONS):
            raise CorpusError(
                "only the thirteen pinned profiles across nine library families are supported"
            )
        for name, recipe in libraries.items():
            if recipe["version"] != VERSIONS[name]:
                raise CorpusError(f"unallowlisted version for {name}")
            family = harness_family(name, recipe)
            if recipe.get("family", family) != family or recipe.get("id", name) != name:
                raise CorpusError(f"{name}: conflicting profile identity or family")
            if not recipe["url"].startswith("https://"):
                raise CorpusError(f"{name}: source provenance URL must use HTTPS")
            for field in ("archive", "root", "license_file", "include"):
                relative_path(recipe[field])
            archive_root(recipe["root"])
            if len(PurePosixPath(recipe["archive"]).parts) != 1:
                raise CorpusError(f"{name}: archive must be a cache basename")
            sources = recipe["sources"]
            is_configured = validate_configured_recipe(name, recipe)
            if not isinstance(sources, list) or (not sources and not is_configured):
                raise CorpusError(f"{name}: explicit sources must be a nonempty list")
            if len(sources) != len(set(sources)):
                raise CorpusError(f"{name}: empty or duplicate explicit sources")
            for source in sources:
                if relative_path(source).suffix != ".c":
                    raise CorpusError(f"{name}: only explicit C sources are allowed")
            recipe_extract_roots(name, recipe)
            validate_png_recipe(name, recipe)
            if not all(
                re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*(=\w+)?", item)
                for item in recipe["defines"]
            ):
                raise CorpusError(f"{name}: invalid compiler define")
            pin = recipe["sha256"]
            if pin is not None and not re.fullmatch(r"[0-9a-f]{64}", pin):
                raise CorpusError(
                    f"{name}: sha256 must be null or 64 lowercase hex digits"
                )
        return data
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        raise CorpusError(f"invalid recipe manifest {path}: {error}") from error


def validate_configured_recipe(library: str, recipe: dict[str, Any]) -> bool:
    if library not in configured.PINS:
        if "build_driver" in recipe:
            raise CorpusError(
                f"{library}: configured build_driver is restricted to the two fixed profiles"
            )
        return False
    expected = {
        "build_driver": "configured",
        "source_class": "public-source-archive",
        "root": library,
        "archive": f"{library}.tar.gz",
        "sha256": configured.PINS[library],
        "include": "include",
        "sources": [],
        "defines": [],
        "supported_targets": list(configured.TARGETS),
        "license_file": "LICENSE.txt" if library == "openssl-3.0.15" else "COPYING",
        "url": (
            "https://github.com/openssl/openssl/releases/download/openssl-3.0.15/openssl-3.0.15.tar.gz"
            if library == "openssl-3.0.15"
            else "https://curl.se/download/curl-8.10.1.tar.gz"
        ),
    }
    allowed_fields = set(expected) | {
        "id",
        "family",
        "harness",
        "version",
        "license",
        "scope",
        "build_condition",
    }
    if set(recipe) - allowed_fields:
        raise CorpusError(f"{library}: unrecognized configured recipe fields")
    for field, value in expected.items():
        if recipe.get(field) != value:
            raise CorpusError(f"{library}: configured profile requires fixed {field}")
    return True


def validate_png_recipe(library: str, recipe: dict[str, Any]) -> None:
    fields = ("dependency", "header_copy", "license_sha256")
    if library != "libpng-1.6.44":
        if any(field in recipe for field in fields):
            raise CorpusError(f"{library}: PNG-only dependency/header/license fields")
        return
    if recipe.get("dependency") != PNG_DEPENDENCY:
        raise CorpusError(
            "libpng-1.6.44: only the fixed zlib-1.2.13 dependency is supported"
        )
    if recipe["sources"] != list(PNG_SOURCES):
        raise CorpusError(
            "libpng-1.6.44: the complete fixed portable C source list is required"
        )
    copy = recipe.get("header_copy")
    if (
        not isinstance(copy, dict)
        or set(copy) != {"source", "destination", "sha256"}
        or copy["source"] != PNG_HEADER_SOURCE
        or copy["destination"] != PNG_HEADER_DESTINATION
        or not isinstance(copy["sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", copy["sha256"])
    ):
        raise CorpusError("libpng-1.6.44: invalid fixed prebuilt header copy")
    if set(recipe["defines"]) != set(PNG_SIMD_DEFINES):
        raise CorpusError(
            "libpng-1.6.44: all upstream SIMD implementations must be disabled"
        )
    if not isinstance(recipe.get("license_sha256"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", recipe["license_sha256"]
    ):
        raise CorpusError("libpng-1.6.44: raw LICENSE SHA-256 is required")


def copy_png_header(source: Path, recipe: dict[str, Any]) -> dict[str, str]:
    copy = recipe["header_copy"]
    original = source / relative_path(copy["source"])
    destination = source / relative_path(copy["destination"])
    if not original.is_file() or original.is_symlink() or destination.exists():
        raise CorpusError(
            "libpng-1.6.44: missing prebuilt header or existing destination"
        )
    digest = sha256(original)
    if digest != copy["sha256"]:
        raise CorpusError("libpng-1.6.44: prebuilt header SHA-256 mismatch")
    with original.open("rb") as stream, destination.open("xb") as output:
        shutil.copyfileobj(stream, output)
    copied_digest = sha256(destination)
    if copied_digest != digest:
        raise CorpusError("libpng-1.6.44: copied header SHA-256 mismatch")
    return {
        "source": copy["source"],
        "destination": copy["destination"],
        "source_sha256": digest,
        "destination_sha256": copied_digest,
        "method": "byte-for-byte upstream prebuilt copy; no configure or target execution",
    }


def png_zlib_recipe() -> dict[str, Any]:
    return load_manifest()["libraries"][PNG_DEPENDENCY]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--list", action="store_true", help="list the roster; creates no outputs"
    )
    result.add_argument(
        "--only",
        action="append",
        choices=tuple(VERSIONS),
        help="repeatable; default zlib",
    )
    result.add_argument(
        "--target",
        action="append",
        choices=TARGETS,
        help="repeatable; default x86_64-linux-musl",
    )
    result.add_argument(
        "--optimization",
        action="append",
        choices=("O1", "O2"),
        help="repeatable; default O1",
    )
    result.add_argument(
        "--source-cache",
        "--archive-cache",
        dest="archive_cache",
        type=Path,
        help="read-only directory of SHA-pinned source archives",
    )
    result.add_argument(
        "--output-dir",
        type=Path,
        help="new/empty .../target/signature-corpus/RUN directory",
    )
    result.add_argument("--zig", default=os.environ.get("ZIG", "zig"))
    result.add_argument(
        "--diagnostic-limit",
        type=int,
        choices=range(513),
        default=None,
        help="optional collector diagnostic row limit (0 disables rows); otherwise keep collector default",
    )
    result.add_argument(
        "--eval",
        dest="evaluator",
        default=os.environ.get("RAMPAGE_EVAL", str(ROOT / "target/debug/rampage-eval")),
    )
    result.add_argument(
        "--builder",
        default=os.environ.get(
            "RAMPAGE_SIGNATURE_CORPUS",
            str(ROOT / "target/debug/examples/signature_corpus"),
        ),
    )
    return result


def select(args: argparse.Namespace) -> list[Selection]:
    return [
        Selection(library, target, optimization)
        for library in dict.fromkeys(args.only or ["zlib"])
        for target in dict.fromkeys(args.target or [TARGETS[0]])
        for optimization in dict.fromkeys(args.optimization or ["O1"])
    ]


def prepare_output(path: Path) -> Path:
    resolved = path.resolve()
    if (
        resolved.parent.name != "signature-corpus"
        or resolved.parent.parent.name != "target"
    ):
        raise CorpusError("--output-dir must be .../target/signature-corpus/RUN")
    if resolved.is_relative_to(ROOT / "tests") or resolved.is_relative_to(
        ROOT / "crates"
    ):
        raise CorpusError("output must not be inside fixtures or bundled data")
    if resolved.exists() and (not resolved.is_dir() or any(resolved.iterdir())):
        raise CorpusError(f"output is not an empty directory: {resolved}")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def checked_archive(cache: Path, recipe: dict[str, Any]) -> Path:
    pin = recipe["sha256"]
    if pin is None:
        raise CorpusError(
            f"{recipe['archive']}: source SHA-256 pin is pending; no download attempted"
        )
    archive = (cache / recipe["archive"]).resolve()
    if not archive.is_relative_to(cache.resolve()) or not archive.is_file():
        raise CorpusError(
            f"archive is missing or escapes the explicit cache: {archive}"
        )
    archive_snapshot(archive, pin)
    return archive


def archive_snapshot(archive: Path, expected_sha256: str | None) -> bytes:
    """Hash and retain one bounded regular-file descriptor's exact compressed bytes."""
    maximum = 128 * 1024 * 1024
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(archive, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise CorpusError(
                    f"source archive snapshot requires a regular file: {archive}"
                )
            if not 0 <= metadata.st_size <= maximum:
                raise CorpusError(
                    f"compressed source archive exceeds snapshot size bound: {archive}"
                )
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                snapshot = stream.read(maximum + 1)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CorpusError(
            f"cannot snapshot source archive {archive}: {error}"
        ) from error
    if len(snapshot) > maximum:
        raise CorpusError(
            f"compressed source archive exceeds snapshot size bound: {archive}"
        )
    actual = hashlib.sha256(snapshot).hexdigest()
    if expected_sha256 is not None and actual != expected_sha256:
        raise CorpusError(
            f"archive SHA-256 mismatch: {archive}: expected {expected_sha256}, got {actual}"
        )
    return snapshot


def extract_archive(
    archive: Path,
    destination: Path,
    root: str,
    roots: list[str] | None = None,
    *,
    expected_sha256: str | None = None,
) -> Path:
    archive_root(root)
    if roots is not None:
        validate_extract_roots(roots)
    snapshot = archive_snapshot(archive, expected_sha256)
    try:
        with tarfile.open(fileobj=io.BytesIO(snapshot), mode="r:gz") as source:
            members: list[tarfile.TarInfo] = []
            names: set[str] = set()
            folded_names: set[str] = set()
            total = 0
            for member in source:
                path = relative_path(member.name)
                if not path.parts or path.parts[0] != root:
                    raise CorpusError(
                        f"archive contains an unexpected root: {member.name}"
                    )
                normalized = str(path)
                if normalized in names:
                    raise CorpusError(f"duplicate archive member: {member.name}")
                folded_name = normalized.casefold()
                if folded_name in folded_names:
                    raise CorpusError(f"case-colliding archive member: {member.name}")
                names.add(normalized)
                folded_names.add(folded_name)
                if member.size < 0:
                    raise CorpusError(
                        f"archive member has a negative size: {member.name}"
                    )
                total += member.size
                if total > 128 * 1024 * 1024 or len(names) > 10000:
                    raise CorpusError("source archive exceeds bounded extraction size")
                if (
                    roots is not None
                    and len(path.parts) > 1
                    and path.parts[1] not in roots
                ):
                    continue
                if not (member.isdir() or member.isfile()):
                    raise CorpusError(
                        f"archive contains a selected link or special file: {member.name}"
                    )
                members.append(member)
            destination.mkdir()
            for member in members:
                output = destination / member.name
                if member.isdir():
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    stream = source.extractfile(member)
                    if stream is None:
                        raise CorpusError(f"cannot read archive member: {member.name}")
                    with stream, output.open("xb") as target:
                        shutil.copyfileobj(stream, target)
        return destination / root
    except (OSError, tarfile.TarError) as error:
        raise CorpusError(f"cannot extract {archive}: {error}") from error


class Commands:
    def __init__(self, directory: Path, *, clean_environment: bool = False) -> None:
        self.directory = directory
        self.records: list[dict[str, Any]] = []
        self.clean_environment = clean_environment
        self.environment = (
            {"PATH": os.environ.get("PATH", os.defpath)}
            if clean_environment
            else dict(os.environ)
        )
        self.environment.update(
            ZIG_GLOBAL_CACHE_DIR=str(directory / "zig-global-cache"),
            ZIG_LOCAL_CACHE_DIR=str(directory / "zig-local-cache"),
            TMPDIR=str(directory / "tmp"),
            SOURCE_DATE_EPOCH="0",
            LC_ALL="C",
        )

    def configured_environment(self) -> dict[str, str]:
        return {
            "PATH": self.environment.get("PATH", os.defpath),
            "HOME": str(self.directory / "configured-home"),
            "TMPDIR": str(self.directory / "tmp"),
            "ZIG_GLOBAL_CACHE_DIR": str(self.directory / "zig-global-cache"),
            "ZIG_LOCAL_CACHE_DIR": str(self.directory / "zig-local-cache"),
            "LC_ALL": "C",
            "TZ": "UTC",
            "SOURCE_DATE_EPOCH": "0",
            "CONFIG_SITE": "/dev/null",
        }

    def run(
        self,
        argv: list[str],
        output: Path | None = None,
        allowed: tuple[int, ...] = (0,),
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        clean_environment: bool | None = None,
    ) -> str:
        index = len(self.records)
        working_directory = self.directory if cwd is None else cwd
        clean = (
            self.clean_environment if clean_environment is None else clean_environment
        )
        if clean:
            base = self.configured_environment()
            environment = {
                key: value
                for key, value in (env or {}).items()
                if key in configured.CLEAN_ENVIRONMENT_KEYS
            }
            environment.update(base)
        else:
            environment = dict(self.environment)
            environment.update(env or {})
        record: dict[str, Any] = {
            "argv": argv,
            "cwd": str(working_directory),
            "env_policy": "configured-clean-allowlist-v1"
            if clean
            else "legacy-inherited-allowlisted-receipt-v1",
            "environment": {
                key: environment[key]
                for key in (sorted(environment) if clean else COMMAND_ENVIRONMENT)
                if key in environment
            },
        }
        self.records.append(record)
        stdout = self.directory / f"command-{index:03}.stdout"
        stderr = self.directory / f"command-{index:03}.stderr"
        record.update(stdout=stdout.name, stderr=stderr.name)
        try:
            (self.directory / "tmp").mkdir(exist_ok=True)
            if clean:
                (self.directory / "configured-home").mkdir(exist_ok=True)
            with stdout.open("wb") as out_stream, stderr.open("wb") as err_stream:
                completed = subprocess.run(
                    argv,
                    cwd=working_directory,
                    env=environment,
                    stdout=out_stream,
                    stderr=err_stream,
                    check=False,
                )
            record["returncode"] = completed.returncode
            text = stdout.read_text(encoding="utf-8")
            if output is not None:
                output.write_text(text, encoding="utf-8")
            if completed.returncode not in allowed:
                raise CorpusError(
                    f"command failed ({completed.returncode}): {argv!r}; see {stderr}"
                )
            return text
        except OSError as error:
            record["error"] = str(error)
            raise CorpusError(f"cannot run {argv[0]}: {error}") from error
        finally:
            write_json(self.directory / "commands.json", self.records)


def executable(value: str) -> str:
    found = shutil.which(value)
    if found is None:
        raise CorpusError(f"required executable not found: {value}")
    return str(Path(found).resolve())


def freeze_measurement_tool(value: str, destination: Path) -> dict[str, Any]:
    """Capture one regular evaluator/collector binary without consulting its source path again."""
    original = Path(executable(value))
    maximum = 256 * 1024 * 1024
    try:
        descriptor = os.open(
            original, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= maximum
            ):
                raise CorpusError(
                    f"measurement tool must be a nonempty regular file within 256 MiB: {original}"
                )
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                snapshot = stream.read(maximum + 1)
        finally:
            os.close(descriptor)
        if not snapshot or len(snapshot) > maximum:
            raise CorpusError(f"measurement tool snapshot exceeds bounds: {original}")
        digest = hashlib.sha256(snapshot).hexdigest()
        with destination.open("xb") as stream:
            stream.write(snapshot)
        destination.chmod(0o555)
        if sha256(destination) != digest:
            raise CorpusError(
                f"captured measurement tool changed before use: {destination}"
            )
        return {
            "original_path": str(original),
            "original_sha256": digest,
            "path": str(destination.resolve()),
            "sha256": digest,
            "bytes": len(snapshot),
            "policy": "bounded-regular-fd-snapshot-create-new-v1",
        }
    except OSError as error:
        raise CorpusError(
            f"cannot capture measurement tool {original}: {error}"
        ) from error


def inspect(
    commands: Commands,
    evaluator: str,
    artifact: Path,
    target: str,
    stripped: bool = False,
) -> dict[str, Any]:
    metadata = json.loads(commands.run([evaluator, "artifact-info", str(artifact)]))
    write_json(artifact.with_suffix(artifact.suffix + ".info.json"), metadata)
    windows = target == "x86_64-windows-gnu"
    if (
        metadata["format"] != ("pe" if windows else "elf")
        or metadata["arch"] != ARCHES[target]
    ):
        raise CorpusError(
            f"unexpected actual artifact headers for {artifact}: {metadata}"
        )
    if target.startswith("thumb-") and not metadata.get("thumb_ranges", 0):
        raise CorpusError(
            f"Thumb profile has no retained Thumb-mode evidence: {artifact}"
        )
    if not windows and metadata["dynamic_function_symbols"]:
        raise CorpusError(
            f"static corpus artifact retains dynamic function symbols: {artifact}"
        )
    symbols = metadata["static_function_symbols"] + (
        0 if windows else metadata["dynamic_function_symbols"]
    )
    if (stripped and (symbols or metadata["debug_sections"])) or (
        not stripped and not symbols and not windows
    ):
        raise CorpusError(
            f"unexpected symbol/strip metadata for {artifact}: {metadata}"
        )
    return metadata


def _replay_pe_link(
    commands: Commands, zig: str, program: Path, pdb: Path
) -> dict[str, Any]:
    """Replay the just-completed Zig COFF link with explicit library retention policy."""
    compiler_index = len(commands.records) - 1
    compiler = commands.records[compiler_index]
    original_argv = compiler["argv"]
    if (
        original_argv[:2] != [zig, "cc"]
        or "-v" not in original_argv
        or "-o" not in original_argv
        or original_argv[original_argv.index("-o") + 1] != str(program)
        or compiler.get("returncode") != 0
    ):
        raise CorpusError(
            "PE replay requires the successful immediately preceding owned Zig -v link"
        )
    for path in (program, pdb):
        if path.parent.resolve() != commands.directory.resolve():
            raise CorpusError(
                "PE replay may overwrite only its current slice's generated EXE/PDB"
            )
        if not path.exists() and path == pdb:
            raise UnsupportedProfile(
                f"PE producer did not emit the required explicit PDB: {pdb}"
            )
        if (
            path.is_symlink()
            or not path.is_file()
            or not 0 < path.stat().st_size <= 256 * 1024 * 1024
        ):
            raise CorpusError(
                f"PE replay requires bounded regular generated output: {path}"
            )
    stderr = commands.directory / compiler["stderr"]
    if stderr.stat().st_size > 16 * 1024 * 1024:
        raise CorpusError("PE compiler stderr exceeds replay evidence bound")
    candidates: list[list[str]] = []
    for line in stderr.read_text(encoding="utf-8").splitlines():
        if not line.startswith("lld-link "):
            continue
        argv = shlex.split(line)
        if f"-OUT:{program}" in argv:
            candidates.append(argv)
    if not candidates:
        raise CorpusError(
            "PE replay lacks a captured lld-link invocation for the owned output"
        )
    captured = candidates[-1]
    if captured.count(f"-OUT:{program}") != 1 or captured.count(f"-PDB:{pdb}") != 1:
        raise CorpusError("PE replay requires exact unique output EXE and PDB operands")
    before = {"program_sha256": sha256(program), "pdb_sha256": sha256(pdb)}
    replay = [zig, "lld-link", *captured[1:], "-OPT:NOREF", "-OPT:NOICF"]
    commands.run(replay, cwd=Path(compiler["cwd"]))
    receipt = pe_linker_receipt(commands, zig, program, pdb)
    receipt["replay"] = {
        "compiler_command_index": compiler_index,
        "compiler_linker_stderr_sha256": sha256(stderr),
        "captured_linker_argv": captured,
        "argv": replay,
        "cwd": compiler["cwd"],
        "zig_sha256": sha256(Path(zig)),
        "before": before,
        "after": {"program_sha256": sha256(program), "pdb_sha256": sha256(pdb)},
    }
    commands.records[-1]["pe_link_replay"] = receipt["replay"]
    write_json(commands.directory / "commands.json", commands.records)
    return receipt


def pe_linker_receipt(
    commands: Commands, zig: str, program: Path, pdb: Path
) -> dict[str, Any]:
    """Require a successfully executed native Zig lld-link argv, not echoed policy text."""
    if not pdb.exists() and not pdb.is_symlink():
        raise UnsupportedProfile(
            f"PE producer did not emit the required explicit PDB; profile unsupported: {pdb}"
        )
    if (
        not pdb.is_absolute()
        or pdb.is_symlink()
        or not pdb.is_file()
        or not 0 < pdb.stat().st_size <= 256 * 1024 * 1024
    ):
        raise CorpusError(
            f"PE producer did not emit the required regular nonempty PDB: {pdb}"
        )
    record = commands.records[-1]
    stderr = commands.directory / record["stderr"]
    argv = record["argv"]
    if argv[:2] != [zig, "lld-link"] or record.get("returncode") != 0:
        raise CorpusError(
            "PE producer requires a successfully recorded native Zig lld-link replay"
        )
    options = [
        argument.upper().removeprefix("/").removeprefix("-") for argument in argv[2:]
    ]
    if not all(option in options for option in ("DEBUG", "OPT:NOREF", "OPT:NOICF")):
        raise CorpusError(
            "PE producer must attest explicit LLD -DEBUG -OPT:NOREF -OPT:NOICF; no GC/ICF fallback"
        )
    if any(option in options for option in ("OPT:REF", "OPT:ICF")):
        raise CorpusError(
            "PE producer linker receipt also enables GC or ICF; conflicting policy is refused"
        )
    if f"-PDB:{pdb}" not in argv or f"-OUT:{program}" not in argv:
        raise CorpusError(
            "PE verbose linker receipt does not identify the required explicit PDB output path"
        )
    return {
        "path": str(pdb),
        "sha256": sha256(pdb),
        "linker_argv": argv,
        "linker_command": shlex.join(argv),
        "linker_stderr_sha256": sha256(stderr),
        "policy": "CodeView/PDB; explicit LLD NOREF/NOICF; Windows OS DLL imports allowed",
    }


def validate_builder_report(
    report: Any, target: str, returncode: int, artifacts: dict[str, Path]
) -> None:
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise CorpusError("builder report must use schema_version 1")
    if (
        report.get("measurement") != "phase2-1-library-signatures"
        or report.get("arch") != ARCHES[target]
    ):
        raise CorpusError("builder report has the wrong measurement or architecture")
    if (
        type(report.get("passed")) is not bool
        or type(report.get("baseline_available")) is not bool
    ):
        raise CorpusError(
            "builder report requires passed and baseline_available booleans"
        )
    if (
        report.get("target_executed") is not False
        or report.get("load_image_equivalent_stripped_twin") is not True
    ):
        raise CorpusError(
            "builder did not attest a non-executed, load-image-equivalent stripped twin"
        )
    if (
        not isinstance(report.get("ownership_scope"), str)
        or not report["ownership_scope"]
    ):
        raise CorpusError("builder report lacks an explicit ownership scope")
    truth = report.get("library_truth")
    if (
        not isinstance(truth, dict)
        or not truth
        or any(
            not isinstance(address, str)
            or not re.fullmatch(r"0x[0-9a-fA-F]+", address)
            or not isinstance(name, str)
            or not name
            for address, name in truth.items()
        )
    ):
        raise CorpusError("builder report lacks nonempty public-strong library_truth")
    if report.get("truth_functions") != len(truth):
        raise CorpusError("builder truth count differs from library_truth")
    for field in ("baseline", "after"):
        metrics = report.get(field)
        if not isinstance(metrics, dict):
            raise CorpusError(f"builder report lacks {field} metrics")
        for count in ("correct", "wrong", "missed", "spurious"):
            if type(metrics.get(count)) is not int or metrics[count] < 0:
                raise CorpusError(f"invalid {field}.{count} metric")
        for ratio in ("precision", "recall"):
            value = metrics.get(ratio)
            if type(value) not in (int, float) or not 0 <= value <= 1:
                raise CorpusError(f"invalid {field}.{ratio} metric")
        if metrics["correct"] + metrics["wrong"] + metrics["missed"] != len(truth):
            raise CorpusError(f"{field} metrics use a different truth denominator")
        denominators = {
            "recall": metrics["correct"] + metrics["missed"],
            "precision": metrics["correct"] + metrics["wrong"] + metrics["spurious"],
        }
        for ratio, denominator in denominators.items():
            expected = metrics["correct"] / denominator if denominator else 0.0
            if not math.isclose(metrics[ratio], expected, rel_tol=0.0, abs_tol=1e-12):
                raise CorpusError(f"{field}.{ratio} disagrees with its counts")
    after = report["after"]
    recall_denominator = after["correct"] + after["missed"]
    gate_passed = (
        recall_denominator > 0
        and 5 * after["correct"] >= 4 * recall_denominator
        and after["wrong"] == 0
        and after["spurious"] == 0
    )
    if (
        report.get("matched_version_recall_gate") != 0.8
        or report["passed"] != gate_passed
    ):
        raise CorpusError(
            "builder passed flag disagrees with the recall/wrong/spurious gate"
        )
    if returncode != (0 if gate_passed else 1):
        raise CorpusError("builder exit status disagrees with its measurement gate")
    for field, artifact in artifacts.items():
        if report.get(field) != sha256(artifact):
            raise CorpusError(
                f"builder report {field} does not bind the produced artifact"
            )


def build_png_zlib(
    archive: Path,
    recipe: dict[str, Any],
    selection: Selection,
    directory: Path,
    commands: Commands,
    zig: str,
) -> tuple[Path, Path, dict[str, Any]]:
    if (
        recipe["version"] != "1.2.13"
        or harness_family(PNG_DEPENDENCY, recipe) != "zlib"
        or "dependency" in recipe
    ):
        raise CorpusError(
            "PNG zlib dependency must be the fixed nonrecursive 1.2.13 profile"
        )
    source = extract_archive(
        archive,
        directory / "dependency-source",
        recipe["root"],
        expected_sha256=recipe["sha256"],
    )
    flags = [
        "-target",
        selection.target,
        f"-{selection.optimization}",
        "-g0",
        "-fno-lto",
        f"-ffile-prefix-map={directory}=.",
        "-I",
        str(source / recipe["include"]),
        *[f"-D{define}" for define in recipe["defines"]],
    ]
    objects: list[Path] = []
    inputs: dict[str, str] = {}
    for index, filename in enumerate(recipe["sources"]):
        unit = source / relative_path(filename)
        inputs[filename] = sha256(unit)
        obj = directory / f"dependency-zlib-{index:02}.o"
        commands.run([zig, "cc", *flags, "-c", str(unit), "-o", str(obj)])
        objects.append(obj)
    library = directory / "dependency-zlib-1.2.13.a"
    commands.run([zig, "ar", "rcsD", str(library), *map(str, objects)])
    return (
        source / recipe["include"],
        library,
        {
            "id": PNG_DEPENDENCY,
            "recipe": recipe,
            "archive_sha256": recipe["sha256"],
            "license_sha256": sha256(source / recipe["license_file"]),
            "source_sha256": inputs,
            "header_sha256": {
                filename: sha256(source / filename)
                for filename in ("zlib.h", "zconf.h")
            },
            "archive": library.name,
            "archive_output_sha256": sha256(library),
            "objects": [obj.name for obj in objects],
            "ownership": "link/header dependency only; excluded from builder --object inputs",
        },
    )


def build_slice(
    selection: Selection,
    recipe: dict[str, Any],
    args: argparse.Namespace,
    directory: Path,
) -> dict[str, Any]:
    directory.mkdir()
    result: dict[str, Any] = {
        "selection": selection.__dict__,
        "status": "failed",
        "recipe": recipe,
        "link_policy": "full_library_gc_disabled",
    }
    commands = Commands(
        directory, clean_environment=selection.library in configured.PINS
    )
    try:
        family = harness_family(selection.library, recipe)
        is_configured = validate_configured_recipe(selection.library, recipe)
        commands.clean_environment = is_configured
        result["env_policy"] = (
            "configured-clean-allowlist-v1"
            if is_configured
            else "legacy-inherited-allowlisted-receipt-v1"
        )
        validate_png_recipe(selection.library, recipe)
        roots = recipe_extract_roots(selection.library, recipe)
        if roots is not None:
            result["materialization"] = {
                "archive_root": recipe["root"],
                "extract_roots": roots,
                "basis": "explicit recipe top-level entries; unselected members are not materialized",
            }
        if is_configured and selection.target not in configured.TARGETS:
            result.update(
                status="unsupported",
                reason="configured OpenSSL/curl profiles support only Linux x86_64/aarch64 musl; no build attempted",
            )
            return result
        windows = selection.target == "x86_64-windows-gnu"
        if windows:
            result["native_format_policy"] = (
                "PE32+ x64 with explicit identity-matched producer PDBs; static selected library archives, "
                "not a fully static Windows executable: OS DLL imports are allowed"
            )
        archive = checked_archive(args.archive_cache, recipe)
        dependency_recipe = None
        dependency_archive = None
        if family == "libpng":
            dependency_recipe = png_zlib_recipe()
            dependency_archive = checked_archive(args.archive_cache, dependency_recipe)
        zig, evaluator, builder = (
            executable(value) for value in (args.zig, args.evaluator, args.builder)
        )
        result["tools"] = {
            name: {"path": path, "sha256": sha256(Path(path))}
            for name, path in (
                ("zig", zig),
                ("evaluator", evaluator),
                ("builder", builder),
            )
        }
        if (
            getattr(args, "zig_sha256_snapshot", None) is not None
            and result["tools"]["zig"]["sha256"] != args.zig_sha256_snapshot
        ):
            result["tool_identity_valid"] = False
            raise CorpusError(
                "installed Zig binary drifted from the run's captured identity"
            )
        frozen_tools = getattr(args, "measurement_tool_snapshot", {})
        for name in ("evaluator", "builder"):
            if name in frozen_tools:
                tool = result["tools"][name]
                frozen = frozen_tools[name]
                if tool["sha256"] != frozen["sha256"] or Path(
                    tool["path"]
                ).resolve() != Path(frozen["path"]):
                    result["tool_identity_valid"] = False
                    raise CorpusError(
                        f"captured {name} binary drifted before case execution"
                    )
        version = commands.run([zig, "version"]).strip()
        result["zig_version"] = version
        if version != "0.17.0":
            raise CorpusError(f"exact Zig 0.17.0 required, found {version!r}")
        source = extract_archive(
            archive,
            directory / "source",
            recipe["root"],
            roots,
            expected_sha256=recipe["sha256"],
        )
        result["archive_sha256"] = recipe["sha256"]
        result["source_snapshot_policy"] = "bounded-regular-fd-sha256-verified-bytes-v1"
        license_path = source / recipe["license_file"]
        result["license_sha256"] = sha256(license_path)
        dependency_libraries: list[str] = []
        dependency_includes: list[str] = []
        configured_build = None
        if is_configured:
            host_tools = {
                name: Path(executable(name)) for name in ("make", "perl", "sh")
            }
            result["tools"].update(
                {
                    name: {"path": str(path), "sha256": sha256(path)}
                    for name, path in host_tools.items()
                }
            )
            build_triplet = ""
            if family == "curl":
                guess = source / "config.guess"
                result["host_build_triplet"] = {
                    "script": str(guess),
                    "sha256": sha256(guess),
                }
                build_triplet = commands.run(
                    [str(host_tools["sh"]), str(guess)],
                    cwd=source,
                    clean_environment=True,
                ).strip()
                result["host_build_triplet"]["value"] = build_triplet
            configured_build = configured.build_configured_profile(
                configured.ConfiguredContext(
                    library=selection.library,
                    target=selection.target,
                    optimization=selection.optimization,
                    source=source,
                    directory=directory,
                    zig=Path(zig),
                    make=host_tools["make"],
                    perl=host_tools["perl"],
                    shell=host_tools["sh"],
                    build_triplet=build_triplet,
                    verified_archive_sha256=result["archive_sha256"],
                    source_class=recipe["source_class"],
                    environment=commands.configured_environment(),
                    run=commands.run,
                    jobs=1,
                )
            )
            result["configured_build"] = configured_build.provenance
        if family == "libpng":
            if result["license_sha256"] != recipe["license_sha256"]:
                raise CorpusError("libpng-1.6.44: raw LICENSE SHA-256 mismatch")
            result["header_copy"] = copy_png_header(source, recipe)
            if dependency_archive is None or dependency_recipe is None:
                raise CorpusError("libpng-1.6.44: fixed zlib dependency is missing")
            include, dependency_library, dependency = build_png_zlib(
                dependency_archive,
                dependency_recipe,
                selection,
                directory,
                commands,
                zig,
            )
            result["dependency"] = dependency
            dependency_includes = ["-I", str(include)]
            dependency_libraries = [str(dependency_library)]
        include_directories = (
            configured_build.include_directories
            if configured_build is not None
            else (source / recipe["include"],)
        )
        flags = [
            "-target",
            selection.target,
            f"-{selection.optimization}",
            *(["-g", "-gcodeview"] if windows else ["-g0"]),
            "-fno-lto",
            f"-ffile-prefix-map={directory}=.",
            *[
                argument
                for include in include_directories
                for argument in ("-I", str(include))
            ],
            *dependency_includes,
            *[f"-D{define}" for define in recipe["defines"]],
        ]
        if configured_build is not None:
            objects = list(configured_build.objects)
            libraries = list(map(str, configured_build.archives))
            link_flags = list(configured_build.link_flags)
        else:
            objects = []
            inputs: dict[str, str] = {}
            for index, filename in enumerate(recipe["sources"]):
                unit = source / filename
                inputs[filename] = sha256(unit)
                obj = directory / f"library-{index:02}.o"
                commands.run([zig, "cc", *flags, "-c", str(unit), "-o", str(obj)])
                objects.append(obj)
            result["source_sha256"] = inputs
            library = directory / f"lib{selection.library}.a"
            commands.run([zig, "ar", "rcsD", str(library), *map(str, objects)])
            libraries = [str(library)]
            link_flags = []
        programs: dict[str, Path] = {}
        harness_hashes: dict[str, str] = {}
        pdbs: dict[str, Path] = {}
        for role in ("reference", "target"):
            harness = ROOT / f"tests/fixtures/src/signature-{family}-{role}.c"
            harness_hashes[role] = sha256(harness)
            harness_object = directory / f"{role}.o"
            commands.run(
                [zig, "cc", *flags, "-c", str(harness), "-o", str(harness_object)]
            )
            program = directory / f"{role}.{'exe' if windows else 'elf'}"
            if windows:
                pdbs[role] = directory / f"{role}.pdb"
            commands.run(
                [
                    zig,
                    "cc",
                    *flags,
                    "-static",
                    *(["-v"] if windows else ["-no-pie"]),
                    "-Wl,--no-gc-sections",
                    str(harness_object),
                    "-Wl,--whole-archive",
                    *libraries,
                    "-Wl,--no-whole-archive",
                    *dependency_libraries,
                    *link_flags,
                    "-lm",
                    "-o",
                    str(program),
                ]
            )
            if windows:
                result.setdefault("pdb_producer", {})[role] = _replay_pe_link(
                    commands, zig, program, pdbs[role]
                )
            inspect(commands, evaluator, program, selection.target)
            programs[role] = program
        result["harness_sha256"] = harness_hashes
        if sha256(programs["reference"]) == sha256(programs["target"]):
            raise CorpusError("reference and target unexpectedly have identical bytes")
        stripped = directory / f"target.stripped.{'exe' if windows else 'elf'}"
        commands.run(
            [
                evaluator,
                "strip-pe" if windows else "strip",
                str(programs["target"]),
                str(stripped),
            ]
        )
        inspect(commands, evaluator, stripped, selection.target, stripped=True)
        database = directory / "db.json"
        report_path = directory / "builder-report.json"
        builder_command = [
            builder,
            "--reference",
            str(programs["reference"]),
            "--target",
            str(programs["target"]),
            "--stripped",
            str(stripped),
            "--output",
            str(database),
            "--report",
            str(report_path),
        ]
        if windows:
            builder_command.extend(
                ["--pdb", str(pdbs["reference"]), "--target-pdb", str(pdbs["target"])]
            )
        if args.diagnostic_limit is not None:
            builder_command.extend(["--diagnostic-limit", str(args.diagnostic_limit)])
        for obj in objects:
            builder_command.extend(["--object", str(obj)])
        commands.run(builder_command, allowed=(0, 1))
        builder_returncode = commands.records[-1]["returncode"]
        if windows and builder_returncode != 0 and not report_path.exists():
            failure_log = directory / commands.records[-1]["stderr"]
            with failure_log.open("r", encoding="utf-8") as stream:
                failure = stream.read(8192).strip()
            if (
                failure
                == "malformed binary: PDB: conflicting function names at one RVA"
            ):
                raise UnsupportedProfile(
                    "PE PDB producer is unsupported by the captured collector: conflicting function names "
                    "at one RVA; no truth denominator or measurement emitted; "
                    f"see {failure_log}"
                )
        compressed = directory / "db.json.gz"
        for artifact in (database, compressed, report_path):
            if not artifact.is_file() or artifact.stat().st_size == 0:
                raise CorpusError(
                    f"builder did not produce a nonempty required artifact: {artifact}"
                )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        result["builder_report"] = report
        validate_builder_report(
            report,
            selection.target,
            builder_returncode,
            {
                "reference_sha256": programs["reference"],
                "symbolized_target_sha256": programs["target"],
                "stripped_target_sha256": stripped,
                "database_sha256": database,
                "compressed_database_sha256": compressed,
                "evaluator_binary_sha256": Path(builder),
                **(
                    {
                        "reference_pdb_sha256": pdbs["reference"],
                        "target_pdb_sha256": pdbs["target"],
                    }
                    if windows
                    else {}
                ),
            },
        )
        if (
            windows
            and report.get("producer_range_source")
            != "explicit_identity_matched_pdb_procedures"
        ):
            raise CorpusError(
                "PE builder did not attest identity-matched PDB procedure ranges"
            )
        if windows:
            for role, pdb in pdbs.items():
                if sha256(pdb) != result["pdb_producer"][role]["sha256"]:
                    raise CorpusError(f"{role} PDB changed after its producer receipt")
        write_json(directory / "truth.json", report["library_truth"])
        result["ownership_scope"] = (
            "public executable strong COFF library functions with explicit matched PDB sizes; "
            "local/hidden/weak coverage excluded"
            if windows
            else "externally visible strong ELF library functions; local/hidden/weak coverage excluded"
        )
        result["measurements"] = {
            "baseline": {
                "status": "measured",
                "available": report["baseline_available"],
                "evaluation": report["baseline"],
            },
            "new": {
                "status": "measured",
                "evaluation": report["after"],
                "gate_passed": report["passed"],
            },
        }
        result["status"] = "measured" if report["passed"] else "measured_failed"
        return result
    except UnsupportedProfile as error:
        result.update(status="unsupported", reason=str(error))
        return result
    except (
        CorpusError,
        configured.ConfiguredBuildError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        result["reason"] = str(error)
        return result
    finally:
        for name in ("zig", "evaluator", "builder"):
            tool = result.get("tools", {}).get(name)
            if tool is None:
                continue
            try:
                if sha256(Path(tool["path"])) != tool["sha256"]:
                    raise CorpusError(
                        f"{name} binary changed during case execution; measurement refused"
                    )
            except (CorpusError, OSError) as error:
                previous = result.get("reason")
                reason = f"{previous}; {error}" if previous else str(error)
                result.update(status="failed", reason=reason, tool_identity_valid=False)
                if "measurements" in result:
                    result["measurements"]["new"]["status"] = (
                        "invalid_producer_identity"
                    )
        if all(
            name in result.get("tools", {}) for name in ("zig", "evaluator", "builder")
        ):
            result.setdefault("tool_identity_valid", True)
        result["artifacts"] = {
            str(path.relative_to(directory)): sha256(path)
            for path in sorted(directory.iterdir())
            if path.is_file()
        }
        write_json(directory / "result.json", result)


def main(argv: list[str] | None = None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        manifest = load_manifest()
        if args.list:
            for library, recipe in manifest["libraries"].items():
                pin = recipe["sha256"] or "PENDING_SHA256"
                print(f"{library} {recipe['version']} sha256={pin}")
                if "scope" in recipe:
                    print(f"  scope: {recipe['scope']}")
            print(
                f"Roster: {len(HARNESS_FAMILIES)} families, {len(VERSIONS)} profile aliases; "
                "not a broad Phase 2 coverage claim"
            )
            print("targets: " + ", ".join(TARGETS))
            print("optimizations: O1, O2; default pilot: zlib / x86_64-linux-musl / O1")
            print(
                "Windows direct-C: requires CodeView/PDB and explicit LLD NOREF/NOICF receipts; "
                "configured OpenSSL/curl: Linux x64/A64 only"
            )
            print(
                "Roster is future coverage, not a coverage claim; only externally visible strong functions are measured"
            )
            return 0
        if args.output_dir is None or args.archive_cache is None:
            cli.error(
                "--output-dir and --source-cache are required unless --list is used"
            )
        args.archive_cache = args.archive_cache.resolve()
        if not args.archive_cache.is_dir():
            raise CorpusError(
                f"archive cache directory does not exist: {args.archive_cache}"
            )
        output = prepare_output(args.output_dir)
        tools_directory = output / "tools"
        tools_directory.mkdir()
        frozen_tools = {
            "evaluator": freeze_measurement_tool(
                args.evaluator, tools_directory / "eval"
            ),
            "builder": freeze_measurement_tool(
                args.builder, tools_directory / "builder"
            ),
        }
        args.evaluator = frozen_tools["evaluator"]["path"]
        args.builder = frozen_tools["builder"]["path"]
        args.measurement_tool_snapshot = frozen_tools
        args.zig = executable(args.zig)
        args.zig_sha256_snapshot = sha256(Path(args.zig))
        write_json(output / "recipes.json", manifest)
        inventory: dict[str, Any] = {
            "schema_version": 1,
            "phase": "2.1",
            "recipe_manifest_sha256": sha256(MANIFEST),
            "runner_sha256": sha256(Path(__file__)),
            "measurement_tool_snapshot": frozen_tools,
            "installed_zig_identity": {
                "path": args.zig,
                "sha256": args.zig_sha256_snapshot,
                "policy": "installed-relative-stdlib; hash-verified-before-and-after-each-case",
            },
            "target_execution": False,
            "download_attempted": False,
            "link_policy": "full_library_gc_disabled",
            "source_snapshot_policy": "bounded-regular-fd-sha256-verified-bytes-v1",
            "configured_environment_policy": "configured-clean-allowlist-v1",
            "limitations": (
                "Pilot public-strong-function measurements only; local/weak coverage is excluded. "
                "The roster is future coverage; failed/unsupported targets remain explicit. "
                "Disabling linker GC changes the truth denominator; prior GC-enabled runs are not directly comparable. "
                "Historical configured runs without snapshot and clean-environment receipts are pre-hardening "
                "evidence only and cannot establish this runner's hardened producer policy. "
                "Historical runs using mutable measurement-tool paths do not establish run-wide binary identity."
            ),
            "slices": {},
        }
        for selection in select(args):
            recipe = manifest["libraries"][selection.library]
            if "scope" in recipe:
                print(f"{selection.library} scope: {recipe['scope']}", flush=True)
            result = build_slice(
                selection,
                recipe,
                args,
                output / selection.name,
            )
            inventory["slices"][selection.name] = result
            write_json(output / "inventory.json", inventory)
            print(
                f"{selection.name}: {result['status']}"
                + (f": {result['reason']}" if "reason" in result else "")
            )
        return (
            0
            if all(row["status"] == "measured" for row in inventory["slices"].values())
            else 1
        )
    except (CorpusError, OSError) as error:
        print(f"signature-corpus: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
