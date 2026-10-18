"""Installed-runtime producers. The parent owns scheduling, inspection, truth and stripping."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import lzma
import os
import re
import shlex
import stat
import sys
import tarfile
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

TARGETS = {
    "x86_64-linux-musl": "x86_64-unknown-linux-musl",
    "aarch64-linux-musl": "aarch64-unknown-linux-musl",
    "x86-linux-musl": "i686-unknown-linux-musl",
    "thumb-linux-musleabi": "arm-unknown-linux-musleabi",
    "x86_64-windows-gnu": "x86_64-pc-windows-gnu",
}
PROFILES = frozenset(
    (
        "musl",
        "libc++",
        "libc++abi",
        "libunwind",
        "compiler-runtime",
        "mingw-support",
        "rust-std",
        "rust-core",
    )
)
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 40000
MAX_NATIVE_INPUTS = 20000
MAX_OWNED_MEMBERS = 2048
MAX_OWNED_BYTES = 256 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
GNU_LINK_VALUE_FLAGS = frozenset(
    (
        "-o",
        "-m",
        "-z",
        "-mllvm",
        "--entry",
        "-e",
        "--image-base",
        "--defsym",
        "-u",
        "--undefined",
    )
)
ROOT = Path(__file__).resolve().parents[1]
RUST_COMPONENT_PINS = {
    (
        "1.87.0",
        "x86_64-unknown-linux-musl",
    ): "074f802189975d7c1bf14cf5269c5f0d77b15eee9b319a2e78db7f5397ca4952",
    (
        "1.87.0",
        "aarch64-unknown-linux-musl",
    ): "15fd0652e2f3a8b678be8a83e396a1103fb1bb941afabe3fdaec706f3bdc85d0",
    (
        "1.87.0",
        "i686-unknown-linux-musl",
    ): "cb7bf64656658619918341b2987fd97d7b368308da16f0f923d767d5c60862b0",
    (
        "1.87.0",
        "x86_64-pc-windows-gnu",
    ): "91d2e98d86457477783838032e8c1cdeca74f904e8daf06bd387e78d4d9080fe",
    (
        "1.99.0",
        "x86_64-unknown-linux-musl",
    ): "b106b0aa4565cc3525fd3161c69203a9e39044e6e6b4d618f261c3eeda14ad50",
    (
        "1.99.0",
        "aarch64-unknown-linux-musl",
    ): "ea8fd309578a09c9e12401621a470e6d6b1047f25933207fb8a39d66647d4561",
    (
        "1.99.0",
        "i686-unknown-linux-musl",
    ): "1da985fdbd913b614a1d879af0d296118e08eeafaecde374d2d86725611f8140",
    (
        "1.99.0",
        "x86_64-pc-windows-gnu",
    ): "a2382bf189d5621e09db647da419a8e1d4c604d60941cb116da00ce34042b1dd",
}


class RuntimeBuildError(Exception):
    """An installed producer failed its explicit provenance contract."""


class RuntimeUnsupported(RuntimeBuildError):
    """The selected installed toolchain cannot supply this target/component."""


class RunCommand(Protocol):
    def __call__(self, argv: list[str], *, cwd: Path, env: Mapping[str, str]) -> str:
        """Record argv/cwd/explicit env and combined output; raise on nonzero exit."""
        ...


@dataclass(frozen=True)
class ArchiveMemberReceipt:
    archive_path: str
    archive_sha256: str
    member_ordinal: int
    original_name: str
    object_path: str
    object_sha256: str
    size: int


@dataclass(frozen=True)
class RuntimeContext:
    """Caller selects an EMPTY absolute target/signature-corpus/<run> directory.

    The CLI may reserve only run/tools/{eval,builder} via measurement_tools before
    validation; no compiler logs, caches, outputs or previous work are admitted.

    run is a host-command recorder, never a target executor. The caller serializes
    these producers within its central job budget. zig and optional rustc are
    resolved installed executables, not rustup proxies. No downloads are performed.
    O1/O2 describe harness compilation only, never the prebuilt runtime libraries.
    """

    profile: str
    target: str
    optimization: str
    directory: Path
    zig: Path
    environment: Mapping[str, str]
    run: RunCommand
    rustc: Path | None = None
    owned_member_limit: int | None = None
    require_link_maps: bool = False
    rust_sysroot: Path | None = None
    rust_component_archive: Path | None = None
    measurement_tools: Path | None = None


@dataclass(frozen=True)
class RuntimeBuild:
    archives: tuple[Path, ...]
    objects: tuple[Path, ...]
    reference: Path
    target: Path
    reference_map: Path | None
    target_map: Path | None
    member_receipts: tuple[ArchiveMemberReceipt, ...]
    provenance: dict[str, Any]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular(path: Path, limit: int) -> None:
    try:
        information = path.stat()
    except OSError as error:
        raise RuntimeBuildError(
            f"cannot inspect required regular file: {path}"
        ) from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(information.st_mode)
        or information.st_size > limit
    ):
        raise RuntimeBuildError(f"expected a bounded regular file: {path}")


def _run_root(path: Path) -> None:
    if not path.is_absolute() or path.resolve() != path or not path.is_dir():
        raise RuntimeBuildError(
            "run directory must be an existing absolute directory without symlink components"
        )
    if path.parent.name != "signature-corpus" or path.parent.parent.name != "target":
        raise RuntimeBuildError(
            "run directory must be caller-selected target/signature-corpus/<run>"
        )


def _safe_member_name(name: str) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or len(name) > 4096
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or "\x00" in name
        or any(ord(char) < 32 for char in name)
        or re.match(r"^[A-Za-z]:", name)
    ):
        raise RuntimeBuildError(f"unsafe archive member name: {name!r}")


def _native_object(data: bytes) -> bool:
    if (
        data.startswith(b"\x7fELF")
        and len(data) >= 52
        and data[4] in (1, 2)
        and data[5] in (1, 2)
    ):
        order = "little" if data[5] == 1 else "big"
        return int.from_bytes(data[16:18], order) == 1
    if len(data) >= 20 and int.from_bytes(data[:2], "little") in (
        0x14C,
        0x8664,
        0x1C0,
        0x1C4,
        0xAA64,
    ):
        sections = int.from_bytes(data[2:4], "little")
        return 0 < sections <= 4096 and data[16:18] == b"\0\0"
    return False


def extract_runtime_archive(
    archive: Path,
    destination: Path,
    run_root: Path,
    *,
    select: Callable[[str], bool] | None = None,
    member_limit: int | None = None,
    inventory: dict[str, int] | None = None,
    member_budget: int = MAX_OWNED_MEMBERS,
    byte_budget: int = MAX_OWNED_BYTES,
) -> tuple[ArchiveMemberReceipt, ...]:
    """Bounded regular Unix ar (GNU/BSD), with ordinal isolation and no ar x.

    Ordinals match object 0.40 ArchiveFile::members().enumerate(): leading special
    tables excluded, ordinary members (including Rust metadata) counted from zero.
    Index/name tables and Rust's exact lib.rmeta/rust.metadata.bin are not code inputs.
    Thin archives, malformed variants, unsafe names, nested archives and bitcode-only
    members fail closed. Native-image admission remains the parent's inspector gate.
    """
    _run_root(run_root)
    if not destination.is_absolute() or destination.resolve() != destination:
        raise RuntimeBuildError("extraction destination must not contain symlinks")
    if (
        not destination.is_relative_to(run_root)
        or destination == run_root
        or destination.exists()
    ):
        raise RuntimeBuildError(
            "extraction requires a new destination strictly within the selected run"
        )
    _regular(archive, MAX_ARCHIVE_BYTES)
    archive_sha = _sha256(archive)
    members: list[tuple[int, str, int, int]] = []
    available = 0
    native_count = 0
    selected_bytes = 0
    long_names = b""
    with archive.open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise RuntimeBuildError(
                "only regular Unix ar archives are supported (not thin archives)"
            )
        size = archive.stat().st_size
        header_count = 0
        ordinal = 0
        prefix_tables: list[str] = []
        ordinary_seen = False
        while stream.tell() < size:
            header_count += 1
            if header_count > MAX_MEMBERS:
                raise RuntimeBuildError("archive member count exceeds bound")
            header = stream.read(60)
            if (
                len(header) != 60
                or header[58:] != b"`\n"
                or not header[48:58].strip().isdigit()
            ):
                raise RuntimeBuildError("malformed ar member header")
            member_size = int(header[48:58])
            offset = stream.tell()
            if (
                member_size > MAX_MEMBER_BYTES
                or offset + member_size + (member_size % 2) > size
            ):
                raise RuntimeBuildError("oversized or truncated ar member")
            try:
                raw_name = header[:16].decode("ascii").rstrip()
            except UnicodeDecodeError as error:
                raise RuntimeBuildError("non-ASCII ar header name") from error
            payload_offset, payload_size = offset, member_size
            if raw_name == "//":
                if long_names:
                    raise RuntimeBuildError("duplicate GNU archive name table")
                long_names = stream.read(member_size)
                name = "//"
            elif raw_name.startswith("#1/"):
                if not raw_name[3:].isdigit():
                    raise RuntimeBuildError("invalid BSD extended member name")
                name_size = int(raw_name[3:])
                if not 0 < name_size <= min(member_size, 4096):
                    raise RuntimeBuildError("invalid BSD extended member name length")
                try:
                    encoded_name = stream.read(name_size)
                    name = encoded_name.split(b"\0", 1)[0].decode("utf-8")
                    if b"\0" in encoded_name and encoded_name.split(b"\0", 1)[1].strip(
                        b"\0"
                    ):
                        raise RuntimeBuildError("unsupported nonzero BSD name padding")
                except UnicodeDecodeError as error:
                    raise RuntimeBuildError(
                        "invalid BSD extended member name encoding"
                    ) from error
                payload_offset += name_size
                payload_size -= name_size
            elif re.fullmatch(r"/\d+", raw_name):
                name_offset = int(raw_name[1:])
                if name_offset >= len(long_names) or (
                    name_offset and long_names[name_offset - 1] not in (0, 10)
                ):
                    raise RuntimeBuildError("invalid GNU archive name offset")
                delimiters = [
                    end
                    for end in (
                        long_names.find(b"\n", name_offset),
                        long_names.find(b"\0", name_offset),
                    )
                    if end >= 0
                ]
                if not delimiters:
                    raise RuntimeBuildError("unterminated GNU archive member name")
                end = min(delimiters)
                if long_names[end] == 10:
                    if end == name_offset or long_names[end - 1] != 47:
                        raise RuntimeBuildError(
                            "invalid GNU archive member name terminator"
                        )
                    end -= 1
                try:
                    name = long_names[name_offset:end].decode("utf-8")
                except UnicodeDecodeError as error:
                    raise RuntimeBuildError(
                        "invalid GNU archive name encoding"
                    ) from error
            else:
                name = (
                    raw_name
                    if raw_name.startswith("/")
                    else (
                        raw_name.split("/", 1)[0]
                        if "/" in raw_name
                        else raw_name.split(" ", 1)[0]
                    )
                )
            special = name in (
                "/",
                "/SYM64/",
                "//",
                "__.SYMDEF",
                "__.SYMDEF SORTED",
                "__.SYMDEF_64",
                "__.SYMDEF_64 SORTED",
                "/<ECSYMBOLS>/",
            )
            if special:
                prefix_tables.append(name)
                accepted = {
                    ("/",),
                    ("/", "//"),
                    ("/", "/"),
                    ("/", "/", "//"),
                    ("/", "/", "/<ECSYMBOLS>/"),
                    ("/", "/", "//", "/<ECSYMBOLS>/"),
                    ("/SYM64/",),
                    ("/SYM64/", "//"),
                    ("//",),
                    ("__.SYMDEF",),
                    ("__.SYMDEF SORTED",),
                    ("__.SYMDEF_64",),
                    ("__.SYMDEF_64 SORTED",),
                }
                if ordinary_seen or tuple(prefix_tables) not in accepted:
                    raise RuntimeBuildError(
                        "unsupported special-member placement/order; object-crate ordinal mismatch"
                    )
            else:
                ordinary_seen = True
                _safe_member_name(name)
                stream.seek(payload_offset)
                prefix = stream.read(min(payload_size, 64))
                if _native_object(prefix):
                    native_count += 1
                    if native_count > MAX_NATIVE_INPUTS:
                        raise RuntimeBuildError(
                            "archive native member count exceeds bound"
                        )
                if (
                    name in ("rust.metadata.bin", "lib.rmeta")
                    and archive.suffix == ".rlib"
                ):
                    if prefix.startswith((b"!<arch>\n", b"!<thin>\n")):
                        raise RuntimeBuildError("nested archives are not metadata")
                elif select is not None and not select(name):
                    pass
                elif not _native_object(prefix):
                    raise RuntimeBuildError(
                        f"member is not a native relocatable object: {name}"
                    )
                else:
                    available += 1
                    if member_limit is None or len(members) < member_limit:
                        members.append((ordinal, name, payload_offset, payload_size))
                        selected_bytes += payload_size
                        if len(members) > member_budget or selected_bytes > byte_budget:
                            raise RuntimeUnsupported(
                                "selected owned objects exceed downstream count/byte bounds"
                            )
                ordinal += 1
            stream.seek(offset + member_size)
            if member_size % 2 and stream.read(1) != b"\n":
                raise RuntimeBuildError("invalid ar member padding")
        if inventory is not None:
            inventory["available"] = available
        if not members and select is None:
            raise RuntimeBuildError("archive contains no native objects")
        destination.mkdir(parents=True)
        receipts: list[ArchiveMemberReceipt] = []
        for ordinal, name, offset, payload_size in members:
            member_directory = destination / f"{ordinal:06d}"
            member_directory.mkdir()
            output = member_directory / "member.o"
            stream.seek(offset)
            payload = stream.read(payload_size)
            if len(payload) != payload_size:
                raise RuntimeBuildError("archive changed during extraction")
            with output.open("xb") as writer:
                writer.write(payload)
            receipts.append(
                ArchiveMemberReceipt(
                    str(archive),
                    archive_sha,
                    ordinal,
                    name,
                    str(output),
                    hashlib.sha256(payload).hexdigest(),
                    payload_size,
                )
            )
    if _sha256(archive) != archive_sha:
        raise RuntimeBuildError("archive changed during extraction")
    return tuple(receipts)


def _linker_commands(output: str) -> list[list[str]]:
    if len(output) > 16 * 1024 * 1024:
        raise RuntimeBuildError("link output exceeds bound")
    commands: list[list[str]] = []
    for line in output.splitlines():
        try:
            words = shlex.split(line)
        except ValueError:
            continue
        linker_names = ("ld.lld", "lld", "lld-link", "rust-lld")
        linker_index = 0 if words and Path(words[0]).name in linker_names else None
        if (
            len(words) >= 2
            and Path(words[0]).name == "zig"
            and words[1] in linker_names
        ):
            linker_index = 1
        if linker_index is not None and "-r" not in words[linker_index + 1 :]:
            commands.append(words[linker_index:])
    return commands


def _command_path(value: str, cwd: Path | None) -> Path | None:
    path = Path(value)
    if path.is_absolute():
        return path.resolve()
    return (cwd / path).resolve() if cwd is not None else None


def final_link_argv(output: str, *, cwd: Path, expected_output: Path) -> list[str]:
    """Select the last actual non-relocatable LLD command for this exact recorded output."""
    matching = []
    for words in _linker_commands(output):
        if words.count("-o") != 1 or any(word.startswith("@") for word in words):
            continue
        index = words.index("-o")
        if (
            index + 1 < len(words)
            and _command_path(words[index + 1], cwd) == expected_output.resolve()
        ):
            matching.append(words)
    if not matching:
        raise RuntimeUnsupported(
            "no actual final LLD argv for the exact compiler output; no replay is guessed"
        )
    return matching[-1]


def archives_from_link_output(
    output: str, *, cwd: Path | None = None, expected_output: Path | None = None
) -> tuple[Path, ...]:
    """Resolve actual link-argv inputs against recorded compiler cwd, never the process cwd or cache scans."""
    commands = (
        [final_link_argv(output, cwd=cwd, expected_output=expected_output)]
        if expected_output is not None and cwd is not None
        else _linker_commands(output)
    )
    found: list[Path] = []
    for words in commands:
        if cwd is not None:
            _, _, _, archives = _link_plan(words, cwd, "archive-parser-unmeasured")
            for archive in archives:
                if archive not in found:
                    found.append(archive)
            continue
        if any(word.startswith(("-l", "-L")) for word in words[1:]):
            raise RuntimeUnsupported(
                "library lookup requires the recorded compiler cwd"
            )
        candidates = words[1:]
        for word in candidates:
            if word.startswith("-") or Path(word).suffix not in (".a", ".rlib"):
                continue
            path = _command_path(word, cwd)
            if path is not None and path not in found:
                _regular(path, MAX_ARCHIVE_BYTES)
                found.append(path)
    return tuple(found)


def _zig_lib_dir(output: str) -> Path:
    match = re.search(r'\.lib_dir\s*=\s*"([^"\n]+)"', output)
    if match:
        return Path(match[1]).resolve()
    try:
        return Path(json.loads(output)["lib_dir"]).resolve()
    except (ValueError, KeyError, TypeError) as error:
        raise RuntimeBuildError(
            "cannot identify actual installed Zig lib_dir from zig env"
        ) from error


def _zig_distribution_root(lib: Path, zig: Path) -> Path:
    if lib == zig.parent / "lib":
        return zig.parent
    elif zig.parent.name == "bin" and lib == zig.parent.parent / "lib/zig":
        return zig.parent.parent
    raise RuntimeBuildError(
        "actual Zig lib_dir does not match a supported installed distribution layout"
    )


def _zig_license(lib: Path, zig: Path) -> Path:
    notice = _zig_distribution_root(lib, zig) / "LICENSE"
    _regular(notice, MAX_MEMBER_BYTES)
    return notice


def _source_provenance(lib: Path, zig: Path, profile: str) -> dict[str, Any]:
    _zig_distribution_root(lib, zig)
    component_roots = {
        "musl": ("libc/musl",),
        "mingw-support": ("libc/mingw",),
        "libc++": ("libcxx", "libcxxabi/src", "libcxxabi/include"),
        "libc++abi": ("libcxxabi", "libcxx/src", "libcxx/include"),
        "libunwind": ("libunwind",),
        "compiler-runtime": ("compiler_rt", "compiler_rt.zig"),
    }
    roots = (*component_roots.get(profile, ()), "libc/include", "include")
    hashes: dict[str, str] = {}
    total = 0
    for relative in roots:
        root = lib / relative
        if not root.exists():
            raise RuntimeBuildError(f"installed Zig runtime sources missing: {root}")
        if root.resolve() != root:
            raise RuntimeBuildError(f"runtime source symlink not supported: {root}")
        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in paths:
            if path.is_symlink():
                raise RuntimeBuildError(f"runtime source symlink not supported: {path}")
            if not path.is_file():
                continue
            total += path.stat().st_size
            if len(hashes) >= 100000 or total > MAX_ARCHIVE_BYTES:
                raise RuntimeBuildError(
                    "installed runtime source inventory exceeds bound"
                )
            hashes[str(path.relative_to(lib))] = _sha256(path)
    notices = {
        "musl": lib / "libc/musl/COPYRIGHT",
        "libc++": lib / "libcxx/LICENSE.TXT",
        "libc++abi": lib / "libcxxabi/LICENSE.TXT",
        "libunwind": lib / "libunwind/LICENSE.TXT",
        "mingw-support": lib / "libc/mingw/COPYING",
    }
    if profile == "compiler-runtime":
        notices[profile] = _zig_license(lib, zig)
    return {
        "source_class": "installed-runtime",
        "source_root": str(lib),
        "source_inventory_roots": list(roots),
        "source_inventory_scope": "selected component, source-unit classification and shared installed headers",
        "source_configuration_header_sha256": hashes,
        "configuration_limitations": (
            "Installed sources/headers and actual driver argv are retained. Producer-internal generated "
            "configuration is not independently recovered; archive hashes identify the exact linked artifacts."
        ),
        "original_notices": {
            name: {"path": str(path), "sha256": _sha256(path)}
            for name, path in notices.items()
            if name == profile
        },
        "compiler_runtime_identity": "Zig compiler_rt.zig and compiler_rt sources; NOT LLVM compiler-rt",
        "license_scope": "Original per-component notices apply; MinGW and musl include component-specific terms.",
    }


def _component_members(
    profile: str, archive: Path, receipts: tuple[ArchiveMemberReceipt, ...], lib: Path
) -> tuple[ArchiveMemberReceipt, ...]:
    select = _member_selector(profile, archive, lib)
    return tuple(receipt for receipt in receipts if select(receipt.original_name))


def _selected_archive(profile: str, archive: Path) -> bool:
    if profile.startswith("rust-"):
        return (
            re.fullmatch(rf"lib{profile[5:]}-[0-9a-f]+\.rlib", archive.name) is not None
        )
    names = {
        "musl": ("libc.a",),
        "libc++": ("libc++.a",),
        "libc++abi": ("libc++abi.a", "libc++.a"),
        "libunwind": ("libunwind.a",),
        "compiler-runtime": ("libcompiler_rt.a", "compiler_rt.a"),
        "mingw-support": ("libmingw32.a", "libmingwex.a", "libmsvcrt-os.a"),
    }
    return archive.name in names.get(profile, ())


def _member_selector(profile: str, archive: Path, lib: Path) -> Callable[[str], bool]:
    combined = profile in ("libc++", "libc++abi") and archive.name == "libc++.a"
    family = "libcxx" if profile == "libc++" else "libcxxabi"
    other = "libcxxabi" if family == "libcxx" else "libcxx"
    stems = (
        {path.stem for path in (lib / family / "src").rglob("*.cpp")}
        if combined
        else set()
    )
    ambiguous = (
        {path.stem for path in (lib / other / "src").rglob("*.cpp")}
        if combined
        else set()
    )

    def selected(name: str) -> bool:
        if not _selected_archive(profile, archive):
            return False
        if not combined:
            return True
        original = PurePosixPath(name)
        stem = original.name.removesuffix(".o").removesuffix(".cpp")
        return family in original.parts or (stem in stems and stem not in ambiguous)

    return selected


def _snapshot_file(source: Path, destination: Path, maximum: int) -> dict[str, str]:
    _regular(source, maximum)
    digest = _sha256(source)
    descriptor = os.open(
        source, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    )
    with os.fdopen(descriptor, "rb") as reader:
        metadata = os.fstat(reader.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise RuntimeBuildError(
                f"native link input is not a bounded regular file: {source}"
            )
        total = 0
        with destination.open("xb") as writer:
            while chunk := reader.read(1024 * 1024):
                total += len(chunk)
                if total > maximum:
                    raise RuntimeBuildError(
                        f"native link input exceeds snapshot bound: {source}"
                    )
                writer.write(chunk)
    _regular(destination, maximum)
    if _sha256(destination) != digest or _sha256(source) != digest:
        raise RuntimeBuildError(f"native link input changed while freezing: {source}")
    destination.chmod(0o444)
    return {"original_path": str(source), "path": str(destination), "sha256": digest}


def _native_input_positions(argv: list[str]) -> tuple[int, ...]:
    positions: list[int] = []
    index = 1
    while index < len(argv):
        word = argv[index]
        if word == "-L" or word in GNU_LINK_VALUE_FLAGS:
            index += 2
            continue
        if not word.startswith("-"):
            positions.append(index)
        index += 1
    return tuple(positions)


def _native_link_inputs(argv: list[str], cwd: Path) -> tuple[Path, ...]:
    if any(word.startswith("-l") for word in argv[1:]):
        raise RuntimeUnsupported(
            "resolve captured -l tokens before native input enumeration"
        )
    inputs: list[Path] = []
    for index in _native_input_positions(argv):
        word = argv[index]
        if Path(word).suffix not in (".a", ".rlib", ".o", ".obj"):
            continue
        path = _command_path(word, cwd)
        if path is not None and path not in inputs:
            _regular(
                path,
                MAX_ARCHIVE_BYTES
                if path.suffix in (".a", ".rlib")
                else MAX_MEMBER_BYTES,
            )
            inputs.append(path)
            if len(inputs) > MAX_NATIVE_INPUTS:
                raise RuntimeUnsupported("native link input count exceeds bound")
    return tuple(inputs)


def _admit_link_dependency(path: Path) -> str:
    _regular(path, MAX_ARCHIVE_BYTES)
    with path.open("rb") as stream:
        prefix = stream.read(64)
    if prefix.startswith(b"!<arch>\n"):
        return "archive"
    if _native_object(prefix):
        _regular(path, MAX_MEMBER_BYTES)
        return "object"
    raise RuntimeUnsupported(
        f"link dependency must be a regular native archive/object, not a script/shared image: {path}"
    )


def _resolve_static_libraries(
    argv: list[str], cwd: Path, role: str
) -> tuple[list[str], list[dict[str, Any]]]:
    if len(argv) > 100000 or sum(len(word) for word in argv) > 16 * 1024 * 1024:
        raise RuntimeUnsupported("captured linker argv exceeds resolver bounds")
    directories: list[Path] = []
    directory_indices: set[int] = set()
    flags = {
        "-Bstatic",
        "-Bdynamic",
        "-static",
        "--static",
        "--no-gc-sections",
        "--gc-sections",
        "--eh-frame-hdr",
        "--no-eh-frame-hdr",
        "--as-needed",
        "--no-as-needed",
        "--start-group",
        "--end-group",
        "-(",
        "-)",
        "--whole-archive",
        "--no-whole-archive",
        "--no-undefined",
        "--allow-multiple-definition",
        "--allow-shlib-undefined",
        "--no-allow-shlib-undefined",
        "--export-dynamic",
        "-E",
        "--discard-all",
        "--discard-locals",
        "--discard-none",
        "-s",
        "--strip-all",
        "--strip-debug",
        "-S",
        "--relax",
        "--no-relax",
        "--no-rosegment",
        "--rosegment",
        "--warn-common",
        "--fatal-warnings",
        "--no-fatal-warnings",
        "--warn-unresolved-symbols",
        "--error-unresolved-symbols",
        "--no-undefined-version",
        "--enable-new-dtags",
        "--disable-new-dtags",
        "--no-dynamic-linker",
        "-pie",
        "--pie",
        "--no-pie",
        "-no-pie",
        "--target1-rel",
        "--target1-abs",
        "--execute-only",
        "--fix-cortex-a53-843419",
        "--fix-cortex-a8",
        "--apply-dynamic-relocs",
        "--no-apply-dynamic-relocs",
        "-O0",
        "-O1",
        "-O2",
        "-O3",
        "-znow",
        "-nostdlib",
        "--build-id",
        "--warn-execstack",
        "--no-warn-execstack",
    }
    equals_flags = (
        "--error-limit=",
        "--build-id=",
        "--hash-style=",
        "--compress-debug-sections=",
        "--threads=",
        "--icf=",
        "--image-base=",
        "--entry=",
        "--defsym=",
        "--undefined=",
        "--unresolved-symbols=",
        "--target2=",
        "--pack-dyn-relocs=",
        "--orphan-handling=",
        "--optimize=",
    )
    forbidden = (
        "--sysroot",
        "-sysroot",
        "--script",
        "--default-script",
        "--version-script",
        "--dynamic-list",
        "--library",
        "--library-path",
        "--start-lib",
        "--end-lib",
        "--push-state",
        "--pop-state",
        "--just-symbols",
        "--retain-symbols-file",
        "--symbol-ordering-file",
        "--plugin",
        "-plugin",
        "-T",
        "-R",
    )
    index = 1
    while index < len(argv):
        word = argv[index]
        if word in GNU_LINK_VALUE_FLAGS or word == "-l":
            if index + 1 >= len(argv):
                raise RuntimeUnsupported(
                    f"missing captured linker option value: {word}"
                )
            index += 2
            continue
        if any(word == flag or word.startswith(flag + "=") for flag in forbidden) or (
            word.startswith(("-T", "-R")) and len(word) > 2
        ):
            raise RuntimeUnsupported(f"unsupported implicit linker-input form: {word}")
        if word == "-L" or word.startswith("-L"):
            directory_indices.add(index)
            if word == "-L":
                index += 1
                if index >= len(argv):
                    raise RuntimeUnsupported("missing -L directory")
                directory_indices.add(index)
                value = argv[index]
            else:
                value = word[2:]
            if (
                not value
                or len(value) > 4096
                or value.startswith(("-", "="))
                or "$" in value
            ):
                raise RuntimeUnsupported(
                    "unsupported -L directory/sysroot substitution"
                )
            path = (cwd / value).resolve()
            if not path.is_dir():
                raise RuntimeUnsupported(
                    f"recorded -L directory is unavailable: {path}"
                )
            directories.append(path)
            if len(directories) > 256:
                raise RuntimeUnsupported("library search directory count exceeds bound")
        index += 1
    resolved = [argv[0]]
    evidence: list[dict[str, Any]] = []
    static = False
    index = 1
    while index < len(argv):
        word = argv[index]
        if index in directory_indices:
            resolved.append(word)
            index += 1
            continue
        if word in GNU_LINK_VALUE_FLAGS:
            if index + 1 >= len(argv) or argv[index + 1].startswith("@"):
                raise RuntimeUnsupported(
                    f"missing/unsupported captured linker option value: {word}"
                )
            if word == "-mllvm" and argv[index + 1] not in (
                "-float-abi=hard",
                "-float-abi=soft",
                "-enable-machine-outliner=never",
            ):
                raise RuntimeUnsupported(
                    "unsupported LLVM option in captured native link"
                )
            resolved.extend(argv[index : index + 2])
            index += 2
            continue
        if word in ("-Bstatic", "-static", "--static"):
            static = True
        elif word == "-Bdynamic":
            static = False
        elif word in (
            "-dn",
            "-dy",
            "-non_shared",
            "-call_shared",
            "-shared",
            "--shared",
        ):
            raise RuntimeUnsupported(f"unsupported linker static/dynamic state: {word}")
        elif word.startswith("-B"):
            raise RuntimeUnsupported(f"unsupported linker lookup state: {word}")
        if word == "-l" or word.startswith("-l"):
            start = index
            name = word[2:]
            if word == "-l":
                index += 1
                if index >= len(argv):
                    raise RuntimeUnsupported("missing -l library basename")
                name = argv[index]
            exact = name.startswith(":")
            basename = name[1:] if exact else name
            if (
                not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,254}", basename)
                or ".." in basename
            ):
                raise RuntimeUnsupported("-l requires a safe simple library basename")
            if not static:
                raise RuntimeUnsupported(
                    f"dynamic/default -l lookup is unsupported: {name}"
                )
            filename = basename if exact else f"lib{basename}.a"
            selected = next(
                (
                    directory / filename
                    for directory in directories
                    if (directory / filename).exists()
                    or (directory / filename).is_symlink()
                ),
                None,
            )
            if selected is None:
                raise RuntimeUnsupported(
                    f"static library missing from recorded -L search order: {name}"
                )
            kind = _admit_link_dependency(selected)
            path = selected.resolve()
            digest = _sha256(path)
            evidence.append(
                {
                    "argv_index": start,
                    "argv_count": index - start + 1,
                    "tokens": argv[start : index + 1],
                    "library": name,
                    "search_directories": [str(directory) for directory in directories],
                    "resolved_path": str(path),
                    "sha256": digest,
                    "lookup_mode": "static-exact" if exact else "static-archive",
                    "kind": kind,
                    "discovery_role": role,
                }
            )
            if len(evidence) > MAX_NATIVE_INPUTS:
                raise RuntimeUnsupported("resolved library count exceeds bound")
            resolved.append(str(path))
        else:
            if word.startswith("-"):
                if word not in flags and not word.startswith(equals_flags):
                    raise RuntimeUnsupported(
                        f"unsupported captured GNU linker option: {word}"
                    )
            else:
                if Path(word).suffix not in (".a", ".rlib", ".o", ".obj"):
                    raise RuntimeUnsupported(
                        f"unsupported positional linker input: {word}"
                    )
                _admit_link_dependency((cwd / word).resolve())
            resolved.append(word)
        index += 1
    return resolved, evidence


def _link_plan(
    argv: list[str], cwd: Path, role: str
) -> tuple[list[str], list[dict[str, Any]], tuple[Path, ...], tuple[Path, ...]]:
    resolved, evidence = _resolve_static_libraries(argv, cwd, role)
    inputs = list(_native_link_inputs(resolved, cwd))
    library_archives = set()
    for record in evidence:
        path = Path(record["resolved_path"])
        if path not in inputs:
            inputs.append(path)
        if record["kind"] == "archive":
            library_archives.add(path)
    if len(inputs) > MAX_NATIVE_INPUTS:
        raise RuntimeUnsupported("native link input count exceeds bound")
    archives = tuple(
        path
        for path in inputs
        if path.suffix in (".a", ".rlib") or path in library_archives
    )
    return resolved, evidence, tuple(inputs), archives


def _revalidate_link_inputs(provenance: dict[str, Any]) -> None:
    expected: dict[str, str] = {}
    for record in provenance.get("native_link_input_snapshots", []):
        for key in ("original_path", "path"):
            if expected.setdefault(record[key], record["sha256"]) != record["sha256"]:
                raise RuntimeBuildError(
                    "native input has conflicting recorded fingerprints"
                )
    _revalidate_fingerprints(expected)


def _revalidate_fingerprints(expected: Mapping[str, str]) -> None:
    for value, digest in expected.items():
        path = Path(value)
        _regular(path, MAX_ARCHIVE_BYTES)
        if _sha256(path) != digest:
            raise RuntimeBuildError(
                f"native link input source changed; measurement rejected: {path}"
            )


def _owned_preflight(
    receipts: list[ArchiveMemberReceipt], receipt_path: Path | None = None
) -> str:
    if (
        not 1 <= len(receipts) <= MAX_OWNED_MEMBERS
        or sum(item.size for item in receipts) > MAX_OWNED_BYTES
    ):
        raise RuntimeUnsupported(
            "selected owned objects exceed downstream count/byte bounds"
        )
    encoded = (
        json.dumps([asdict(receipt) for receipt in receipts], indent=2, sort_keys=True)
        + "\n"
    )
    if len(encoded.encode("utf-8")) > MAX_RECEIPT_BYTES:
        raise RuntimeUnsupported("owned member receipts exceed downstream 1 MiB bound")
    if receipt_path is not None:
        _regular(receipt_path, MAX_RECEIPT_BYTES)
        if receipt_path.read_text(encoding="utf-8") != encoded:
            raise RuntimeBuildError(
                "owned member receipt JSON changed before link/publication"
            )
    return encoded


def _harness(profile: str, role: str) -> Path:
    family = (
        "rust"
        if profile.startswith("rust-")
        else ("cpp" if profile in ("libc++", "libc++abi", "libunwind") else "c")
    )
    suffix = {"rust": "rs", "cpp": "cpp", "c": "c"}[family]
    return ROOT / f"tests/fixtures/src/signature-runtime-{family}-{role}.{suffix}"


def _validate_context(context: RuntimeContext) -> None:
    if context.profile not in PROFILES or context.target not in TARGETS:
        raise RuntimeUnsupported(
            "unsupported installed runtime profile/target; Darwin is not an evaluation target"
        )
    if context.optimization not in ("O1", "O2"):
        raise RuntimeBuildError("only harness O1/O2 are supported")
    if context.rust_sysroot is not None and not context.profile.startswith("rust-"):
        raise RuntimeBuildError(
            "--rust-sysroot applies only to explicit Rust std/core profiles"
        )
    if (
        context.owned_member_limit is not None
        and not 1 <= context.owned_member_limit <= MAX_OWNED_MEMBERS
    ):
        raise RuntimeBuildError(
            "explicit owned member limit must be within archive member bounds"
        )
    _run_root(context.directory)
    entries = set(context.directory.iterdir())
    if context.measurement_tools is not None:
        if context.measurement_tools != context.directory / "tools":
            raise RuntimeBuildError(
                "measurement tools must be captured within this run's tools directory"
            )
        if (
            context.measurement_tools.is_symlink()
            or not context.measurement_tools.is_dir()
        ):
            raise RuntimeBuildError("measurement tools directory must be ordinary")
        if {path.name for path in context.measurement_tools.iterdir()} != {
            "eval",
            "builder",
        }:
            raise RuntimeBuildError(
                "measurement tools directory must contain only captured eval/builder"
            )
        for path in context.measurement_tools.iterdir():
            _regular(path, MAX_OWNED_BYTES)
        entries.discard(context.measurement_tools)
    if entries:
        raise RuntimeBuildError(
            "runtime producer requires an empty caller-selected run directory"
        )
    if not context.zig.is_absolute() or context.zig.resolve() != context.zig:
        raise RuntimeBuildError("supply the resolved installed Zig executable")
    _regular(context.zig, MAX_ARCHIVE_BYTES)
    if context.profile == "musl" and "windows" in context.target:
        raise RuntimeUnsupported("musl is not a Windows runtime")
    if context.profile == "mingw-support" and "windows" not in context.target:
        raise RuntimeUnsupported("MinGW support requires a Windows GNU target")


def _component_module() -> Any:
    name = "_signature_runtime_component"
    specification = importlib.util.spec_from_file_location(
        name, ROOT / "tools/signature_rust_component.py"
    )
    if specification is None or specification.loader is None:
        raise RuntimeBuildError("cannot load fixed Rust component snapshot verifier")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _isolated_rust_component(
    context: RuntimeContext, release: str, target: str
) -> dict[str, Any]:
    """Verify an operator-materialized sysroot and receipt; never extract or run installers.

    Consume the parent's signature_rust_component schema verbatim. All component
    files, including self-contained CRT/archive inputs, are checked. Archive pins
    are caller-reviewed hashes, not an independent publisher-authentication claim.
    """
    root = context.rust_sysroot
    if root is None:
        raise RuntimeUnsupported("isolated Rust verification requires --rust-sysroot")
    receipt_path = root / "component-receipt.json"
    if (
        not root.is_absolute()
        or root.resolve() != root
        or not root.is_dir()
        or not any(parent.name == "target" for parent in root.parents)
    ):
        raise RuntimeBuildError(
            "isolated Rust sysroot must be an absolute nonsymlink directory under target"
        )
    _regular(receipt_path, 1024 * 1024)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict):
        raise RuntimeBuildError("Rust component receipt must be a JSON object")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("version") != release
        or receipt.get("target") != target
        or receipt.get("sysroot") != str(root)
        or receipt.get("installer_executed") is not False
        or receipt.get("target_executed") is not False
    ):
        raise RuntimeBuildError(
            "Rust component receipt does not match actual compiler release/sysroot/target"
        )
    pin = RUST_COMPONENT_PINS.get((release, target))
    if pin is None or receipt.get("archive_sha256") != pin:
        raise RuntimeBuildError(
            "Rust component source archive is not the reviewed exact release/target pin"
        )
    libraries = root / "lib/rustlib" / target / "lib"
    actual = sorted(
        path for path in root.rglob("*") if path.is_file() and path != receipt_path
    )
    hashes = receipt.get("file_sha256")
    if (
        not actual
        or len(actual) > MAX_MEMBERS
        or not isinstance(hashes, dict)
        or set(hashes) != {str(path.relative_to(root)) for path in actual}
    ):
        raise RuntimeBuildError(
            "Rust component receipt must inventory every exact-target component file"
        )
    archive = context.rust_component_archive
    if archive is None and isinstance(receipt.get("archive_path"), str):
        archive = Path(receipt["archive_path"])
    if archive is None or not archive.is_absolute():
        raise RuntimeUnsupported(
            "isolated Rust requires --rust-component-archive or an absolute receipt archive_path"
        )
    verifier = _component_module()
    try:
        source_hashes = verifier.component_file_hashes(archive, pin, release, target)
    except (
        verifier.ComponentError,
        OSError,
        ValueError,
        EOFError,
        lzma.LZMAError,
        tarfile.TarError,
    ) as error:
        raise RuntimeBuildError(
            f"cannot bind isolated component to pinned archive bytes: {error}"
        ) from error
    if source_hashes != hashes:
        raise RuntimeBuildError(
            "component receipt file hashes do not match pinned archive payload bytes"
        )
    total = 0
    for path in actual:
        if path.resolve() != path or not path.is_relative_to(libraries):
            raise RuntimeBuildError(
                "isolated Rust component path contains a symlink or another target"
            )
        _regular(path, MAX_ARCHIVE_BYTES)
        total += path.stat().st_size
        if (
            total > 2 * MAX_ARCHIVE_BYTES
            or _sha256(path) != hashes[str(path.relative_to(root))]
        ):
            raise RuntimeBuildError(
                "isolated Rust component bytes exceed bounds or differ from component receipt"
            )
    return {
        "path": str(receipt_path),
        "sha256": _sha256(receipt_path),
        "receipt": receipt,
        "archive_path": str(archive),
        "archive_sha256": pin,
        "snapshot_verifier_sha256": _sha256(ROOT / "tools/signature_rust_component.py"),
        "verification_scope": "pinned bounded archive payload == receipt hashes == all component file bytes",
    }


def _rust_setup(
    context: RuntimeContext, env: Mapping[str, str]
) -> tuple[list[str], dict[str, Any]]:
    rustc = context.rustc
    if (
        rustc is None
        or not rustc.is_absolute()
        or rustc.resolve() != rustc
        or rustc.name != "rustc"
    ):
        raise RuntimeUnsupported(
            "supply an explicit resolved matching installed rustc, not a rustup proxy"
        )
    _regular(rustc, MAX_ARCHIVE_BYTES)
    version = context.run(
        [str(rustc), "--version", "--verbose"], cwd=context.directory, env=env
    )
    installed_sysroot = Path(
        context.run(
            [str(rustc), "--print", "sysroot"], cwd=context.directory, env=env
        ).strip()
    )
    if context.target == "thumb-linux-musleabi":
        raise RuntimeUnsupported(
            "no exact installed Rust Thumb Linux musleabi std target mapping; ARM is not Thumb"
        )
    target = TARGETS[context.target]
    sysroot = context.rust_sysroot or installed_sysroot
    component = None
    if context.rust_sysroot is not None:
        release_match = re.search(r"^release: (\S+)$", version, re.MULTILINE)
        if release_match is None:
            raise RuntimeBuildError(
                "actual rustc verbose version lacks a release for component matching"
            )
        component = _isolated_rust_component(context, release_match[1], target)
    libraries = sysroot / "lib/rustlib" / target / "lib"
    selected = sorted(libraries.glob(f"lib{context.profile[5:]}-*.rlib"))
    if not sysroot.is_absolute() or len(selected) != 1:
        raise RuntimeUnsupported(
            f"operator must install exact {target} std/core component for {rustc}; no host fallback"
        )
    documentation = installed_sysroot / "share/doc/rust"
    notices = [
        documentation / "COPYRIGHT-library.html",
        documentation / "COPYRIGHT.html",
    ]
    notices.extend(sorted((documentation / "licenses").glob("*.txt")))
    installed_notices = {
        str(path): _sha256(path)
        for path in notices
        if path.is_file() and not path.is_symlink()
    }
    if not installed_notices:
        raise RuntimeUnsupported(
            "installed Rust runtime original copyright/license notices are required"
        )
    wrapper = context.directory / "rust-linker"
    _write_rust_linker(context, wrapper, ())
    args = [
        str(rustc),
        "--edition=2021",
        "--target",
        target,
        "-Cpanic=abort",
        "-Clto=off",
        f"-Copt-level={context.optimization[1:]}",
        "-Cdebuginfo=0",
        "-Ccodegen-units=1",
        "-Ctarget-feature=+crt-static",
        "-Clinker-flavor=ld.lld",
        "-Csave-temps=yes",
        f"-Clinker={wrapper}",
        "-Clink-arg=--no-gc-sections",
    ]
    if context.rust_sysroot is not None:
        args.extend(("--sysroot", str(sysroot)))
    return args, {
        "rustc": {
            "path": str(rustc),
            "sha256": _sha256(rustc),
            "version_output": version,
        },
        "sysroot": str(sysroot),
        "exact_component_target": target,
        "compiler_installed_sysroot": str(installed_sysroot),
        "isolated_component_provenance": component,
        "selected_installed_component": str(selected[0]),
        "selected_installed_component_sha256": _sha256(selected[0]),
        "rust_original_notices_sha256": installed_notices,
        "rust_license_scope": "Rust std/core MIT OR Apache-2.0; retain library third-party notices",
        "rust_source_availability": "installed rlib provenance; rust-src is not claimed or required",
        "runtime_optimization": "installed artifact; not inferred from harness optimization",
    }


def _write_rust_linker(
    context: RuntimeContext, path: Path, objects: tuple[Path, ...]
) -> None:
    """Fixed host helper records the exact raw LLD command before exec, never runs target code."""
    executable = str(context.zig)
    owned = [str(obj) for obj in objects]
    log = str(path.with_suffix(".argv.log"))
    with path.open("x", encoding="utf-8") as stream:
        stream.write(
            f"#!{sys.executable}\n"
            "import os\nimport shlex\nimport sys\n"
            "dispatch = sys.argv[1:3] == ['-flavor', 'gnu']\n"
            f"arguments = {owned!r} + (sys.argv[3:] if dispatch else sys.argv[1:])\n"
            f"with open({log!r}, 'a', encoding='utf-8') as stream:\n"
            "    stream.write(shlex.join(['ld.lld', *arguments]) + '\\n')\n"
            f"os.execv({executable!r}, [{executable!r}, 'ld.lld', *arguments])\n"
        )
    path.chmod(0o755)


def _rust_recorded_link_output(compiler: list[str], output: str) -> str:
    linker = next(
        (
            Path(arg.removeprefix("-Clinker="))
            for arg in compiler
            if arg.startswith("-Clinker=")
        ),
        None,
    )
    if linker is None:
        raise RuntimeBuildError("Rust compiler command lacks the fixed producer linker")
    log = linker.with_suffix(".argv.log")
    _regular(log, 16 * 1024 * 1024)
    return output + "\n" + log.read_text(encoding="utf-8")


def _recheck_rust_component(
    context: RuntimeContext, provenance: dict[str, Any]
) -> None:
    if context.rust_sysroot is None:
        return
    initial = provenance["isolated_component_provenance"]
    receipt = initial["receipt"]
    current = _isolated_rust_component(context, receipt["version"], receipt["target"])
    if current["sha256"] != initial["sha256"]:
        raise RuntimeBuildError(
            "isolated Rust component receipt changed during production"
        )


def build_runtime_profile(context: RuntimeContext) -> RuntimeBuild:
    """Discover actual driver link inputs, freeze them, then link identical owned objects twice.

    Parent integration: public-strong stays default. Every measured output uses
    the same installed Zig's embedded ld.lld to replay captured final GNU argv,
    replacing executable/output and dependency paths with checked regular snapshots,
    and appending --icf=none/--no-relax. Maps remain opt-in. Owned receipt paths
    stay unchanged. Original driver links are unmeasured discovery evidence only.
    Never infer weak/hidden ownership from symbol names. Receipt membership alone
    is candidate provenance, not proof that a symbol won the final link. Retain the
    parent's ELF/PE inspection, symbolized/stripped twin and zero-named-truth gates.
    No executable produced here is ever run. No automatic whole-link failure fallback.
    """
    _validate_context(context)
    env = dict(context.environment)
    env.update(LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="0")
    version = context.run([str(context.zig), "version"], cwd=context.directory, env=env)
    if version.strip() != "0.17.0":
        raise RuntimeUnsupported(
            f"installed runtime driver requires Zig 0.17.0, found {version.strip()!r}"
        )
    zig_env = context.run([str(context.zig), "env"], cwd=context.directory, env=env)
    lib = _zig_lib_dir(zig_env)
    provenance = _source_provenance(lib, context.zig, context.profile)
    provenance.update(
        profile=context.profile,
        target=context.target,
        harness_optimization=context.optimization,
        runtime_optimization="Zig installed-driver policy, NOT harness O1/O2",
        zig={
            "path": str(context.zig),
            "sha256": _sha256(context.zig),
            "version_output": version,
        },
        host_target_execution=False,
        zig_env_output=zig_env,
    )
    lld_version = context.run(
        [str(context.zig), "ld.lld", "--version"], cwd=context.directory, env=env
    )
    if not re.search(r"\bLLD\s*22\.1\.8\b", lld_version):
        raise RuntimeUnsupported(
            "native replay requires the installed Zig's embedded LLD 22.1.8"
        )
    provenance["embedded_lld"] = {
        "path": str(context.zig),
        "sha256": _sha256(context.zig),
        "subcommand": "ld.lld",
        "version_output": lld_version,
    }
    rust = context.profile.startswith("rust-")
    if rust:
        compiler, rust_provenance = _rust_setup(context, env)
        provenance.update(rust_provenance)
    else:
        driver = (
            "c++" if context.profile in ("libc++", "libc++abi", "libunwind") else "cc"
        )
        compiler = [
            str(context.zig),
            driver,
            "-target",
            context.target,
            f"-{context.optimization}",
            "-g0",
            "-fno-lto",
            "-static",
            "-v",
            "-Wl,--no-gc-sections",
        ]
        if driver == "cc":
            compiler.extend(("-fno-builtin", "-lm"))
    extension = ".exe" if "windows" in context.target else ""
    discovery = context.directory / f"discovery{extension}"
    reference_source = _harness(context.profile, "reference")
    target_source = _harness(context.profile, "target")
    discovery_output = context.run(
        [*compiler, str(reference_source), "-o", str(discovery)],
        cwd=context.directory,
        env=env,
    )
    if rust:
        discovery_output = _rust_recorded_link_output(compiler, discovery_output)
    discovery_captured = final_link_argv(
        discovery_output, cwd=context.directory, expected_output=discovery
    )
    _, discovery_libraries, discovery_inputs, observed = _link_plan(
        discovery_captured, context.directory, "discovery-unmeasured"
    )
    if not observed:
        raise RuntimeUnsupported(
            "driver emitted no explicit archive paths in actual final linker argv"
        )
    if rust and Path(provenance["selected_installed_component"]) not in observed:
        raise RuntimeBuildError(
            "actual Rust link did not use the exact selected installed target component"
        )
    frozen_directory = context.directory / "frozen"
    frozen_directory.mkdir()
    receipts: list[ArchiveMemberReceipt] = []
    frozen: list[Path] = []
    dependency_records: list[dict[str, str]] = []
    frozen_records: list[dict[str, str]] = []
    available_member_count = 0
    for ordinal, archive in enumerate(observed):
        digest = _sha256(archive)
        dependency_records.append({"path": str(archive), "sha256": digest})
        if not _selected_archive(context.profile, archive):
            continue
        archive_directory = frozen_directory / f"{ordinal:04d}"
        archive_directory.mkdir()
        copy = archive_directory / archive.name
        _snapshot_file(archive, copy, MAX_ARCHIVE_BYTES)
        inventory: dict[str, int] = {}
        remaining = (
            context.owned_member_limit - len(receipts)
            if context.owned_member_limit is not None
            else None
        )
        owned = extract_runtime_archive(
            copy,
            archive_directory / "objects",
            context.directory,
            select=_member_selector(context.profile, archive, lib),
            member_limit=remaining,
            inventory=inventory,
            member_budget=MAX_OWNED_MEMBERS - len(receipts),
            byte_budget=MAX_OWNED_BYTES - sum(receipt.size for receipt in receipts),
        )
        available_member_count += inventory["available"]
        if owned:
            frozen.append(copy)
            receipts.extend(owned)
            frozen_records.append(
                {
                    "original_path": str(archive),
                    "frozen_path": str(copy),
                    "sha256": digest,
                }
            )
    if not receipts:
        raise RuntimeUnsupported(
            "actual link inputs contain no unambiguous native member provenance for this component"
        )
    receipt_json = _owned_preflight(receipts)
    (context.directory / "archive-member-receipts.json").write_text(
        receipt_json, encoding="utf-8"
    )
    objects = tuple(Path(receipt.object_path) for receipt in receipts)
    if rust:
        owned_linker = context.directory / "rust-owned-linker"
        _write_rust_linker(context, owned_linker, objects)
        compiler = [
            f"-Clinker={owned_linker}" if arg.startswith("-Clinker=") else arg
            for arg in compiler
        ]
        provenance["rust_owned_linker"] = {
            "path": str(owned_linker),
            "sha256": _sha256(owned_linker),
            "input_order": "explicit owned objects before rustc archive dependencies",
        }
        provenance["rust_linker_host_helper"] = {
            "path": sys.executable,
            "sha256": _sha256(Path(sys.executable).resolve()),
        }
    provenance.update(
        actual_discovery_link_output=discovery_output,
        discovery_native_inputs=[
            {"path": str(path), "sha256": _sha256(path), "measured": False}
            for path in discovery_inputs
        ],
        discovery_library_search=discovery_libraries,
        link_dependencies=dependency_records,
        native_link_input_snapshots=[],
        frozen_archives=frozen_records,
        archive_member_receipts=[asdict(receipt) for receipt in receipts],
        available_component_native_members=available_member_count,
        selected_component_native_members=len(receipts),
        operator_selected_member_limit=context.owned_member_limit,
        member_ordinal_basis="object 0.40 ArchiveFile::members().enumerate(): zero-based; includes Rust metadata",
        coverage="explicit-native-member-subset; not full SDK/runtime coverage",
        ownership=(
            "candidate member provenance plus actual LLVM final maps; winning-object adapter required"
            if context.require_link_maps
            else "public-strong only; weak/hidden attribution excluded"
        ),
        link_retention="every selected frozen native object is an explicit input; GC explicitly disabled",
        icf_policy="Every measured output uses embedded LLD replay with --icf=none and --no-relax",
        measured_output_policy="snapshot-backed native replay only; original Zig links are unmeasured discovery",
        dependency_scope="unselected runtime archives/rlibs are dependencies, not owned signature inputs",
        harness_sha256={
            "reference": _sha256(reference_source),
            "target": _sha256(target_source),
        },
    )
    outputs: dict[str, Path] = {}
    maps: dict[str, Path | None] = {}
    snapshot_directory = context.directory / "link-inputs"
    snapshot_directory.mkdir()
    shared_snapshots: dict[Path, dict[str, str]] = {}
    for role, source in (("reference", reference_source), ("target", target_source)):
        _owned_preflight(receipts, context.directory / "archive-member-receipts.json")
        _revalidate_link_inputs(provenance)
        for record in dependency_records:
            if _sha256(Path(record["path"])) != record["sha256"]:
                raise RuntimeBuildError(
                    "runtime dependency differs from discovery link"
                )
        _recheck_rust_component(context, provenance)
        output = context.directory / f"{role}{extension}"
        compiler_output = context.directory / f"{role}.zig-link{extension}"
        object_args = [] if rust else [str(path) for path in objects]
        argv = [*compiler, str(source), *object_args, "-o", str(compiler_output)]
        link_output = context.run(argv, cwd=context.directory, env=env)
        if rust:
            link_output = _rust_recorded_link_output(compiler, link_output)
        _regular(compiler_output, MAX_ARCHIVE_BYTES)
        captured = final_link_argv(
            link_output, cwd=context.directory, expected_output=compiler_output
        )
        resolved, library_search, native_inputs, final_dependencies = _link_plan(
            captured, context.directory, f"{role}-driver-unmeasured"
        )
        if not final_dependencies:
            raise RuntimeBuildError(
                "final link emitted no archive dependency provenance"
            )
        discovery_hashes = {
            record["path"]: record["sha256"] for record in dependency_records
        }
        for dependency in final_dependencies:
            if (
                str(dependency) not in discovery_hashes
                or _sha256(dependency) != discovery_hashes[str(dependency)]
            ):
                raise RuntimeBuildError(
                    f"runtime dependency differs from discovery link: {dependency}"
                )
        provenance[f"{role}_link_output"] = link_output
        snapshots: list[dict[str, str]] = []
        for path in native_inputs:
            if path not in shared_snapshots:
                record = (
                    {
                        "original_path": str(path),
                        "path": str(path),
                        "sha256": _sha256(path),
                    }
                    if path in objects
                    else _snapshot_file(
                        path,
                        snapshot_directory
                        / f"{len(shared_snapshots):05d}{path.suffix}",
                        MAX_ARCHIVE_BYTES
                        if path in final_dependencies
                        else MAX_MEMBER_BYTES,
                    )
                )
                record["discovery_role"] = f"{role}-driver-unmeasured"
                shared_snapshots[path] = record
                provenance["native_link_input_snapshots"].append(record)
            snapshots.append(shared_snapshots[path])
        for record in snapshots:
            record["consumed_path"] = record["path"]
            record["consumed_sha256"] = record["sha256"]
        provenance[f"{role}_native_link_inputs"] = snapshots
        for record in library_search:
            snapshot = shared_snapshots[Path(record["resolved_path"])]
            if record["sha256"] != snapshot["sha256"]:
                raise RuntimeBuildError(
                    "resolved static library changed before native replay"
                )
            record.update(
                consumed_path=snapshot["path"], consumed_sha256=snapshot["sha256"]
            )
        provenance[f"{role}_library_search"] = library_search
        if Path(captured[0]).name != "ld.lld":
            raise RuntimeUnsupported(
                "embedded ELF replay requires an actual captured ld.lld invocation"
            )
        if any(obj not in native_inputs for obj in objects):
            raise RuntimeBuildError(
                "captured final linker argv omits an explicit owned object"
            )
        link_map = (
            context.directory / f"{role}.map" if context.require_link_maps else None
        )
        replay = [str(context.zig), "ld.lld", *resolved[1:]]
        replay[replay.index("-o") + 1] = str(output)
        replacements = {record["original_path"]: record["path"] for record in snapshots}
        for index in _native_input_positions(resolved):
            word = resolved[index]
            path = _command_path(word, context.directory)
            if path is not None and str(path) in replacements:
                replay[index + 1] = replacements[str(path)]
        replay.extend(("--icf=none", "--no-relax"))
        if link_map is not None:
            replay.append(f"-Map={link_map}")
        zig_hash = _sha256(compiler_output)
        _recheck_rust_component(context, provenance)
        _owned_preflight(receipts, context.directory / "archive-member-receipts.json")
        _revalidate_link_inputs(provenance)
        before = {
            record["consumed_path"]: _sha256(Path(record["consumed_path"]))
            for record in snapshots
        }
        replay_output = context.run(replay, cwd=context.directory, env=env)
        _revalidate_link_inputs(provenance)
        after = {
            record["consumed_path"]: _sha256(Path(record["consumed_path"]))
            for record in snapshots
        }
        _regular(output, MAX_ARCHIVE_BYTES)
        if link_map is not None:
            _regular(link_map, MAX_ARCHIVE_BYTES)
        provenance[f"{role}_embedded_lld_replay"] = {
            "captured_argv": captured,
            "resolved_static_argv": resolved,
            "replay_argv": replay,
            "cwd": str(context.directory),
            "zig_link_path": str(compiler_output),
            "zig_link_sha256": zig_hash,
            "zig_link_measured": False,
            "final_path": str(output),
            "final_sha256": _sha256(output),
            "final_measured": True,
            "replay_output": replay_output,
            "native_input_sha256_before": before,
            "native_input_sha256_after": after,
        }
        provenance[f"{role}_link_map"] = (
            {"path": str(link_map), "sha256": _sha256(link_map)} if link_map else None
        )
        maps[role] = link_map
        outputs[role] = output
    for receipt in receipts:
        if _sha256(Path(receipt.object_path)) != receipt.object_sha256:
            raise RuntimeBuildError("frozen owned object changed between links")
    _recheck_rust_component(context, provenance)
    _revalidate_link_inputs(provenance)
    for record in dependency_records:
        if _sha256(Path(record["path"])) != record["sha256"]:
            raise RuntimeBuildError("runtime dependency differs from discovery link")
    if _sha256(context.zig) != provenance["embedded_lld"]["sha256"]:
        raise RuntimeBuildError(
            "installed Zig/embedded LLD executable changed during production"
        )
    with (context.directory / "runtime-provenance.json").open(
        "x", encoding="utf-8"
    ) as stream:
        json.dump(provenance, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return RuntimeBuild(
        tuple(frozen),
        objects,
        outputs["reference"],
        outputs["target"],
        maps["reference"],
        maps["target"],
        tuple(receipts),
        provenance,
    )


def _corpus_module() -> Any:
    name = "_signature_runtime_parent"
    specification = importlib.util.spec_from_file_location(
        name, ROOT / "tools/signature-corpus.py"
    )
    if specification is None or specification.loader is None:
        raise RuntimeBuildError("cannot load fixed parent corpus helpers")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def _revalidate_runtime(built: RuntimeBuild) -> None:
    if built.member_receipts:
        _owned_preflight(
            list(built.member_receipts),
            built.reference.parent / "archive-member-receipts.json",
        )
    _revalidate_link_inputs(built.provenance)
    expected: dict[str, str] = {}
    for record in built.provenance["link_dependencies"]:
        expected[record["path"]] = record["sha256"]
    for receipt in built.member_receipts:
        for path, digest in (
            (receipt.object_path, receipt.object_sha256),
            (receipt.archive_path, receipt.archive_sha256),
        ):
            if expected.setdefault(path, digest) != digest:
                raise RuntimeBuildError(
                    "owned input has conflicting recorded fingerprints"
                )
    _revalidate_fingerprints(expected)


def _revalidate_measurement_tools(snapshots: dict[str, Any]) -> None:
    for record in snapshots.values():
        path = Path(record["path"])
        _regular(path, MAX_OWNED_BYTES)
        if _sha256(path) != record["sha256"]:
            raise RuntimeBuildError(f"captured measurement tool changed: {path}")


def main(argv: list[str] | None = None) -> int:
    """Single-slice CLI reusing parent command recording and ELF measurement gates."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--optimization", choices=("O1", "O2"), default="O2")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--zig", default="zig")
    parser.add_argument("--rustc")
    parser.add_argument("--rust-sysroot", type=Path)
    parser.add_argument("--rust-component-archive", type=Path)
    parser.add_argument(
        "--owned-member-limit",
        type=int,
        help="explicit ordinal-prefix subset; never claimed as full runtime coverage",
    )
    parser.add_argument("--eval", dest="evaluator", required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument(
        "--ownership-scope",
        choices=("public-strong", "linked-artifact"),
        default="public-strong",
    )
    args = parser.parse_args(argv)
    directory = args.output_dir.absolute()
    directory.mkdir(parents=True, exist_ok=True)
    _run_root(directory)
    if any(directory.iterdir()):
        parser.error("--output-dir must be empty; existing work is never overwritten")
    corpus = _corpus_module()
    commands = corpus.Commands(directory, clean_environment=True)
    result: dict[str, Any] = {
        "schema_version": 1,
        "source_class": "installed-runtime",
        "profile": args.profile,
        "target": args.target,
        "harness_optimization": args.optimization,
        "target_executed": False,
        "status": "unsupported",
        "ownership_scope": args.ownership_scope,
        "inventory": {
            "requested_zig": args.zig,
            "requested_rustc": args.rustc,
            "component_policy": "exact installed target only; no installers, downloads or Darwin fallback",
        },
    }

    def combined(argv: list[str], *, cwd: Path, env: Mapping[str, str]) -> str:
        stdout = commands.run(argv, cwd=cwd, env=env)
        record = commands.records[-1]
        stderr_path = directory / record["stderr"]
        _regular(stderr_path, 16 * 1024 * 1024)
        return stdout + "\n" + stderr_path.read_text(encoding="utf-8")

    frozen_tools: dict[str, Any] = {}
    result["measurement_tool_snapshot"] = frozen_tools
    exit_code = 1
    built: RuntimeBuild | None = None
    context: RuntimeContext | None = None
    try:
        tools_directory = directory / "tools"
        tools_directory.mkdir()
        for name, requested in (
            ("evaluator", args.evaluator),
            ("builder", args.builder),
        ):
            frozen_tools[name] = corpus.freeze_measurement_tool(
                requested,
                tools_directory / ("eval" if name == "evaluator" else "builder"),
            )
        zig = Path(corpus.executable(args.zig))
        rustc = Path(corpus.executable(args.rustc)) if args.rustc else None
        rust_sysroot = args.rust_sysroot.absolute() if args.rust_sysroot else None
        component_archive = (
            args.rust_component_archive.absolute()
            if args.rust_component_archive
            else None
        )
        evaluator, builder = (
            frozen_tools["evaluator"]["path"],
            frozen_tools["builder"]["path"],
        )
        result["inventory"].update(
            zig=str(zig),
            rustc=str(rustc) if rustc else None,
            evaluator=evaluator,
            builder=builder,
            rust_sysroot=str(rust_sysroot) if rust_sysroot else None,
        )
        if "windows" in args.target:
            raise RuntimeUnsupported(
                "PE/PDB runtime evaluation needs parent Windows driver integration; no ELF spoof"
            )
        environment = commands.configured_environment()
        context = RuntimeContext(
            args.profile,
            args.target,
            args.optimization,
            directory,
            zig,
            environment,
            combined,
            rustc,
            args.owned_member_limit,
            args.ownership_scope == "linked-artifact",
            rust_sysroot,
            component_archive,
            tools_directory,
        )
        built = build_runtime_profile(context)
        result["runtime_provenance"] = built.provenance
        corpus.inspect(commands, evaluator, built.reference, args.target)
        corpus.inspect(commands, evaluator, built.target, args.target)
        if _sha256(built.reference) == _sha256(built.target):
            raise RuntimeBuildError(
                "reference and target unexpectedly have identical bytes"
            )
        stripped = directory / "target.stripped.elf"
        commands.run([evaluator, "strip", str(built.target), str(stripped)])
        corpus.inspect(commands, evaluator, stripped, args.target, stripped=True)
        database, report_path = directory / "db.json", directory / "builder-report.json"
        builder_argv = [
            builder,
            "--reference",
            str(built.reference),
            "--target",
            str(built.target),
            "--stripped",
            str(stripped),
            "--output",
            str(database),
            "--report",
            str(report_path),
        ]
        for obj in built.objects:
            builder_argv.extend(("--object", str(obj)))
        if args.ownership_scope == "linked-artifact":
            if built.reference_map is None or built.target_map is None:
                raise RuntimeUnsupported(
                    "linked-artifact ownership requires actual producer link maps"
                )
            builder_argv.extend(
                (
                    "--ownership-scope",
                    "linked-artifact",
                    "--reference-map",
                    str(built.reference_map),
                    "--target-map",
                    str(built.target_map),
                    "--member-receipts",
                    str(directory / "archive-member-receipts.json"),
                )
            )
        commands.run(builder_argv, allowed=(0, 1))
        returncode = commands.records[-1]["returncode"]
        compressed = directory / "db.json.gz"
        for artifact in (database, compressed, report_path):
            _regular(artifact, MAX_ARCHIVE_BYTES)
            if artifact.stat().st_size == 0:
                raise RuntimeBuildError(f"builder produced empty artifact: {artifact}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if not report.get("library_truth"):
            raise RuntimeUnsupported(
                "zero named runtime truth is unsupported, not 100 percent recall"
            )
        corpus.validate_builder_report(
            report,
            args.target,
            returncode,
            {
                "evaluator_binary_sha256": Path(builder),
                "reference_sha256": built.reference,
                "symbolized_target_sha256": built.target,
                "stripped_target_sha256": stripped,
                "database_sha256": database,
                "compressed_database_sha256": compressed,
            },
        )
        corpus.write_json(directory / "truth.json", report["library_truth"])
        result.update(
            builder_report=report,
            status="measured" if report["passed"] else "measured_failed",
        )
        exit_code = 0 if report["passed"] else 1
    except RuntimeUnsupported as error:
        result["reason"] = str(error)
        exit_code = 2
    except (
        RuntimeBuildError,
        corpus.CorpusError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        result.update(status="failed", reason=str(error))
        exit_code = 1
    finally:
        try:
            _revalidate_measurement_tools(frozen_tools)
            if built is not None:
                _revalidate_runtime(built)
                if context is not None:
                    _recheck_rust_component(context, built.provenance)
        except (
            RuntimeBuildError,
            corpus.CorpusError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
        ) as error:
            result.update(status="failed", reason=str(error), publication_rejected=True)
            exit_code = 1
        result["artifacts"] = {
            str(path.relative_to(directory)): _sha256(path)
            for path in sorted(directory.iterdir())
            if path.is_file()
        }
        corpus.write_json(directory / "result.json", result)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
