"""Two fixed offline source-unit profiles; never execute a produced target."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import re
import shlex
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FRAGMENTS = {
    "llvm-compiler-rt-generic8": "portable-compiler-rt-fragment.json",
    "glibc-strverscmp-portable": "portable-glibc-fragment.json",
}
FUNCTIONS = {
    "llvm-compiler-rt-generic8": (
        "__clzdi2",
        "__ctzdi2",
        "__paritydi2",
        "__popcountdi2",
        "__cmpdi2",
        "__ucmpdi2",
        "__muldi3",
        "__udivmoddi4",
    ),
    "glibc-strverscmp-portable": ("__strverscmp",),
}
FLAGS = (
    "--no-default-config",
    "--target=x86_64-unknown-linux-musl",
    "-std=gnu11",
    "-O2",
    "-g",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-pic",
    "-fno-pie",
    "-ffunction-sections",
    "-fdata-sections",
    "-nostdinc",
)
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "_signature_portable_core", ROOT / "tools/signature-corpus.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load existing signature corpus helpers")
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)


class PortableError(Exception):
    """A fixed portable profile failed admission or provenance validation."""


def safe_name(name: str) -> str:
    """Validate every logical archive name, including unselected members."""
    normalized = name.rstrip("/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or len(name) > 4096
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in normalized.split("/"))
        or "\\" in name
        or ":" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise PortableError(f"unsafe archive/input name: {name!r}")
    return normalized


def snapshot(
    source: Path, destination: Path, maximum: int, expected: str
) -> dict[str, Any]:
    """Hash a bounded regular descriptor while copying to a new immutable input."""
    if source.absolute() != source.resolve():
        raise PortableError(f"linked or noncanonical input: {source}")
    descriptor = os.open(
        source, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise PortableError(f"nonregular, empty or oversized input: {source}")
        digest = hashlib.sha256()
        total = 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        with (
            os.fdopen(descriptor, "rb", closefd=False) as incoming,
            destination.open("xb") as outgoing,
        ):
            while block := incoming.read(min(1024 * 1024, maximum + 1 - total)):
                total += len(block)
                if total > maximum:
                    raise PortableError(f"growing input exceeded bound: {source}")
                digest.update(block)
                outgoing.write(block)
        after = os.fstat(descriptor)
        if (
            total != before.st_size
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or digest.hexdigest() != expected
        ):
            raise PortableError(f"changed input or SHA256 pin mismatch: {source}")
        destination.chmod(0o444)
        return {
            "original_path": str(source),
            "path": str(destination),
            "sha256": expected,
            "bytes": total,
        }
    finally:
        os.close(descriptor)


def physical_admission(
    stream: io.BufferedIOBase, bounds: dict[str, int]
) -> dict[str, int]:
    """Bound raw expanded tar bytes and metadata before tarfile can consume PAX."""
    extent = 0
    headers = 0
    ended = False

    def read(size: int) -> bytes:
        nonlocal extent
        block = stream.read(min(size, bounds["physical_tar_bytes"] + 1 - extent))
        extent += len(block)
        if extent > bounds["physical_tar_bytes"]:
            raise PortableError("physical expanded tar budget exceeded")
        return block

    while header := read(512):
        if len(header) != 512:
            raise PortableError("partial physical tar header")
        if not any(header):
            ended = True
            continue
        if ended:
            raise PortableError("nonzero tar data after end marker")
        headers += 1
        if headers > bounds["physical_headers"]:
            raise PortableError("physical tar header budget exceeded")
        information = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        size = information.size
        metadata = information.type in (
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
        )
        limit = bounds["metadata_bytes"] if metadata else bounds["member_bytes"]
        if not 0 <= size <= limit:
            raise PortableError("physical member/metadata budget exceeded")
        if not metadata or information.name not in ("././@PaxHeader", "././@LongLink"):
            safe_name(information.name)
        remaining = (size + 511) // 512 * 512
        while remaining:
            block = read(min(remaining, 1024 * 1024))
            if not block:
                raise PortableError("truncated physical tar payload")
            remaining -= len(block)
    if not ended:
        raise PortableError("missing physical tar end marker")
    return {"physical_tar_bytes": extent, "physical_headers": headers}


def materialize(
    archive: Path, destination: Path, recipe: dict[str, Any]
) -> dict[str, Any]:
    """Admit the whole pinned archive; materialize only the finite hash allowlist."""
    bounds = recipe["bounds"]
    descriptor = os.open(
        archive, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    )
    with os.fdopen(descriptor, "rb") as incoming:
        information = os.fstat(incoming.fileno())
        if (
            not stat.S_ISREG(information.st_mode)
            or not 0 < information.st_size <= bounds["compressed_bytes"]
        ):
            raise PortableError("nonregular or oversized compressed snapshot")
        compressed = incoming.read(bounds["compressed_bytes"] + 1)
    if (
        len(compressed) != information.st_size
        or hashlib.sha256(compressed).hexdigest() != recipe["archive_sha256"]
    ):
        raise PortableError("compressed snapshot changed or failed its pin")
    if archive.name.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
            physical = physical_admission(stream, bounds)
    else:
        with lzma.LZMAFile(io.BytesIO(compressed), mode="rb") as stream:
            physical = physical_admission(stream, bounds)
    wanted = recipe["selected_sha256"]
    selected: dict[str, bytes] = {}
    seen: set[str] = set()
    nondirectories: set[str] = set()
    directories: set[str] = set()
    root = recipe["archive_root"]
    selected_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(compressed), mode="r|*") as stream:
        for member in stream:
            name = safe_name(member.name)
            if name != root and not name.startswith(root + "/"):
                raise PortableError(f"archive member outside declared root: {name}")
            if (
                name in seen
                or (not member.isdir() and name in directories)
                or any(
                    str(parent) in nondirectories
                    for parent in PurePosixPath(name).parents
                )
            ):
                raise PortableError(f"duplicate or obstructed archive path: {name}")
            seen.add(name)
            directories.update(str(parent) for parent in PurePosixPath(name).parents)
            if member.isdir():
                directories.add(name)
            if (
                len(seen) > bounds["physical_headers"]
                or not 0 <= member.size <= bounds["member_bytes"]
            ):
                raise PortableError("logical archive budget exceeded")
            if not (member.isfile() or member.isdir() or member.issym()):
                raise PortableError(f"unsupported archive member kind: {name}")
            if not member.isdir():
                nondirectories.add(name)
            if name not in wanted:
                continue
            if not member.isfile() or member.sparse is not None:
                raise PortableError(
                    f"selected archive member is not an ordinary file: {name}"
                )
            selected_bytes += member.size
            if selected_bytes > bounds["selected_bytes"]:
                raise PortableError("selected payload budget exceeded")
            incoming = stream.extractfile(member)
            if incoming is None:
                raise PortableError(f"missing selected payload: {name}")
            data = incoming.read(member.size + 1)
            if (
                len(data) != member.size
                or hashlib.sha256(data).hexdigest() != wanted[name]
            ):
                raise PortableError(f"selected source SHA256 mismatch: {name}")
            selected[name] = data
    if selected.keys() != wanted.keys():
        raise PortableError("missing predeclared selected source or notice")
    for name, data in selected.items():
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as stream:
            stream.write(data)
        output.chmod(0o444)
    return {
        **physical,
        "logical_members": len(seen),
        "selected_files": len(selected),
        "selected_bytes": selected_bytes,
    }


def verify_inventory(inventory: dict[str, str]) -> None:
    for name, expected in inventory.items():
        path = Path(name)
        if path.is_symlink() or not path.is_file() or core.sha256(path) != expected:
            raise PortableError(f"changed consumed input/tool: {name}")


def validate_symbols(text: str, strong: set[str], weak: dict[str, str]) -> None:
    actual: dict[str, str] = {}
    locations: dict[str, tuple[str, str, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if (
            len(parts) == 8
            and parts[3] == "FUNC"
            and parts[4] in ("GLOBAL", "WEAK")
            and parts[6] != "UND"
        ):
            if parts[5] != "DEFAULT" or parts[7] in actual:
                raise PortableError("hidden or duplicate source function")
            actual[parts[7]] = parts[4]
            locations[parts[7]] = (parts[1], parts[2], parts[6])
    expected = {**dict.fromkeys(strong, "GLOBAL"), **dict.fromkeys(weak, "WEAK")}
    if actual != expected:
        raise PortableError(
            f"source function ownership differs from declaration: {actual!r}"
        )
    if any(locations[alias] != locations[original] for alias, original in weak.items()):
        raise PortableError("weak alias does not retain the original function extent")


def validate_report(
    report: dict[str, Any],
    recipe: dict[str, Any],
    objects: list[Path],
    artifacts: dict[str, Path],
    code: int,
) -> None:
    core.validate_builder_report(report, "x86_64-linux-musl", code, artifacts)
    expected = set(FUNCTIONS[recipe["profile"]])
    truth = report["library_truth"]
    if (
        report.get("ownership_scope_id") != "public_strong"
        or len(truth) != len(expected)
        or set(truth.values()) != expected
        or report.get("library_defined_names") != len(expected)
        or report.get("library_object_count") != len(objects)
        or sorted(report.get("library_object_sha256", []))
        != sorted(core.sha256(obj) for obj in objects)
    ):
        raise PortableError(
            "collector lost or changed predeclared source-object ownership"
        )


def produce(args: argparse.Namespace, directory: Path) -> dict[str, Any]:
    fragment = ROOT / "tests/fixtures/signatures" / FRAGMENTS[args.profile]
    recipe = json.loads(fragment.read_text(encoding="utf-8"))
    if (
        recipe["profile"] != args.profile
        or tuple(recipe["functions"]) != FUNCTIONS[args.profile]
        or tuple("__" + Path(unit).stem for unit in recipe["units"])
        != FUNCTIONS[args.profile]
    ):
        raise PortableError("fixed profile declaration changed")
    inventory = {
        str(path): core.sha256(path)
        for path in (
            Path(__file__).resolve(),
            fragment,
            ROOT / "tools/signature-corpus.py",
            ROOT / "tools/signature_configured.py",
        )
    }
    core.write_json(directory / "predeclared-profile.json", recipe)
    archive = directory / recipe["archive_file"]
    archive_receipt = snapshot(
        Path(args.source_cache).absolute() / recipe["archive_file"],
        archive,
        recipe["bounds"]["compressed_bytes"],
        recipe["archive_sha256"],
    )
    inventory[str(archive)] = recipe["archive_sha256"]
    admission = materialize(archive, directory / "source", recipe)
    for name, digest in recipe["selected_sha256"].items():
        inventory[str(directory / "source" / name)] = digest
    commands = core.Commands(directory, clean_environment=True)
    tools: dict[str, Any] = {}
    (directory / "tools").mkdir()
    for name, value in (("eval", args.evaluator), ("builder", args.builder)):
        tools[name] = core.freeze_measurement_tool(value, directory / "tools" / name)
        inventory[tools[name]["path"]] = tools[name]["sha256"]
    for name, value in (("clang", args.clang), ("zig", args.zig)):
        path = Path(core.executable(value))
        tools[name] = {"path": str(path), "sha256": core.sha256(path)}
    clang = tools["clang"]["path"]
    zig = tools["zig"]["path"]
    for name in ("llvm-nm", "llvm-readelf"):
        path = Path(clang).parent / name
        tools[name] = {"path": core.executable(str(path)), "sha256": core.sha256(path)}
    for name in ("clang", "llvm-nm", "llvm-readelf"):
        tools[name]["version"] = commands.run([tools[name]["path"], "--version"])
        if not re.search(r"\b22\.1\.8\b", tools[name]["version"]):
            raise PortableError(f"required trusted LLVM 22.1.8 host tool: {name}")
    tools["zig"]["version"] = commands.run([zig, "version"]).strip()
    tools["zig"]["lld_version"] = commands.run([zig, "ld.lld", "--version"])
    if tools["zig"]["version"] != "0.17.0" or not re.search(
        r"\bLLD 22\.1\.8\b", tools["zig"]["lld_version"]
    ):
        raise PortableError("required Zig 0.17.0 / LLD 22.1.8 host producer")
    for tool in tools.values():
        inventory[tool["path"]] = tool["sha256"]
    resource = (
        Path(
            commands.run([clang, "--no-default-config", "-print-resource-dir"]).strip()
        ).resolve()
        / "include"
    )
    zig_headers = Path(zig).parent.parent / "lib/zig/libc/include"
    header_receipts = []
    for name, digest in recipe["header_sha256"].items():
        provider, relative = name.split("/", 1)
        source = (resource if provider == "clang" else zig_headers) / relative
        output = directory / "headers" / name
        header_receipts.append(snapshot(source, output, 1024 * 1024, digest))
        inventory[str(output)] = digest
    fixtures: dict[str, Path] = {}
    for name, digest in recipe["fixture_sha256"].items():
        output = directory / "harness" / Path(name).name
        snapshot(ROOT / name, output, 64 * 1024, digest)
        inventory[str(output)] = digest
        inventory[str(ROOT / name)] = digest
        fixtures[Path(name).name] = output
    includes = []
    if args.profile == "glibc-strverscmp-portable":
        for subdirectory in ("zig/x86_64-linux-musl", "zig/generic-musl"):
            includes.extend(["-isystem", str(directory / "headers" / subdirectory)])
    else:
        includes = ["-isystem", str(directory / "headers/clang")]
    base = [clang, *FLAGS, *includes]
    extra = []
    if args.profile == "glibc-strverscmp-portable":
        extra = ["-include", str(fixtures["signature-portable-glibc-symbols.h"])]
    inputs = {
        "recipe": recipe,
        "archive": archive_receipt,
        "archive_admission": admission,
        "tools": tools,
        "headers": header_receipts,
        "selected_source_and_notice_bytes": [
            {
                "archive_member": name,
                "sha256": digest,
                "bytes": (directory / "source" / name).stat().st_size,
            }
            for name, digest in recipe["selected_sha256"].items()
        ],
        "compile_flags": [*FLAGS, *includes, *extra],
        "source_body_modifications": [],
        "target_executed": False,
    }
    core.write_json(directory / "producer-inputs.json", inputs)
    inventory[str(directory / "producer-inputs.json")] = core.sha256(
        directory / "producer-inputs.json"
    )
    dependencies = []

    def compile_source(source: Path, output: Path, extra_flags: list[str]) -> None:
        depfile = output.with_suffix(".d")
        verify_inventory(inventory)
        commands.run(
            [
                *base,
                *extra_flags,
                "-MD",
                "-MF",
                str(depfile),
                "-MT",
                "deps",
                "-c",
                str(source),
                "-o",
                str(output),
            ]
        )
        paths = shlex.split(depfile.read_text().replace("\\\n", " ").split(":", 1)[1])
        if str(source) not in paths or any(path not in inventory for path in paths):
            raise PortableError(
                "compiler consumed an unpinned source/header dependency"
            )
        verify_inventory(inventory)
        dependencies.append(
            {
                "source": str(source),
                "object": str(output),
                "dependency_file_sha256": core.sha256(depfile),
                "dependencies": {path: inventory[path] for path in paths},
            }
        )
        inventory[str(output)] = core.sha256(output)

    objects = []
    source_root = directory / "source" / recipe["archive_root"]
    for unit in recipe["units"]:
        obj = directory / (Path(unit).stem + ".o")
        compile_source(source_root / unit, obj, extra)
        if commands.run(
            [tools["llvm-nm"]["path"], "--undefined-only", str(obj)]
        ).strip():
            raise PortableError("source object has undefined runtime dependencies")
        symbols = commands.run(
            [
                tools["llvm-readelf"]["path"],
                "--elf-output-style=GNU",
                "--symbols",
                "--wide",
                str(obj),
            ]
        )
        validate_symbols(symbols, {"__" + Path(unit).stem}, recipe["weak_aliases"])
        objects.append(obj)
    programs = {}
    family = "compiler-rt" if args.profile == "llvm-compiler-rt-generic8" else "glibc"
    for role in ("reference", "target"):
        harness = fixtures[f"signature-portable-{family}-{role}.c"]
        harness_object = directory / f"{role}.o"
        compile_source(harness, harness_object, [])
        program = directory / f"{role}.elf"
        ordered = (
            [*objects, harness_object]
            if role == "reference"
            else [harness_object, *reversed(objects)]
        )
        verify_inventory(inventory)
        commands.run(
            [
                zig,
                "ld.lld",
                "-m",
                "elf_x86_64",
                "-static",
                "--icf=none",
                "--no-relax",
                "--no-gc-sections",
                "--entry=profile_entry",
                "-Map=" + str(directory / f"{role}.map"),
                "-o",
                str(program),
                *map(str, ordered),
            ]
        )
        core.inspect(commands, tools["eval"]["path"], program, "x86_64-linux-musl")
        if commands.run(
            [tools["llvm-nm"]["path"], "--undefined-only", str(program)]
        ).strip():
            raise PortableError("linked freestanding fixture retains undefined symbols")
        layout = commands.run(
            [
                tools["llvm-readelf"]["path"],
                "--elf-output-style=GNU",
                "--program-headers",
                "--dynamic-table",
                str(program),
            ]
        )
        if re.search(r"\b(INTERP|DYNAMIC|NEEDED)\b", layout):
            raise PortableError("freestanding fixture has dynamic runtime dependencies")
        inventory[str(program)] = core.sha256(program)
        programs[role] = program
    if inventory[str(programs["reference"])] == inventory[str(programs["target"])]:
        raise PortableError("harness fixtures are not distinct")
    core.write_json(directory / "dependencies.json", dependencies)
    stripped = directory / "target.stripped.elf"
    commands.run(
        [tools["eval"]["path"], "strip", str(programs["target"]), str(stripped)]
    )
    core.inspect(
        commands, tools["eval"]["path"], stripped, "x86_64-linux-musl", stripped=True
    )
    verify_inventory(inventory)
    database = directory / "db.json"
    report_path = directory / "builder-report.json"
    argv = [
        tools["builder"]["path"],
        "--ownership-scope",
        "public-strong",
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
    for obj in objects:
        argv.extend(["--object", str(obj)])
    commands.run(argv, allowed=(0, 1))
    code = commands.records[-1]["returncode"]
    report = json.loads(report_path.read_text())
    artifacts = {
        "reference_sha256": programs["reference"],
        "symbolized_target_sha256": programs["target"],
        "stripped_target_sha256": stripped,
        "database_sha256": database,
        "compressed_database_sha256": directory / "db.json.gz",
        "evaluator_binary_sha256": Path(tools["builder"]["path"]),
    }
    validate_report(report, recipe, objects, artifacts, code)
    verify_inventory(inventory)
    return {
        "schema_version": 1,
        "profile": args.profile,
        "passed": report["passed"],
        "producer_inputs": inputs,
        "builder_report": report,
        "consumed_input_sha256": inventory,
        "artifact_sha256": {
            field: core.sha256(path) for field, path in artifacts.items()
        },
        "evidence_sha256": {
            str(path): core.sha256(path)
            for path in (
                directory / "predeclared-profile.json",
                directory / "dependencies.json",
                report_path,
                directory / "reference.map",
                directory / "target.map",
            )
        },
        "commands_sha256": core.sha256(directory / "commands.json"),
        "command_log_sha256": {
            str(directory / record[key]): core.sha256(directory / record[key])
            for record in commands.records
            for key in ("stdout", "stderr")
        },
        "target_executed": False,
        "publication": "Data-only candidate; parent integration remains separate",
    }


def fresh_directory(value: str) -> Path:
    directory = Path(value).absolute()
    if directory != directory.resolve() or not directory.is_relative_to(
        ROOT / "target"
    ):
        raise PortableError(
            "output must be a new canonical directory below repository target/"
        )
    directory.mkdir()
    return directory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=FRAGMENTS, required=True)
    parser.add_argument("--source-cache", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--clang", default="/opt/homebrew/Cellar/llvm@22/22.1.8/bin/clang"
    )
    parser.add_argument("--zig", default="/opt/homebrew/Cellar/zig/0.17.0/bin/zig")
    parser.add_argument(
        "--eval",
        dest="evaluator",
        default=str(ROOT / "target/phase2-1/delivery-tools-v4/eval"),
    )
    parser.add_argument(
        "--builder",
        default=str(ROOT / "target/phase2-1/runtime-optimized-tools/builder"),
    )
    args = parser.parse_args()
    directory = None
    try:
        directory = fresh_directory(args.output_dir)
        result = produce(args, directory)
        core.write_json(directory / "result.json", result)
        print(
            json.dumps(
                {
                    "profile": args.profile,
                    "passed": result["passed"],
                    "result": str(directory / "result.json"),
                }
            )
        )
        return 0 if result["passed"] else 1
    except (
        PortableError,
        core.CorpusError,
        OSError,
        ValueError,
        tarfile.TarError,
        EOFError,
        lzma.LZMAError,
    ) as error:
        if directory is not None:
            core.write_json(
                directory / "failure.json",
                {
                    "profile": args.profile,
                    "error": str(error),
                    "target_executed": False,
                },
            )
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
