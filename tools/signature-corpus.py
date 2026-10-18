#!/usr/bin/env python3
"""Build an offline, source-owned signature pilot without executing target code."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests/fixtures/signatures/recipes.json"
VERSIONS = {"zlib": "1.3.1", "lz4": "1.10.0", "lua": "5.4.7"}
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
                "only the pinned zlib, lz4 and Lua recipe roster is supported"
            )
        for name, recipe in libraries.items():
            if recipe["version"] != VERSIONS[name]:
                raise CorpusError(f"unallowlisted version for {name}")
            if not recipe["url"].startswith("https://"):
                raise CorpusError(f"{name}: source provenance URL must use HTTPS")
            for field in ("archive", "root", "license_file", "include"):
                relative_path(recipe[field])
            if len(PurePosixPath(recipe["archive"]).parts) != 1:
                raise CorpusError(f"{name}: archive must be a cache basename")
            sources = recipe["sources"]
            if not sources or len(sources) != len(set(sources)):
                raise CorpusError(f"{name}: empty or duplicate explicit sources")
            for source in sources:
                if relative_path(source).suffix != ".c":
                    raise CorpusError(f"{name}: only explicit C sources are allowed")
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
    actual = sha256(archive)
    if actual != pin:
        raise CorpusError(
            f"archive SHA-256 mismatch: {archive}: expected {pin}, got {actual}"
        )
    return archive


def extract_archive(archive: Path, destination: Path, root: str) -> Path:
    try:
        with tarfile.open(archive, "r:gz") as source:
            members: list[tarfile.TarInfo] = []
            names: set[str] = set()
            total = 0
            for member in source:
                members.append(member)
                path = relative_path(member.name)
                if (
                    not path.parts
                    or path.parts[0] != root
                    or not (member.isdir() or member.isfile())
                ):
                    raise CorpusError(
                        f"archive contains an unexpected root, link or special file: {member.name}"
                    )
                normalized = str(path)
                if normalized in names:
                    raise CorpusError(f"duplicate archive member: {member.name}")
                names.add(normalized)
                total += member.size
                if total > 128 * 1024 * 1024 or len(members) > 10000:
                    raise CorpusError("source archive exceeds bounded extraction size")
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
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.records: list[dict[str, Any]] = []
        self.environment = dict(os.environ)
        self.environment.update(
            ZIG_GLOBAL_CACHE_DIR=str(directory / "zig-global-cache"),
            ZIG_LOCAL_CACHE_DIR=str(directory / "zig-local-cache"),
            TMPDIR=str(directory / "tmp"),
            SOURCE_DATE_EPOCH="0",
            LC_ALL="C",
        )

    def run(
        self,
        argv: list[str],
        output: Path | None = None,
        allowed: tuple[int, ...] = (0,),
    ) -> str:
        index = len(self.records)
        record: dict[str, Any] = {
            "argv": argv,
            "cwd": str(self.directory),
            "environment": {
                key: self.environment[key]
                for key in (
                    "ZIG_GLOBAL_CACHE_DIR",
                    "ZIG_LOCAL_CACHE_DIR",
                    "SOURCE_DATE_EPOCH",
                    "LC_ALL",
                    "TMPDIR",
                )
            },
        }
        self.records.append(record)
        stdout = self.directory / f"command-{index:03}.stdout"
        stderr = self.directory / f"command-{index:03}.stderr"
        record.update(stdout=stdout.name, stderr=stderr.name)
        try:
            (self.directory / "tmp").mkdir(exist_ok=True)
            with stdout.open("wb") as out_stream, stderr.open("wb") as err_stream:
                completed = subprocess.run(
                    argv,
                    cwd=self.directory,
                    env=self.environment,
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


def inspect(
    commands: Commands,
    evaluator: str,
    artifact: Path,
    target: str,
    stripped: bool = False,
) -> dict[str, Any]:
    metadata = json.loads(commands.run([evaluator, "artifact-info", str(artifact)]))
    write_json(artifact.with_suffix(artifact.suffix + ".info.json"), metadata)
    if metadata["format"] != "elf" or metadata["arch"] != ARCHES[target]:
        raise CorpusError(
            f"unexpected actual artifact headers for {artifact}: {metadata}"
        )
    if target.startswith("thumb-") and not metadata.get("thumb_ranges", 0):
        raise CorpusError(
            f"Thumb profile has no retained Thumb-mode evidence: {artifact}"
        )
    if metadata["dynamic_function_symbols"]:
        raise CorpusError(
            f"static corpus artifact retains dynamic function symbols: {artifact}"
        )
    symbols = metadata["static_function_symbols"] + metadata["dynamic_function_symbols"]
    if (stripped and (symbols or metadata["debug_sections"])) or (
        not stripped and not symbols
    ):
        raise CorpusError(
            f"unexpected symbol/strip metadata for {artifact}: {metadata}"
        )
    return metadata


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
    commands = Commands(directory)
    try:
        if selection.target.endswith("windows-gnu"):
            result.update(
                status="unsupported",
                reason="PE stripping/sized library-function truth is not supported by this pilot",
            )
            return result
        archive = checked_archive(args.archive_cache, recipe)
        result["archive_sha256"] = sha256(archive)
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
        version = commands.run([zig, "version"]).strip()
        result["zig_version"] = version
        if version != "0.17.0":
            raise CorpusError(f"exact Zig 0.17.0 required, found {version!r}")
        source = extract_archive(archive, directory / "source", recipe["root"])
        license_path = source / recipe["license_file"]
        result["license_sha256"] = sha256(license_path)
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
            unit = source / filename
            inputs[filename] = sha256(unit)
            obj = directory / f"library-{index:02}.o"
            commands.run([zig, "cc", *flags, "-c", str(unit), "-o", str(obj)])
            objects.append(obj)
        result["source_sha256"] = inputs
        library = directory / f"lib{selection.library}.a"
        commands.run([zig, "ar", "rcsD", str(library), *map(str, objects)])
        programs: dict[str, Path] = {}
        harness_hashes: dict[str, str] = {}
        for role in ("reference", "target"):
            harness = (
                ROOT / f"tests/fixtures/src/signature-{selection.library}-{role}.c"
            )
            harness_hashes[role] = sha256(harness)
            harness_object = directory / f"{role}.o"
            commands.run(
                [zig, "cc", *flags, "-c", str(harness), "-o", str(harness_object)]
            )
            program = directory / f"{role}.elf"
            commands.run(
                [
                    zig,
                    "cc",
                    *flags,
                    "-static",
                    "-no-pie",
                    "-Wl,--no-gc-sections",
                    str(harness_object),
                    "-Wl,--whole-archive",
                    str(library),
                    "-Wl,--no-whole-archive",
                    "-lm",
                    "-o",
                    str(program),
                ]
            )
            inspect(commands, evaluator, program, selection.target)
            programs[role] = program
        result["harness_sha256"] = harness_hashes
        if sha256(programs["reference"]) == sha256(programs["target"]):
            raise CorpusError("reference and target unexpectedly have identical bytes")
        stripped = directory / "target.stripped.elf"
        commands.run([evaluator, "strip", str(programs["target"]), str(stripped)])
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
        for obj in objects:
            builder_command.extend(["--object", str(obj)])
        commands.run(builder_command, allowed=(0, 1))
        builder_returncode = commands.records[-1]["returncode"]
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
            },
        )
        write_json(directory / "truth.json", report["library_truth"])
        result["ownership_scope"] = (
            "externally visible strong ELF library functions; local/hidden/weak coverage excluded"
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
    except (CorpusError, OSError, ValueError, KeyError, TypeError) as error:
        result["reason"] = str(error)
        return result
    finally:
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
            print("targets: " + ", ".join(TARGETS))
            print("optimizations: O1, O2; default pilot: zlib / x86_64-linux-musl / O1")
            print(
                "Windows: unsupported (PE strip/truth); other targets require producer verification"
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
        write_json(output / "recipes.json", manifest)
        inventory: dict[str, Any] = {
            "schema_version": 1,
            "phase": "2.1",
            "recipe_manifest_sha256": sha256(MANIFEST),
            "runner_sha256": sha256(Path(__file__)),
            "target_execution": False,
            "download_attempted": False,
            "link_policy": "full_library_gc_disabled",
            "limitations": (
                "Pilot public-strong-function measurements only; local/weak coverage is excluded. "
                "The roster is future coverage; failed/unsupported targets remain explicit. "
                "Disabling linker GC changes the truth denominator; prior GC-enabled runs are not directly comparable."
            ),
            "slices": {},
        }
        for selection in select(args):
            result = build_slice(
                selection,
                manifest["libraries"][selection.library],
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
