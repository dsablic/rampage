"""Bounded source-oracle measurements of owned fixtures; never execute fixture code."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import statistics
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

if __package__:
    from . import cpp_virtual_corpus as supervisor
else:
    import cpp_virtual_corpus as supervisor

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT = supervisor.MAX_TEXT
MAX_ERROR = supervisor.MAX_STDERR
PHASES = (
    "configuration_ms",
    "metadata_ms",
    "replay_ms",
    "mapping_ms",
    "execution_ms",
    "total_ms",
)
COUNT_FIELDS = (
    "retained_symbols",
    "retained_imports",
    "references",
    "decoded_instructions",
    "decoded_bytes",
    "walk_blocks",
    "stub_aliases",
)
FAILURE_CODES = frozenset(
    {
        "external_deadline",
        "stdout_limit",
        "stderr_limit",
        "stdin_closed_before_request",
        "guardian_missing_result",
        "guardian_cleanup_deadline",
        "guardian_reap_deadline",
        "rss_sampling_unavailable",
        "unsupported_separate_group_descendant",
        "owned_descendants_outlived_leader",
        "observed_owned_group_rss_limit",
    }
)


@dataclass(frozen=True)
class Case:
    fixture: str
    entry: str
    image_format: str
    architecture: str
    compiler: str
    oracle: str


CASES = (
    Case(
        "hello-x64-dyn.elf", "main", "ELF", "x86:LE:64:", "gcc", "greeting_return_five"
    ),
    Case("hello-x64.exe", "add", "PE", "x86:LE:64:", "windows", "two_argument_sum"),
    Case(
        "hello-x64.macho", "_main", "MachO", "x86:LE:64:", "gcc", "greeting_return_five"
    ),
)
ARM_CASE = Case(
    "hello-arm64.elf", "main", "ELF", "AARCH64:", "default", "greeting_return_five"
)


class MeasurementError(Exception):
    """Invalid measurement inputs or incomplete evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MeasurementError(message)


def require_string(value: Any, message: str) -> str:
    if not isinstance(value, str) or not value:
        raise MeasurementError(message)
    return value


def require_object(value: Any, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MeasurementError(message)
    return value


def require_uint(value: Any, message: str, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise MeasurementError(message)
    return value


def fingerprint(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--worker", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--backend", choices=("inline",), default="inline")
    parser.add_argument("--repeats", type=int, choices=(1, 2, 3), default=3)
    parser.add_argument("--include-arm64", action="store_true")
    return parser.parse_args(argv)


def validate_image(data: bytes, case: Case) -> None:
    if case.image_format == "ELF":
        machine = 183 if case.architecture == "AARCH64:" else 62
        require(
            data[:6] == b"\x7fELF\x02\x01"
            and int.from_bytes(data[18:20], "little") == machine,
            "fixture is not the requested ELF architecture",
        )
        require(len(data) >= 64, "truncated ELF64 header")
        require(
            int.from_bytes(data[52:54], "little") == 64, "invalid ELF64 header size"
        )
        program_offset = int.from_bytes(data[32:40], "little")
        section_offset = int.from_bytes(data[40:48], "little")
        program_size = int.from_bytes(data[54:56], "little")
        program_count = int.from_bytes(data[56:58], "little")
        section_size = int.from_bytes(data[58:60], "little")
        section_count = int.from_bytes(data[60:62], "little")
        for offset, size, count, expected in (
            (program_offset, program_size, program_count, 56),
            (section_offset, section_size, section_count, 64),
        ):
            if count:
                require(
                    offset >= 64
                    and size == expected
                    and offset + size * count <= len(data),
                    "ELF header table outside file",
                )
            else:
                require(offset == 0, "extended ELF numbering unsupported")
        for index in range(program_count):
            start = program_offset + index * program_size
            offset = int.from_bytes(data[start + 8 : start + 16], "little")
            size = int.from_bytes(data[start + 32 : start + 40], "little")
            require(offset + size <= len(data), "ELF segment outside file")
        for index in range(section_count):
            start = section_offset + index * section_size
            kind = int.from_bytes(data[start + 4 : start + 8], "little")
            offset = int.from_bytes(data[start + 24 : start + 32], "little")
            size = int.from_bytes(data[start + 32 : start + 40], "little")
            if kind != 8:
                require(offset + size <= len(data), "ELF section outside file")
    elif case.image_format == "PE":
        offset = int.from_bytes(data[60:64], "little")
        require(
            data[:2] == b"MZ"
            and offset >= 64
            and data[offset : offset + 6] == b"PE\x00\x00\x64\x86",
            "fixture is not x86-64 PE",
        )
        require(offset + 24 <= len(data), "truncated PE COFF header")
        sections = int.from_bytes(data[offset + 6 : offset + 8], "little")
        optional_size = int.from_bytes(data[offset + 20 : offset + 22], "little")
        optional = offset + 24
        table = optional + optional_size
        require(
            optional_size >= 112
            and table <= len(data)
            and data[optional : optional + 2] == b"\x0b\x02",
            "truncated or invalid PE32+ optional header",
        )
        directories = int.from_bytes(data[optional + 108 : optional + 112], "little")
        require(
            112 + directories * 8 <= optional_size,
            "PE directory table outside optional header",
        )
        require(
            sections > 0 and table + sections * 40 <= len(data),
            "PE section table outside file",
        )
        header_size = int.from_bytes(data[optional + 60 : optional + 64], "little")
        require(
            table + sections * 40 <= header_size <= len(data), "PE headers outside file"
        )
        for index in range(sections):
            start = table + index * 40
            size = int.from_bytes(data[start + 16 : start + 20], "little")
            position = int.from_bytes(data[start + 20 : start + 24], "little")
            require(position + size <= len(data), "PE section data outside file")
    else:
        require(
            data[:8] == b"\xcf\xfa\xed\xfe\x07\x00\x00\x01",
            "fixture is not x86-64 Mach-O",
        )
        require(len(data) >= 32, "truncated Mach-O 64-bit header")
        commands = int.from_bytes(data[16:20], "little")
        command_bytes = int.from_bytes(data[20:24], "little")
        end = 32 + command_bytes
        require(
            end <= len(data) and commands <= command_bytes // 8,
            "Mach-O commands outside file",
        )
        cursor = 32
        for _ in range(commands):
            require(cursor + 8 <= end, "truncated Mach-O command")
            size = int.from_bytes(data[cursor + 4 : cursor + 8], "little")
            require(
                size >= 8 and size % 8 == 0 and cursor + size <= end,
                "invalid Mach-O command size",
            )
            cursor += size
        require(cursor == end, "Mach-O command count/size mismatch")


def preflight(arguments: argparse.Namespace) -> dict[str, Any]:
    require(
        arguments.backend == "inline",
        "isolated backend unsupported by this measurement guardian",
    )
    require(os.name == "posix", "POSIX supervision required")
    require(hasattr(os, "WNOWAIT"), "non-reaping child observation required")
    require(arguments.repeats in (1, 2, 3), "invalid repeat count")
    output = arguments.output.absolute()
    require(
        not output.exists() and not output.is_symlink(), "output must not already exist"
    )
    parent = output.parent.resolve(strict=True)
    require(
        parent.is_dir() and not parent.is_relative_to(ROOT),
        "output must be in caller-owned external scratch",
    )
    binaries = {}
    for name in ("cli", "worker"):
        path = getattr(arguments, name).resolve(strict=True)
        require(
            path.is_file() and os.access(path, os.X_OK),
            f"{name} must be an executable file",
        )
        binaries[name] = supervisor.file_digest(path, supervisor.MAX_EXECUTABLE)
    cases = (*CASES, ARM_CASE) if arguments.include_arm64 else CASES
    fixtures = []
    for case in cases:
        path = ROOT / "tests/fixtures/bin" / case.fixture
        fixture_bytes = supervisor.bounded_read(path, supervisor.MAX_IMAGE)
        validate_image(fixture_bytes, case)
        fixtures.append(
            {
                **asdict(case),
                "sha256": hashlib.sha256(fixture_bytes).hexdigest(),
            }
        )
    return {
        "fixtures": fixtures,
        "executables_sha256": binaries,
        "source_sha256": supervisor.file_digest(
            ROOT / "tests/fixtures/src/hello.c", supervisor.MAX_TEXT
        ),
        "runner_sha256": supervisor.file_digest(Path(__file__), supervisor.MAX_TEXT),
        "supervisor_sha256": supervisor.file_digest(
            Path(supervisor.__file__), supervisor.MAX_TEXT
        ),
        "repeats": arguments.repeats,
        "settings": {
            "backend": "inline",
            "backend_scope": (
                "inline only; Rust workers intentionally own a separate process group, "
                "unsupported by this guardian; worker executable hashed for provenance only, never executed"
            ),
            "isolated_wall_seconds": None,
            "isolated_rss_bytes": None,
            "image": "same complete fixture bytes in both modes",
            "annotations": "none; fresh fixture copies without sidecars",
            "native_options": "CLI defaults, same explicit per-format compiler override in both modes",
            "tokens": True,
            "per_child_seconds": 30,
            "run_budget_seconds": 120,
            "stdout_limit_bytes": MAX_OUTPUT,
            "stderr_limit_bytes": MAX_ERROR,
        },
    }


def prepare_inputs(
    arguments: argparse.Namespace, scratch: Path, manifest: dict[str, Any]
) -> Path:
    inline = scratch / "inline"
    inline.mkdir()
    cli = inline / "rampage"
    shutil.copy2(arguments.cli.resolve(), cli)
    require(
        not (inline / "rampage-worker").exists(),
        "inline CLI must have no sibling worker",
    )
    require(
        supervisor.file_digest(cli, supervisor.MAX_EXECUTABLE)
        == manifest["executables_sha256"]["cli"],
        "CLI changed since preflight",
    )
    for fixture in manifest["fixtures"]:
        destination = scratch / fixture["fixture"]
        shutil.copyfile(ROOT / "tests/fixtures/bin" / fixture["fixture"], destination)
        require(
            supervisor.file_digest(destination, supervisor.MAX_IMAGE)
            == fixture["sha256"],
            "fixture changed since preflight",
        )
    return cli


def invocation(
    cli: Path, image: Path, case: dict[str, Any], backend: str, mode: str
) -> tuple[list[str], dict[str, str]]:
    require(
        backend == "inline", "isolated backend unsupported by this measurement guardian"
    )
    environment = dict(os.environ)
    environment.pop("RAMPAGE_WORKER", None)
    environment["LC_ALL"] = "C"
    command = [
        str(cli),
        "--json",
        "decompile",
        str(image),
        "--at",
        case["entry"],
        "--compiler",
        case["compiler"],
    ]
    if mode == "exact":
        command.append("--exact-entry")
    return command, environment


def validate_result(
    data: bytes, case: dict[str, Any], backend: str, mode: str
) -> dict[str, Any]:
    require(
        backend == "inline", "isolated backend unsupported by this measurement guardian"
    )
    result = supervisor.decode_json(data, "CLI output")
    code = require_string(result.get("code"), "missing root code")
    require("decompilation" not in result, "unexpected wrapped response")
    address = require_string(result.get("address"), "missing root address")
    language = require_string(result.get("language_id"), "missing language ID")
    require(
        re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", address) is not None,
        "invalid canonical address",
    )
    expected_language = (
        "AARCH64:LE:64:v8A:"
        if case["architecture"] == "AARCH64:"
        else "x86:LE:64:default:"
    ) + case["compiler"]
    require(language == expected_language, "wrong canonical language or compiler")
    if case["oracle"] == "greeting_return_five":
        require(
            re.search(r"return\s+5\s*;", code) is not None,
            "source return-value oracle failed",
        )
        require(
            re.search(r'\b_?puts(?:@plt)?\s*\(\s*"rampage fixture greeting"\s*\)', code)
            is not None,
            "source puts/string oracle failed",
        )
    else:
        structure = require_object(result.get("structure"), "missing structure")
        signature = require_object(structure.get("signature"), "missing signature")
        parameters = signature.get("parameters")
        if not isinstance(parameters, list) or len(parameters) != 2:
            raise MeasurementError("source argument-count oracle failed")
        names = [
            require_string(
                require_object(parameter, "invalid parameter").get("name"),
                "missing argument names",
            )
            for parameter in parameters
        ]
        left, right = (re.escape(name) for name in names)
        addition = (
            rf"return\s+\(?\s*(?:{left}\s*\+\s*{right}|{right}\s*\+\s*{left})\s*\)?\s*;"
        )
        require(re.search(addition, code) is not None, "source addition oracle failed")
    phases = None
    context_evidence = None
    if mode == "exact":
        context = require_object(result.get("context"), "missing exact context")
        require(context.get("scope") == "exact_entry", "wrong exact scope")
        require(
            context.get("validation") == "analyst_asserted", "wrong CLI entry assertion"
        )
        require(
            context.get("full_image_mapping") is True,
            "full-image mapping not confirmed",
        )
        require(context.get("mapped_backing_checked") is True, "backing not checked")
        require(
            context.get("execution") == "in_process_native", "wrong observed backend"
        )
        timings = require_object(context.get("timings"), "missing exact timings")
        phases = {
            key: require_uint(timings.get(key), "invalid timings") for key in PHASES
        }
        raw_counts = require_object(context.get("counts"), "missing context counts")
        require(
            set(raw_counts) == {*COUNT_FIELDS, "context_budget_exhausted"},
            "invalid count fields",
        )
        counts: dict[str, int | bool] = {
            key: require_uint(raw_counts.get(key), "invalid context count")
            for key in COUNT_FIELDS
        }
        exhausted = raw_counts.get("context_budget_exhausted")
        if not isinstance(exhausted, bool):
            raise MeasurementError("invalid context budget flag")
        counts["context_budget_exhausted"] = exhausted
        omissions = context.get("omissions")
        if not isinstance(omissions, list) or len(omissions) > 64:
            raise MeasurementError("invalid omission list")
        if any(
            not isinstance(item, str)
            or len(json.dumps(item, ensure_ascii=True).encode("ascii")) > 8192
            for item in omissions
        ):
            raise MeasurementError("invalid omission text")
        omission_bytes = json.dumps(
            omissions, ensure_ascii=True, separators=(",", ":")
        ).encode()
        require(len(omission_bytes) <= 65536, "omission text exceeds bound")
        context_evidence = {
            "execution": "in_process_native",
            "mapped_regions": require_uint(
                context.get("mapped_regions"), "invalid mapped regions", 65536
            ),
            "mapped_backed_bytes": require_uint(
                context.get("mapped_backed_bytes"),
                "invalid mapped byte count",
                128 * 1024 * 1024,
            ),
            "counts": counts,
            "omission_count": len(omissions),
            "omissions_sha256": hashlib.sha256(omission_bytes).hexdigest(),
        }
    else:
        require("context" not in result, "legacy response unexpectedly has context")
    return {
        "language_id": language,
        "address": address,
        "source_oracle": "passed",
        "exact_timings_ms": phases,
        "exact_context": context_evidence,
    }


def observation(result: supervisor.ProcessResult) -> dict[str, Any]:
    resident = result.max_observed_summed_rss_bytes
    available = result.rss_samples > 0 and resident is not None and resident > 0
    failure_code = (
        result.failure
        if result.failure in FAILURE_CODES
        else ("supervision_error" if result.failure else None)
    )
    return {
        "wall_seconds": result.wall_seconds,
        "returncode": result.returncode,
        "supervision_failure": failure_code,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "rss": {
            "max_observed_summed_bytes": resident if available else None,
            "status": "observed" if available else "unavailable",
            "samples": result.rss_samples,
            "sampling_error_count": len(result.rss_sampling_errors),
            "scope": "inline CLI only; guardian and sampler excluded; shared-inclusive",
            "metric": "sampled maximum, not guaranteed peak or private memory",
            "cli_peak_rss_bytes": None,
            "worker_peak_rss_bytes": None,
        },
    }


def distribution(values: list[float | int]) -> dict[str, float | int] | None:
    if not values:
        return None
    return {"median": statistics.median(values), "min": min(values), "max": max(values)}


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = sorted({(row["fixture"], row["backend"], row["mode"]) for row in records})
    summaries = []
    for fixture, backend, mode in groups:
        rows = [
            row
            for row in records
            if (row["fixture"], row["backend"], row["mode"]) == (fixture, backend, mode)
        ]
        passed = [row for row in rows if row["status"] == "passed"]
        summaries.append(
            {
                "fixture": fixture,
                "backend": backend,
                "mode": mode,
                "passed": len(passed),
                "failed": sum(row["status"] == "failed" for row in rows),
                "not_run": sum(row["status"] == "not_run" for row in rows),
                "successful_wall_seconds": distribution(
                    [row["wall_seconds"] for row in passed]
                ),
                "successful_sampled_group_rss_bytes": distribution(
                    [
                        row["rss"]["max_observed_summed_bytes"]
                        for row in passed
                        if row["rss"]["max_observed_summed_bytes"] is not None
                    ]
                ),
                "successful_exact_timings_ms": {
                    phase: distribution(
                        [row["evidence"]["exact_timings_ms"][phase] for row in passed]
                    )
                    for phase in PHASES
                }
                if mode == "exact"
                else None,
            }
        )
    return summaries


def measure(arguments: argparse.Namespace, manifest: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + 120
    records: list[dict[str, Any]] = []
    supervision_unavailable = False
    require(
        arguments.backend == "inline",
        "isolated backend unsupported by this measurement guardian",
    )
    with tempfile.TemporaryDirectory(
        prefix="entry-measurements-", dir=arguments.output.parent
    ) as directory:
        scratch = Path(directory)
        cli = prepare_inputs(arguments, scratch, manifest)
        for case in manifest["fixtures"]:
            for repeat in range(arguments.repeats):
                for mode in (
                    ("exact", "legacy") if repeat % 2 == 0 else ("legacy", "exact")
                ):
                    row: dict[str, Any] = {
                        "fixture": case["fixture"],
                        "backend": "inline",
                        "mode": mode,
                        "repeat": repeat + 1,
                    }
                    records.append(row)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or supervision_unavailable:
                        reason = (
                            "supervision_unavailable"
                            if supervision_unavailable
                            else "run_budget_exhausted"
                        )
                        row.update(status="not_run", failure=reason)
                        continue
                    command, environment = invocation(
                        cli, scratch / case["fixture"], case, "inline", mode
                    )
                    try:
                        result = supervisor.run_process(
                            command,
                            scratch,
                            min(30, remaining),
                            environment=environment,
                            stdout_limit=MAX_OUTPUT,
                            stderr_limit=MAX_ERROR,
                        )
                    except (supervisor.CorpusError, OSError):
                        row.update(status="failed", failure="supervision_exception")
                        supervision_unavailable = True
                        continue
                    row.update(observation(result))
                    row["status"] = "failed"
                    if (
                        result.failure not in (None, "rss_sampling_unavailable")
                        or result.returncode != 0
                    ):
                        row["failure"] = "supervision_or_process_failure"
                        if result.failure and any(
                            marker in result.failure
                            for marker in ("cleanup", "reap", "separate_group")
                        ):
                            supervision_unavailable = True
                        continue
                    try:
                        row["evidence"] = validate_result(
                            result.stdout, case, "inline", mode
                        )
                    except MeasurementError as error:
                        row["failure"] = "response_or_source_oracle_failed"
                        row["validation_failure"] = str(error)
                    except supervisor.CorpusError:
                        row["failure"] = "invalid_cli_json"
                    else:
                        if (
                            row["rss"]["status"] == "observed"
                            and result.failure is None
                        ):
                            row["status"] = "passed"
                        else:
                            row["failure"] = "failed_missing_rss"
    return {
        "schema_version": 1,
        "manifest": manifest,
        "manifest_sha256": fingerprint(manifest),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "elapsed_seconds": time.monotonic() - started,
        "records": records,
        "summary": summarize(records),
    }


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        manifest = preflight(arguments)
        report = measure(arguments, manifest)
        with arguments.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
    except (MeasurementError, supervisor.CorpusError, OSError, ValueError) as error:
        print(f"entry measurements failed: {type(error).__name__}", file=sys.stderr)
        return 2
    return 0 if all(row["status"] == "passed" for row in report["records"]) else 1


if __name__ == "__main__":
    for cancellation_signal in supervisor.CANCELLATION_SIGNALS:
        signal.signal(cancellation_signal, supervisor.interrupt)
    try:
        raise SystemExit(main())
    except supervisor.CorpusInterrupted:
        print(
            "entry measurements interrupted; owned children cleaned up", file=sys.stderr
        )
        raise SystemExit(130) from None
