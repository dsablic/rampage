#!/usr/bin/env python3
"""Measure independent CLI decompilations against explicit corpus assertions."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

try:
    import resource
except ImportError:
    resource = None


MANIFEST_SCHEMA = "rampage-decompiler-corpus-v1"
BASELINE_SCHEMA = "rampage-decompiler-baseline-v1"
REPORT_SCHEMA = "rampage-decompiler-corpus-report-v1"
ASSERTION_CATEGORIES = {
    "expected_contains": "text",
    "expected_not_contains": "text",
    "expected_params": "signature",
    "expected_signature": "signature",
    "expected_calls": "calls",
    "expected_strings": "strings",
    "expected_switch_targets": "switch",
    "expected_switch_case_values": "switch",
}


class CorpusError(Exception):
    """Invalid corpus or reference input."""


@dataclass
class Case:
    case_id: str
    image: Path
    function: str
    arch: str | None = None
    compiler: str | None = None
    assertions: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    reference_source: str | None = None


@dataclass
class Capture:
    data: bytearray = field(default_factory=bytearray)
    total_bytes: int = 0
    exceeded: bool = False
    error: str | None = None
    cleanup_error: str | None = None


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def parse_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"non-finite JSON number {value}")
    return number


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=reject_json_constant,
            parse_float=parse_json_float,
        )
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        raise CorpusError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise CorpusError(f"{path}: expected a JSON object")
    return value


def require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CorpusError(f"{context}: expected a nonempty string")
    return value


def validate_assertions(value: dict[str, Any], context: str) -> dict[str, Any]:
    assertions = {
        key: item for key, item in value.items() if key in ASSERTION_CATEGORIES
    }
    unknown = [
        key
        for key in value
        if key.startswith("expected_") and key not in ASSERTION_CATEGORIES
    ]
    if unknown:
        raise CorpusError(f"{context}: unknown assertions {unknown}")
    for key, expected in assertions.items():
        if key == "expected_signature":
            if not isinstance(expected, dict) or not expected:
                raise CorpusError(f"{context}.{key}: expected a nonempty object")
            if set(expected) - {"return_type", "calling_convention", "variadic"}:
                raise CorpusError(f"{context}.{key}: unknown signature field")
            for name, item in expected.items():
                if name == "variadic" and not isinstance(item, bool):
                    raise CorpusError(f"{context}.{key}.variadic: expected a boolean")
                if name == "return_type":
                    require_string(item, f"{context}.{key}.{name}")
                if name == "calling_convention" and item is not None:
                    require_string(item, f"{context}.{key}.{name}")
        elif key == "expected_params":
            if (
                isinstance(expected, int)
                and not isinstance(expected, bool)
                and expected >= 0
            ):
                continue
            if not isinstance(expected, list):
                raise CorpusError(
                    f"{context}.{key}: expected a count or ordered parameter list"
                )
            for parameter in expected:
                if (
                    not isinstance(parameter, dict)
                    or not parameter
                    or set(parameter) - {"name", "type"}
                ):
                    raise CorpusError(
                        f"{context}.{key}: parameter fields are name and type"
                    )
                for name, item in parameter.items():
                    require_string(item, f"{context}.{key}.{name}")
        elif key == "expected_calls":
            if not isinstance(expected, list):
                raise CorpusError(f"{context}.{key}: expected a list")
            for call in expected:
                if (
                    not isinstance(call, dict)
                    or not call
                    or set(call) - {"name", "target", "indirect"}
                ):
                    raise CorpusError(
                        f"{context}.{key}: call fields are name, target and indirect"
                    )
                for name, item in call.items():
                    if name == "indirect":
                        if not isinstance(item, bool):
                            raise CorpusError(
                                f"{context}.{key}.indirect: expected a boolean"
                            )
                    elif name == "target":
                        parse_address(item)
                    else:
                        require_string(item, f"{context}.{key}.{name}")
        else:
            if not isinstance(expected, list):
                raise CorpusError(f"{context}.{key}: expected a list")
            for item in expected:
                if key == "expected_switch_targets":
                    parse_address(item)
                elif key == "expected_switch_case_values":
                    if not isinstance(item, int) or isinstance(item, bool) or item < 0:
                        raise CorpusError(
                            f"{context}.{key}: expected unsigned integer bit patterns"
                        )
                else:
                    require_string(item, f"{context}.{key}")
    return assertions


def parse_address(value: Any) -> int:
    try:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise TypeError("not an integer or address string")
        address = int(value, 0) if isinstance(value, str) else value
        if address < 0:
            raise ValueError("negative address")
        return address
    except (TypeError, ValueError) as error:
        raise CorpusError(f"invalid address {value!r}: {error}") from error


def numeric_selector_address(selector: str) -> int | None:
    text = selector.strip()
    if text.lower().startswith("0x"):
        return parse_address(text)
    try:
        address = int(text, 10)
    except ValueError:
        return None
    return parse_address(address)


def validate_output_path(output: Path, protected: set[Path]) -> None:
    resolved = output.resolve()
    if resolved in protected:
        raise CorpusError(
            "output must not overwrite the executable, an image, manifest or baseline"
        )
    if output.exists():
        for path in protected:
            try:
                same_file = output.samefile(path)
            except FileNotFoundError:
                continue
            if same_file:
                raise CorpusError(
                    f"output is a hard link or alias of protected input {path}"
                )


def load_manifest(path: Path) -> tuple[list[Case], dict[str, Any]]:
    manifest = read_json(path)
    if manifest.get("schema") != MANIFEST_SCHEMA or not isinstance(
        manifest.get("cases"), list
    ):
        raise CorpusError(f"{path}: expected schema {MANIFEST_SCHEMA} and a cases list")
    metadata = manifest.get("metadata", {})
    if not isinstance(metadata, dict):
        raise CorpusError(f"{path}: metadata must be an object")
    cases = []
    for index, value in enumerate(manifest["cases"]):
        context = f"{path}: cases[{index}]"
        if not isinstance(value, dict):
            raise CorpusError(f"{context}: expected an object")
        case_metadata = value.get("metadata", {})
        if not isinstance(case_metadata, dict):
            raise CorpusError(f"{context}: metadata must be an object")
        cases.append(
            Case(
                case_id=require_string(value.get("id"), f"{context}.id"),
                image=(
                    path.parent / require_string(value.get("image"), f"{context}.image")
                ).resolve(),
                function=require_string(value.get("function"), f"{context}.function"),
                arch=require_string(value["arch"], f"{context}.arch")
                if "arch" in value
                else None,
                compiler=require_string(value["compiler"], f"{context}.compiler")
                if "compiler" in value
                else None,
                assertions=validate_assertions(value, context),
                metadata=case_metadata,
                reference_source=(
                    require_string(
                        value["reference_source"], f"{context}.reference_source"
                    )
                    if "reference_source" in value
                    else None
                ),
            )
        )
    validate_case_ids(cases)
    return cases, metadata


def validate_case_ids(cases: list[Case]) -> None:
    identifiers = [case.case_id for case in cases]
    if len(set(identifiers)) != len(identifiers):
        raise CorpusError("case IDs must be unique")


def load_baseline(path: Path) -> dict[str, Any]:
    baseline = read_json(path)
    if baseline.get("schema") != BASELINE_SCHEMA or not isinstance(
        baseline.get("cases"), list
    ):
        raise CorpusError(f"{path}: expected schema {BASELINE_SCHEMA} and a cases list")
    reference = baseline.get("reference")
    if not isinstance(reference, dict):
        raise CorpusError(f"{path}: reference must identify the tool and version")
    require_string(reference.get("tool"), f"{path}: reference.tool")
    require_string(reference.get("version"), f"{path}: reference.version")
    if not isinstance(baseline.get("settings"), dict):
        raise CorpusError(f"{path}: settings must be an object")
    identifiers = set()
    for value in baseline["cases"]:
        if not isinstance(value, dict):
            raise CorpusError(f"{path}: baseline case must be an object")
        identifier = require_string(value.get("id"), f"{path}: case.id")
        if identifier in identifiers:
            raise CorpusError(f"{path}: duplicate baseline ID {identifier}")
        identifiers.add(identifier)
        digest = require_string(
            value.get("image_sha256"), f"{path}: {identifier}.image_sha256"
        )
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise CorpusError(
                f"{path}: {identifier}: image_sha256 must be 64 lowercase hex digits"
            )
        require_string(value.get("function"), f"{path}: {identifier}.function")
        parse_address(value.get("address"))
        require_string(value.get("language_id"), f"{path}: {identifier}.language_id")
        for key in ("arch", "compiler"):
            if key not in value:
                raise CorpusError(
                    f"{path}: {identifier}.{key} must be explicit (string or null)"
                )
            if value[key] is not None:
                require_string(value[key], f"{path}: {identifier}.{key}")
        validate_assertions(value, f"{path}: {identifier}")
    return baseline


def hash_file(path: Path) -> str:
    try:
        with path.open("rb") as source:
            digest = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise CorpusError(f"cannot hash {path}: {error}") from error


def stop_process(process: subprocess.Popen[bytes]) -> str | None:
    group_error = None
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return None
        except OSError as error:
            group_error = str(error)
    if process.poll() is not None:
        return None
    try:
        process.kill()
    except OSError as error:
        if process.poll() is None:
            return f"cannot terminate live subprocess {process.pid}: {error}; process-group error: {group_error}"
    return None


def drain_output(
    stream: BinaryIO, capture: Capture, limit: int, process: subprocess.Popen[bytes]
) -> None:
    try:
        with stream:
            while chunk := stream.read(65536):
                capture.total_bytes += len(chunk)
                remaining = max(0, limit - len(capture.data))
                capture.data.extend(chunk[:remaining])
                if capture.total_bytes > limit and not capture.exceeded:
                    capture.exceeded = True
                    capture.cleanup_error = stop_process(process)
    except (OSError, ValueError) as error:
        capture.error = f"cannot drain subprocess output: {error}"
        capture.cleanup_error = stop_process(process)


def child_usage() -> dict[str, float] | None:
    if resource is None:
        return None
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    multiplier = 1 if sys.platform == "darwin" else 1024
    return {
        "user_seconds": usage.ru_utime,
        "system_seconds": usage.ru_stime,
        "max_rss_bytes_high_water": usage.ru_maxrss * multiplier,
    }


def run_process(
    command: list[str], timeout: float, output_limit: int
) -> dict[str, Any]:
    stdout = Capture()
    stderr = Capture()
    before = child_usage()
    started = time.perf_counter()
    failure = None
    returncode = None
    readers: list[threading.Thread] = []
    cleanup_errors: list[str] = []
    try:
        with ExitStack() as streams:
            stdout_read, stdout_write = os.pipe()
            stdout_stream = streams.enter_context(
                os.fdopen(stdout_read, "rb", buffering=0)
            )
            stdout_writer = streams.enter_context(os.fdopen(stdout_write, "wb"))
            stderr_read, stderr_write = os.pipe()
            stderr_stream = streams.enter_context(
                os.fdopen(stderr_read, "rb", buffering=0)
            )
            stderr_writer = streams.enter_context(os.fdopen(stderr_write, "wb"))
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_writer,
                    stderr=stderr_writer,
                    start_new_session=os.name == "posix",
                )
            finally:
                stdout_writer.close()
                stderr_writer.close()
            for stream, capture in ((stdout_stream, stdout), (stderr_stream, stderr)):
                reader = threading.Thread(
                    target=drain_output,
                    args=(stream, capture, output_limit, process),
                    daemon=True,
                )
                reader.start()
                readers.append(reader)
            try:
                process.communicate(
                    timeout=max(0, timeout - (time.perf_counter() - started))
                )
            except subprocess.TimeoutExpired:
                failure = "timeout"
                if error := stop_process(process):
                    cleanup_errors.append(error)
                try:
                    process.communicate(timeout=1.0)
                except subprocess.TimeoutExpired:
                    cleanup_errors.append(
                        f"subprocess {process.pid} still alive after termination attempt"
                    )
            for reader in readers:
                reader.join(max(0, timeout - (time.perf_counter() - started)))
            if any(reader.is_alive() for reader in readers):
                failure = failure or "timeout"
                if error := stop_process(process):
                    cleanup_errors.append(error)
                cleanup_deadline = time.perf_counter() + 1.0
                for reader in readers:
                    reader.join(max(0, cleanup_deadline - time.perf_counter()))
                if any(reader.is_alive() for reader in readers):
                    cleanup_errors.append(
                        "output readers still active after termination attempt"
                    )
            returncode = process.returncode
    except OSError as error:
        failure = f"spawn_error: {error}"
    after = child_usage()
    cleanup_errors += [
        capture.cleanup_error for capture in (stdout, stderr) if capture.cleanup_error
    ]
    if stdout.exceeded or stderr.exceeded:
        failure = "output_limit"
    elif stdout.error or stderr.error:
        failure = stdout.error or stderr.error
    elif failure is None and returncode != 0:
        failure = (
            "signal" if returncode is not None and returncode < 0 else "nonzero_exit"
        )
    usage = None
    if before is not None and after is not None:
        usage = {
            "children_user_seconds_delta": after["user_seconds"]
            - before["user_seconds"],
            "children_system_seconds_delta": after["system_seconds"]
            - before["system_seconds"],
            "children_max_rss_bytes_high_water": after["max_rss_bytes_high_water"],
        }
    return {
        "failure": failure,
        "returncode": returncode,
        "elapsed_seconds": time.perf_counter() - started,
        "stdout_bytes": stdout.total_bytes,
        "stderr_bytes": stderr.total_bytes,
        "stdout": bytes(stdout.data),
        "stderr": bytes(stderr.data).decode("utf-8", errors="replace"),
        "resources": usage,
        "cleanup_errors": list(dict.fromkeys(cleanup_errors)),
    }


def validate_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CorpusError("decompile JSON must be an object")
    parse_address(value.get("address"))
    for key in ("code", "name", "language_id"):
        if not isinstance(value.get(key), str):
            raise CorpusError(f"decompile JSON needs string {key}")
        try:
            value[key].encode("utf-8")
        except UnicodeError as error:
            raise CorpusError(f"decompile JSON has invalid UTF-8 {key}") from error
    if not value["code"].strip() or not value["language_id"].strip():
        raise CorpusError("decompile JSON needs nonempty code and language_id")
    tokens = value.get("tokens")
    if not isinstance(tokens, list) or any(
        not isinstance(token, dict) or not isinstance(token.get("kind"), str)
        for token in tokens
    ):
        raise CorpusError("decompile JSON needs a tokens list with string kinds")
    structure = value.get("structure")
    if not isinstance(structure, dict) or not isinstance(
        structure.get("signature"), dict
    ):
        raise CorpusError("decompile JSON needs structure.signature")
    signature = structure["signature"]
    if not isinstance(signature.get("variadic"), bool):
        raise CorpusError("decompile JSON needs a boolean signature.variadic")
    if "calling_convention" not in signature or (
        signature["calling_convention"] is not None
        and not isinstance(signature["calling_convention"], str)
    ):
        raise CorpusError(
            "decompile JSON needs a string or null signature.calling_convention"
        )
    if not isinstance(signature.get("return_type"), dict) or not isinstance(
        signature["return_type"].get("name"), str
    ):
        raise CorpusError("decompile JSON needs a signature return type")
    parameters = signature.get("parameters")
    if not isinstance(parameters, list) or any(
        not isinstance(parameter, dict)
        or not isinstance(parameter.get("name"), str)
        or not isinstance(parameter.get("data_type"), dict)
        or not isinstance(parameter["data_type"].get("name"), str)
        for parameter in parameters
    ):
        raise CorpusError("decompile JSON needs typed signature parameters")
    for key in ("blocks", "calls", "jump_tables"):
        if not isinstance(structure.get(key), list) or any(
            not isinstance(item, dict) for item in structure[key]
        ):
            raise CorpusError(f"decompile JSON needs a structure.{key} object list")
    block_indices = set()
    for block in structure["blocks"]:
        index = block.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise CorpusError("decompile JSON needs nonnegative integer block indices")
        if index in block_indices:
            raise CorpusError("decompile JSON needs unique block indices")
        block_indices.add(index)
        for key in ("start", "end"):
            if key not in block:
                raise CorpusError(f"decompile JSON needs block.{key}")
            if block[key] is not None:
                parse_address(block[key])
        if (
            block["start"] is not None
            and block["end"] is not None
            and parse_address(block["end"]) < parse_address(block["start"])
        ):
            raise CorpusError("decompile JSON block end must not precede start")
        successors = block.get("successors")
        if not isinstance(successors, list) or any(
            not isinstance(index, int) or isinstance(index, bool) or index < 0
            for index in successors
        ):
            raise CorpusError(
                "decompile JSON needs nonnegative integer block successors"
            )
    if any(
        index not in block_indices
        for block in structure["blocks"]
        for index in block["successors"]
    ):
        raise CorpusError(
            "decompile JSON block successors must reference recovered block indices"
        )
    for call in structure["calls"]:
        if "target" not in call or not isinstance(call.get("indirect"), bool):
            raise CorpusError("decompile JSON needs call target and indirect fields")
        if call["target"] is not None:
            parse_address(call["target"])
        if call.get("name") is not None and not isinstance(call["name"], str):
            raise CorpusError("decompile JSON needs string or null call names")
    for table in structure["jump_tables"]:
        if "switch_address" not in table:
            raise CorpusError("decompile JSON needs jump table switch_address")
        if table["switch_address"] is not None:
            parse_address(table["switch_address"])
        if not isinstance(table.get("partial"), bool):
            raise CorpusError("decompile JSON needs boolean jump table partial")
        if not isinstance(table.get("targets"), list):
            raise CorpusError("decompile JSON needs jump table targets")
        for target in table["targets"]:
            parse_address(target)
        if not isinstance(table.get("case_values", []), list):
            raise CorpusError("decompile JSON needs a jump table case_values list")
        if table.get("case_values") and len(table["case_values"]) != len(
            table["targets"]
        ):
            raise CorpusError(
                "decompile JSON jump table case_values must be empty or aligned with targets"
            )
        for label in table.get("case_values", []):
            if label is not None and (
                not isinstance(label, int) or isinstance(label, bool) or label < 0
            ):
                raise CorpusError(
                    "decompile JSON needs unsigned integer or null switch case values"
                )
    return value


def evaluate_assertions(
    assertions: dict[str, Any],
    result: dict[str, Any] | None,
    source: str,
    unavailable: str | None,
) -> list[dict[str, Any]]:
    checks = []
    structure = result["structure"] if result is not None else None
    for key, expected in assertions.items():
        items = (
            [expected] if key in {"expected_params", "expected_signature"} else expected
        )
        for item in items:
            passed = None
            unavailable_reason = unavailable
            if result is not None and unavailable is None and structure is not None:
                code = result["code"]
                signature = structure["signature"]
                if key in {"expected_contains", "expected_strings"}:
                    passed = item in code
                elif key == "expected_not_contains":
                    passed = item not in code
                elif key == "expected_params":
                    parameters = signature["parameters"]
                    observed = [
                        {"name": value["name"], "type": value["data_type"]["name"]}
                        for value in parameters
                    ]
                    passed = (
                        len(parameters) == item
                        if isinstance(item, int)
                        else len(observed) == len(item)
                        and all(
                            all(actual[name] == value for name, value in want.items())
                            for actual, want in zip(observed, item)
                        )
                    )
                elif key == "expected_signature":
                    observed_signature = {
                        "return_type": signature["return_type"]["name"],
                        "calling_convention": signature.get("calling_convention"),
                        "variadic": signature.get("variadic"),
                    }
                    passed = all(
                        observed_signature[name] == value
                        for name, value in item.items()
                    )
                elif key == "expected_calls":
                    passed = any(
                        all(
                            parse_address(call[name]) == parse_address(value)
                            if name == "target" and call.get(name) is not None
                            else call.get(name) == value
                            for name, value in item.items()
                        )
                        for call in structure["calls"]
                    )
                elif key == "expected_switch_targets":
                    passed = any(
                        parse_address(target) == parse_address(item)
                        for table in structure["jump_tables"]
                        for target in table["targets"]
                    )
                elif key == "expected_switch_case_values":
                    passed = any(
                        item in table.get("case_values", [])
                        for table in structure["jump_tables"]
                    )
                    if not passed and any(
                        table["targets"] and not table.get("case_values")
                        for table in structure["jump_tables"]
                    ):
                        passed = None
                        unavailable_reason = "switch_case_values_unavailable"
            checks.append(
                {
                    "source": source,
                    "category": ASSERTION_CATEGORIES[key],
                    "assertion": key,
                    "expected": item,
                    "passed": passed,
                    "unavailable_reason": unavailable_reason
                    if passed is None
                    else None,
                }
            )
    return checks


def run_case(
    executable: str,
    case: Case,
    timeout: float,
    output_limit: int,
    isolated: bool,
    baseline_case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    command = [executable, "--json"]
    if case.arch is not None:
        command += ["--arch", case.arch]
    command += ["decompile", str(case.image), "--at", case.function]
    if case.compiler is not None:
        command += ["--compiler", case.compiler]
    if isolated:
        command.append("--isolated")
    record: dict[str, Any] = {
        "id": case.case_id,
        "image": str(case.image),
        "image_sha256": None,
        "function": case.function,
        "actual_address": None,
        "arch": case.arch,
        "compiler_requested": case.compiler,
        "metadata": case.metadata,
        "reference_source": case.reference_source,
        "command": command,
        "success": False,
        "failure": None,
        "returncode": None,
        "stderr": "",
        "elapsed_seconds": None,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "resources": None,
        "cleanup_errors": [],
        "metrics": None,
    }
    result = None
    try:
        record["image_sha256"] = hash_file(case.image)
    except CorpusError as error:
        record["failure"] = f"image_error: {error}"
    else:
        execution = run_process(command, timeout, output_limit)
        stdout = execution.pop("stdout")
        record.update(execution)
        if record["failure"] is None:
            try:
                result = validate_result(
                    json.loads(
                        stdout,
                        parse_constant=reject_json_constant,
                        parse_float=parse_json_float,
                    )
                )
            except (ValueError, UnicodeError, CorpusError, RecursionError) as error:
                record["failure"] = f"malformed_json: {error}"
            else:
                actual_address = parse_address(result["address"])
                record["actual_address"] = hex(actual_address)
                try:
                    requested_address = numeric_selector_address(case.function)
                except CorpusError as error:
                    record["failure"] = f"selector_error: {error}"
                else:
                    if (
                        requested_address is not None
                        and requested_address != actual_address
                    ):
                        record["failure"] = (
                            f"address_mismatch: requested {requested_address:#x}, returned {actual_address:#x}"
                        )
                    else:
                        record["success"] = True
                structure = result["structure"]
                record["metrics"] = {
                    "name": result["name"],
                    "language_id": result["language_id"],
                    "compiler_id": result["language_id"].rsplit(":", 1)[-1],
                    "warning_lines": sum(
                        "WARNING:" in line for line in result["code"].splitlines()
                    ),
                    "stderr_warning_lines": sum(
                        "WARNING:" in line for line in record["stderr"].splitlines()
                    ),
                    "code_bytes": len(result["code"].encode("utf-8")),
                    "signature": structure["signature"],
                    "parameter_count": len(structure["signature"]["parameters"]),
                    "calls": structure["calls"],
                    "call_count": len(structure["calls"]),
                    "typed_call_count": None,
                    "token_count": len(result["tokens"]),
                    "token_counts_by_kind": dict(
                        sorted(
                            Counter(token["kind"] for token in result["tokens"]).items()
                        )
                    ),
                    "recovered_block_count": len(structure["blocks"]),
                    "switch_count": len(structure["jump_tables"]),
                    "switch_target_count": sum(
                        len(table["targets"]) for table in structure["jump_tables"]
                    ),
                    "switches": structure["jump_tables"],
                }
    checks = evaluate_assertions(case.assertions, result, "fixture", record["failure"])
    baseline_status = "not_provided"
    if baseline_case is not None:
        identity = {
            "image_sha256": record["image_sha256"],
            "function": case.function,
            "arch": case.arch,
            "compiler": case.compiler,
        }
        mismatches = [
            key for key, value in identity.items() if baseline_case[key] != value
        ]
        if result is not None and baseline_case["language_id"] != result["language_id"]:
            mismatches.append("language_id")
        if result is not None and parse_address(
            baseline_case["address"]
        ) != parse_address(result["address"]):
            mismatches.append("address")
        baseline_status = (
            "identity_mismatch"
            if mismatches
            else "matched"
            if record["success"]
            else "unavailable"
        )
        record["baseline_identity_mismatches"] = mismatches
        record["baseline_reference_source"] = baseline_case.get("reference_source")
        checks += evaluate_assertions(
            validate_assertions(baseline_case, case.case_id),
            result,
            "baseline",
            "baseline_identity_mismatch" if mismatches else record["failure"],
        )
    record["baseline_status"] = baseline_status
    record["checks"] = checks
    record["case_passed"] = (
        record["success"]
        and baseline_status not in {"identity_mismatch", "unavailable"}
        and all(check["passed"] is True for check in checks)
    )
    return record


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    checks = [check for record in records for check in record["checks"]]

    def summarize_checks(selected: list[dict[str, Any]]) -> dict[str, Any]:
        total = len(selected)
        passed = sum(check["passed"] is True for check in selected)
        failed = sum(check["passed"] is False for check in selected)
        evaluated = passed + failed
        return {
            "total": total,
            "evaluated": evaluated,
            "passed": passed,
            "failed": failed,
            "unavailable": total - evaluated,
            "passed_over_total": passed / total if total else None,
            "passed_over_evaluated": passed / evaluated if evaluated else None,
        }

    successful = sum(record["success"] for record in records)
    return {
        "case_count": len(records),
        "successful_cases": successful,
        "failed_cases": len(records) - successful,
        "passed_cases": sum(record["case_passed"] for record in records),
        "success_rate": successful / len(records) if records else None,
        "assertions": summarize_checks(checks),
        "assertions_by_category": {
            category: summarize_checks(
                [check for check in checks if check["category"] == category]
            )
            for category in sorted(set(ASSERTION_CATEGORIES.values()))
        },
        "assertions_by_source": {
            source: summarize_checks(
                [check for check in checks if check["source"] == source]
            )
            for source in ("fixture", "baseline")
        },
        "baseline_status_counts": dict(
            sorted(Counter(record["baseline_status"] for record in records).items())
        ),
        "elapsed_seconds_total": sum(
            record["elapsed_seconds"] or 0 for record in records
        ),
        "stdout_bytes_total": sum(record["stdout_bytes"] for record in records),
        "warning_lines_total": sum(
            record["metrics"]["warning_lines"]
            for record in records
            if record["success"]
        ),
        "warning_lines_case_denominator": successful,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rampage", help="CLI executable path or name on PATH")
    parser.add_argument(
        "--case", nargs=2, action="append", default=[], metavar=("IMAGE", "FUNCTION")
    )
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="wall-clock seconds per case"
    )
    parser.add_argument(
        "--max-output-bytes",
        type=int,
        default=16 * 1024 * 1024,
        help="limit for each output stream",
    )
    parser.add_argument(
        "--isolated", action="store_true", help="also pass --isolated to the CLI"
    )
    parser.add_argument(
        "--arch", help="default architecture selection; a manifest case can override it"
    )
    parser.add_argument(
        "--compiler", help="default compiler selection; a manifest case can override it"
    )
    arguments = parser.parse_args(argv)
    if (
        not math.isfinite(arguments.timeout)
        or arguments.timeout <= 0
        or arguments.max_output_bytes <= 0
    ):
        parser.error(
            "timeout must be finite and positive; max-output-bytes must be positive"
        )
    try:
        cases, metadata = (
            load_manifest(arguments.manifest) if arguments.manifest else ([], {})
        )
        cases += [
            Case(f"cli-{index + 1}", Path(image).resolve(), function)
            for index, (image, function) in enumerate(arguments.case)
        ]
        if not cases:
            raise CorpusError("provide at least one --case or a nonempty --manifest")
        validate_case_ids(cases)
        for case in cases:
            case.arch = case.arch or arguments.arch
            case.compiler = case.compiler or arguments.compiler
        baseline = load_baseline(arguments.baseline) if arguments.baseline else None
        baseline_cases = (
            {case["id"]: case for case in baseline["cases"]} if baseline else {}
        )
        unknown = set(baseline_cases) - {case.case_id for case in cases}
        if unknown:
            raise CorpusError(f"baseline IDs absent from corpus: {sorted(unknown)}")
        executable = shutil.which(arguments.rampage)
        if executable is None:
            raise CorpusError(
                f"CLI executable not found or not executable: {arguments.rampage}"
            )
        executable = str(Path(executable).resolve())
        protected = {Path(executable), *(case.image.resolve() for case in cases)}
        protected.update(
            path.resolve() for path in (arguments.manifest, arguments.baseline) if path
        )
        if arguments.output:
            validate_output_path(arguments.output, protected)
        executable_hash = hash_file(Path(executable))
        records = [
            run_case(
                executable,
                case,
                arguments.timeout,
                arguments.max_output_bytes,
                arguments.isolated,
                baseline_cases.get(case.case_id),
            )
            for case in cases
        ]
        report = {
            "schema": REPORT_SCHEMA,
            "runner": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "rampage": {"path": executable, "sha256": executable_hash},
            "settings": {
                "timeout_seconds": arguments.timeout,
                "max_output_bytes_per_stream": arguments.max_output_bytes,
                "isolated": arguments.isolated,
                "process_per_case": True,
            },
            "metadata": metadata,
            "baseline": {
                key: value for key, value in baseline.items() if key != "cases"
            }
            if baseline
            else None,
            "limitations": [
                "Assertions measure selected recovered facts or literal text, not semantic equivalence.",
                "Call prototypes are not exported; typed_call_count is unavailable, not zero.",
                "String assertions test literal rendered text, not a recovered-string inventory.",
                "Child CPU deltas cover reaped children; max RSS is a cumulative high-water, not per-case memory.",
                "Reference identity checks do not establish matched analysis mappings, types or options.",
            ],
            "cases": records,
            "aggregate": aggregate(records),
        }
        rendered = json.dumps(report, indent=2, allow_nan=False) + "\n"
        if arguments.output:
            validate_output_path(arguments.output, protected)
            arguments.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0 if all(record["case_passed"] for record in records) else 1
    except (CorpusError, OSError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
