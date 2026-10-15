"""Compare bounded, owned C++ methods using checked consumer inputs, never target execution."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import platform
import re
import select
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from itertools import pairwise
from pathlib import Path
from types import FrameType
from typing import Any, NoReturn

MAX_IMAGE = 1024 * 1024
MAX_EXECUTABLE = 512 * MAX_IMAGE
MAX_TEXT = 1024 * 1024
MAX_STDERR = 64 * 1024
MAX_METHODS = 128
MAX_METHOD_TEXT = MAX_TEXT // MAX_METHODS
SAMPLE_INTERVAL = 0.05
LANGUAGE = "x86:LE:64:default"
ORGANIZATION = {
    "pointer_size": 8,
    "int_size": 4,
    "long_size": 8,
    "scalar_alignments": [1, 2, 4, 8],
}
OPTIONS = {
    "respect_readonly": False,
    "protoeval": "default",
    "max_instructions": 100000,
    "max_jumptable": 1024,
    "simplification": "decompile",
    "c_code": True,
    "syntax_tree": True,
}
OPAQUE_POINTER = {
    "kind": "pointer",
    "name": "",
    "size": 8,
    "alignment": 8,
    "pointee": {"name": "void", "kind": "void", "size": 0, "alignment": 1},
}
OPAQUE_STORAGE_ROLE = "opaque_projection_storage_not_exact_producer_type"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMP = Path(tempfile.gettempdir())


class CorpusError(Exception):
    """Missing, inconsistent or unsupported benchmark evidence."""


class CorpusInterrupted(Exception):
    """Catchable cancellation that must unwind the entire lane, not only one method."""


def interrupt(signum: int, _frame: FrameType | None) -> NoReturn:
    raise CorpusInterrupted(f"runner interrupted by signal {signum}")


def require(condition: Any, message: str) -> None:
    if not condition:
        raise CorpusError(message)


def object_value(value: Any, context: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{context}: expected object")
    return value


def array_value(value: Any, context: str) -> list[Any]:
    require(isinstance(value, list), f"{context}: expected array")
    return value


def string_value(value: Any, context: str) -> str:
    require(
        isinstance(value, str) and bool(value), f"{context}: expected nonempty string"
    )
    return value


def integer(value: Any, context: str, maximum: int = (1 << 63) - 1) -> int:
    require(
        type(value) is int and 0 <= value <= maximum,
        f"{context}: invalid bounded integer",
    )
    return value


def address(value: Any) -> int:
    if isinstance(value, str):
        require(
            re.fullmatch(r"0x[0-9a-fA-F]+", value),
            "expected explicit hexadecimal address",
        )
        return integer(int(value, 16), "address")
    return integer(value, "address")


def identifier(value: Any) -> str:
    name = string_value(value, "identifier")
    require(
        re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,127}", name),
        f"invalid identifier: {name!r}",
    )
    return name


def match_text(pattern: str, text: str, context: str) -> re.Match[str]:
    result = re.fullmatch(pattern, text)
    if result is None:
        raise CorpusError(context)
    return result


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def fingerprint(value: Any) -> str:
    return digest_bytes(canonical(value))


def digest_value(value: Any, context: str) -> str:
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
        f"{context}: invalid SHA-256",
    )
    return value


def bounded_read(path: Path, maximum: int) -> bytes:
    try:
        require(path.is_file(), f"not a regular input file: {path}")
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as error:
        raise CorpusError(f"cannot read {path}: {error}") from error
    require(len(data) <= maximum, f"input exceeds {maximum} bytes: {path}")
    return data


def file_digest(path: Path, maximum: int) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        before = path.stat()
        require(
            path.is_file() and before.st_size <= maximum, f"binary input bound: {path}"
        )
        with path.open("rb") as stream:
            while block := stream.read(65536):
                total += len(block)
                require(total <= maximum, f"binary grew beyond bound: {path}")
                digest.update(block)
        after = path.stat()
        attributes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(
            all(getattr(before, name) == getattr(after, name) for name in attributes)
            and total == before.st_size,
            f"binary changed during hashing: {path}",
        )
    except OSError as error:
        raise CorpusError(f"cannot hash executable {path}: {error}") from error
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise CorpusError(f"non-finite JSON number: {value}")


def json_float(value: str) -> float:
    result = float(value)
    require(math.isfinite(result), "non-finite JSON exponent")
    return result


def json_integer(value: str) -> int:
    require(len(value.lstrip("-")) <= 20, "JSON integer exceeds 64-bit text bound")
    return int(value)


def decode_json(data: bytes, context: str) -> dict[str, Any]:
    require(len(data) <= 4 * MAX_TEXT, f"{context}: JSON exceeds bound")
    try:
        value = json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=json_float,
            parse_int=json_integer,
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise CorpusError(f"{context}: invalid JSON: {error}") from error
    return object_value(value, context)


def read_json(path: Path) -> dict[str, Any]:
    return decode_json(bounded_read(path, 4 * MAX_TEXT), str(path))


@dataclass
class ProcessResult:
    command: list[str]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    wall_seconds: float
    failure: str | None
    max_observed_summed_rss_bytes: int | None
    rss_samples: int
    rss_sampling_errors: list[str] = dataclass_field(default_factory=list)
    rss_attempts: int = 0
    rss_no_group_samples: int = 0
    rss_zero_samples: int = 0
    supervision: str = "unavailable_or_fake"
    observed_owned_pids: list[int] = dataclass_field(default_factory=list)
    observed_owned_groups: list[int] = dataclass_field(default_factory=list)
    guardian_returncode: int | None = None
    owned_group: int | None = None
    observed_escaped_pids: list[int] = dataclass_field(default_factory=list)

    def metadata(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
            "wall_seconds": self.wall_seconds,
            "failure": self.failure,
            "stderr": self.stderr.decode("utf-8", "replace"),
            "stdout_bytes": len(self.stdout),
            "supervision": {
                "method": self.supervision,
                "guardian_returncode": self.guardian_returncode,
                "owned_group": self.owned_group,
                "startup": "guardian armed before tool fork/pre-exec/exec; no synchronous Popen handoff",
                "limits": (
                    "single-threaded POSIX; no real-time guarantee for OS fork, scheduling "
                    "or unkillable kernel waits"
                ),
                "cleanup": (
                    "parent retains its guardian child unreaped through the final owned-group signal; "
                    "faulted tool/sampler descendants use their OS-designated reaper"
                ),
            },
            "rss": {
                "metric": "max_observed_summed_rss_supported_tool_group",
                "bytes": self.max_observed_summed_rss_bytes,
                "samples": self.rss_samples,
                "status": "observed" if self.rss_samples else "unavailable",
                "attempts": self.rss_attempts,
                "no_owned_group_samples": self.rss_no_group_samples,
                "zero_rss_owned_group_samples": self.rss_zero_samples,
                "interval_seconds": SAMPLE_INTERVAL,
                "interval_semantics": "minimum delay after a completed snapshot; ps duration and scheduling add jitter",
                "platform": platform.system(),
                "source": "/bin/ps -axo pid=,ppid=,pgid=,rss=,lstart=,stat= (KiB)",
                "observed_owned_pids": self.observed_owned_pids,
                "observed_owned_groups": self.observed_owned_groups,
                "observed_escaped_pids": self.observed_escaped_pids,
                "ownership": (
                    "observed members of held guardian group; guardian/sampler excluded; "
                    "ancestry detects escapes only"
                ),
                "ownership_limits": "separate-group descendants are unsupported, excluded from RSS and never signalled",
                "errors": self.rss_sampling_errors,
                "limitation": "sampled shared-inclusive RSS sum, not a guaranteed or private peak",
            },
        }


def parse_rss(text: str, process_group: int) -> int | None:
    total = 0
    found = False
    for line in text.splitlines():
        columns = line.split()
        require(
            len(columns) == 2 and all(item.isdecimal() for item in columns),
            "malformed ps RSS row",
        )
        if int(columns[0]) == process_group:
            found = True
            total += int(columns[1]) * 1024
    return total if found else None


def kill_owned_group(process_group: int) -> None:
    """Signal a direct child group only while its leader remains unreaped by this caller."""
    require(
        process_group > 1 and process_group != os.getpgrp(),
        "refusing unowned process group",
    )
    owned_child_ended(process_group)
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return


CANCELLATION_SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


@dataclass(frozen=True)
class ProcessObservation:
    pid: int
    parent: int
    group: int
    rss_bytes: int
    started: str
    status: str


def parse_process_snapshot(text: str) -> dict[int, ProcessObservation]:
    result = {}
    for line in text.splitlines():
        columns = line.split()
        require(
            len(columns) == 10 and all(item.isdecimal() for item in columns[:4]),
            "malformed process snapshot",
        )
        pid, parent, group, resident = (int(item) for item in columns[:4])
        require(pid not in result, "duplicate process snapshot PID")
        result[pid] = ProcessObservation(
            pid, parent, group, resident * 1024, " ".join(columns[4:9]), columns[9]
        )
    return result


def update_owned_processes(
    snapshot: dict[int, ProcessObservation],
    root: int,
    known: dict[int, ProcessObservation],
) -> dict[int, ProcessObservation]:
    current = {
        pid: observation
        for pid, observation in snapshot.items()
        if pid in known and observation.started == known[pid].started
    }
    if root in snapshot and (
        root not in known or snapshot[root].started == known[root].started
    ):
        current[root] = snapshot[root]
    while True:
        added = {
            pid: observation
            for pid, observation in snapshot.items()
            if pid not in current and observation.parent in current
        }
        if not added:
            break
        current.update(added)
        require(len(current) <= 128, "owned descendant process count bound")
    known.update(current)
    require(len(known) <= 128, "observed descendant process count bound")
    return current


def owned_child_ended(pid: int) -> bool:
    exited = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    return exited is not None and exited.si_pid == pid


def reap_direct_child(pid: int, timeout: float) -> int | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited:
            return os.waitstatus_to_exitcode(status)
        select.select([], [], [], min(0.005, max(0, deadline - time.monotonic())))
    return None


def unavailable_resources(message: str) -> dict[str, Any]:
    return {
        "maximum": None,
        "samples": 0,
        "attempts": 0,
        "no_group": 0,
        "zero": 0,
        "errors": [message[:128]],
        "owned_pids": [],
        "owned_groups": [],
        "escaped_pids": [],
    }


def guardian_child_exit(events: int) -> NoReturn:
    error = sys.exc_info()[1]
    message = "guardian_exception: " + (
        str(error) if error is not None else "guardian returned unexpectedly"
    )
    try:
        emit_guard_event(
            events,
            {
                "event": "finished",
                "returncode": None,
                "failure": message[:1024],
                "resources": unavailable_resources(message),
            },
        )
    finally:
        os._exit(126)


def close_descriptors(descriptors: set[int]) -> None:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def exec_command(
    command: list[str],
    scratch: Path,
    environment: dict[str, str] | None,
    input_descriptor: int,
    output_descriptor: int,
    error_descriptor: int,
    original_mask: set[int],
) -> NoReturn:
    os.dup2(input_descriptor, 0)
    os.dup2(output_descriptor, 1)
    os.dup2(error_descriptor, 2)
    close_descriptors(
        {input_descriptor, output_descriptor, error_descriptor} - {0, 1, 2}
    )
    os.chdir(scratch)
    for signum in CANCELLATION_SIGNALS | {signal.SIGPIPE}:
        signal.signal(signum, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
    os.execvpe(
        command[0],
        command,
        environment if environment is not None else dict(os.environ),
    )


def emit_guard_event(descriptor: int, value: dict[str, Any]) -> None:
    encoded = canonical(value) + b"\n"
    require(len(encoded) < 4096, "guardian event bound")
    require(os.write(descriptor, encoded) == len(encoded), "short guardian event write")


def guardian_main(
    command: list[str],
    scratch: Path,
    environment: dict[str, str] | None,
    deadline: float,
    start_gate: int,
    events: int,
    input_descriptor: int,
    output_descriptor: int,
    error_descriptor: int,
    descriptors: set[int],
    original_mask: set[int],
) -> NoReturn:
    tool_pid: int | None = None
    returncode: int | None = None
    failure: str | None = None
    known: dict[int, ProcessObservation] = {}
    sampled_pids: set[int] = set()
    escaped_pids: set[int] = set()
    completed = False
    resources = unavailable_resources("")
    resources["errors"] = []
    group = os.getpid()
    try:
        os.setpgid(0, 0)
        close_descriptors(
            descriptors
            - {
                start_gate,
                events,
                input_descriptor,
                output_descriptor,
                error_descriptor,
            }
        )
        require(
            os.read(start_gate, 1) == b"g",
            "guardian startup cancelled before group registration",
        )
        os.close(start_gate)
        if time.monotonic() >= deadline:
            failure = "external_deadline"
            completed = True
            raise CorpusInterrupted("deadline before tool fork")
        tool_pid = os.fork()
        if tool_pid == 0:
            try:
                os.dup2(error_descriptor, 2)
                os.close(events)
                exec_command(
                    command,
                    scratch,
                    environment,
                    input_descriptor,
                    output_descriptor,
                    error_descriptor,
                    original_mask,
                )
            except (OSError, CorpusError, ValueError) as error:
                message = f"tool pre-exec failure: {error}".encode("utf-8", "replace")[
                    :2048
                ]
                try:
                    os.write(2, message)
                except OSError:
                    os._exit(127)
            finally:
                os._exit(127)
        emit_guard_event(events, {"event": "started", "tool_pid": tool_pid})
        close_descriptors({input_descriptor, output_descriptor, error_descriptor})
        next_sample = time.monotonic()
        while True:
            now = time.monotonic()
            if now >= deadline:
                failure = "external_deadline"
                break
            if now >= next_sample:
                resources["attempts"] += 1
                try:
                    snapshot = sample_processes(
                        scratch, min(0.1, max(0.001, deadline - now))
                    )
                    current = update_owned_processes(snapshot, tool_pid, known)
                    escaped_pids.update(
                        pid
                        for pid, observation in current.items()
                        if observation.group != group
                        and not observation.status.startswith("Z")
                    )
                    if escaped_pids:
                        failure = "unsupported_separate_group_descendant"
                        break
                    supported = {
                        pid: observation
                        for pid, observation in snapshot.items()
                        if observation.group == group and pid != group
                    }
                    sampled_pids.update(supported)
                    if supported:
                        resident = sum(
                            observation.rss_bytes for observation in supported.values()
                        )
                        resources["maximum"] = max(resources["maximum"] or 0, resident)
                        resources["samples"] += 1
                        resources["zero"] += int(resident == 0)
                        if resident > 2 * 1024 * MAX_IMAGE:
                            failure = "observed_owned_group_rss_limit"
                            break
                    else:
                        resources["no_group"] += 1
                except (CorpusError, OSError, UnicodeError) as error:
                    if len(resources["errors"]) < 4:
                        resources["errors"].append(str(error)[:128])
                next_sample = time.monotonic() + SAMPLE_INTERVAL
            waited, status = os.waitpid(tool_pid, os.WNOHANG)
            if waited:
                returncode = os.waitstatus_to_exitcode(status)
                final = sample_processes(scratch, 0.1)
                current = update_owned_processes(final, tool_pid, known)
                escaped_pids.update(
                    pid
                    for pid, observation in current.items()
                    if observation.group != group
                    and not observation.status.startswith("Z")
                )
                if escaped_pids:
                    failure = "unsupported_separate_group_descendant"
                elif any(
                    observation.group == group
                    and pid != group
                    and not observation.status.startswith("Z")
                    for pid, observation in final.items()
                ):
                    failure = "owned_descendants_outlived_leader"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "external_deadline"
                break
            select.select([], [], [], min(0.02, remaining))
        completed = True
    finally:
        try:
            if not completed:
                error = sys.exc_info()[1]
                failure = "guardian_exception: " + (
                    str(error) if error is not None else "unknown guardian failure"
                )
                resources = unavailable_resources(failure)
            else:
                resources["owned_pids"] = sorted(sampled_pids)
                resources["owned_groups"] = [group] if sampled_pids else []
                resources["escaped_pids"] = sorted(escaped_pids)
            emit_guard_event(
                events,
                {
                    "event": "finished",
                    "returncode": returncode,
                    "failure": failure,
                    "resources": resources,
                },
            )
        finally:
            os._exit(0 if completed else 126)


def collect_guard_events(buffer: bytearray, state: dict[str, Any]) -> None:
    require(len(buffer) <= 4096, "guardian status exceeds bound")
    while b"\n" in buffer:
        line, _separator, remaining = buffer.partition(b"\n")
        buffer[:] = remaining
        event = decode_json(bytes(line), "guardian event")
        if event.get("event") == "started":
            require(state.get("tool_pid") is None, "duplicate guardian start event")
            state["tool_pid"] = integer(event.get("tool_pid"), "observed tool PID")
        else:
            require(
                event.get("event") == "finished" and not state["finished"],
                "invalid guardian finish event",
            )
            returncode = event.get("returncode")
            require(
                (type(returncode) is int and -128 <= returncode <= 255)
                or (returncode is None and isinstance(event.get("failure"), str)),
                "invalid guarded return code",
            )
            require(
                event.get("failure") is None or isinstance(event.get("failure"), str),
                "invalid guard failure",
            )
            state.update(
                finished=True, returncode=returncode, failure=event.get("failure")
            )
            state["resources"] = object_value(
                event.get("resources"), "guardian resource observations"
            )


def reap_guardian(
    guardian_pid: int,
    state: dict[str, Any],
    scratch: Path,
) -> bool:
    cleanup_error: str | None = None
    try:
        exited_before_registration = (
            state.get("group_registered") is False
            and state.get("start_released") is False
            and owned_child_ended(guardian_pid)
        )
        if not exited_before_registration:
            try:
                kill_owned_group(guardian_pid)
            except PermissionError:
                if not owned_child_ended(guardian_pid):
                    raise
                snapshot = sample_processes(scratch, 0.2)
                if any(
                    item.group == guardian_pid and not item.status.startswith("Z")
                    for item in snapshot.values()
                ):
                    raise
    except (OSError, CorpusError) as error:
        cleanup_error = f"owned_group_cleanup_failed: {error}"
    finally:
        state["guardian_returncode"] = reap_direct_child(guardian_pid, 1.0)
    if state["guardian_returncode"] is None:
        cleanup_error = cleanup_error or "guardian_reap_deadline"
    if cleanup_error:
        state["cleanup_error"] = cleanup_error
    return state["guardian_returncode"] is not None and cleanup_error is None


def sample_processes(scratch: Path, timeout: float) -> dict[int, ProcessObservation]:
    """Read ps using one directly owned sampler child; never signal a PID obtained from its output."""
    descriptors: set[int] = set()
    sampler_pid: int | None = None
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CANCELLATION_SIGNALS)
    try:
        read_descriptor, write_descriptor = os.pipe()
        descriptors.update({read_descriptor, write_descriptor})
        sampler_pid = os.fork()
        if sampler_pid == 0:
            try:
                os.close(read_descriptor)
                null = os.open(os.devnull, os.O_RDWR)
                environment = {**os.environ, "LC_ALL": "C"}
                exec_command(
                    ["/bin/ps", "-axo", "pid=,ppid=,pgid=,rss=,lstart=,stat="],
                    scratch,
                    environment,
                    null,
                    write_descriptor,
                    null,
                    old_mask,
                )
            finally:
                os._exit(127)
        os.close(write_descriptor)
        descriptors.remove(write_descriptor)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        os.set_blocking(read_descriptor, False)
        deadline = time.monotonic() + timeout
        output = bytearray()
        eof = False
        while time.monotonic() < deadline:
            waited, status = os.waitpid(sampler_pid, os.WNOHANG)
            if waited:
                reaped_sampler = sampler_pid
                sampler_pid = None
                require(os.waitstatus_to_exitcode(status) == 0, "ps sampling failed")
                while block := os.read(read_descriptor, 65536):
                    require(len(output) + len(block) <= MAX_TEXT, "ps output bound")
                    output.extend(block)
                snapshot = parse_process_snapshot(output.decode("ascii"))
                snapshot.pop(reaped_sampler, None)
                return snapshot
            if eof:
                select.select(
                    [], [], [], min(0.005, max(0, deadline - time.monotonic()))
                )
                continue
            if not select.select(
                [read_descriptor], [], [], max(0, deadline - time.monotonic())
            )[0]:
                break
            block = os.read(read_descriptor, 65536)
            if not block:
                eof = True
                continue
            require(len(output) + len(block) <= MAX_TEXT, "ps output bound")
            output.extend(block)
        raise CorpusError("ps sampling deadline")
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, CANCELLATION_SIGNALS)
        try:
            if sampler_pid is not None and sampler_pid > 0:
                if not owned_child_ended(sampler_pid):
                    try:
                        os.kill(sampler_pid, signal.SIGKILL)
                    except PermissionError:
                        if not owned_child_ended(sampler_pid):
                            raise
                require(
                    reap_direct_child(sampler_pid, 0.5) is not None,
                    "RSS sampler cleanup deadline",
                )
        finally:
            close_descriptors(descriptors)
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def run_process(
    command: list[str],
    scratch: Path,
    timeout: float,
    payload: bytes = b"",
    environment: dict[str, str] | None = None,
    stdout_limit: int = MAX_TEXT,
    stderr_limit: int = MAX_STDERR,
) -> ProcessResult:
    """Capture a tool whose pre-exec and execution deadline is enforced by an already-running guardian."""
    require(os.name == "posix", "process-group supervision requires POSIX")
    require(
        hasattr(os, "fork") and hasattr(signal, "pthread_sigmask"),
        "Unix guardian unavailable",
    )
    require(
        hasattr(os, "waitid") and hasattr(os, "WNOWAIT"),
        "non-reaping Unix child observation unavailable",
    )
    require(
        threading.active_count() == 1, "fork guardian requires a single-threaded runner"
    )
    require(0 < timeout <= 600 and math.isfinite(timeout), "invalid process deadline")
    require(len(payload) <= 4 * MAX_TEXT, "request exceeds bound")
    require(
        0 < stdout_limit <= MAX_TEXT and 0 < stderr_limit <= MAX_STDERR,
        "invalid pipe capture bounds",
    )
    started = time.monotonic()
    guardian_pid: int | None = None
    descriptors: set[int] = set()
    state: dict[str, Any] = {
        "process_group": None,
        "group_registered": False,
        "start_released": False,
        "finished": False,
        "returncode": None,
        "failure": None,
    }
    guard_buffer = bytearray()
    control_write: int | None = None
    event_read: int | None = None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    failure = None
    sent = 0
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CANCELLATION_SIGNALS)
    try:
        pipes = []
        for _index in range(5):
            pair = os.pipe()
            pipes.append(pair)
            descriptors.update(pair)
        (
            (control_read, control_write),
            (event_read, event_write),
            (input_read, input_write),
            (output_read, output_write),
            (error_read, error_write),
        ) = pipes
        guardian_pid = os.fork()
        if guardian_pid == 0:
            try:
                try:
                    guardian_main(
                        command,
                        scratch,
                        environment,
                        started + timeout,
                        control_read,
                        event_write,
                        input_read,
                        output_write,
                        error_write,
                        descriptors,
                        original_mask,
                    )
                finally:
                    guardian_child_exit(event_write)
            finally:
                os._exit(126)
        state["process_group"] = guardian_pid
        try:
            os.setpgid(guardian_pid, guardian_pid)
        except (PermissionError, ProcessLookupError):
            if not owned_child_ended(guardian_pid):
                raise
        else:
            state["group_registered"] = True
        child_descriptors = {
            control_read,
            event_write,
            input_read,
            output_write,
            error_write,
        }
        close_descriptors(child_descriptors)
        descriptors.difference_update(child_descriptors)
        if state["group_registered"]:
            try:
                require(
                    os.write(control_write, b"g") == 1,
                    "short guardian startup gate write",
                )
                state["start_released"] = True
            except BrokenPipeError:
                if not owned_child_ended(guardian_pid):
                    raise
        os.close(control_write)
        descriptors.remove(control_write)
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        with selectors.DefaultSelector() as selector:
            for name, descriptor in (
                ("stdout", output_read),
                ("stderr", error_read),
                ("guard", event_read),
            ):
                os.set_blocking(descriptor, False)
                selector.register(descriptor, selectors.EVENT_READ, name)
            os.set_blocking(input_write, False)
            if payload:
                selector.register(input_write, selectors.EVENT_WRITE, "stdin")
            else:
                os.close(input_write)
                descriptors.remove(input_write)
            while selector.get_map() or not state["finished"]:
                now = time.monotonic()
                if now - started >= timeout:
                    failure = "external_deadline"
                    break
                for key, _event in selector.select(
                    min(SAMPLE_INTERVAL, max(0, timeout - (now - started)))
                ):
                    if key.data == "stdin":
                        try:
                            sent += os.write(key.fd, payload[sent : sent + 65536])
                        except BrokenPipeError:
                            failure = "stdin_closed_before_request"
                            break
                        if sent == len(payload):
                            selector.unregister(key.fd)
                            os.close(key.fd)
                            descriptors.remove(key.fd)
                        continue
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fd)
                        if key.data == "guard" and not state["finished"]:
                            failure = "guardian_missing_result"
                            break
                        continue
                    if key.data == "guard":
                        guard_buffer.extend(block)
                        collect_guard_events(guard_buffer, state)
                        if state["finished"] and state["failure"] is not None:
                            failure = state["failure"]
                            break
                        continue
                    captured = output[key.data]
                    remaining = limits[key.data] - len(captured)
                    captured.extend(block[:remaining])
                    if len(block) > remaining:
                        failure = f"{key.data}_limit"
                        break
                if failure:
                    break
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, CANCELLATION_SIGNALS)
        try:
            if control_write is not None and control_write in descriptors:
                close_descriptors({control_write})
                descriptors.remove(control_write)
            if (
                guardian_pid is not None
                and guardian_pid > 0
                and not reap_guardian(guardian_pid, state, scratch)
            ):
                failure = failure or "guardian_cleanup_deadline"
            if event_read is not None and event_read in descriptors:
                os.set_blocking(event_read, False)
                while block := os.read(event_read, 4096):
                    guard_buffer.extend(block)
                    collect_guard_events(guard_buffer, state)
        finally:
            close_descriptors(descriptors)
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
    if (
        state["failure"] == "external_deadline"
        or failure is None
        or (failure == "guardian_cleanup_deadline" and state["failure"] is not None)
    ):
        failure = state["failure"]
    require(
        not state.get("protocol_error"),
        f"guardian protocol failure: {state.get('protocol_error')}",
    )
    if not state["finished"] and failure is None:
        failure = "guardian_missing_result"
    if state.get("cleanup_error"):
        failure = (
            f"{failure}; {state['cleanup_error']}"
            if failure
            else state["cleanup_error"]
        )
    resources = state.get("resources")
    if not isinstance(resources, dict) or state.get("cleanup_error"):
        resources = unavailable_resources(
            failure or "guardian finished without resource observations"
        )
    samples = integer(resources.get("samples"), "RSS observations")
    if samples == 0 and failure is None:
        failure = "rss_sampling_unavailable"
    return ProcessResult(
        command,
        state["returncode"],
        bytes(output["stdout"]),
        bytes(output["stderr"]),
        time.monotonic() - started,
        failure,
        resources["maximum"],
        samples,
        resources["errors"],
        resources["attempts"],
        resources["no_group"],
        resources["zero"],
        "unix_guardian_fork_exec",
        resources["owned_pids"],
        resources["owned_groups"],
        state.get("guardian_returncode"),
        guardian_pid if state["group_registered"] else None,
        resources["escaped_pids"],
    )


def process_json(result: ProcessResult, context: str) -> dict[str, Any]:
    require(result.failure is None, f"{context}: {result.failure}")
    require(
        result.returncode == 0,
        f"{context}: exit {result.returncode}: {result.stderr.decode(errors='replace')}",
    )
    return decode_json(result.stdout, context)


@dataclass(frozen=True)
class ElfSymbol:
    name: str
    address: int
    size: int
    kind: int
    section: int


@dataclass
class ElfImage:
    data: bytes
    mappings: list[dict[str, Any]]
    symbols: list[ElfSymbol]

    def exact_symbol(self, name: str, function: bool = True) -> ElfSymbol:
        matches = [symbol for symbol in self.symbols if symbol.name == name]
        require(len(matches) == 1, f"{name}: missing or ambiguous exact ELF symbol")
        symbol = matches[0]
        require(
            symbol.section != 0 and symbol.size > 0,
            f"{name}: undefined or empty ELF symbol",
        )
        if function:
            require(
                symbol.kind == 2 and symbol.size <= 128,
                f"{name}: not a bounded ELF function",
            )
            owners = [
                item
                for item in self.mappings
                if covers(item, symbol.address, symbol.size)
            ]
            require(
                len(owners) == 1 and owners[0]["executable"],
                f"{name}: not uniquely executable-backed",
            )
            require(
                symbol.address + symbol.size
                <= owners[0]["base"] + len(bytes.fromhex(owners[0]["hex_bytes"])),
                f"{name}: method extends into zero fill",
            )
            aliases = [
                other
                for other in self.symbols
                if other.kind == 2 and other.address == symbol.address
            ]
            require(len(aliases) == 1, f"{name}: function address alias")
        return symbol

    def read_va(self, start: int, size: int) -> bytes:
        owners = [item for item in self.mappings if covers(item, start, size)]
        require(len(owners) == 1, "ELF VA is not uniquely mapped")
        item = owners[0]
        data = bytes.fromhex(item["hex_bytes"]).ljust(item["size"], b"\0")
        return data[start - item["base"] : start - item["base"] + size]


def covers(mapping: dict[str, Any], start: int, size: int) -> bool:
    return (
        mapping["base"] <= start and start + size <= mapping["base"] + mapping["size"]
    )


def slice_bytes(data: bytes, offset: int, size: int) -> bytes:
    require(
        0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
        "ELF range exceeds file",
    )
    return data[offset : offset + size]


def parse_elf(data: bytes) -> ElfImage:
    """Read bounded ELF64 PT_LOAD and symbol facts independently of either backend loader."""
    require(64 <= len(data) <= MAX_IMAGE, "ELF file bound")
    header = struct.unpack("<16sHHIQQQIHHHHHH", data[:64])
    (
        ident,
        elf_type,
        machine,
        version,
        _entry,
        phoff,
        shoff,
        _flags,
        ehsize,
        phsize,
        phnum,
        shsize,
        shnum,
        _names,
    ) = header
    require(
        ident[:7] == b"\x7fELF\x02\x01\x01", "requires ELF64 little-endian version 1"
    )
    require(
        (elf_type, machine, version, ehsize, phsize, shsize) == (2, 62, 1, 64, 56, 64),
        "unsupported ELF header",
    )
    require(0 < phnum <= 32 and 0 < shnum <= 128, "ELF table count bound")
    mappings: list[dict[str, Any]] = []
    total = 0
    for index in range(phnum):
        kind, flags, offset, base, _physical, backed, size, alignment = struct.unpack(
            "<IIQQQQQQ", slice_bytes(data, phoff + index * 56, 56)
        )
        if kind != 1:
            continue
        require(
            0 < size <= MAX_IMAGE and backed <= size and base + size < 1 << 63,
            "invalid PT_LOAD size",
        )
        require(
            flags <= 7 and alignment in {0, 1, 4096},
            "unsupported PT_LOAD flags/alignment",
        )
        require(
            alignment <= 1 or base % alignment == offset % alignment,
            "PT_LOAD alignment mismatch",
        )
        total += size
        require(total <= MAX_IMAGE, "aggregate PT_LOAD memory exceeds 1 MiB")
        mappings.append(
            {
                "base": base,
                "hex_bytes": slice_bytes(data, offset, backed).hex(),
                "size": size,
                "readable": bool(flags & 4),
                "writable": bool(flags & 2),
                "executable": bool(flags & 1),
            }
        )
    mappings.sort(key=lambda item: item["base"])
    require(mappings, "ELF has no PT_LOAD")
    for left, right in pairwise(mappings):
        require(
            left["base"] + left["size"] <= right["base"], "overlapping PT_LOAD regions"
        )
    sections = [
        struct.unpack("<IIQQQQIIQQ", slice_bytes(data, shoff + index * 64, 64))
        for index in range(shnum)
    ]
    tables = [section for section in sections if section[1] == 2]
    require(len(tables) == 1, "ELF requires one static symbol table")
    table = tables[0]
    require(
        table[9] == 24 and table[5] % 24 == 0 and table[5] // 24 <= 256,
        "ELF symbol count/width bound",
    )
    require(
        table[6] < len(sections) and sections[table[6]][1] == 3,
        "invalid ELF symbol string table",
    )
    names = sections[table[6]]
    strings = slice_bytes(data, names[4], names[5])
    symbols = []
    for offset in range(table[4], table[4] + table[5], 24):
        name_offset, info, _visibility, section, symbol_address, size = struct.unpack(
            "<IBBHQQ", slice_bytes(data, offset, 24)
        )
        require(name_offset < len(strings), "ELF symbol name outside table")
        end = strings.find(b"\0", name_offset)
        require(0 <= end - name_offset <= 256, "ELF symbol name bound")
        try:
            name = strings[name_offset:end].decode("ascii")
        except UnicodeError as error:
            raise CorpusError("non-ASCII owned ELF symbol") from error
        if info & 15 == 2 and section != 0:
            require(section < len(sections), "function symbol section index")
            owner = sections[section]
            require(
                owner[1] == 1 and owner[2] & 6 == 6,
                "function symbol is not in allocated executable PROGBITS",
            )
            require(
                owner[3] <= symbol_address
                and symbol_address + size <= owner[3] + owner[5],
                "function symbol exceeds its executable section",
            )
        symbols.append(ElfSymbol(name, symbol_address, size, info & 15, section))
    return ElfImage(data, mappings, symbols)


@dataclass(frozen=True)
class Expression:
    base: str
    delta: int = 0


TOKEN = re.compile(r"\s*(->|0[xX][0-9a-fA-F]+|[0-9]+|[A-Za-z_][A-Za-z_0-9]*|[()+\-])")
CASTS_32 = {"int", "uint", "int4", "uint4", "unsigned int", "signed int"}
CASTS_BYTE = {"byte", "uint1", "uchar", "unsigned char"}


class ExpressionParser:
    """Recognize only one named field/parameter with constant 32-bit additions and safe casts."""

    def __init__(self, text: str, self_name: str, replacement: str | None) -> None:
        require(len(text) <= 4096, "expression exceeds bound")
        self.tokens: list[str] = []
        position = 0
        while position < len(text.rstrip()):
            match = TOKEN.match(text, position)
            if match is None:
                raise CorpusError("unsupported rendered-expression token")
            self.tokens.append(match.group(1))
            position = match.end()
        require(0 < len(self.tokens) <= 256, "expression token bound")
        self.position = 0
        self.self_name = identifier(self_name)
        self.replacement = identifier(replacement) if replacement else None

    def take(self) -> str:
        require(self.position < len(self.tokens), "incomplete expression")
        token = self.tokens[self.position]
        self.position += 1
        return token

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def atom(self, depth: int = 0) -> Expression:
        require(depth < 32, "expression nesting bound")
        token = self.take()
        if token == "(":
            closing = self.position
            while closing < len(self.tokens) and re.fullmatch(
                r"[A-Za-z_][A-Za-z_0-9]*", self.tokens[closing]
            ):
                closing += 1
            cast = " ".join(self.tokens[self.position : closing])
            if (
                closing < len(self.tokens)
                and self.tokens[closing] == ")"
                and cast in CASTS_32 | CASTS_BYTE
            ):
                self.position = closing + 1
                value = self.atom(depth + 1)
                require(
                    cast not in CASTS_BYTE or value == Expression("field:tail"),
                    "narrowing cast unsupported",
                )
                return value
            value = self.additive(depth + 1)
            require(self.take() == ")", "unbalanced expression")
            return value
        if token == self.self_name:
            require(self.take() == "->", "self must be an explicit field base")
            member = self.take()
            require(member in {"count", "tail"}, "unsupported field")
            return Expression(f"field:{member}")
        if token == self.replacement:
            return Expression("parameter:replacement")
        sign = 1
        if token in {"+", "-"}:
            sign = -1 if token == "-" else 1
            token = self.take()
        require(
            re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", token),
            "unknown expression identifier",
        )
        value = int(token, 16 if token.lower().startswith("0x") else 10)
        require(value <= 0xFFFFFFFF, "constant exceeds 32-bit expression bound")
        return Expression("constant", sign * value & 0xFFFFFFFF)

    def additive(self, depth: int = 0) -> Expression:
        value = self.atom(depth)
        while self.peek() in {"+", "-"}:
            operator = self.take()
            right = self.atom(depth)
            if (
                value.base == "constant"
                and right.base != "constant"
                and operator == "+"
            ):
                value, right = right, value
            require(
                right.base == "constant",
                "multiple field/parameter accesses or unsupported subtraction",
            )
            amount = right.delta if operator == "+" else -right.delta
            value = Expression(value.base, (value.delta + amount) & 0xFFFFFFFF)
        return value

    def parse(self) -> Expression:
        result = self.additive()
        require(self.position == len(self.tokens), "unsupported trailing expression")
        require(
            result.base != "constant", "constant output does not establish field access"
        )
        return result


def expression(
    text: str, self_name: str = "self", replacement: str | None = "replacement"
) -> Expression:
    return ExpressionParser(text, self_name, replacement).parse()


def rendered_expression(code: str, parameters: list[str], write: bool) -> Expression:
    require(len(code.encode()) <= MAX_METHOD_TEXT, "rendered output text bound")
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", code, flags=re.DOTALL)
    require(
        clean.count("{") == 1 and clean.count("}") == 1,
        "unsupported function/control-flow body",
    )
    opening, closing = clean.index("{"), clean.index("}")
    require(not clean[closing + 1 :].strip(), "trailing rendered output")
    require(len(parameters) == (2 if write else 1), "unexpected actual parameter count")
    statements = [
        item.strip() for item in clean[opening + 1 : closing].split(";") if item.strip()
    ]
    if write:
        require(
            len(statements) in {1, 2}, "write has additional statements/side effects"
        )
        require(
            len(statements) == 1 or statements[-1] == "return",
            "write has nonvoid return",
        )
        assignment = statements[0].split("=")
        require(len(assignment) == 2, "expected exactly one count store")
        match_text(
            r"[()\s]*" + re.escape(parameters[0]) + r"\s*->\s*count[()\s]*",
            assignment[0],
            "unsupported store lvalue",
        )
        require(
            expression(assignment[0], parameters[0], parameters[1])
            == Expression("field:count"),
            "wrong store",
        )
        return expression(assignment[1], parameters[0], parameters[1])
    require(len(statements) == 1, "read has additional statements")
    returned = re.fullmatch(r"return\s+(.+)", statements[0], flags=re.DOTALL)
    if returned is None:
        raise CorpusError("expected one return expression")
    return expression(returned.group(1), parameters[0], None)


@dataclass
class Method:
    symbol: str
    record: str
    field: str
    write: bool
    expected: Expression
    address: int = 0
    size: int = 0
    declaration: str = ""
    emitted_name: str = ""
    parameter_names: list[str] = dataclass_field(default_factory=list)
    return_size: int = 4
    layout_name: str = ""


def load_methods(oracle: dict[str, Any], source: str) -> list[Method]:
    methods = []
    entries = array_value(oracle["groups"]["records"]["methods"], "oracle methods")
    require(0 < len(entries) <= MAX_METHODS, "oracle method count bound")
    for item in entries:
        record = oracle["records"][item["record"]]["tag"]
        access = item["access"]
        require(
            access in {"read-signed", "read-unsigned", "write"},
            "unknown oracle method access",
        )
        method_name = (
            "writeCount"
            if access == "write"
            else "readCount"
            if item["field"] == "count"
            else "readTail"
        )
        pattern = (
            rf"\b{re.escape(record)}::{method_name}\s*\([^()]*\)\s*\{{([^{{}}]*)\}}"
        )
        bodies = re.findall(pattern, source)
        require(
            len(bodies) == 1,
            f"{record}::{method_name}: independent source body unavailable/ambiguous",
        )
        source_body = re.sub(r"\b(count|tail)\b", r"self->\1", bodies[0])
        source_body = re.sub(
            r"static_cast\s*<\s*unsigned\s+int\s*>\s*\(\s*self->tail\s*\)",
            "(unsigned int)(self->tail)",
            source_body,
        )
        write = access == "write"
        source_expression = rendered_expression(
            "void independent() {" + source_body + "}",
            ["self", "replacement"] if write else ["self"],
            write,
        )
        fact = object_value(item.get("expression"), "independent oracle expression")
        origin = string_value(fact.get("source"), "oracle expression source")
        name = string_value(fact.get("name"), "oracle expression name")
        require(
            origin in {"field", "parameter"}, "unsupported oracle expression origin"
        )
        add = fact.get("add")
        if type(add) is not int or not -(1 << 31) <= add < 1 << 31:
            raise CorpusError("oracle expression constant bound")
        expected = Expression(f"{origin}:{name}", add & 0xFFFFFFFF)
        require(
            expected.base
            == ("parameter:replacement" if write else f"field:{item['field']}"),
            "independent oracle expression does not match declared access kind",
        )
        require(
            source_expression == expected,
            f"{record}::{method_name}: source and independent oracle disagree",
        )
        return_size = integer(
            item.get("return_size"), "independent oracle return width", 8
        )
        require(
            return_size == (0 if write else 4),
            "oracle return width disagrees with method access",
        )
        methods.append(
            Method(
                item["symbol"],
                record,
                item["field"],
                write,
                expected,
                return_size=return_size,
            )
        )
    require(
        len({item.symbol for item in methods}) == len(methods),
        "duplicate oracle methods",
    )
    return methods


def check_elf_oracle(
    image: ElfImage, oracle: dict[str, Any], methods: list[Method]
) -> None:
    for method in methods:
        symbol = image.exact_symbol(method.symbol)
        method.address, method.size = symbol.address, symbol.size
    ordered = sorted(methods, key=lambda item: item.address)
    for left, right in pairwise(ordered):
        require(
            left.address + left.size <= right.address, "oracle method ranges overlap"
        )
    for table in oracle["groups"]["records"]["tables"]:
        symbol = image.exact_symbol(table["symbol"], function=False)
        expected = [
            image.exact_symbol(word).address if isinstance(word, str) else word
            for word in table["words"]
        ]
        require(
            symbol.size == 8 * len(expected),
            "vtable word count differs from independent oracle",
        )
        actual = list(
            struct.unpack(
                "<" + "Q" * len(expected), image.read_va(symbol.address, symbol.size)
            )
        )
        require(actual == expected, "raw vtable words differ from independent oracle")


def collect_review(
    executable: Path,
    image: Path,
    scratch: Path,
    timeout: float,
    environment: dict[str, str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    processes = []
    first: dict[str, Any] | None = None
    offset = 0
    for _page in range(10):
        command = [
            str(executable),
            "--json",
            "type",
            "import-debug-layouts",
            str(image),
            "--limit",
            "1000",
        ]
        if offset:
            command.extend(["--offset", str(offset)])
        result = run_process(command, scratch, timeout, environment=environment)
        processes.append(result.metadata())
        receipt = process_json(result, "consumer preview")
        require(
            receipt.get("ok") is True and receipt.get("status") == "preview",
            "consumer preview rejected",
        )
        for name in ("review_sha256", "image_sha256", "compiler_spec_sha256"):
            digest_value(receipt.get(name), name)
        if first is None:
            first = receipt
        for name in (
            "review_sha256",
            "image_sha256",
            "compiler_spec_sha256",
            "details_total",
        ):
            require(receipt.get(name) == first.get(name), f"pagination changed {name}")
        require(receipt.get("offset") == offset, "pagination offset mismatch")
        page = array_value(receipt.get("details"), "receipt details")
        require(
            0 < len(page) <= 1000 or receipt.get("details_total") == 0,
            "invalid evidence page length",
        )
        rows.extend(object_value(row, "receipt row") for row in page)
        next_offset = receipt.get("next_offset")
        if next_offset is None:
            require(len(rows) == receipt.get("details_total"), "missing evidence rows")
            require(first is not None, "missing first page")
            return {**first, "details": rows}, processes
        require(
            type(next_offset) is int and next_offset == offset + len(page),
            "noncontiguous evidence pagination",
        )
        require(next_offset > offset, "evidence pagination did not progress")
        offset = next_offset
    raise CorpusError("consumer evidence exceeds ten pages")


def scalar_semantics(
    descriptor: dict[str, Any], signed: bool, size: int, alignment: int
) -> None:
    kind = descriptor.get("kind")
    allowed = (
        {"signed_integer", "signed_character"}
        if signed
        else {"unsigned_integer", "unsigned_character"}
    )
    if size != 1:
        allowed.discard("signed_character")
        allowed.discard("unsigned_character")
    require(kind in allowed, "scalar signedness/kind differs from independent source")
    require(
        integer(descriptor.get("size"), "scalar width", 8) == size
        and integer(descriptor.get("alignment"), "scalar alignment", 8) == alignment,
        "scalar width/alignment",
    )
    identifier(descriptor.get("name"))


def validate_projection(
    rows: list[dict[str, Any]],
    type_data: dict[str, Any],
    field_rows: list[dict[str, Any]],
    layout: dict[str, Any],
    dwarf_version: int | None,
) -> dict[str, Any]:
    require(
        "projections" not in type_data,
        "draft inline projections are not the final receipt schema",
    )
    candidates = [
        row
        for row in rows
        if row.get("kind") == "projection" and row.get("type_name") == layout["name"]
    ]
    require(
        len(candidates) == 1, "exactly one separate opaque vptr projection row required"
    )
    row = candidates[0]
    require(
        row.get("source") == "virtual_evidence"
        and row.get("status") == "read_only"
        and row.get("storage_role") == OPAQUE_STORAGE_ROLE,
        "projection evidence source/status/storage role",
    )
    require(
        field_rows[0].get("storage_role") == OPAQUE_STORAGE_ROLE,
        "checked vptr field lacks opaque storage role",
    )
    require(
        all(member.get("storage_role") is None for member in field_rows[1:]),
        "ordinary fields must not claim opaque projection storage",
    )
    projection = object_value(row.get("data"), "opaque projection metadata")
    require(
        projection.get("kind") == "opaque_vptr"
        and integer(projection.get("field_index"), "projection field index", 127) == 0,
        "projection must bind the first opaque vptr field",
    )
    source = object_value(projection.get("source"), "projection source facts")
    unit = integer(type_data.get("unit_offset"), "checked type CU", 131071)
    require(
        integer(source.get("unit_offset"), "projection source CU", 131071) == unit,
        "projection source belongs to a foreign CU",
    )
    require(
        integer(source.get("language"), "projection producer language", 65535)
        in {4, 0x1A, 0x21, 0x2A},
        "projection source is not a supported C++ producer",
    )
    version = integer(source.get("dwarf_version"), "projection DWARF version", 5)
    require(
        version in {4, 5} and (dwarf_version is None or version == dwarf_version),
        "projection source DWARF version mismatch",
    )
    require(
        integer(source.get("address_size"), "projection source address size", 8) == 8,
        "projection source address width mismatch",
    )
    roles = set()
    for role in (
        "record_id",
        "member_id",
        "pointer_id",
        "pointee_pointer_id",
        "subroutine_id",
    ):
        identity = object_value(projection.get(role), f"projection {role}")
        require(
            integer(identity.get("unit_offset"), f"{role} CU", 131071) == unit,
            "foreign projection role CU",
        )
        die = integer(identity.get("die_offset"), f"{role} DIE", 131071)
        require(
            unit < die and die not in roles,
            "projection role identities must be distinct bounded DIEs",
        )
        roles.add(die)
    require(
        projection["record_id"]["die_offset"] == type_data["die_offset"],
        "projection record identity differs from checked type",
    )
    require(
        integer(projection.get("record_byte_size"), "projected record size", MAX_IMAGE)
        == layout["size"]
        and integer(projection.get("record_alignment"), "projected record alignment", 8)
        == layout["alignment"]
        and integer(
            projection.get("member_offset"), "projected member offset", MAX_IMAGE
        )
        == 0,
        "projection record/member facts differ from checked layout",
    )
    for name in (
        "member_byte_size",
        "member_alignment",
        "pointer_byte_size",
        "pointer_alignment",
        "pointee_pointer_byte_size",
        "pointee_pointer_alignment",
    ):
        require(name in projection, f"missing optional producer fact: {name}")
        require(
            projection[name] is None or integer(projection[name], name, 8) == 8,
            "conflicting opaque projection producer width/alignment",
        )
    return projection


def validate_consumer(
    receipt: dict[str, Any],
    oracle: dict[str, Any],
    methods: list[Method],
    image_sha: str,
    dwarf_version: int | None = None,
) -> list[dict[str, Any]]:
    require(receipt.get("image_sha256") == image_sha, "receipt image identity mismatch")
    rows = receipt["details"]
    layouts = []
    names: dict[str, str] = {}
    identities = set()
    for record_key in oracle["groups"]["records"]["records"]:
        record = oracle["records"][record_key]
        expected = oracle["layouts"][record["layout"]]
        matches = [
            row
            for row in rows
            if row.get("kind") == "type"
            and row.get("source") == "checked"
            and row.get("status") == "verified"
            and row.get("data", {}).get("original_name") == record["tag"]
        ]
        require(
            len(matches) == 1, f"{record['tag']}: one verified consumer type required"
        )
        data = matches[0]["data"]
        identity = (
            integer(data.get("unit_offset"), "unit offset"),
            integer(data.get("die_offset"), "DIE offset"),
        )
        require(
            identity not in identities and identity[0] < identity[1] < 131072,
            "record DIE identity mismatch",
        )
        identities.add(identity)
        layout = dict(object_value(data.get("layout"), "consumer layout"))
        name = identifier(layout.get("name"))
        require(name not in names.values(), "consumer merged distinct records")
        names[record["tag"]] = name
        require(
            layout.get("size") == expected["size"]
            and layout.get("alignment") == expected["alignment"],
            "consumer record size/alignment differs from oracle",
        )
        require(
            canonical(layout.get("organization")) == canonical(ORGANIZATION),
            "consumer data organization mismatch",
        )
        field_rows = [
            row
            for row in rows
            if row.get("kind") == "field"
            and row.get("source") == "checked"
            and row.get("status") == "verified"
            and row.get("type_name") == name
        ]
        fields = [object_value(row.get("data"), "checked field") for row in field_rows]
        require(
            len(fields) == 3,
            "consumer record must contain exactly opaque vptr/count/tail",
        )
        require(
            canonical(fields[0])
            == canonical(
                {"name": "rampage_vptr", "offset": 0, "size": 8, "ty": OPAQUE_POINTER}
            ),
            "consumer vptr must be exact opaque void pointer, not integer/undefined/callback",
        )
        for actual, fact in zip(fields[1:], expected["fields"]):
            require(
                all(actual.get(key) == fact[key] for key in ("name", "offset", "size")),
                "consumer field mismatch",
            )
            require(
                actual.get("ty", {}).get("kind") == "scalar",
                "source data field is not scalar",
            )
            scalar_semantics(
                actual["ty"]["scalar"],
                fact["name"] == "count",
                fact["size"],
                fact["alignment"],
            )
        validate_projection(rows, data, field_rows, layout, dwarf_version)
        layout["fields"] = fields
        layouts.append(layout)
    method_identities = set()
    for method in methods:
        matches = [
            row
            for row in rows
            if row.get("kind") == "function"
            and row.get("source") == "checked"
            and row.get("status") == "approved"
            and row.get("data", {}).get("original_name") == method.symbol
        ]
        require(
            len(matches) == 1,
            f"{method.symbol}: one exact approved mangled method required",
        )
        data = matches[0]["data"]
        method_identity = (
            integer(data.get("unit_offset"), "method unit offset"),
            integer(data.get("die_offset"), "method DIE offset"),
        )
        require(
            method_identity not in method_identities
            and method_identity not in identities
            and method_identity[0] < method_identity[1] < 131072,
            "method DIE identity mismatch",
        )
        method_identities.add(method_identity)
        require(
            address(data.get("address")) == method.address,
            "consumer method VA differs from ELF oracle",
        )
        method.layout_name = names[method.record]
        require(
            data.get("dependencies") == [method.layout_name],
            "consumer method dependency identity mismatch",
        )
        declaration = string_value(data.get("declaration"), "consumer declaration")
        match = match_text(
            r"(void|int4|uint4|int|unsigned int)\s+([A-Za-z_][A-Za-z_0-9]*)\(([^()]*)\);",
            declaration,
            "unsupported accepted C prototype",
        )
        return_type, emitted, arguments = match.groups()
        require(
            return_type
            in (
                {"void"}
                if method.write
                else {"uint4", "unsigned int"}
                if method.field == "tail"
                else {"int4", "int"}
            ),
            "consumer return kind/width differs from source",
        )
        parts = [item.strip() for item in arguments.split(",")]
        require(
            len(parts) == (2 if method.write else 1),
            "consumer prototype parameter count mismatch",
        )
        self_match = match_text(
            re.escape(method.layout_name) + r"\s*\*\s*([A-Za-z_][A-Za-z_0-9]*)",
            parts[0],
            "mutable record-pointer self required",
        )
        require(
            self_match.group(1) == "self",
            "explicit parameter must be named self, not injected this",
        )
        parameter_names = ["self"]
        if method.write:
            value_match = match_text(
                r"(?:int4|int)\s+([A-Za-z_][A-Za-z_0-9]*)",
                parts[1],
                "replacement must be a signed 32-bit value parameter",
            )
            parameter_names.append(identifier(value_match.group(1)))
        require(
            len(set(parameter_names)) == len(parameter_names),
            "duplicate consumer parameter names",
        )
        method.declaration = declaration
        method.emitted_name = identifier(emitted)
        method.parameter_names = parameter_names
    return layouts


def layout_declarations(layouts: list[dict[str, Any]]) -> str:
    declarations = []
    for layout in layouts:
        fields = []
        for member in layout["fields"]:
            descriptor = member["ty"]
            if descriptor["kind"] == "pointer":
                name = descriptor["pointee"]["name"] + " *"
            else:
                name = descriptor["scalar"]["name"]
            fields.append(f" {name} {member['name']};")
        declarations.append(
            f"struct {layout['name']} {{\n" + "\n".join(fields) + "\n};"
        )
    return "\n".join(declarations)


def worker_request(
    image: ElfImage,
    layouts: list[dict[str, Any]],
    methods: list[Method],
    selected: Method,
    context: str,
) -> dict[str, Any]:
    operations: list[dict[str, Any]] = [
        {"op": "parse_types", "declarations": layout_declarations([layout])}
        for layout in layouts
    ]
    operations.extend(
        {
            "op": "assert_plain_struct_layout",
            "layout": layout,
            "expected_context": context,
        }
        for layout in layouts
    )
    for method in methods:
        operations.append(
            {"op": "symbol", "address": method.address, "name": method.emitted_name}
        )
        operations.append(
            {
                "op": "prototype",
                "address": method.address,
                "indirect": False,
                "declaration": method.declaration,
            }
        )
    return {
        "version": 4,
        "arch": "x86_64",
        "big_endian": False,
        "options": {"platform": "default", "compiler": "gcc", "arm_be8": False},
        "mappings": image.mappings,
        "code_modes": [],
        "operations": operations,
        "decompile": {
            "address": selected.address,
            "name": selected.emitted_name,
            "thumb": False,
        },
        "tokens": True,
        "validate_only": False,
    }


def storage_core(storage: dict[str, Any]) -> dict[str, Any]:
    return {key: storage.get(key) for key in ("kind", "space", "address", "size")}


def native_output(response: dict[str, Any], method: Method) -> dict[str, Any]:
    require(
        integer(response.get("version"), "native protocol version", 4) == 4,
        "native protocol version mismatch",
    )
    require(
        response.get("status") == "ok",
        f"native protocol failure: {response.get('message', 'missing or invalid success status')}",
    )
    output = object_value(response.get("output"), "native output")
    require(
        output.get("language_id") == LANGUAGE + ":gcc",
        "native language/compiler mismatch",
    )
    require(
        output.get("data_organization") == {"pointer": 8, "int": 4, "long": 8},
        "native organization mismatch",
    )
    structure = object_value(output.get("structure"), "native structure")
    require(
        structure.get("provenance") == "engine_recovered",
        "native engine provenance unavailable",
    )
    signature = object_value(structure.get("signature"), "native signature")
    require(
        integer(signature.get("return_type", {}).get("size"), "native return width", 8)
        == method.return_size,
        "native return width mismatch",
    )
    return_name = signature.get("return_type", {}).get("name")
    if method.write:
        return_names = {"void"}
    elif method.field == "tail":
        return_names = {"uint4", "uint", "unsigned int"}
    else:
        return_names = {"int4", "int"}
    require(
        return_name in return_names, "native return semantic type unavailable/mismatch"
    )
    require(signature.get("variadic") is False, "unexpected native variadic signature")
    require(
        signature.get("calling_convention") == "__stdcall",
        "native GCC/SysV model mismatch",
    )
    parameters = array_value(signature.get("parameters"), "native parameters")
    require(
        len(parameters) == len(method.parameter_names),
        "native actual parameter count mismatch",
    )
    for index, parameter in enumerate(parameters):
        require(
            parameter.get("data_type", {}).get("size") == (8 if index == 0 else 4),
            "native parameter width",
        )
        display_type = string_value(
            parameter.get("data_type", {}).get("name"), "native parameter type"
        )
        if index == 0:
            require(
                re.sub(r"\s+", "", display_type) == method.layout_name + "*",
                "native self record identity",
            )
        else:
            require(display_type in {"int4", "int"}, "native replacement semantic type")
        storage = object_value(parameter.get("storage"), "native parameter storage")
        require(
            storage.get("kind") == "processor" and storage.get("space") == "register",
            "native storage unavailable",
        )
        integer(storage.get("address"), "native storage address")
        require(storage.get("size") == (8 if index == 0 else 4), "native storage width")
        require(not storage.get("pieces"), "unsupported native split parameter storage")
        identifier(parameter.get("name"))
    diagnostics = object_value(
        structure.get("diagnostics"), "native recovery diagnostics"
    )
    require(
        diagnostics.get("bad_data") is False
        and diagnostics.get("unimplemented") is False,
        "native partial recovery",
    )
    for key in ("unresolved_calls", "unresolved_indirect_jumps", "partial_jump_tables"):
        require(diagnostics.get(key) == 0, f"native incomplete recovery: {key}")
    warnings = array_value(diagnostics.get("warnings"), "native recovery warnings")
    require(len(warnings) <= 128, "native warning count bound")
    for warning in warnings:
        object_value(warning, "native warning")
    return output


def integration_expression(result: dict[str, Any], method: Method) -> Expression:
    require(
        address(result.get("address")) == method.address, "fresh CLI method VA mismatch"
    )
    require(
        result.get("language_id") == LANGUAGE + ":gcc",
        "fresh CLI language/compiler mismatch",
    )
    structure = object_value(result.get("structure"), "fresh CLI structure")
    require(
        structure.get("provenance") == "engine_recovered",
        "fresh CLI recovery provenance unavailable",
    )
    signature = object_value(structure.get("signature"), "fresh CLI signature")
    return_type = object_value(signature.get("return_type"), "fresh CLI return type")
    require(
        integer(return_type.get("size"), "fresh CLI return width", 8)
        == method.return_size,
        "fresh CLI return width mismatch",
    )
    if method.write:
        expected_names = {"void"}
    elif method.field == "tail":
        expected_names = {"uint4", "uint", "unsigned int"}
    else:
        expected_names = {"int4", "int"}
    require(
        return_type.get("name") in expected_names,
        "fresh CLI return semantic type mismatch",
    )
    require(
        signature.get("calling_convention") == "__stdcall"
        and signature.get("variadic") is False,
        "fresh CLI prototype model mismatch",
    )
    parameters = array_value(signature.get("parameters"), "fresh CLI parameters")
    require(
        len(parameters) == len(method.parameter_names),
        "fresh CLI parameter count mismatch",
    )
    names = []
    for index, parameter in enumerate(parameters):
        names.append(identifier(parameter.get("name")))
        data_type = object_value(parameter.get("data_type"), "fresh CLI parameter type")
        require(
            data_type.get("size") == (8 if index == 0 else 4),
            "fresh CLI parameter width mismatch",
        )
        label = string_value(data_type.get("name"), "fresh CLI parameter type label")
        if index == 0:
            require(
                re.sub(r"\s+", "", label) == method.layout_name + "*",
                "fresh CLI self record mismatch",
            )
        else:
            require(label in {"int4", "int"}, "fresh CLI replacement type mismatch")
    diagnostics = object_value(
        structure.get("diagnostics"), "fresh CLI recovery diagnostics"
    )
    require(
        diagnostics.get("bad_data") is False
        and diagnostics.get("unimplemented") is False,
        "fresh CLI incomplete recovery",
    )
    require(
        all(
            diagnostics.get(key) == 0
            for key in (
                "unresolved_calls",
                "unresolved_indirect_jumps",
                "partial_jump_tables",
            )
        ),
        "fresh CLI unresolved recovery",
    )
    require(
        result.get("recovery_status") in {"no_reported_issues", "warnings"},
        "fresh CLI recovery unavailable",
    )
    return rendered_expression(
        string_value(result.get("code"), "fresh CLI code"), names, method.write
    )


def specification_identity(bundle: Path, installed: Path) -> tuple[str, dict[str, Any]]:
    manifest = hashlib.sha256()
    files = sorted(path for path in bundle.rglob("*") if path.is_file())
    require(0 < len(files) <= 1024, "bundled specification manifest unavailable/bound")
    for path in files:
        relative = path.relative_to(bundle).as_posix().encode()
        content = bounded_read(path, 32 * MAX_IMAGE)
        manifest.update(struct.pack("<Q", len(relative)))
        manifest.update(relative)
        manifest.update(struct.pack("<Q", len(content)))
        manifest.update(content)
    selected = {}
    for name in ("x86-64.sla", "x86-64.pspec", "x86-64-gcc.cspec"):
        relative = Path("Ghidra/Processors/x86/data/languages") / name
        expected = digest_bytes(bounded_read(bundle / relative, 32 * MAX_IMAGE))
        actual = digest_bytes(bounded_read(installed / relative, 32 * MAX_IMAGE))
        require(actual == expected, f"installed Ghidra specification mismatch: {name}")
        selected[name] = {"sha256": actual, "path": str(installed / relative)}
    return manifest.hexdigest(), selected


def reference_results(
    export: dict[str, Any], request: dict[str, Any], methods: list[Method]
) -> dict[str, dict[str, Any]]:
    require(
        export.get("schema") == "rampage-cpp-virtual-reference-v1",
        "reference export schema mismatch",
    )
    require(export.get("ok") is True, f"reference setup failed: {export.get('error')}")
    require(
        export.get("input_sha256") == request["input_sha256"],
        "reference request identity mismatch",
    )
    require(
        export.get("memory_sha256") == request["memory_sha256"],
        "reference memory readback mismatch",
    )
    require(
        export.get("memory_validated") is True,
        "reference memory validation unavailable",
    )
    require(
        export.get("layout_validated") is True, "reference layout readback unavailable"
    )
    require(
        export.get("analysis_mode") == "DISABLED",
        "reference auto-analysis was not disabled",
    )
    require(
        export.get("language_id") == LANGUAGE and export.get("compiler_id") == "gcc",
        "reference language/compiler",
    )
    require(
        export.get("default_model") == "__stdcall",
        "reference GCC/SysV default model mismatch",
    )
    require(
        export.get("effective_options") == OPTIONS,
        "reference effective option mismatch",
    )
    require(
        export.get("specifications") == request["specifications"],
        "reference specification hashes mismatch",
    )
    require(export.get("ghidra_version") == "12.1.4", "actual Ghidra version mismatch")
    require(
        export.get("scratch_settings_owned") is True,
        "reference application directory ownership unavailable",
    )
    directories = object_value(
        export.get("runtime_directories"), "actual reference runtime directories"
    )
    root = Path(
        string_value(request.get("scratch_root"), "request scratch root")
    ).resolve()
    expected_parents = {
        "user_home": root / "h",
        "java_temp": root,
        "application_settings": root / "gs",
        "application_cache": root / "gc",
        "application_temp": root / "gt",
    }
    for name, parent in expected_parents.items():
        actual = Path(
            string_value(directories.get(name), f"actual reference {name}")
        ).resolve()
        require(
            actual.is_relative_to(parent),
            f"actual reference {name} escaped runner scratch",
        )
    rows = array_value(export.get("methods"), "reference method results")
    require(len(rows) <= len(methods), "reference extra method results")
    result = {}
    for row in rows:
        symbol = string_value(row.get("symbol"), "reference symbol")
        require(symbol not in result, "duplicate reference method identity")
        result[symbol] = row
    require(
        set(result) <= {item.symbol for item in methods},
        "reference method identities mismatch",
    )
    for method in methods:
        if method.symbol in result:
            require(
                address(result[method.symbol].get("address")) == method.address,
                "reference method VA mismatch",
            )
    return result


def reference_parameters(row: dict[str, Any], method: Method) -> list[dict[str, Any]]:
    require(
        row.get("ok") is True,
        f"reference decompilation unavailable: {row.get('error')}",
    )
    require(
        integer(row.get("return_size"), "reference return width", 8)
        == method.return_size,
        "reference return width mismatch",
    )
    expected_return = (
        "void"
        if method.write
        else "unsigned_integer"
        if method.field == "tail"
        else "signed_integer"
    )
    require(
        row.get("return_kind") == expected_return,
        "reference return semantic kind mismatch",
    )
    parameters = array_value(row.get("parameters"), "reference parameters")
    require(
        len(parameters) == len(method.parameter_names),
        "reference parameter count mismatch",
    )
    require(
        row.get("calling_convention") == "__stdcall",
        "reference prototype model mismatch",
    )
    for index, parameter in enumerate(parameters):
        require(
            parameter.get("size") == (8 if index == 0 else 4),
            "reference parameter width mismatch",
        )
        require(
            parameter.get("kind")
            == ("record_pointer" if index == 0 else "signed_integer"),
            "reference parameter semantic kind mismatch",
        )
        if index == 0:
            require(
                parameter.get("record_name") == method.layout_name,
                "reference self record identity mismatch",
            )
        identifier(parameter.get("name"))
    return parameters


def match_parameter_storage(
    row: dict[str, Any], method: Method, native: dict[str, Any] | None
) -> None:
    parameters = reference_parameters(row, method)
    if native is None:
        raise CorpusError(
            "native storage unavailable; reference matching cannot be established"
        )
    native_parameters = native["structure"]["signature"]["parameters"]
    require(
        len(native_parameters) == len(parameters),
        "native/reference storage parameter count mismatch",
    )
    for expected, actual in zip(native_parameters, parameters):
        require(
            storage_core(expected["storage"]) == actual.get("storage"),
            "reference/native parameter storage mismatch",
        )


def validate_reference_method(row: dict[str, Any], method: Method) -> Expression:
    parameters = reference_parameters(row, method)
    return rendered_expression(
        row["text"], [item["name"] for item in parameters], method.write
    )


def score_reference_case(
    case: dict[str, Any],
    row: dict[str, Any],
    method: Method,
    native: dict[str, Any] | None,
) -> None:
    case["reference_success"] = row.get("ok") is True
    case["reference_oracle_match"] = False
    case["settings_matched"] = False
    case["agreement"] = False
    try:
        actual = validate_reference_method(row, method)
        case["reference_expression"] = {"base": actual.base, "delta_u32": actual.delta}
        case["reference_oracle_match"] = actual == method.expected
        case["raw_expression_equality"] = case["reference_expression"] == case.get(
            "native_expression"
        )
        case["agreement"] = (
            case.get("native_oracle_match") is True
            and case["reference_oracle_match"] is True
            and case["raw_expression_equality"] is True
        )
        require(
            case["reference_oracle_match"],
            "reference rendered expression differs from independent source",
        )
    except (CorpusError, ValueError, KeyError, TypeError, AttributeError) as error:
        case["failures"].append({"stage": "reference_oracle", "message": str(error)})
    try:
        match_parameter_storage(row, method, native)
        case["settings_matched"] = True
    except (CorpusError, ValueError, KeyError, TypeError, AttributeError) as error:
        case["failures"].append({"stage": "settings", "message": str(error)})
    if not case["agreement"]:
        case["failures"].append(
            {
                "stage": "agreement",
                "message": "both independently oracle-validated results required",
            }
        )


def memory_digest(mappings: list[dict[str, Any]]) -> str:
    """Hash exact ranges, permissions, every backed/zero byte, and therefore every inter-range gap."""
    digest = hashlib.sha256()
    for mapping in mappings:
        flags = (
            int(mapping["readable"]) * 4
            + int(mapping["writable"]) * 2
            + int(mapping["executable"])
        )
        backed = bytes.fromhex(mapping["hex_bytes"])
        digest.update(
            struct.pack("<QQQB", mapping["base"], mapping["size"], len(backed), flags)
        )
        digest.update(backed.ljust(mapping["size"], b"\0"))
    return digest.hexdigest()


def summarize(
    cases: list[dict[str, Any]], warnings: list[dict[str, Any]]
) -> dict[str, Any]:
    counts = {"selected": len(cases)}
    for name in (
        "admitted",
        "native_success",
        "reference_success",
        "settings_matched",
        "native_oracle_match",
        "reference_oracle_match",
        "raw_expression_equality",
        "agreement",
        "integration_success",
    ):
        counts[name] = sum(item.get(name) is True for item in cases)
    counts["refusals"] = sum(bool(item.get("failures")) for item in cases)
    return {
        "counts": counts,
        "denominator": len(cases),
        "warning_categories": dict(
            Counter(item.get("category", "unclassified") for item in warnings)
        ),
    }


def executable_path(value: str, context: str) -> Path:
    path = Path(value).expanduser().resolve()
    require(
        path.is_file() and os.access(path, os.X_OK),
        f"{context}: missing explicit executable: {path}",
    )
    return path


def copy_inline_cli(
    executable: Path, scratch: Path, expected_sha256: str
) -> tuple[Path, str]:
    before = executable.stat()
    require(
        stat.S_ISREG(before.st_mode) and before.st_size <= MAX_EXECUTABLE,
        "CLI copy input size/type bound",
    )
    directory = scratch / "bin" / "c"
    directory.mkdir(parents=True)
    copied = directory / "rampage"
    total = 0
    digest = hashlib.sha256()
    with executable.open("rb") as source, copied.open("xb") as destination:
        while block := source.read(min(65536, MAX_EXECUTABLE - total + 1)):
            total += len(block)
            require(total <= MAX_EXECUTABLE, "CLI grew beyond copy bound")
            digest.update(block)
            destination.write(block)
    after = executable.stat()
    attributes = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mode",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    require(
        total == before.st_size
        and all(getattr(before, name) == getattr(after, name) for name in attributes),
        "CLI changed during physical copy",
    )
    require(
        digest.hexdigest() == expected_sha256,
        "CLI physical copy differs from recorded binary identity",
    )
    copied.chmod(stat.S_IMODE(before.st_mode))
    copied_sha256 = file_digest(copied, MAX_EXECUTABLE)
    require(
        copied_sha256 == expected_sha256
        and not copied.is_symlink()
        and not copied.samefile(executable),
        "CLI copy must be a distinct byte-identical physical file",
    )
    require(
        list(directory.iterdir()) == [copied],
        "CLI scratch bin must contain only the copied CLI",
    )
    return copied, copied_sha256


def child_environment(scratch: Path) -> dict[str, str]:
    environment = dict(os.environ)
    require(
        not environment.get("GHIDRA_INSTALL_DIR"),
        "GHIDRA_INSTALL_DIR override prevents bundled checked comparison",
    )
    environment.pop("RAMPAGE_WORKER", None)
    environment.update(
        {
            "HOME": str(scratch / "h"),
            "TMPDIR": str(scratch),
            "XDG_CACHE_HOME": str(scratch / "c"),
            "XDG_CONFIG_HOME": str(scratch / "config"),
            "XDG_DATA_HOME": str(scratch / "data"),
            "XDG_STATE_HOME": str(scratch / "state"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    (scratch / "h").mkdir(exist_ok=True)
    return environment


def reference_environment(
    environment: dict[str, str], scratch: Path, java_home: Path
) -> dict[str, str]:
    result = dict(environment)
    for option in (
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "JAVA_OPTS",
        "GHIDRA_JAVA_OPTIONS",
        "GHIDRA_HEADLESS_JAVA_OPTIONS",
    ):
        result.pop(option, None)
    properties = {
        "user.home": scratch / "h",
        "java.io.tmpdir": scratch,
        "application.settingsdir": scratch / "gs",
        "application.cachedir": scratch / "gc",
        "application.tempdir": scratch / "gt",
    }
    for path in properties.values():
        path.mkdir(exist_ok=True)
    require(
        all(
            not any(character in str(path) for character in ('"', "\\", "\n", "\r"))
            for path in properties.values()
        ),
        "temporary root is not representable in Java option quoting",
    )
    result.update(
        {
            "JAVA_HOME": str(java_home),
            "JAVA_HOME_OVERRIDE": str(java_home),
            "GHIDRA_USER_HOME": str(scratch / "h"),
            "JAVA_TOOL_OPTIONS": " ".join(
                f'-D{name}="{path}"' for name, path in properties.items()
            ),
        }
    )
    return result


def collect_warnings(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    warnings = []
    for row in receipt.get("details", []):
        if row.get("kind") == "warning":
            warnings.append(
                {
                    "category": "consumer_" + row.get("source", "unknown"),
                    "evidence": row,
                }
            )
        elif row.get("status") in {"not_approved", "unverified", "preserved"}:
            warnings.append(
                {"category": "consumer_refusal_or_preservation", "evidence": row}
            )
        elif row.get("kind") not in {"type", "field", "function", "parameter"}:
            warnings.append(
                {"category": "additional_consumer_evidence", "evidence": row}
            )
    return warnings


def run_corpus(arguments: argparse.Namespace) -> dict[str, Any]:
    cases: list[dict[str, Any]] = [
        {"selection_index": index, "failures": []} for index in range(6)
    ]
    warnings: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema": "rampage-cpp-virtual-corpus-v1",
        "ok": False,
        "variant": arguments.variant,
        "comparison": "controlled protocol-4 backend comparison; separate fresh CLI apply/decompile integration",
        "evidence_scope": "bounded rendered expressions over tiny owned methods, not semantic equivalence or P-code",
        "expression_model": "one source field/parameter plus constants modulo 2^32; restricted safe casts/promotions",
        "bounds": {
            "image_bytes": MAX_IMAGE,
            "aggregate_mapped_bytes": MAX_IMAGE,
            "aggregate_rendered_text_bytes": MAX_TEXT,
            "rendered_bytes_per_method": MAX_METHOD_TEXT,
            "selected_methods": 6,
            "method_hard_limit": MAX_METHODS,
            "stdout_bytes_per_process": MAX_TEXT,
            "stderr_bytes_per_process": MAX_STDERR,
        },
        "limitations": [
            "no target execution",
            "no RTTI/vtable-slot call resolution",
            "native return storage unavailable",
            "virtual wrappers not selected or resolved",
            (
                "CLI integration selects native fallback via a physical CLI copy with no worker override or sibling; "
                "isolated CLI parity belongs to separate core tests"
            ),
            (
                "only descendants inheriting the owned guardian group are supported; "
                "observed escapes are refused, not signalled"
            ),
            (
                "replacement analysis tools are trusted, not authenticated or OS-sandboxed; "
                "undetected detachment is unsupported"
            ),
            "cold means a fresh process, not cold filesystem caches",
            "cold native cases and one cold Java batch have distinct timing scopes; no speed score",
        ],
        "cases": cases,
        "warnings": warnings,
        "processes": [],
    }
    started = time.monotonic()
    try:
        oracle_path = Path(
            string_value(
                os.environ.get("RAMPAGE_DEBUG_CPP_VIRTUAL_ORACLE"), "oracle environment"
            )
        ).resolve()
        fixture_root = Path(
            string_value(
                os.environ.get("RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES"),
                "fixture environment",
            )
        )
        oracle = read_json(oracle_path)
        source_path = oracle_path.parent / oracle["groups"]["records"]["source"]
        source_bytes = bounded_read(source_path, MAX_TEXT)
        methods = load_methods(oracle, source_bytes.decode("utf-8"))
        require(
            len(methods) == 6,
            "bounded selection requires exactly six independent oracle methods",
        )
        cases[:] = [
            {
                "symbol": method.symbol,
                "record": method.record,
                "failures": [],
                "expected_expression": {
                    "base": method.expected.base,
                    "delta_u32": method.expected.delta,
                },
            }
            for method in methods
        ]
        report["oracle_sha256"], report["source_sha256"] = (
            fingerprint(oracle),
            digest_bytes(source_bytes),
        )
        report["negative_groups"] = {
            name: {
                "status": "not_selected",
                "reason": "positive six-method bounded lane",
            }
            for name in oracle["groups"]
            if name != "records"
        }
        image_path = (fixture_root / arguments.variant / "records.debug.elf").resolve()
        image = parse_elf(bounded_read(image_path, MAX_IMAGE))
        check_elf_oracle(image, oracle, methods)
        report["raw_vtable_words_match"] = True
        report["vtable_prefix_status"] = "UnverifiedPrefix"
        original_cli = executable_path(arguments.rampage, "rampage CLI")
        worker = executable_path(arguments.worker, "native worker")
        launcher = executable_path(arguments.ghidra_headless, "Ghidra headless")
        java_home = Path(arguments.java_home).expanduser().resolve()
        executable_path(str(java_home / "bin/java"), "JDK")
        report["binaries"] = {
            "cli_sha256": file_digest(original_cli, MAX_EXECUTABLE),
            "worker_sha256": file_digest(worker, MAX_EXECUTABLE),
            "headless_launcher_sha256": file_digest(launcher, MAX_IMAGE),
        }
        bundle_context, specifications = specification_identity(
            ROOT / "crates/rampage-decompiler/specs", launcher.parent.parent
        )
        temporary_root = Path(os.environ.get("TMPDIR") or str(DEFAULT_TEMP))
        require(
            temporary_root.is_dir(),
            "approved temporary parent unavailable; set TMPDIR explicitly",
        )
        with tempfile.TemporaryDirectory(prefix="cv", dir=temporary_root) as temporary:
            scratch = Path(temporary)
            environment = child_environment(scratch)
            executable, copied_sha256 = copy_inline_cli(
                original_cli, scratch, report["binaries"]["cli_sha256"]
            )
            report["binaries"]["copied_cli_sha256"] = copied_sha256
            report["execution_mode"] = "inline_native_no_worker_override_or_sibling"
            owned_image = scratch / "i.elf"
            owned_image.write_bytes(image.data)
            receipt, preview_processes = collect_review(
                executable, owned_image, scratch, arguments.timeout, environment
            )
            report["processes"].extend(preview_processes)
            warnings.extend(collect_warnings(receipt))
            require(
                receipt["compiler_spec_sha256"] == bundle_context,
                "CLI compiler manifest differs from source bundle",
            )
            layouts = validate_consumer(
                receipt,
                oracle,
                methods,
                digest_bytes(image.data),
                4 if arguments.variant == "dwarf4-o1" else 5,
            )
            report["consumer"] = {
                key: value for key, value in receipt.items() if key != "details"
            }
            report["accepted_layouts"] = layouts
            selected_symbols = {method.symbol for method in methods}
            report["selected_consumer_evidence"] = [
                row
                for row in receipt["details"]
                if row.get("source") == "checked"
                and (
                    row.get("kind") in {"type", "field"}
                    and row.get("status") == "verified"
                    or row.get("kind") == "function"
                    and row.get("status") == "approved"
                    and row.get("data", {}).get("original_name") in selected_symbols
                )
            ]
            report["selected_consumer_evidence"].extend(
                row
                for row in receipt["details"]
                if row.get("kind") == "projection"
                and row.get("type_name") in {layout["name"] for layout in layouts}
            )
            for case in cases:
                case["admitted"] = True
            apply_command = [
                str(executable),
                "--json",
                "type",
                "import-debug-layouts",
                str(owned_image),
                "--limit",
                "1000",
                "--apply",
                "--review-sha256",
                receipt["review_sha256"],
            ]
            applied = run_process(
                apply_command, scratch, arguments.timeout, environment=environment
            )
            report["processes"].append(applied.metadata())
            apply_receipt = process_json(applied, "consumer apply")
            require(
                apply_receipt.get("ok") is True
                and apply_receipt.get("whole_apply_succeeded") is True
                and apply_receipt.get("status") == "applied",
                "consumer whole apply failed",
            )
            require(
                apply_receipt.get("review_sha256") == receipt["review_sha256"],
                "apply review identity changed",
            )
            native_outputs: dict[str, dict[str, Any]] = {}
            requests: list[dict[str, Any]] = []
            for method, case in zip(methods, cases):
                case["address"] = hex(method.address)
                request = worker_request(
                    image, layouts, methods, method, bundle_context
                )
                requests.append(request)
                try:
                    native = run_process(
                        [str(worker)],
                        scratch,
                        arguments.timeout,
                        canonical(request),
                        environment,
                        stdout_limit=MAX_TEXT // (4 * len(methods)),
                    )
                    case["native_process"] = native.metadata()
                    if native.stderr:
                        warnings.append(
                            {
                                "category": "native_stderr",
                                "symbol": method.symbol,
                                "evidence": native.stderr.decode("utf-8", "replace"),
                            }
                        )
                    response = process_json(native, "native worker")
                    case["native_response"] = response
                    case["native_success"] = (
                        response.get("status") == "ok"
                        and type(response.get("version")) is int
                        and response.get("version") == 4
                    )
                    output = native_output(response, method)
                    native_outputs[method.symbol] = output
                    for warning in output["structure"]["diagnostics"]["warnings"]:
                        warnings.append(
                            {
                                "category": "native_recovery_"
                                + warning.get("kind", "unknown"),
                                "symbol": method.symbol,
                                "evidence": warning,
                            }
                        )
                    parameter_names = [
                        item["name"]
                        for item in output["structure"]["signature"]["parameters"]
                    ]
                    actual = rendered_expression(
                        output["text"], parameter_names, method.write
                    )
                    case["native_oracle_match"] = actual == method.expected
                    case["native_expression"] = {
                        "base": actual.base,
                        "delta_u32": actual.delta,
                    }
                    require(
                        case["native_oracle_match"],
                        "native rendered expression differs from independent source",
                    )
                except (
                    CorpusError,
                    OSError,
                    ValueError,
                    KeyError,
                    TypeError,
                    AttributeError,
                    subprocess.SubprocessError,
                ) as error:
                    case["failures"].append({"stage": "native", "message": str(error)})
                try:
                    integrated = run_process(
                        [
                            str(executable),
                            "--json",
                            "decompile",
                            str(owned_image),
                            "--at",
                            hex(method.address),
                        ],
                        scratch,
                        arguments.timeout,
                        environment=environment,
                    )
                    case["integration_process"] = integrated.metadata()
                    integration = process_json(integrated, "fresh CLI integration")
                    case["integration_response"] = integration
                    require(
                        integration_expression(integration, method) == method.expected,
                        "fresh CLI integration expression mismatch",
                    )
                    case["integration_success"] = True
                except (
                    CorpusError,
                    OSError,
                    ValueError,
                    KeyError,
                    TypeError,
                    AttributeError,
                    subprocess.SubprocessError,
                ) as error:
                    case["failures"].append(
                        {"stage": "integration", "message": str(error)}
                    )
            reference_request: dict[str, Any] = {
                "schema": "rampage-cpp-virtual-input-v1",
                "scratch_root": str(scratch.resolve()),
                "language_id": LANGUAGE,
                "compiler_id": "gcc",
                "options": OPTIONS,
                "mappings": image.mappings,
                "memory_sha256": memory_digest(image.mappings),
                "layouts": layouts,
                "declarations": layout_declarations(layouts),
                "operations": requests[0]["operations"],
                "compiler_spec_sha256": bundle_context,
                "specifications": specifications,
                "timeout_seconds": min(30, max(1, int(arguments.timeout))),
                "methods": [
                    {
                        "symbol": method.symbol,
                        "address": method.address,
                        "size": method.size,
                        "name": method.emitted_name,
                        "declaration": method.declaration,
                    }
                    for method in methods
                ],
            }
            input_sha = fingerprint(reference_request)
            reference_request["input_sha256"] = input_sha
            report["effective_input_options_sha256"] = input_sha
            report["native_requests_sha256"] = [fingerprint(item) for item in requests]
            report["memory_sha256"] = reference_request["memory_sha256"]
            script_directory = scratch / "s"
            script_directory.mkdir()
            shutil.copyfile(
                Path(__file__).with_name("ghidra_cpp_virtual_export.java"),
                script_directory / "ghidra_cpp_virtual_export.java",
            )
            request_path, export_path = scratch / "q.json", scratch / "e.json"
            request_path.write_bytes(canonical(reference_request))
            java_environment = reference_environment(environment, scratch, java_home)
            reference_command = [
                str(launcher),
                str(scratch),
                "p",
                "-import",
                str(owned_image),
                "-noanalysis",
                "-processor",
                LANGUAGE,
                "-cspec",
                "gcc",
                "-scriptPath",
                str(script_directory),
                "-postScript",
                "ghidra_cpp_virtual_export.java",
                str(request_path),
                str(export_path),
                "-log",
                str(scratch / "g.log"),
                "-scriptlog",
                str(scratch / "s.log"),
                "-deleteProject",
            ]
            reference = run_process(
                reference_command,
                scratch,
                arguments.timeout,
                environment=java_environment,
            )
            report["reference_cold_batch_process"] = reference.metadata()
            require(
                reference.failure is None and reference.returncode == 0,
                "reference process failed/deadline/output bound",
            )
            export = read_json(export_path)
            report["reference_export"] = export
            reference_rows = reference_results(export, reference_request, methods)
            report["reference_setup"] = {
                key: value for key, value in export.items() if key != "methods"
            }
            if export.get("setup_warning"):
                warnings.append(
                    {
                        "category": "reference_setup_warning",
                        "evidence": export["setup_warning"],
                    }
                )
            for method, case in zip(methods, cases):
                row = reference_rows.get(method.symbol)
                if row is None:
                    case["failures"].append(
                        {
                            "stage": "reference",
                            "message": "reference method result missing",
                        }
                    )
                    continue
                case["reference"] = row
                if row.get("warning"):
                    warnings.append(
                        {
                            "category": "reference_success_warning",
                            "symbol": method.symbol,
                            "evidence": row["warning"],
                        }
                    )
                score_reference_case(
                    case, row, method, native_outputs.get(method.symbol)
                )
    except (
        CorpusError,
        CorpusInterrupted,
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        subprocess.SubprocessError,
    ) as error:
        report["error"] = str(error)
        for case in cases:
            case["failures"].append({"stage": "gate", "message": str(error)})
    report["metrics"] = summarize(cases, warnings)
    report["wall_seconds"] = time.monotonic() - started
    report["ok"] = bool(cases) and all(
        not case["failures"] and case.get("agreement") is True for case in cases
    )
    return report


def parser() -> argparse.ArgumentParser:
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument(
        "--rampage", required=True, help="explicit rampage CLI executable"
    )
    arguments.add_argument(
        "--worker", required=True, help="explicit protocol-4 worker executable"
    )
    arguments.add_argument(
        "--ghidra-headless",
        required=True,
        help="explicit installed analyzeHeadless launcher",
    )
    arguments.add_argument(
        "--java-home",
        required=True,
        help="installed JDK home, applied only to reference process",
    )
    arguments.add_argument(
        "--variant", choices=("dwarf4-o1", "dwarf5-o2"), default="dwarf5-o2"
    )
    arguments.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="startup-inclusive deadline per subprocess, <=600s",
    )
    arguments.add_argument(
        "--output", type=Path, help="explicit new report path; otherwise JSON to stdout"
    )
    return arguments


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if not math.isfinite(arguments.timeout) or not 0 < arguments.timeout <= 600:
        parser().error("--timeout must be finite, positive and at most 600 seconds")
    previous = {
        signum: signal.signal(signum, interrupt)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    }
    try:
        report = run_corpus(arguments)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    text = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if arguments.output:
        try:
            with arguments.output.open("x", encoding="utf-8") as stream:
                stream.write(text)
        except OSError as error:
            print(
                f"cannot create new report {arguments.output}: {error}", file=sys.stderr
            )
            return 1
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
