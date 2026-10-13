from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import re
import uuid
from pathlib import Path
from typing import Any

PROTOCOL = "rampage-lldb-query-v1"
MAX_REQUEST_BYTES = 16384
MAX_RESPONSE_BYTES = 262144
DEFAULT_RESPONSE_BYTES = 65536
MIN_RESPONSE_BYTES = 1024
MAX_MODULES = 4096
MAX_THREADS = 4096
MAX_PAGE_ITEMS = 128
MAX_METADATA_BYTES = 1048576
MAX_MEMORY_BYTES = 65536
MAX_MAPPING_QUERIES = 1024
SESSION_ID = uuid.uuid4().hex
OPERATIONS = {
    "describe_session": set(),
    "list_modules": {"offset", "limit"},
    "list_threads": {"offset", "limit"},
    "read_registers": {"thread_id", "registers"},
    "read_memory": {"address", "size", "permissions", "thread_id"},
}
REGISTER_NAMES = {
    "aarch64": [f"x{index}" for index in range(31)] + ["sp", "pc", "cpsr"],
    "arm": [f"r{index}" for index in range(13)] + ["sp", "lr", "pc", "cpsr"],
    "x86_64": ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp"]
    + [f"r{index}" for index in range(8, 16)]
    + ["rip", "rflags"],
}
ARM32_MACHINES = {
    "arm",
    "armeb",
    "armv7",
    "armv7a",
    "armv7l",
    "armv7s",
    "armv7k",
    "thumb",
    "thumbeb",
    "thumbv7",
    "thumbv7a",
    "thumbv7s",
    "thumbv7k",
}
CURRENT_STOP_REASON_NAMES = (
    "eStopReasonTrace",
    "eStopReasonBreakpoint",
    "eStopReasonWatchpoint",
    "eStopReasonSignal",
    "eStopReasonException",
    "eStopReasonExec",
    "eStopReasonPlanComplete",
    "eStopReasonThreadExiting",
    "eStopReasonInstrumentation",
    "eStopReasonProcessorTrace",
    "eStopReasonFork",
    "eStopReasonVFork",
    "eStopReasonVForkDone",
    "eStopReasonInterrupt",
)
REGION_DESCRIPTION = re.compile(
    r"\[(0x[0-9a-fA-F]{1,16})-(0x[0-9a-fA-F]{1,16}) ([Rr?-][Ww?-][Xx?-])\]"
)


def load_snapshot_helpers() -> Any:
    specification = importlib.util.spec_from_file_location(
        "_rampage_bridge_snapshot_helpers", Path(__file__).with_name("lldb_snapshot.py")
    )
    if specification is None or specification.loader is None:
        raise ImportError("cannot load LLDB snapshot helpers")
    helpers = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(helpers)
    return helpers


_snapshot = load_snapshot_helpers()


class QueryError(Exception):
    code: str

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def encode_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    )


def integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise QueryError(
            "invalid_request", f"{field} must be an integer in [{minimum}, {maximum}]"
        )
    return value


def address(value: Any, field: str) -> int:
    if isinstance(value, str):
        if not value.startswith("0x") or not 3 <= len(value) <= 18:
            raise QueryError(
                "invalid_request", f"{field} must be an integer or a hexadecimal string"
            )
        if any(character not in "0123456789abcdefABCDEF" for character in value[2:]):
            raise QueryError(
                "invalid_request", f"{field} contains invalid hexadecimal digits"
            )
        value = int(value, 16)
    return integer(value, field, 0, 2**64 - 2)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QueryError("invalid_request", "duplicate JSON object field")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise QueryError("invalid_request", "non-finite JSON numbers are not supported")


def parse_request(command: str) -> dict[str, Any]:
    try:
        encoded_size = (
            len(command.encode("utf-8"))
            if len(command) <= MAX_REQUEST_BYTES
            else len(command)
        )
    except UnicodeError as error:
        raise QueryError(
            "invalid_request", "request must contain valid UTF-8 text"
        ) from error
    if len(command) > MAX_REQUEST_BYTES or encoded_size > MAX_REQUEST_BYTES:
        raise QueryError("limit_exceeded", "request exceeds input byte limit")
    try:
        request = json.loads(
            command, object_pairs_hook=unique_object, parse_constant=reject_constant
        )
    except (ValueError, RecursionError) as error:
        raise QueryError(
            "invalid_request", "request must be a single JSON object"
        ) from error
    if not isinstance(request, dict):
        raise QueryError("invalid_request", "request must be a JSON object")
    integer(request.get("version"), "version", 1, 1)
    operation = request.get("operation")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise QueryError(
            "invalid_request", "operation is not in the read-only allowlist"
        )
    allowed = {
        "version",
        "operation",
        "expected_token",
        "response_budget",
    } | OPERATIONS[operation]
    if request.keys() - allowed:
        raise QueryError("invalid_request", "unknown request fields")
    integer(
        request.get("response_budget", DEFAULT_RESPONSE_BYTES),
        "response_budget",
        MIN_RESPONSE_BYTES,
        MAX_RESPONSE_BYTES,
    )
    token = request.get("expected_token")
    if token is None and (
        "expected_token" in request or operation != "describe_session"
    ):
        raise QueryError("invalid_request", "this operation requires expected_token")
    if token is not None:
        if not isinstance(token, dict) or set(token) != {
            "backend",
            "session_id",
            "process_unique_id",
            "stop_id",
            "target_index",
        }:
            raise QueryError("invalid_request", "invalid expected_token fields")
        if token["backend"] != "lldb-sb" or not isinstance(token["session_id"], str):
            raise QueryError("invalid_request", "invalid token backend or session")
        if not 1 <= len(token["session_id"]) <= 128:
            raise QueryError("invalid_request", "invalid token session length")
        integer(token["process_unique_id"], "process_unique_id", 1, 2**64 - 1)
        integer(token["stop_id"], "stop_id", 0, 2**64 - 1)
        integer(token["target_index"], "target_index", 0, 2**32 - 2)
    if operation in {"list_modules", "list_threads"}:
        integer(request.get("offset", 0), "offset", 0, max(MAX_MODULES, MAX_THREADS))
        integer(request.get("limit", 32), "limit", 1, MAX_PAGE_ITEMS)
    if operation == "read_registers" or "thread_id" in request:
        integer(
            address(request.get("thread_id"), "thread_id"), "thread_id", 1, 2**64 - 2
        )
    if operation == "read_registers" and "registers" in request:
        names = request["registers"]
        if not isinstance(names, list) or not 1 <= len(names) <= 34:
            raise QueryError(
                "invalid_request", "registers must be a bounded nonempty list"
            )
        if any(not isinstance(name, str) or len(name) > 16 for name in names):
            raise QueryError("invalid_request", "invalid register name")
        if len(set(names)) != len(names):
            raise QueryError("invalid_request", "duplicate register names")
        if not set(names) <= set().union(*REGISTER_NAMES.values()):
            raise QueryError(
                "invalid_request", "register name is not in the read-only allowlist"
            )
    if operation == "read_memory":
        start = address(request.get("address"), "address")
        size = integer(request.get("size"), "size", 1, MAX_MEMORY_BYTES)
        if start + size > 2**64 - 1:
            raise QueryError("invalid_request", "requested memory range overflows")
        if request.get("permissions") not in ("r--", "rw-", "r-x", "rwx"):
            raise QueryError(
                "invalid_request", "permissions must be exactly r--, rw-, r-x or rwx"
            )
    return request


def backend_integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    try:
        return integer(value, field, minimum, maximum)
    except QueryError as error:
        raise QueryError("unavailable", f"invalid LLDB {field}") from error


def bounded_text(value: Any, field: str, limit: int = 4096) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > limit
        or len(value.encode("utf-8")) > limit
    ):
        raise QueryError("limit_exceeded", f"LLDB {field} exceeds text limit")
    return value


def described_permissions(region: Any, lldb: Any) -> str:
    if not hasattr(lldb, "SBStream") or not hasattr(region, "GetDescription"):
        raise QueryError(
            "unavailable", "LLDB SDK cannot distinguish unknown memory permissions"
        )
    stream = lldb.SBStream()
    if region.GetDescription(stream) is not True:
        raise QueryError(
            "unavailable", "LLDB memory permission description is unavailable"
        )
    description = bounded_text(stream.GetData(), "memory region description", 256)
    match = (
        REGION_DESCRIPTION.fullmatch(description) if description is not None else None
    )
    if match is None:
        raise QueryError(
            "unavailable", "unsupported LLDB memory permission description"
        )
    if (int(match[1], 16), int(match[2], 16)) != (
        region.GetRegionBase(),
        region.GetRegionEnd(),
    ):
        raise QueryError(
            "unavailable", "LLDB memory description differs from region bounds"
        )
    return match[3].lower()


def permission_flags(region: Any) -> tuple[bool, bool, bool]:
    flags = region.IsReadable(), region.IsWritable(), region.IsExecutable()
    if any(type(flag) is not bool for flag in flags):
        raise QueryError("unavailable", "invalid LLDB memory permission flags")
    return flags


def require_permission_description_support(lldb: Any) -> None:
    """Refuse SDKs whose default unknown permissions are indistinguishable from known No."""
    if not hasattr(lldb, "SBMemoryRegionInfo"):
        raise QueryError("unavailable", "LLDB memory permission inspection is required")
    unknown = lldb.SBMemoryRegionInfo()
    description = described_permissions(unknown, lldb)
    if permission_flags(unknown) != (False, False, False) or "-" in description:
        raise QueryError(
            "unavailable", "LLDB SDK conflates unknown and denied memory permissions"
        )


def known_permissions(region: Any, lldb: Any) -> str:
    description = described_permissions(region, lldb)
    flags = permission_flags(region)
    actual = "".join(
        letter if flags[index] else "-" for index, letter in enumerate("rwx")
    )
    if description != actual:
        raise QueryError(
            "unavailable", "memory permissions are unknown or inconsistent in LLDB SDK"
        )
    return actual


class QueryContext:
    debugger: Any
    lldb: Any
    target: Any
    process: Any
    pid: int
    token: dict[str, Any]
    target_context: tuple[str, int, int]
    modules: list[dict[str, Any]]
    threads: list[dict[str, Any]]
    register_contexts: dict[int, dict[str, Any]]
    mapping_context: list[dict[str, Any]] | None
    memory_request: tuple[int, int, str] | None
    mapping_queries: int

    def __init__(
        self, debugger: Any, lldb: Any, expected: dict[str, Any] | None
    ) -> None:
        self.debugger, self.lldb = debugger, lldb
        self.target = debugger.GetSelectedTarget()
        if not self.target.IsValid():
            raise QueryError(
                "unavailable", "select an existing authorized stopped LLDB target"
            )
        self.process = self.target.GetProcess()
        self.pid = backend_integer(self.process.GetProcessID(), "PID", 1, 2**64 - 1)
        self.token, self.target_context = self.read_identity()
        if expected is not None and expected != self.token:
            raise QueryError(
                "stale_token",
                "expected_token does not identify the current backend session/process/stop",
            )
        self.register_contexts = {}
        self.mapping_context = None
        self.memory_request = None
        self.mapping_queries = 0
        self.modules = self.read_modules()
        self.threads = self.read_threads()
        self.ensure_identity()

    def read_identity(self) -> tuple[dict[str, Any], tuple[str, int, int]]:
        target = self.debugger.GetSelectedTarget()
        process = target.GetProcess()
        if (
            not target.IsValid()
            or not process.IsValid()
            or process.GetState() != self.lldb.eStateStopped
        ):
            raise QueryError(
                "unavailable",
                "process must already be stopped; bridge never launches, attaches or stops it",
            )
        debugger_id = backend_integer(
            self.debugger.GetID(), "debugger ID", 0, 2**64 - 1
        )
        token = {
            "backend": "lldb-sb",
            "session_id": f"{SESSION_ID}:{debugger_id}",
            "process_unique_id": backend_integer(
                process.GetUniqueID(), "process unique ID", 1, 2**64 - 1
            ),
            "stop_id": backend_integer(
                process.GetStopID(True), "stop ID", 0, 2**64 - 1
            ),
            "target_index": backend_integer(
                self.debugger.GetIndexOfTarget(target), "target index", 0, 2**32 - 2
            ),
        }
        triple = bounded_text(target.GetTriple(), "target triple", 256)
        if not triple:
            raise QueryError("unavailable", "target triple is unknown")
        context = (
            triple,
            backend_integer(target.GetByteOrder(), "byte order", 0, 255),
            backend_integer(target.GetAddressByteSize(), "address byte size", 1, 8),
        )
        return token, context

    def ensure_identity(self) -> None:
        try:
            token, context = self.read_identity()
            if (token, context) != (self.token, self.target_context):
                raise QueryError(
                    "state_changed",
                    "session/process/stop or target context changed during query",
                )
            if (
                self.process.GetState() != self.lldb.eStateStopped
                or self.process.GetUniqueID() != token["process_unique_id"]
            ):
                raise QueryError(
                    "state_changed", "original process changed during query"
                )
            if self.process.GetStopID(True) != token["stop_id"]:
                raise QueryError(
                    "state_changed", "original stop identity changed during query"
                )
            if self.process.GetProcessID() != self.pid:
                raise QueryError(
                    "state_changed", "original process provenance changed during query"
                )
        except QueryError as error:
            raise QueryError(
                "state_changed",
                "session/process/stop or target context changed during query",
            ) from error

    def byte_order(self, order: int) -> str:
        if order == self.lldb.eByteOrderLittle:
            return "little"
        if order == self.lldb.eByteOrderBig:
            return "big"
        return "unknown"

    def architecture(self) -> str:
        machine = self.target_context[0].split("-")[0]
        if machine in {"arm64", "arm64e", "aarch64", "aarch64_be"}:
            if self.target_context[2] != 8 or "ilp32" in self.target_context[0]:
                raise QueryError(
                    "unavailable", "unsupported AArch64 address width or ILP32 ABI"
                )
            return "aarch64"
        if machine.startswith(("arm64", "aarch64")):
            raise QueryError("unavailable", "unsupported AArch64 architecture variant")
        if machine in ARM32_MACHINES:
            if self.target_context[2] != 4:
                raise QueryError("unavailable", "unsupported ARM32 address width")
            return "arm"
        if machine.startswith(("arm", "thumb")):
            raise QueryError(
                "unavailable", "unsupported ARM32 architecture variant or ABI"
            )
        return machine

    def read_modules(self) -> list[dict[str, Any]]:
        count = backend_integer(
            self.target.GetNumModules(), "module count", 0, MAX_MODULES
        )
        modules: list[dict[str, Any]] = []
        metadata_bytes = 0
        for index in range(count):
            self.ensure_identity()
            module = self.target.GetModuleAtIndex(index)
            if not module.IsValid():
                raise QueryError("unavailable", "invalid module during enumeration")
            header = module.GetObjectFileHeaderAddress()
            load, image = header.GetLoadAddress(self.target), header.GetFileAddress()
            byte_order = backend_integer(
                module.GetByteOrder(), "module byte order", 0, 255
            )
            row = {
                "index": index,
                "name": bounded_text(module.GetFileSpec().GetFilename(), "module name"),
                "path": bounded_text(str(module.GetFileSpec()), "module path"),
                "uuid": bounded_text(module.GetUUIDString(), "module UUID", 256),
                "triple": bounded_text(module.GetTriple(), "module triple", 256),
                "target_byte_order": self.byte_order(byte_order),
                "lldb_byte_order": byte_order,
                "address_byte_size": backend_integer(
                    module.GetAddressByteSize(), "module address size", 0, 8
                ),
                "runtime_base": None
                if load == self.lldb.LLDB_INVALID_ADDRESS
                else hex(backend_integer(load, "module load address", 0, 2**64 - 2)),
                "image_base": None
                if image == self.lldb.LLDB_INVALID_ADDRESS
                else hex(backend_integer(image, "module image address", 0, 2**64 - 2)),
            }
            metadata_bytes += len(encode_json(row))
            if metadata_bytes > MAX_METADATA_BYTES:
                raise QueryError(
                    "limit_exceeded", "module metadata exceeds inspection budget"
                )
            modules.append(row)
        return modules

    def read_threads(self) -> list[dict[str, Any]]:
        count = backend_integer(
            self.process.GetNumThreads(), "thread count", 0, MAX_THREADS
        )
        threads: list[dict[str, Any]] = []
        seen: set[int] = set()
        for index in range(count):
            self.ensure_identity()
            identity, reason, stopped = self.read_thread_context(
                self.process.GetThreadAtIndex(index)
            )
            if identity in seen:
                raise QueryError("unavailable", "duplicate LLDB thread identity")
            seen.add(identity)
            threads.append(
                {
                    "index": index,
                    "thread_id": hex(identity),
                    "stop_reason": reason,
                    "is_stopped": stopped,
                }
            )
        return threads

    def read_thread_context(self, thread: Any) -> tuple[int, int, bool]:
        identity, reason, stopped = _snapshot.thread_context(thread)
        backend_integer(identity, "thread identity", 1, 2**64 - 2)
        backend_integer(reason, "thread stop reason", 0, 2**32 - 1)
        if type(stopped) is not bool:
            raise QueryError("unavailable", "invalid thread stop flag")
        return identity, reason, stopped

    def core_register_names(self) -> set[str]:
        arch = self.architecture()
        if arch not in REGISTER_NAMES:
            raise QueryError(
                "unavailable",
                "named-register queries are unsupported for this architecture",
            )
        if self.target_context[2] != (4 if arch == "arm" else 8):
            raise QueryError(
                "unavailable", "target address size differs from register architecture"
            )
        return {"rip", "rsp", "rflags"} if arch == "x86_64" else {"pc", "sp", "cpsr"}

    def thread_stop_evidence(self, expected: dict[str, Any]) -> dict[str, Any]:
        """Use SDK state or current stop info without rewriting the raw IsStopped flag.

        SDK source: swiftlang/llvm-project commit 1b669c3f63758879bb0c517a589abdea4c6efbeb.
        SBThread::GetStopReason uses the process run lock; IsStopped reads Thread::GetState.
        Thread::GetStopInfo selects or refreshes stop info against the process stop ID.
        """
        stopped, reason = expected["is_stopped"], expected["stop_reason"]
        if stopped is True:
            source = "SBThread.IsStopped"
        else:
            invalid = getattr(self.lldb, "eStopReasonInvalid", None)
            no_reason = getattr(self.lldb, "eStopReasonNone", None)
            known = {
                value
                for name in CURRENT_STOP_REASON_NAMES
                if type(value := getattr(self.lldb, name, None)) is int
            }
            if (
                type(invalid) is not int
                or type(no_reason) is not int
                or reason in {invalid, no_reason}
                or reason not in known
            ):
                raise QueryError(
                    "unavailable",
                    "thread has neither affirmative SDK state nor recognized current stop info",
                )
            source = "SBThread.GetStopReason/current-process-stop"
        return {"source": source, "is_stopped": stopped, "stop_reason": reason}

    def ensure_selected_thread_context(
        self, thread: Any, expected: dict[str, Any]
    ) -> None:
        self.ensure_identity()
        if self.read_thread_context(thread) != (
            int(expected["thread_id"], 16),
            expected["stop_reason"],
            expected["is_stopped"],
        ):
            raise QueryError("state_changed", "selected thread stop context changed")
        owner = thread.GetProcess()
        if (
            not owner.IsValid()
            or owner.GetState() != self.lldb.eStateStopped
            or owner.GetUniqueID() != self.token["process_unique_id"]
            or owner.GetStopID(True) != self.token["stop_id"]
            or owner.GetProcessID() != self.pid
        ):
            raise QueryError(
                "state_changed",
                "selected thread does not belong to the expected stopped process",
            )
        self.ensure_identity()

    def read_register_context(self, identity: int, names: set[str]) -> dict[str, Any]:
        self.ensure_identity()
        expected = next(
            (row for row in self.threads if row["thread_id"] == hex(identity)), None
        )
        if expected is None:
            raise QueryError(
                "unavailable", "requested thread is not a member of the stopped process"
            )
        evidence = self.thread_stop_evidence(expected)
        thread = self.process.GetThreadByID(identity)
        self.ensure_selected_thread_context(thread, expected)
        frame = thread.GetFrameAtIndex(0)
        self.ensure_selected_thread_context(thread, expected)
        frame_context = _snapshot.frame_context(frame)
        backend_integer(frame_context[0], "frame ID", 0, 0)
        backend_integer(frame_context[1], "frame PC", 0, 2**64 - 2)
        backend_integer(frame_context[2], "frame SP", 0, 2**64 - 2)
        values: dict[str, int] = {}
        for name in sorted(names):
            self.ensure_selected_thread_context(thread, expected)
            value = _snapshot.register_value(frame, name, identity, self.lldb)
            self.ensure_selected_thread_context(thread, expected)
            if value is None:
                raise QueryError(
                    "unavailable", f"required/requested register {name} is unavailable"
                )
            backend_integer(value, f"register {name}", 0, 2**64 - 1)
            if value >= 2 ** (8 * self.target_context[2]):
                raise QueryError(
                    "unavailable", f"register {name} exceeds architecture width"
                )
            if name in {"cpsr", "rflags"} and value >= 2**32:
                raise QueryError(
                    "unavailable", "status register exceeds supported width"
                )
            values[name] = value
        pc_name, sp_name = (
            ("rip", "rsp") if self.architecture() == "x86_64" else ("pc", "sp")
        )
        if values[pc_name] != frame_context[1] or values[sp_name] != frame_context[2]:
            raise QueryError(
                "state_changed",
                "PC/SP registers differ from the fresh top-frame context",
            )
        return {
            "stop_evidence": evidence,
            "frame_id": frame_context[0],
            "pc": hex(frame_context[1]),
            "sp": hex(frame_context[2]),
            "registers": {name: hex(value) for name, value in values.items()},
        }

    def data_byte_order(
        self, registers: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        arch = self.architecture()
        if arch == "arm" and registers is not None:
            status = int(registers["registers"]["cpsr"], 16)
            return {
                "order": "big" if status & (1 << 9) else "little",
                "source": "selected-thread CPSR.E",
            }
        if arch in {"arm", "aarch64"}:
            return {
                "order": "unknown",
                "source": "target byte order does not establish ARM data endianness",
            }
        return {
            "order": self.byte_order(self.target_context[1]),
            "source": "LLDB target byte order",
        }

    def read_mappings(
        self, start: int, size: int, permissions: str
    ) -> list[dict[str, Any]]:
        if not hasattr(self.lldb, "SBMemoryRegionInfo") or not hasattr(
            self.process, "GetMemoryRegionInfo"
        ):
            raise QueryError(
                "unavailable", "LLDB memory permission inspection is required"
            )
        current, end = start, start + size
        mappings: list[dict[str, Any]] = []
        while current < end:
            self.ensure_identity()
            if self.mapping_queries >= MAX_MAPPING_QUERIES:
                raise QueryError(
                    "limit_exceeded", "memory mapping inspection budget exhausted"
                )
            self.mapping_queries += 1
            region = self.lldb.SBMemoryRegionInfo()
            error = self.process.GetMemoryRegionInfo(current, region)
            if not error.Success() or not region.IsMapped():
                raise QueryError(
                    "unavailable",
                    "requested memory range contains unavailable mappings",
                )
            base, limit = region.GetRegionBase(), region.GetRegionEnd()
            backend_integer(base, "mapping base", 0, 2**64 - 1)
            backend_integer(limit, "mapping end", 0, 2**64 - 1)
            if not 0 <= base <= current < limit <= 2**64 - 1:
                raise QueryError(
                    "unavailable", "invalid or nonprogressing memory mapping bounds"
                )
            actual = known_permissions(region, self.lldb)
            if actual != permissions or actual[0] != "r":
                raise QueryError(
                    "unavailable",
                    "requested memory permissions do not exactly match readable mapping",
                )
            mappings.append(
                {"base": hex(base), "end": hex(limit), "permissions": actual}
            )
            current = min(end, limit)
        self.ensure_identity()
        return mappings

    def verify(self) -> None:
        try:
            self.ensure_identity()
            if (
                self.read_modules() != self.modules
                or self.read_threads() != self.threads
            ):
                raise QueryError(
                    "state_changed",
                    "module provenance or thread membership/stop context changed",
                )
            for identity, registers in self.register_contexts.items():
                names = set(registers["registers"])
                if self.read_register_context(identity, names) != registers:
                    raise QueryError(
                        "state_changed", "fresh frame/register/status context changed"
                    )
            if (
                self.memory_request is not None
                and self.read_mappings(*self.memory_request) != self.mapping_context
            ):
                raise QueryError("state_changed", "memory mapping provenance changed")
            self.ensure_identity()
        except (QueryError, ValueError) as error:
            raise QueryError(
                "state_changed",
                "query provenance changed or became unavailable during revalidation",
            ) from error

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        self.architecture()
        operation = request["operation"]
        if operation == "describe_session":
            return {
                "pid": self.pid,
                "state": "stopped",
                "triple": self.target_context[0],
                "architecture": self.architecture(),
                "target_byte_order": self.byte_order(self.target_context[1]),
                "data_byte_order": self.data_byte_order(),
                "address_byte_size": self.target_context[2],
                "module_count": len(self.modules),
                "thread_count": len(self.threads),
                "operations": sorted(OPERATIONS),
                "limits": {
                    "request_bytes": MAX_REQUEST_BYTES,
                    "response_bytes": MAX_RESPONSE_BYTES,
                    "memory_bytes": MAX_MEMORY_BYTES,
                    "page_items": MAX_PAGE_ITEMS,
                    "modules": MAX_MODULES,
                    "threads": MAX_THREADS,
                },
            }
        if operation in {"list_modules", "list_threads"}:
            rows = self.modules if operation == "list_modules" else self.threads
            offset, limit = request.get("offset", 0), request.get("limit", 32)
            if offset > len(rows):
                raise QueryError("invalid_request", "offset exceeds enumeration count")
            end = min(len(rows), offset + limit)
            return {
                "items": rows[offset:end],
                "offset": offset,
                "total": len(rows),
                "next_offset": end if end < len(rows) else None,
            }
        registers = None
        if operation == "read_registers" or "thread_id" in request:
            identity = address(request["thread_id"], "thread_id")
            required = self.core_register_names()
            names = (
                set(request.get("registers", REGISTER_NAMES[self.architecture()]))
                if operation == "read_registers"
                else required
            )
            if not names <= set(REGISTER_NAMES[self.architecture()]):
                raise QueryError(
                    "invalid_request", "register names do not match target architecture"
                )
            registers = self.read_register_context(identity, names | required)
            self.register_contexts[identity] = registers
        if operation == "read_registers":
            return {
                "thread_id": hex(identity),
                "required_registers": sorted(required),
                "context": registers,
                "data_byte_order": self.data_byte_order(registers),
            }
        start, size, permissions = (
            address(request["address"], "address"),
            request["size"],
            request["permissions"],
        )
        if 2 * size + MIN_RESPONSE_BYTES > request.get(
            "response_budget", DEFAULT_RESPONSE_BYTES
        ):
            raise QueryError(
                "response_too_large",
                "raw memory would exceed response budget; request fewer bytes",
            )
        if start + size > 2 ** (8 * self.target_context[2]):
            raise QueryError(
                "invalid_request", "memory range exceeds target address width"
            )
        self.memory_request = start, size, permissions
        require_permission_description_support(self.lldb)
        self.mapping_context = self.read_mappings(start, size, permissions)
        self.ensure_identity()
        error = self.lldb.SBError()
        data = self.process.ReadMemory(start, size, error)
        self.ensure_identity()
        if not error.Success() or not isinstance(data, bytes) or len(data) != size:
            raise QueryError(
                "unavailable", "LLDB did not return the complete requested byte range"
            )
        return {
            "address": hex(start),
            "size": size,
            "permissions": permissions,
            "bytes_hex": data.hex(),
            "data_byte_order": self.data_byte_order(registers),
            "stop_evidence": registers["stop_evidence"]
            if registers is not None
            else None,
            "thread_id": request.get("thread_id"),
            "interpretation": "raw-bytes-only",
            "read_semantics": "LLDB ReadMemory may normalize software-breakpoint trap bytes",
        }


def query_json(debugger: Any, command: str, lldb: Any | None = None) -> str:
    """Return bounded JSON from an existing authorized stopped LLDB session, never a snapshot proof."""
    budget = DEFAULT_RESPONSE_BYTES
    operation: str | None = None
    try:
        request = parse_request(command)
        budget = request.get("response_budget", DEFAULT_RESPONSE_BYTES)
        operation = request["operation"]
        api = lldb if lldb is not None else importlib.import_module("lldb")
        context = QueryContext(debugger, api, request.get("expected_token"))
        data = context.execute(request)
        content = encode_json({"operation": operation, "data": data})
        response = {
            "protocol": PROTOCOL,
            "ok": True,
            "operation": operation,
            "token": context.token,
            "data": data,
            "observation": {
                "content_sha256": hashlib.sha256(content.encode("ascii")).hexdigest(),
                "consistency": "revalidated-non-atomic",
                "atomic_snapshot": False,
                "identity_scope": "content hash is not stop identity or proof of a point-in-time snapshot",
            },
        }
        encoded = encode_json(response)
        if len(encoded) > budget:
            raise QueryError(
                "response_too_large",
                "response exceeds byte budget; reduce page limit or memory size",
            )
        context.verify()
        return encoded
    except QueryError as error:
        code, message = error.code, str(error)[:256]
    except ValueError as error:
        code, message = "unavailable", str(error)[:256]
    except (
        AttributeError,
        ImportError,
        RuntimeError,
        TypeError,
        LookupError,
        OSError,
        OverflowError,
        RecursionError,
    ):
        code, message = "backend_error", "LLDB query failed; no observation returned"
    failure: dict[str, Any] = {
        "protocol": PROTOCOL,
        "ok": False,
        "operation": operation,
        "error": {"code": code, "message": message},
    }
    encoded = encode_json(failure)
    if len(encoded) > budget:
        failure["error"]["message"] = "Query failed; no observation returned"
        encoded = encode_json(failure)
    return encoded


def query(
    debugger: Any, command: str, result: Any, internal_dict: dict[str, Any]
) -> None:
    """LLDB script command accepting one raw JSON object and emitting one JSON response."""
    result.AppendMessage(query_json(debugger, command))


def __lldb_init_module(debugger: Any, internal_dict: dict[str, Any]) -> None:
    debugger.HandleCommand("command script add -f lldb_bridge.query rampage-query")
