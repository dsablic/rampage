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
MAX_RESOLUTION_WORK = 16384
MAX_MODULE_SECTIONS = 4096
MAX_SECTION_DEPTH = 32
SESSION_ID = uuid.uuid4().hex
OPERATIONS = {
    "describe_session": set(),
    "list_modules": {"offset", "limit"},
    "list_threads": {"offset", "limit"},
    "read_registers": {"thread_id", "registers"},
    "read_memory": {"address", "size", "permissions", "thread_id"},
    "resolve_module_address": {"module_uuid", "file_address"},
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
MODULE_UUID = re.compile(r"[0-9a-fA-F-]{2,149}")


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


def normalized_module_uuid(value: Any) -> str:
    if not isinstance(value, str) or MODULE_UUID.fullmatch(value) is None:
        raise QueryError(
            "invalid_request", "module_uuid must be a bounded hexadecimal SDK UUID"
        )
    digits = value.replace("-", "").lower()
    if not 2 <= len(digits) <= 128 or len(digits) % 2:
        raise QueryError(
            "invalid_request", "module_uuid must contain 1..64 hexadecimal bytes"
        )
    parts = [digits[:8], digits[8:12], digits[12:16], digits[16:20]]
    parts.extend(digits[index : index + 12] for index in range(20, len(digits), 12))
    canonical = "-".join(part for part in parts if part)
    if value.lower() not in {digits, canonical}:
        raise QueryError(
            "invalid_request", "module_uuid has non-SDK separator placement"
        )
    return canonical


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
    if operation == "resolve_module_address":
        normalized_module_uuid(request.get("module_uuid"))
        address(request.get("file_address"), "file_address")
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
    module_handles: list[Any]
    threads: list[dict[str, Any]]
    register_contexts: dict[int, dict[str, Any]]
    mapping_context: list[dict[str, Any]] | None
    memory_request: tuple[int, int, str] | None
    mapping_queries: int
    resolution_work: int
    resolution_query: bool
    resolution_request: tuple[str, int] | None
    resolution_context: dict[str, Any] | None
    resolution_module: Any
    resolution_section: Any
    resolution_hierarchy: list[dict[str, Any]] | None

    def __init__(
        self,
        debugger: Any,
        lldb: Any,
        expected: dict[str, Any] | None,
        operation: str | None = None,
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
        self.resolution_work = 0
        self.resolution_query = operation == "resolve_module_address"
        self.resolution_request = None
        self.resolution_context = None
        self.resolution_module = None
        self.resolution_section = None
        self.resolution_hierarchy = None
        self.module_handles = []
        self.modules = self.read_modules(remember_handles=True)
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

    def read_modules(self, remember_handles: bool = False) -> list[dict[str, Any]]:
        """Keep resolution metadata free of SDK header lookups that can search sections without a cap."""
        if self.resolution_query:
            self.charge_resolution_work()
        count = backend_integer(
            self.target.GetNumModules(), "module count", 0, MAX_MODULES
        )
        modules: list[dict[str, Any]] = []
        metadata_bytes = 0
        for index in range(count):
            if self.resolution_query:
                self.charge_resolution_work()
            self.ensure_identity()
            module = self.target.GetModuleAtIndex(index)
            if not module.IsValid():
                raise QueryError("unavailable", "invalid module during enumeration")
            if remember_handles:
                self.module_handles.append(module)
            header_addresses = None
            if not self.resolution_query:
                header = module.GetObjectFileHeaderAddress()
                header_addresses = (
                    header.GetLoadAddress(self.target),
                    header.GetFileAddress(),
                )
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
            }
            if header_addresses is not None:
                load, image = header_addresses
                row["runtime_base"] = (
                    None
                    if load == self.lldb.LLDB_INVALID_ADDRESS
                    else hex(backend_integer(load, "module load address", 0, 2**64 - 2))
                )
                row["image_base"] = (
                    None
                    if image == self.lldb.LLDB_INVALID_ADDRESS
                    else hex(
                        backend_integer(image, "module image address", 0, 2**64 - 2)
                    )
                )
            metadata_bytes += len(encode_json(row))
            if metadata_bytes > MAX_METADATA_BYTES:
                raise QueryError(
                    "limit_exceeded", "module metadata exceeds inspection budget"
                )
            modules.append(row)
        return modules

    def read_threads(self) -> list[dict[str, Any]]:
        if self.resolution_query:
            self.charge_resolution_work()
        count = backend_integer(
            self.process.GetNumThreads(), "thread count", 0, MAX_THREADS
        )
        threads: list[dict[str, Any]] = []
        seen: set[int] = set()
        for index in range(count):
            if self.resolution_query:
                self.charge_resolution_work()
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
        """AArch64 CPSR lacks EL0 DATA endianness; SDK byte-order getters use ArchSpec.

        See SBTarget.cpp and SBProcess.cpp at Swift LLVM
        1b669c3f63758879bb0c517a589abdea4c6efbeb; neither getter samples SCTLR_EL1.E0E.
        """
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
            if self.resolution_request is not None:
                data, module, section, hierarchy = self.resolve_module_address(
                    *self.resolution_request
                )
                if (
                    data != self.resolution_context
                    or module != self.resolution_module
                    or section != self.resolution_section
                    or hierarchy != self.resolution_hierarchy
                ):
                    raise QueryError(
                        "state_changed", "module/section address mapping changed"
                    )
            self.ensure_identity()
        except (QueryError, ValueError) as error:
            raise QueryError(
                "state_changed",
                "query provenance changed or became unavailable during revalidation",
            ) from error

    def charge_resolution_work(self) -> None:
        self.ensure_identity()
        if self.resolution_work >= MAX_RESOLUTION_WORK:
            raise QueryError(
                "limit_exceeded", "module/section inspection budget exhausted"
            )
        self.resolution_work += 1

    def selected_module(
        self, target: Any, selected_uuid: str
    ) -> tuple[Any, dict[str, Any]]:
        self.charge_resolution_work()
        count = backend_integer(target.GetNumModules(), "module count", 0, MAX_MODULES)
        matches: list[tuple[Any, dict[str, Any]]] = []
        for index in range(count):
            self.charge_resolution_work()
            module = target.GetModuleAtIndex(index)
            if not module.IsValid():
                raise QueryError("unavailable", "invalid module during UUID selection")
            raw_uuid = bounded_text(module.GetUUIDString(), "module UUID", 256)
            if raw_uuid is None:
                continue
            try:
                actual_uuid = normalized_module_uuid(raw_uuid)
            except QueryError:
                continue
            if actual_uuid != selected_uuid:
                continue
            if (
                index >= len(self.modules)
                or self.modules[index]["uuid"] != raw_uuid
                or module != self.module_handles[index]
            ):
                raise QueryError("state_changed", "module UUID provenance changed")
            matches.append((module, self.modules[index]))
        if len(matches) != 1:
            raise QueryError(
                "unavailable",
                "module_uuid must identify exactly one selected-target module",
            )
        return matches[0]

    def read_section_structure(self, module: Any) -> list[dict[str, Any]]:
        self.charge_resolution_work()
        count = backend_integer(module.GetNumSections(), "section count", 0, 2**64 - 1)
        if count > MAX_MODULE_SECTIONS:
            raise QueryError(
                "limit_exceeded", "module section count exceeds inspection budget"
            )
        pending = [(module, count, [], None)]
        structure: list[dict[str, Any]] = []
        scheduled = count
        while pending:
            owner, count, path, parent_index = pending.pop()
            if len(path) >= MAX_SECTION_DEPTH:
                raise QueryError(
                    "limit_exceeded", "module section depth exceeds inspection budget"
                )
            for index in range(count):
                self.charge_resolution_work()
                section = (
                    owner.GetSectionAtIndex(index)
                    if parent_index is None
                    else owner.GetSubSectionAtIndex(index)
                )
                if not section.IsValid():
                    raise QueryError(
                        "unavailable", "invalid section during module traversal"
                    )
                child_path = path + [index]
                parent = section.GetParent()
                if (
                    parent_index is None
                    and parent.IsValid()
                    or parent_index is not None
                    and (
                        not parent.IsValid()
                        or parent != structure[parent_index]["handle"]
                    )
                ):
                    raise QueryError(
                        "unavailable",
                        "SDK section parent differs from bounded hierarchy",
                    )
                children = backend_integer(
                    section.GetNumSubSections(),
                    "subsection count",
                    0,
                    2**64 - 1,
                )
                scheduled += children
                if scheduled > MAX_MODULE_SECTIONS:
                    raise QueryError(
                        "limit_exceeded",
                        "module section count exceeds inspection budget",
                    )
                section_index = len(structure)
                structure.append(
                    {
                        "handle": section,
                        "index_path": child_path,
                        "parent_index": parent_index,
                        "children": children,
                    }
                )
                if children:
                    pending.append((section, children, child_path, section_index))
        self.ensure_identity()
        return structure

    def read_section_hierarchy(self, module: Any, target: Any) -> list[dict[str, Any]]:
        structure = self.read_section_structure(module)
        hierarchy: list[dict[str, Any]] = []
        metadata_bytes = 0
        for row in structure:
            self.charge_resolution_work()
            section = row["handle"]
            metadata = {
                "index_path": row["index_path"],
                "file_base": backend_integer(
                    section.GetFileAddress(), "section file address", 0, 2**64 - 1
                ),
                "load_base": backend_integer(
                    section.GetLoadAddress(target),
                    "section load address",
                    0,
                    2**64 - 1,
                ),
                "size": backend_integer(
                    section.GetByteSize(), "section size", 0, 2**64 - 1
                ),
                "name": bounded_text(section.GetName(), "section name"),
            }
            metadata_bytes += len(encode_json(metadata))
            if metadata_bytes > MAX_METADATA_BYTES:
                raise QueryError(
                    "limit_exceeded", "section metadata exceeds inspection budget"
                )
            hierarchy.append({**row, **metadata})
        if self.read_section_structure(module) != structure:
            raise QueryError(
                "state_changed",
                "SDK section hierarchy changed during bounded inspection",
            )
        self.ensure_identity()
        return hierarchy

    def bound_section_chain(
        self, hierarchy: list[dict[str, Any]], file_address: int, width: int
    ) -> list[dict[str, Any]]:
        matches = []
        for index, row in enumerate(hierarchy):
            self.charge_resolution_work()
            if (
                row["children"] == 0
                and row["file_base"] <= file_address < row["file_base"] + row["size"]
            ):
                matches.append(index)
        if len(matches) != 1:
            raise QueryError(
                "unavailable",
                "file address must identify one bounded leaf section, not a gap or container",
            )
        chain = []
        current: int | None = matches[0]
        while current is not None:
            self.charge_resolution_work()
            row = hierarchy[current]
            chain.append(row)
            current = row["parent_index"]
        chain.reverse()
        parent = None
        for row in chain:
            self.charge_resolution_work()
            file_base, load_base, size = row["file_base"], row["load_base"], row["size"]
            if load_base == self.lldb.LLDB_INVALID_ADDRESS:
                raise QueryError(
                    "unavailable",
                    "known loaded ancestors are required; independent child loads are unsupported",
                )
            if (
                file_base == self.lldb.LLDB_INVALID_ADDRESS
                or size == 0
                or file_base + size > min(2**64 - 1, 2 ** (8 * width))
                or load_base + size > min(2**64 - 1, 2 ** (8 * self.target_context[2]))
            ):
                raise QueryError(
                    "unavailable",
                    "invalid, unloaded or overflowing section ancestor range",
                )
            if parent is not None:
                relative = file_base - parent["file_base"]
                inherited_load = parent["load_base"] + relative
                if (
                    relative < 0
                    or relative + size > parent["size"]
                    or inherited_load > 2**64 - 2
                    or load_base != inherited_load
                    or load_base + size > parent["load_base"] + parent["size"]
                ):
                    raise QueryError(
                        "unavailable",
                        "inconsistent or overflowing inherited section mapping",
                    )
            parent = row
        return chain

    def resolution_mapping(self, process: Any, load: int) -> dict[str, Any]:
        self.ensure_identity()
        if self.mapping_queries >= MAX_MAPPING_QUERIES:
            raise QueryError(
                "limit_exceeded", "memory mapping inspection budget exhausted"
            )
        self.mapping_queries += 1
        region = self.lldb.SBMemoryRegionInfo()
        error = process.GetMemoryRegionInfo(load, region)
        if not error.Success() or region.IsMapped() is not True:
            raise QueryError("unavailable", "resolved load address is not mapped")
        base = backend_integer(region.GetRegionBase(), "mapping base", 0, 2**64 - 1)
        end = backend_integer(region.GetRegionEnd(), "mapping end", 0, 2**64 - 1)
        permissions = known_permissions(region, self.lldb)
        if (
            not base <= load < end <= min(2**64 - 1, 2 ** (8 * self.target_context[2]))
            or permissions[0] != "r"
        ):
            raise QueryError(
                "unavailable",
                "resolved load address is not in a known readable mapping",
            )
        return {"base": hex(base), "end": hex(end), "permissions": permissions}

    def resolve_module_address(
        self, selected_uuid: str, file_address: int
    ) -> tuple[dict[str, Any], Any, Any, list[dict[str, Any]]]:
        """Observe SDK section mapping, not a header slide or a static-layout proof.

        SDK source: swiftlang/llvm-project
        commit 1b669c3f63758879bb0c517a589abdea4c6efbeb.
        SBAddress(section, offset) avoids the module's unbounded native section search.
        Section.GetLoadBaseAddress adds inherited offsets without overflow checks.
        Ancestor ranges and additions are checked before constructing the address.
        SBSection.GetTargetByteSize is deprecated and returns the constant 1 in this SDK.
        """
        self.ensure_identity()
        target = self.debugger.GetSelectedTarget()
        if target != self.target:
            raise QueryError("state_changed", "selected SDK target changed")
        module, row = self.selected_module(target, selected_uuid)
        width = backend_integer(
            module.GetAddressByteSize(), "module address size", 1, 8
        )
        triple = bounded_text(module.GetTriple(), "module triple", 256)
        order = backend_integer(module.GetByteOrder(), "module byte order", 0, 255)
        if not triple or self.byte_order(order) == "unknown":
            raise QueryError(
                "unavailable", "selected module architecture/byte order is unknown"
            )
        if file_address >= 2 ** (8 * width):
            raise QueryError(
                "invalid_request", "file address exceeds selected module address width"
            )
        hierarchy = self.read_section_hierarchy(module, target)
        chain = self.bound_section_chain(hierarchy, file_address, width)
        leaf = chain[-1]
        section, start, load_base, size = (
            leaf["handle"],
            leaf["file_base"],
            leaf["load_base"],
            leaf["size"],
        )
        if self.read_section_hierarchy(module, target) != hierarchy:
            raise QueryError(
                "state_changed",
                "SDK section hierarchy changed before address construction",
            )
        current_target = self.debugger.GetSelectedTarget()
        if (
            current_target != target
            or self.selected_module(current_target, selected_uuid)[0] != module
        ):
            raise QueryError(
                "state_changed", "SDK target/module changed before address construction"
            )
        self.charge_resolution_work()
        if (module.GetAddressByteSize(), module.GetTriple(), module.GetByteOrder()) != (
            width,
            triple,
            order,
        ):
            raise QueryError(
                "state_changed",
                "selected module context changed before address construction",
            )
        self.charge_resolution_work()
        resolved = self.lldb.SBAddress(section, file_address - start)
        self.charge_resolution_work()
        if not resolved.IsValid() or resolved.GetModule() != module:
            raise QueryError(
                "unavailable", "file address does not resolve in the selected module"
            )
        if not resolved.GetSection().IsValid() or resolved.GetSection() != section:
            raise QueryError("unavailable", "file address has no SDK section evidence")
        offset = backend_integer(resolved.GetOffset(), "section offset", 0, 2**64 - 2)
        load = backend_integer(
            resolved.GetLoadAddress(target), "resolved load address", 0, 2**64 - 2
        )
        resolved_file = backend_integer(
            resolved.GetFileAddress(), "resolved file address", 0, 2**64 - 2
        )
        if (
            start + size > min(2**64 - 1, 2 ** (8 * width))
            or load_base + size > min(2**64 - 1, 2 ** (8 * self.target_context[2]))
            or not start <= file_address < start + size
            or offset != file_address - start
            or resolved_file != file_address
            or load != load_base + offset
        ):
            raise QueryError(
                "unavailable",
                "invalid, overflowing or inconsistent SDK section mapping",
            )
        if self.read_section_hierarchy(module, target) != hierarchy:
            raise QueryError(
                "state_changed",
                "SDK section hierarchy changed during address construction",
            )
        require_permission_description_support(self.lldb)
        mapping = self.resolution_mapping(target.GetProcess(), load)
        if self.read_section_hierarchy(module, target) != hierarchy:
            raise QueryError(
                "state_changed",
                "SDK section hierarchy changed during mapping inspection",
            )
        self.ensure_identity()
        return (
            {
                "module_uuid": selected_uuid,
                "module": row,
                "module_context": {
                    "triple": triple,
                    "object_byte_order": self.byte_order(order),
                    "address_byte_size": width,
                    "data_byte_order": {
                        "order": "unknown",
                        "source": "no runtime data interpretation",
                    },
                },
                "file_address": hex(file_address),
                "load_address": hex(load),
                "section": {
                    "index_path": leaf["index_path"],
                    "name": leaf["name"],
                    "file_base": hex(start),
                    "file_end": hex(start + size),
                    "load_base": hex(load_base),
                    "load_end": hex(load_base + size),
                    "offset": hex(offset),
                    "ancestors": [
                        {
                            "index_path": row["index_path"],
                            "name": row["name"],
                            "file_base": hex(row["file_base"]),
                            "file_end": hex(row["file_base"] + row["size"]),
                            "load_base": hex(row["load_base"]),
                            "load_end": hex(row["load_base"] + row["size"]),
                        }
                        for row in chain[:-1]
                    ],
                },
                "mapping": mapping,
                "interpretation": "raw-addresses-only",
                "address_semantics": (
                    "LLDB file virtual address, not a file byte offset"
                ),
                "proven_flow": False,
                "proven_layout": False,
            },
            module,
            section,
            hierarchy,
        )

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
                    "resolution_work": MAX_RESOLUTION_WORK,
                    "module_sections": MAX_MODULE_SECTIONS,
                    "section_depth": MAX_SECTION_DEPTH,
                    "module_uuid_bytes": 64,
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
        if operation == "resolve_module_address":
            self.resolution_request = (
                normalized_module_uuid(request["module_uuid"]),
                address(request["file_address"], "file_address"),
            )
            data, module, section, hierarchy = self.resolve_module_address(
                *self.resolution_request
            )
            self.resolution_context = data
            self.resolution_module, self.resolution_section = module, section
            self.resolution_hierarchy = hierarchy
            return data
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
        context = QueryContext(debugger, api, request.get("expected_token"), operation)
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


def serve(
    debugger: Any, command: str, result: Any, internal_dict: dict[str, Any]
) -> None:
    """Serve bounded local read-only queries only when explicitly started by the LLDB operator."""
    specification = importlib.util.spec_from_file_location(
        "_rampage_bridge_transport", Path(__file__).with_name("lldb_transport.py")
    )
    if specification is None or specification.loader is None:
        result.SetError("cannot load LLDB local query transport")
        return
    transport = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(transport)

    def preflight(current: Any) -> None:
        context = QueryContext(current, importlib.import_module("lldb"), None)
        context.verify()

    try:
        transport.serve_command(debugger, command, result, query_json, preflight)
    except QueryError as error:
        result.SetError(f"rampage-query-serve: {error}")


def __lldb_init_module(debugger: Any, internal_dict: dict[str, Any]) -> None:
    debugger.HandleCommand("command script add -f lldb_bridge.query rampage-query")
    debugger.HandleCommand(
        "command script add -f lldb_bridge.serve rampage-query-serve"
    )
