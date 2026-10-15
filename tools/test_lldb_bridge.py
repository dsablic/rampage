from __future__ import annotations

import importlib.util
import json
import socket
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


def load_bridge() -> Any:
    specification = importlib.util.spec_from_file_location(
        "lldb_bridge", Path(__file__).with_name("lldb_bridge.py")
    )
    assert specification is not None and specification.loader is not None
    bridge = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(bridge)
    return bridge


class Error:
    success: bool = True

    def Success(self) -> bool:
        return self.success


class Stream:
    data: str = ""

    def GetData(self) -> str:
        return self.data


class Region:
    base: int = 0
    end: int = 0
    permissions: str = "???"
    mapped: bool = False

    def IsMapped(self) -> bool:
        return self.mapped

    def GetRegionBase(self) -> int:
        return self.base

    def GetRegionEnd(self) -> int:
        return self.end

    def IsReadable(self) -> bool:
        return self.permissions[0] == "r"

    def IsWritable(self) -> bool:
        return self.permissions[1] == "w"

    def IsExecutable(self) -> bool:
        return self.permissions[2] == "x"

    def GetDescription(self, stream: Stream) -> bool:
        rendered = "".join(
            letter if state != "-" else "-"
            for letter, state in zip("RWX", self.permissions, strict=True)
        )
        stream.data = f"[0x{self.base:016x}-0x{self.end:016x} {rendered}]"
        return True


class Thread:
    identity: int
    valid: bool = True
    stopped: bool = True
    reason: int = 3
    frame_valid: bool = True
    frame_id: int = 0
    pc_override: int | None = None
    sp_override: int | None = None
    registers: dict[str, int]
    frames: int = 0
    queries: list[str]
    on_register: Callable[[str], None] | None = None
    process: Process | None = None

    def __init__(self, identity: int = 1) -> None:
        self.identity = identity
        self.registers = {f"x{index}": index for index in range(31)} | {
            "pc": 0x1000,
            "sp": 0x8000,
            "cpsr": 0,
        }
        self.queries = []

    def IsValid(self) -> bool:
        return self.valid

    def IsStopped(self) -> bool:
        return self.stopped

    def GetThreadID(self) -> int:
        return self.identity

    def GetStopReason(self) -> int:
        return self.reason

    def GetProcess(self) -> Any:
        return (
            self.process
            if self.process is not None
            else SimpleNamespace(IsValid=lambda: False)
        )

    def GetFrameAtIndex(self, index: int) -> Any:
        assert index == 0
        self.frames += 1
        pc = (
            self.pc_override
            if self.pc_override is not None
            else self.registers.get("pc", self.registers.get("rip", 0x1000))
        )
        sp = (
            self.sp_override
            if self.sp_override is not None
            else self.registers.get("sp", self.registers.get("rsp", 0x8000))
        )
        return SimpleNamespace(
            IsValid=lambda: self.frame_valid,
            GetFrameID=lambda: self.frame_id,
            GetPC=lambda: pc,
            GetSP=lambda: sp,
            FindRegister=self.find_register,
        )

    def find_register(self, name: str) -> Any:
        self.queries.append(name)
        value = self.registers.get(name)
        if self.on_register is not None:
            self.on_register(name)
        return SimpleNamespace(
            IsValid=lambda: value is not None, GetValueAsUnsigned=lambda error: value
        )


class FileSpec:
    name: str
    path: str

    def __init__(self, name: str) -> None:
        self.name, self.path = name, f"/owned/{name}"

    def GetFilename(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.path


class Module:
    valid: bool = True
    uuid: str = "01234567-89ab-cdef-0123-456789abcdef"
    runtime: int = 0x1000
    image: int = 0x100000000
    triple: str = "arm64-apple-macosx"
    order: int = 0
    width: int = 8
    filespec: FileSpec
    sections: list[Section]
    resolutions: list[int]
    addresses: list[int]
    on_resolve: Callable[[], None] | None = None
    on_address: Callable[[], None] | None = None

    def __init__(self, name: str = "fixture") -> None:
        self.filespec = FileSpec(name)
        self.sections = [Section(self, self.image, self.runtime, 0x1000)]
        self.resolutions = []
        self.addresses = []

    def IsValid(self) -> bool:
        return self.valid

    def GetObjectFileHeaderAddress(self) -> Any:
        return SimpleNamespace(
            GetLoadAddress=lambda target: self.runtime,
            GetFileAddress=lambda: self.image,
        )

    def GetUUIDString(self) -> str:
        return self.uuid

    def GetFileSpec(self) -> FileSpec:
        return self.filespec

    def GetTriple(self) -> str:
        return self.triple

    def GetByteOrder(self) -> int:
        return self.order

    def GetAddressByteSize(self) -> int:
        return self.width

    def GetNumSections(self) -> int:
        return len(self.sections)

    def GetSectionAtIndex(self, index: int) -> Section:
        return self.sections[index]

    def ResolveFileAddress(self, file_address: int) -> ResolvedAddress:
        self.resolutions.append(file_address)
        selected = self.find_section(self.sections, file_address, 2**32 - 1)
        offset = file_address - selected.GetFileAddress() if selected is not None else 0
        result = ResolvedAddress(selected, offset)
        if self.on_resolve is not None:
            self.on_resolve()
        return result

    def find_section(
        self, sections: list[Section], file_address: int, depth: int
    ) -> Section | None:
        for section in sections:
            base = section.GetFileAddress()
            if (
                base != 2**64 - 1
                and base <= file_address
                and file_address - base < section.GetByteSize()
            ):
                child = (
                    self.find_section(section.children, file_address, depth - 1)
                    if depth
                    else None
                )
                return child if child is not None else section
        return None


class GuardedHeaderModule(Module):
    header_allowed: bool = True
    header_calls: int = 0

    def GetObjectFileHeaderAddress(self) -> Any:
        self.header_calls += 1
        assert self.header_allowed, (
            "resolution attempted an uncapped object-file header lookup"
        )
        return super().GetObjectFileHeaderAddress()


class Section:
    module: Module
    file: int
    load: int
    size: int
    _children: list[Section]
    parent: Section | None = None
    name: str = "__text"
    valid: bool = True

    def __init__(self, module: Module, file: int, load: int, size: int) -> None:
        self.module, self.file, self.load, self.size = module, file, load, size
        self._children = []

    @property
    def children(self) -> list[Section]:
        return self._children

    @children.setter
    def children(self, children: list[Section]) -> None:
        self._children = children
        for child in children:
            child.parent = self

    def IsValid(self) -> bool:
        return self.valid

    def GetName(self) -> str:
        return self.name

    def GetNumSubSections(self) -> int:
        return len(self.children)

    def GetParent(self) -> Any:
        return (
            self.parent
            if self.parent is not None
            else SimpleNamespace(IsValid=lambda: False)
        )

    def GetSubSectionAtIndex(self, index: int) -> Section:
        return self.children[index]

    def GetFileAddress(self) -> int:
        return self.file

    def GetLoadAddress(self, target: Target) -> int:
        assert target.IsValid()
        if self.parent is not None:
            parent_load = self.parent.GetLoadAddress(target)
            if parent_load != 2**64 - 1:
                relative = self.GetFileAddress() - self.parent.GetFileAddress()
                return (parent_load + relative) % 2**64
        return self.load

    def GetByteSize(self) -> int:
        return self.size


class InheritedSection(Section):
    relative_file_offset: int

    def __init__(
        self,
        parent: Section,
        relative_file_offset: int,
        size: int,
        direct_load: int = 2**64 - 1,
    ) -> None:
        super().__init__(parent.module, 0, direct_load, size)
        self.parent, self.relative_file_offset = parent, relative_file_offset

    def GetFileAddress(self) -> int:
        assert self.parent is not None
        return (self.parent.GetFileAddress() + self.relative_file_offset) % 2**64


class ResolvedAddress:
    section: Section | None
    offset: int
    valid: bool = True

    def __init__(self, section: Section | None, offset: int) -> None:
        self.section, self.offset = section, offset

    def IsValid(self) -> bool:
        return self.valid and self.section is not None

    def GetModule(self) -> Module | None:
        return self.section.module if self.section is not None else None

    def GetSection(self) -> Section | None:
        return self.section

    def GetFileAddress(self) -> int:
        assert self.section is not None
        return (self.section.GetFileAddress() + self.offset) % 2**64

    def GetOffset(self) -> int:
        return self.offset

    def GetLoadAddress(self, target: Target) -> int:
        assert self.section is not None
        return (self.section.GetLoadAddress(target) + self.GetOffset()) % 2**64


class SdkAddress(ResolvedAddress):
    def __init__(self, section: Section, offset: int) -> None:
        super().__init__(section, offset)
        section.module.addresses.append(self.GetFileAddress())
        if section.module.on_address is not None:
            section.module.on_address()


class Process:
    valid: bool = True
    state: int = 1
    pid: int = 42
    unique_id: int = 7
    stop_id: int = 10
    expression_stop_id: int = 0
    threads: list[Thread]
    reads: list[tuple[int, int]]
    mapping_queries: list[int]
    mappings: list[tuple[int, int, str]]
    on_read: Callable[[], None] | None = None
    short_read: bool = False
    failed_read: bool = False

    def __init__(self) -> None:
        self.threads = [Thread()]
        self.reads, self.mapping_queries = [], []
        self.mappings = [(0x1000, 0x2000, "r-x")]

    def IsValid(self) -> bool:
        return self.valid

    def GetState(self) -> int:
        return self.state

    def GetProcessID(self) -> int:
        return self.pid

    def GetUniqueID(self) -> int:
        return self.unique_id

    def GetStopID(self, include_expression_stops: bool = False) -> int:
        assert include_expression_stops
        return self.stop_id + self.expression_stop_id

    def GetNumThreads(self) -> int:
        return len(self.threads)

    def GetThreadAtIndex(self, index: int) -> Thread:
        thread = self.threads[index]
        thread.process = self
        return thread

    def GetThreadByID(self, identity: int) -> Any:
        thread = next(
            (thread for thread in self.threads if thread.identity == identity),
            SimpleNamespace(IsValid=lambda: False),
        )
        if isinstance(thread, Thread):
            thread.process = self
        return thread

    def GetMemoryRegionInfo(self, address: int, region: Region) -> Error:
        self.mapping_queries.append(address)
        mapping = next(
            (
                mapping
                for mapping in self.mappings
                if mapping[0] <= address < mapping[1]
            ),
            None,
        )
        region.mapped = mapping is not None
        if mapping is not None:
            region.base, region.end, region.permissions = mapping
        return Error()

    def ReadMemory(self, address: int, size: int, error: Error) -> bytes:
        self.reads.append((address, size))
        if self.on_read is not None:
            self.on_read()
        error.success = not self.failed_read
        return b"\x12" * (size - 1 if self.short_read else size)


class Target:
    valid: bool = True
    triple: str = "arm64-apple-macosx"
    order: int = 0
    width: int = 8
    process: Process
    modules: list[Module]

    def __init__(self) -> None:
        self.process, self.modules = Process(), [Module()]

    def IsValid(self) -> bool:
        return self.valid

    def GetProcess(self) -> Process:
        return self.process

    def GetTriple(self) -> str:
        return self.triple

    def GetByteOrder(self) -> int:
        return self.order

    def GetAddressByteSize(self) -> int:
        return self.width

    def GetNumModules(self) -> int:
        return len(self.modules)

    def GetModuleAtIndex(self, index: int) -> Module:
        return self.modules[index]


class Debugger:
    identity: int = 1
    target_index: int = 0
    target: Target

    def __init__(self) -> None:
        self.target = Target()

    def GetSelectedTarget(self) -> Target:
        return self.target

    def GetID(self) -> int:
        return self.identity

    def GetIndexOfTarget(self, target: Target) -> int:
        assert target is self.target
        return self.target_index


@pytest.fixture
def environment(monkeypatch: pytest.MonkeyPatch) -> Any:
    bridge = load_bridge()
    api = SimpleNamespace(
        SBError=Error,
        SBMemoryRegionInfo=Region,
        SBStream=Stream,
        SBAddress=SdkAddress,
        eStateStopped=1,
        eByteOrderLittle=0,
        eByteOrderBig=1,
        LLDB_INVALID_ADDRESS=2**64 - 1,
        eStopReasonInvalid=0,
        eStopReasonNone=1,
        eStopReasonTrace=2,
        eStopReasonBreakpoint=3,
        eStopReasonWatchpoint=4,
        eStopReasonSignal=5,
        eStopReasonException=6,
    )
    monkeypatch.setitem(sys.modules, "lldb", api)
    debugger = Debugger()
    return SimpleNamespace(
        bridge=bridge,
        api=api,
        debugger=debugger,
        target=debugger.target,
        process=debugger.target.process,
        thread=debugger.target.process.threads[0],
    )


def send(
    environment: Any, operation: str = "describe_session", **fields: Any
) -> dict[str, Any]:
    request = {"version": 1, "operation": operation, **fields}
    encoded = environment.bridge.query_json(
        environment.debugger, json.dumps(request), environment.api
    )
    budget = fields.get("response_budget", environment.bridge.DEFAULT_RESPONSE_BYTES)
    if type(budget) is not int or not (
        environment.bridge.MIN_RESPONSE_BYTES
        <= budget
        <= environment.bridge.MAX_RESPONSE_BYTES
    ):
        budget = environment.bridge.DEFAULT_RESPONSE_BYTES
    assert len(encoded.encode("ascii")) <= budget
    return json.loads(encoded)


def token(environment: Any) -> dict[str, Any]:
    response = send(environment)
    assert response["ok"], response
    return response["token"]


def read_memory(
    environment: Any, expected: dict[str, Any], **fields: Any
) -> dict[str, Any]:
    return send(
        environment,
        "read_memory",
        expected_token=expected,
        **({"address": "0x1000", "size": 4, "permissions": "r-x"} | fields),
    )


def resolve_address(
    environment: Any, expected: dict[str, Any], **fields: Any
) -> dict[str, Any]:
    return send(
        environment,
        "resolve_module_address",
        expected_token=expected,
        **({"module_uuid": Module.uuid, "file_address": "0x100000004"} | fields),
    )


def assert_error(response: dict[str, Any], code: str | None = None) -> None:
    assert response["ok"] is False, response
    assert (
        "data" not in response
        and "token" not in response
        and "observation" not in response
    )
    if code is not None:
        assert response["error"]["code"] == code, response


def test_describe_stop_identity_is_not_pid_or_content_identity(
    environment: Any,
) -> None:
    response = send(environment)
    assert response["ok"]
    assert response["token"]["process_unique_id"] == environment.process.unique_id
    assert response["token"]["process_unique_id"] != response["data"]["pid"]
    assert response["token"]["stop_id"] == environment.process.stop_id
    assert response["data"]["state"] == "stopped"
    assert response["data"]["data_byte_order"]["order"] == "unknown"
    assert response["observation"]["atomic_snapshot"] is False
    assert environment.process.reads == []
    environment.process.stop_id += 1
    next_response = send(environment)
    assert next_response["token"] != response["token"]
    assert (
        next_response["observation"]["content_sha256"]
        == response["observation"]["content_sha256"]
    )


@pytest.mark.parametrize("machine", ["arm64", "arm64e", "aarch64"])
def test_arm64_architecture_defaults_and_cpsr_never_prove_runtime_data_order(
    environment: Any, monkeypatch: pytest.MonkeyPatch, machine: str
) -> None:
    environment.target.triple = f"{machine}-apple-macosx14.0.0"
    environment.target.modules[0].triple = environment.target.triple
    monkeypatch.setattr(
        environment.process,
        "GetByteOrder",
        environment.target.GetByteOrder,
        raising=False,
    )
    expected = token(environment)
    unknown = {
        "order": "unknown",
        "source": "target byte order does not establish ARM data endianness",
    }
    for status in [0, 1 << 9, 0xF0000000]:
        environment.thread.registers["cpsr"] = status
        session = send(environment, expected_token=expected)
        assert session["ok"], session
        assert session["data"]["architecture"] == "aarch64"
        assert session["data"]["target_byte_order"] == "little"
        assert session["data"]["data_byte_order"] == unknown
        registers = send(
            environment,
            "read_registers",
            expected_token=expected,
            thread_id=1,
            registers=["pc", "sp", "cpsr"],
        )
        assert registers["ok"], registers
        assert registers["data"]["data_byte_order"] == unknown
        assert int(registers["data"]["context"]["registers"]["cpsr"], 16) == status
        memory = read_memory(environment, expected, thread_id=1)
        assert memory["ok"], memory
        assert memory["data"]["data_byte_order"] == unknown
        assert memory["data"]["interpretation"] == "raw-bytes-only"
        resolved = resolve_address(environment, expected)
        assert resolved["ok"], resolved
        assert resolved["data"]["module_context"]["data_byte_order"] == {
            "order": "unknown",
            "source": "no runtime data interpretation",
        }
    assert environment.process.stop_id == expected["stop_id"]


@pytest.mark.parametrize(
    "command",
    [
        "",
        "{",
        "[]",
        "null",
        "true",
        '{"version":1,"version":1}',
        '{"version":NaN}',
        '{"version":Infinity}',
        "[" * 1500,
        '{"version":true,"operation":"describe_session"}',
        '{"version":1,"operation":[]}',
    ],
)
def test_malformed_json_never_reaches_backend(environment: Any, command: str) -> None:
    response = json.loads(environment.bridge.query_json(None, command, None))
    assert_error(response, "invalid_request")


def test_invalid_utf8_request_is_refused_before_backend(environment: Any) -> None:
    response = json.loads(environment.bridge.query_json(None, "\ud800"))
    assert_error(response, "invalid_request")


def test_backend_error_text_cannot_exceed_requested_response_budget(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken() -> int:
        raise ValueError("\U00010000" * 1000)

    monkeypatch.setattr(environment.process, "GetUniqueID", broken)
    assert_error(send(environment, response_budget=1024), "unavailable")


def test_backend_enumeration_race_still_returns_json(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def disappeared(index: int) -> Module:
        raise IndexError("module disappeared during enumeration")

    monkeypatch.setattr(environment.target, "GetModuleAtIndex", disappeared)
    assert_error(send(environment), "backend_error")


@pytest.mark.parametrize(
    "field,value",
    [
        ("identity", True),
        ("identity", 0),
        ("reason", 2**32),
        ("reason", True),
        ("stopped", 1),
    ],
)
def test_invalid_backend_thread_context_is_not_coerced(
    environment: Any, field: str, value: Any
) -> None:
    setattr(environment.thread, field, value)
    assert_error(send(environment))


def test_boolean_backend_register_is_not_accepted_as_integer(environment: Any) -> None:
    environment.thread.registers["x0"] = True
    assert_error(
        send(
            environment,
            "read_registers",
            expected_token=token(environment),
            thread_id=1,
            registers=["x0"],
        ),
        "unavailable",
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"operation": "continue"},
        {"operation": "command", "command": "expr 1"},
        {"expression": "foo()"},
        {"output": "/tmp/capture"},
        {"version": 2},
        {"response_budget": True},
        {"response_budget": 0},
        {"response_budget": 262145},
        {"expected_token": None},
    ],
)
def test_unknown_or_unsafe_request_fields_are_rejected_before_backend(
    environment: Any, fields: dict[str, Any]
) -> None:
    request = {"version": 1, "operation": "describe_session"} | fields
    response = json.loads(environment.bridge.query_json(None, json.dumps(request)))
    assert_error(response, "invalid_request")


def test_request_byte_limit_applies_before_json_parse_or_backend(
    environment: Any,
) -> None:
    response = json.loads(
        environment.bridge.query_json(
            None, " " * (environment.bridge.MAX_REQUEST_BYTES + 1)
        )
    )
    assert_error(response, "limit_exceeded")
    response = json.loads(
        environment.bridge.query_json(None, "é" * environment.bridge.MAX_REQUEST_BYTES)
    )
    assert_error(response, "limit_exceeded")


@pytest.mark.parametrize(
    "operation",
    [
        "list_modules",
        "list_threads",
        "read_registers",
        "read_memory",
        "resolve_module_address",
    ],
)
def test_data_operations_require_explicit_stop_token(
    environment: Any, operation: str
) -> None:
    assert_error(send(environment, operation), "invalid_request")
    assert environment.process.reads == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("stop_id", 99),
        ("process_unique_id", 99),
        ("target_index", 1),
        ("session_id", "another-backend-session"),
    ],
)
def test_stale_tokens_are_rejected_before_any_observation(
    environment: Any, field: str, value: Any
) -> None:
    expected = token(environment)
    expected[field] = value
    assert_error(read_memory(environment, expected), "stale_token")
    assert environment.process.reads == environment.process.mapping_queries == []


@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "wrong-type", "boolean", "backend"]
)
def test_malformed_token_is_not_coerced(environment: Any, mutation: str) -> None:
    expected = token(environment)
    if mutation == "missing":
        expected.pop("stop_id")
    elif mutation == "extra":
        expected["pid"] = 42
    elif mutation == "wrong-type":
        expected["session_id"] = []
    elif mutation == "boolean":
        expected["stop_id"] = True
    else:
        expected["backend"] = "arbitrary"
    assert_error(read_memory(environment, expected), "invalid_request")
    assert environment.process.reads == []


def test_session_reload_and_pid_reuse_do_not_reuse_stop_token(environment: Any) -> None:
    expected = token(environment)
    environment.process.unique_id += 1
    assert_error(read_memory(environment, expected), "stale_token")
    environment.process.unique_id -= 1
    environment.bridge = load_bridge()
    assert_error(read_memory(environment, expected), "stale_token")


@pytest.mark.parametrize("invalid", ["running", "target", "process"])
def test_bridge_never_stops_or_creates_invalid_process(
    environment: Any, invalid: str
) -> None:
    if invalid == "running":
        environment.process.state = 2
    elif invalid == "target":
        environment.target.valid = False
    else:
        environment.process.valid = False
    assert_error(send(environment), "unavailable")
    assert environment.process.reads == []


@pytest.mark.parametrize("operation", ["list_modules", "list_threads"])
def test_metadata_pages_are_complete_valid_json_with_explicit_cursor(
    environment: Any, operation: str
) -> None:
    environment.target.modules = [Module(f"fixture-{index}") for index in range(3)]
    environment.process.threads = [Thread(index) for index in range(1, 4)]
    expected = token(environment)
    response = send(environment, operation, expected_token=expected, offset=0, limit=2)
    assert response["ok"], response
    assert len(response["data"]["items"]) == 2
    assert response["data"]["next_offset"] == 2
    final = send(environment, operation, expected_token=expected, offset=2, limit=2)
    assert len(final["data"]["items"]) == 1 and final["data"]["next_offset"] is None
    empty = send(environment, operation, expected_token=expected, offset=3)
    assert empty["data"]["items"] == []
    assert_error(
        send(environment, operation, expected_token=expected, offset=4),
        "invalid_request",
    )
    assert_error(
        send(environment, operation, expected_token=expected, limit=0),
        "invalid_request",
    )
    assert_error(
        send(
            environment,
            operation,
            expected_token=expected,
            limit=environment.bridge.MAX_PAGE_ITEMS + 1,
        ),
        "invalid_request",
    )


def test_unloaded_or_unidentified_modules_are_not_silently_omitted(
    environment: Any,
) -> None:
    module = environment.target.modules[0]
    module.runtime = environment.api.LLDB_INVALID_ADDRESS
    module.uuid = ""
    response = send(environment, "list_modules", expected_token=token(environment))
    assert response["ok"] and len(response["data"]["items"]) == 1
    assert response["data"]["items"][0]["runtime_base"] is None
    assert response["data"]["items"][0]["uuid"] == ""


@pytest.mark.parametrize("kind", ["modules", "threads", "text", "aggregate"])
def test_enumeration_and_metadata_limits_fail_closed(
    environment: Any, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    if kind == "modules":
        monkeypatch.setattr(
            environment.target,
            "GetNumModules",
            lambda: environment.bridge.MAX_MODULES + 1,
        )
    elif kind == "threads":
        monkeypatch.setattr(
            environment.process,
            "GetNumThreads",
            lambda: environment.bridge.MAX_THREADS + 1,
        )
    elif kind == "text":
        environment.target.modules[0].filespec.path = "x" * 4097
    else:
        monkeypatch.setattr(environment.bridge, "MAX_METADATA_BYTES", 10)
    assert_error(send(environment))
    assert environment.process.reads == []


def test_response_budget_never_emits_truncated_json_or_partial_rows(
    environment: Any,
) -> None:
    environment.target.modules[0].filespec.path = "x" * 4096
    expected = token(environment)
    response = send(
        environment, "list_modules", expected_token=expected, response_budget=1024
    )
    assert_error(response, "response_too_large")
    assert_error(
        read_memory(environment, expected, size=1024, response_budget=1024),
        "response_too_large",
    )
    assert environment.process.reads == []


def test_memory_reads_exact_requested_bytes_only_and_rechecks_permissions(
    environment: Any,
) -> None:
    response = read_memory(environment, token(environment), address="0x1001", size=3)
    assert response["ok"], response
    assert response["data"]["bytes_hex"] == "121212"
    assert response["data"]["data_byte_order"]["order"] == "unknown"
    assert response["data"]["interpretation"] == "raw-bytes-only"
    assert "normalize" in response["data"]["read_semantics"]
    assert environment.process.reads == [(0x1001, 3)]
    assert environment.process.mapping_queries == [0x1001, 0x1001]


@pytest.mark.parametrize(
    "fields",
    [
        {"size": 0},
        {"size": -1},
        {"size": True},
        {"size": 65537},
        {"address": -1},
        {"address": True},
        {"address": "0x-1"},
        {"address": "1000"},
        {"address": "expr()"},
        {"address": "0xfffffffffffffffe", "size": 4},
        {"permissions": "---"},
        {"permissions": []},
        {"interpret_as": "u32"},
    ],
)
def test_invalid_memory_specification_never_reads(
    environment: Any, fields: dict[str, Any]
) -> None:
    assert_error(
        read_memory(environment, token(environment), **fields), "invalid_request"
    )
    assert environment.process.reads == []


@pytest.mark.parametrize("permissions", ["rw-", "rwx", "r--", "---"])
def test_mismatched_permissions_are_not_relaxed_to_readable(
    environment: Any, permissions: str
) -> None:
    environment.process.mappings = [(0x1000, 0x2000, permissions)]
    assert_error(read_memory(environment, token(environment)), "unavailable")
    assert environment.process.reads == []


@pytest.mark.parametrize("permissions", ["r??", "r?-", "r-?", "???", "?--"])
def test_unknown_permissions_are_not_fabricated_as_known_no(
    environment: Any, permissions: str
) -> None:
    environment.process.mappings = [(0x1000, 0x2000, permissions)]
    assert_error(
        read_memory(environment, token(environment), permissions="r--"), "unavailable"
    )
    assert environment.process.reads == []


@pytest.mark.parametrize("permissions", ["r--", "rw-", "r-x", "rwx"])
def test_all_known_readable_permission_combinations_still_require_exact_matches(
    environment: Any, permissions: str
) -> None:
    environment.process.mappings = [(0x1000, 0x2000, permissions)]
    response = read_memory(environment, token(environment), permissions=permissions)
    assert response["ok"], response
    assert response["data"]["permissions"] == permissions
    assert environment.process.reads == [(0x1000, 4)]


def test_known_no_and_unknown_have_same_booleans_but_only_known_no_is_accepted(
    environment: Any,
) -> None:
    denied, unknown = Region(), Region()
    denied.permissions, unknown.permissions = "r--", "r??"
    assert denied.IsWritable() is unknown.IsWritable() is False
    assert denied.IsExecutable() is unknown.IsExecutable() is False
    environment.process.mappings = [(0x1000, 0x2000, "r--")]
    expected = token(environment)
    assert read_memory(environment, expected, permissions="r--")["ok"]
    environment.process.mappings = [(0x1000, 0x2000, "r??")]
    assert_error(read_memory(environment, expected, permissions="r--"), "unavailable")
    assert environment.process.reads == [(0x1000, 4)]


def test_question_mark_sdk_description_also_refuses_unknown_permissions(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def describe(region: Region, stream: Stream) -> bool:
        stream.data = (
            f"[0x{region.base:016x}-0x{region.end:016x} {region.permissions.upper()}]"
        )
        return True

    monkeypatch.setattr(Region, "GetDescription", describe)
    environment.process.mappings = [(0x1000, 0x2000, "r--")]
    expected = token(environment)
    assert read_memory(environment, expected, permissions="r--")["ok"]
    environment.process.mappings = [(0x1000, 0x2000, "r??")]
    assert_error(read_memory(environment, expected, permissions="r--"), "unavailable")


@pytest.mark.parametrize(
    "failure",
    [
        "missing-stream",
        "missing-description",
        "collapsed",
        "failed",
        "format",
        "bounds",
    ],
)
def test_sdk_without_reliable_permission_distinction_refuses_memory_reads(
    environment: Any, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    if failure == "missing-stream":
        monkeypatch.delattr(environment.api, "SBStream")
    elif failure == "missing-description":
        monkeypatch.delattr(Region, "GetDescription")
    else:

        def describe(region: Region, stream: Stream) -> bool:
            if failure == "failed":
                return False
            if failure == "format":
                stream.data = "SDK-specific unrecognized layout"
            else:
                base = region.base + 1 if failure == "bounds" else region.base
                permissions = "---" if failure == "collapsed" else "RWX"
                stream.data = f"[0x{base:016x}-0x{region.end:016x} {permissions}]"
            return True

        monkeypatch.setattr(Region, "GetDescription", describe)
    assert_error(read_memory(environment, token(environment)), "unavailable")
    assert environment.process.reads == environment.process.mapping_queries == []


def test_permissions_becoming_unknown_during_read_discard_all_bytes(
    environment: Any,
) -> None:
    environment.process.mappings = [(0x1000, 0x2000, "r--")]
    expected = token(environment)

    def unknown() -> None:
        environment.process.mappings = [(0x1000, 0x2000, "r??")]

    environment.process.on_read = unknown
    assert_error(read_memory(environment, expected, permissions="r--"), "state_changed")


@pytest.mark.parametrize("gap", [False, True])
def test_mapping_coverage_does_not_synthesize_gaps(environment: Any, gap: bool) -> None:
    environment.process.mappings = [
        (0x1000, 0x1002, "r-x"),
        (0x1003 if gap else 0x1002, 0x2000, "r-x"),
    ]
    response = read_memory(environment, token(environment))
    if gap:
        assert_error(response, "unavailable")
        assert environment.process.reads == []
    else:
        assert response["ok"]
        assert environment.process.reads == [(0x1000, 4)]
        assert environment.process.mapping_queries == [0x1000, 0x1002] * 2


@pytest.mark.parametrize(
    "bounds", [(0x1001, 0x2000), (0x1000, 0x1000), (0x1000, 2**64)]
)
def test_invalid_mapping_bounds_fail_closed(
    environment: Any, monkeypatch: pytest.MonkeyPatch, bounds: tuple[int, int]
) -> None:
    def malformed(address: int, region: Region) -> Error:
        region.base, region.end = bounds
        region.mapped, region.permissions = True, "r-x"
        return Error()

    monkeypatch.setattr(environment.process, "GetMemoryRegionInfo", malformed)
    assert_error(read_memory(environment, token(environment)), "unavailable")
    assert environment.process.reads == []


def test_missing_mapping_api_refuses_read(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(environment.api, "SBMemoryRegionInfo")
    assert_error(read_memory(environment, token(environment)), "unavailable")
    assert environment.process.reads == []


def test_mapping_query_budget_is_shared_by_preflight_and_revalidation(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(environment.bridge, "MAX_MAPPING_QUERIES", 3)
    environment.process.mappings = [(0x1000, 0x1002, "r-x"), (0x1002, 0x2000, "r-x")]
    assert_error(read_memory(environment, token(environment)), "state_changed")
    assert len(environment.process.mapping_queries) == 3


@pytest.mark.parametrize("failure", ["short", "error"])
def test_partial_or_failed_reads_never_return_any_content(
    environment: Any, failure: str
) -> None:
    environment.process.short_read = failure == "short"
    environment.process.failed_read = failure == "error"
    assert_error(read_memory(environment, token(environment)), "unavailable")


def mutate(environment: Any, change: str) -> None:
    if change == "stop":
        environment.process.stop_id += 1
    elif change == "expression-stop":
        environment.process.expression_stop_id += 1
    elif change == "state":
        environment.process.state = 2
    elif change == "unique-id":
        environment.process.unique_id += 1
    elif change == "pid":
        environment.process.pid += 1
    elif change == "selected-target":
        environment.debugger.target = Target()
        environment.debugger.target.process.unique_id += 1
    elif change == "triple":
        environment.target.triple = "arm64-unknown-linux"
    elif change == "byte-order":
        environment.target.order = 1
    elif change == "width":
        environment.target.width = 4
    elif change.startswith("module-"):
        module = environment.target.modules[0]
        if change == "module-slide":
            module.runtime += 0x1000
        elif change == "module-uuid":
            module.uuid = "other"
        elif change == "module-path":
            module.filespec.path = "/changed"
        elif change == "module-triple":
            module.triple = "x86_64-apple-macosx"
        elif change == "module-order":
            module.order = 1
        elif change == "module-width":
            module.width = 4
        else:
            environment.target.modules.append(Module("another"))
    elif change == "membership":
        environment.process.threads.clear()
    elif change == "thread-add":
        environment.process.threads.append(Thread(2))
    elif change == "reason":
        environment.thread.reason += 1
    elif change == "stopped":
        environment.thread.stopped = False
    elif change == "frame":
        environment.thread.frame_valid = False
    elif change in {"pc", "sp", "cpsr", "x0"}:
        environment.thread.registers[change] += 1
    elif change == "mapping-permissions":
        environment.process.mappings = [(0x1000, 0x2000, "rw-")]
    else:
        environment.process.mappings = [(0x1000, 0x3000, "r-x")]


@pytest.mark.parametrize(
    "change",
    [
        "stop",
        "expression-stop",
        "state",
        "unique-id",
        "pid",
        "selected-target",
        "triple",
        "byte-order",
        "width",
        "module-slide",
        "module-uuid",
        "module-path",
        "module-triple",
        "module-order",
        "module-width",
        "module-add",
        "membership",
        "thread-add",
        "reason",
        "stopped",
        "frame",
        "pc",
        "sp",
        "cpsr",
        "mapping-permissions",
        "mapping-bounds",
    ],
)
def test_memory_rejects_changed_provenance_without_returning_bytes(
    environment: Any, change: str
) -> None:
    expected = token(environment)
    environment.process.on_read = lambda: mutate(environment, change)
    assert_error(read_memory(environment, expected, thread_id=1), "state_changed")
    assert environment.process.reads == [(0x1000, 4)]


@pytest.mark.parametrize("change", ["stop", "module-slide", "thread-add", "cpsr", "pc"])
def test_final_revalidation_occurs_after_response_serialization(
    environment: Any, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    expected = token(environment)
    original_encode = environment.bridge.encode_json

    def encode(value: Any) -> str:
        encoded = original_encode(value)
        if isinstance(value, dict) and value.get("ok") is True:
            mutate(environment, change)
        return encoded

    monkeypatch.setattr(environment.bridge, "encode_json", encode)
    assert_error(read_memory(environment, expected, thread_id=1), "state_changed")


def test_named_register_queries_use_fresh_frames_and_required_status(
    environment: Any,
) -> None:
    response = send(
        environment,
        "read_registers",
        expected_token=token(environment),
        thread_id="0x1",
        registers=["x0"],
    )
    assert response["ok"], response
    assert response["data"]["context"]["registers"] == {
        "pc": "0x1000",
        "sp": "0x8000",
        "cpsr": "0x0",
        "x0": "0x0",
    }
    assert environment.thread.frames == 2
    assert environment.thread.queries.count("cpsr") == 2


@pytest.mark.parametrize("machine,width", [("armv7", 4), ("arm64", 8), ("x86_64", 8)])
@pytest.mark.parametrize("operation", ["read_registers", "read_memory"])
@pytest.mark.parametrize("reason", [0, 1, 99])
def test_false_state_without_current_stop_info_is_rejected_before_frame_or_register_access(
    environment: Any, machine: str, width: int, operation: str, reason: int
) -> None:
    environment.target.triple, environment.target.width = (
        f"{machine}-unknown-linux",
        width,
    )
    environment.thread.stopped = False
    environment.thread.reason = reason
    expected = token(environment)
    fields = {"thread_id": 1, "registers": ["rax" if machine == "x86_64" else "pc"]}
    response = (
        send(environment, operation, expected_token=expected, **fields)
        if operation == "read_registers"
        else read_memory(environment, expected, thread_id=1)
    )
    assert_error(response, "unavailable")
    assert environment.thread.frames == 0 and environment.thread.queries == []
    assert environment.process.reads == environment.process.mapping_queries == []


@pytest.mark.parametrize("reason", [2, 3, 4, 5, 6])
def test_false_raw_state_with_recognized_current_stop_info_reads_revalidated_registers(
    environment: Any, reason: int
) -> None:
    environment.thread.stopped, environment.thread.reason = False, reason
    expected = token(environment)
    response = send(
        environment,
        "read_registers",
        expected_token=expected,
        thread_id=1,
        registers=["x0"],
    )
    assert response["ok"], response
    assert response["data"]["context"]["stop_evidence"] == {
        "source": "SBThread.GetStopReason/current-process-stop",
        "is_stopped": False,
        "stop_reason": reason,
    }
    assert environment.thread.frames == 2
    metadata = send(environment, "list_threads", expected_token=expected)
    assert metadata["data"]["items"][0]["is_stopped"] is False


def test_false_state_with_current_arm32_stop_info_establishes_only_selected_cpsr_context(
    environment: Any,
) -> None:
    environment.target.triple, environment.target.width = "armv7-unknown-linux", 4
    environment.thread.stopped, environment.thread.reason = (
        False,
        environment.api.eStopReasonBreakpoint,
    )
    environment.thread.registers["cpsr"] = 1 << 9
    response = read_memory(environment, token(environment), thread_id=1)
    assert response["ok"], response
    assert response["data"]["data_byte_order"]["order"] == "big"
    assert response["data"]["stop_evidence"] == {
        "source": "SBThread.GetStopReason/current-process-stop",
        "is_stopped": False,
        "stop_reason": environment.api.eStopReasonBreakpoint,
    }
    assert environment.thread.frames == 2


def test_false_state_cannot_guess_reason_codes_when_sdk_constants_are_missing(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment.thread.stopped = False
    monkeypatch.delattr(environment.api, "eStopReasonNone")
    assert_error(
        send(
            environment,
            "read_registers",
            expected_token=token(environment),
            thread_id=1,
            registers=["pc"],
        ),
        "unavailable",
    )
    assert environment.thread.frames == 0 and environment.thread.queries == []


@pytest.mark.parametrize(
    "change",
    [
        "reason-none",
        "reason-invalid",
        "reason-other",
        "stop",
        "expression-stop",
        "state",
        "membership",
        "stopped",
        "cpsr",
    ],
)
def test_current_stop_info_path_rejects_mutations_during_reads(
    environment: Any, change: str
) -> None:
    environment.thread.stopped = False
    expected = token(environment)

    def register(name: str) -> None:
        if change.startswith("reason-"):
            environment.thread.reason = {
                "reason-none": 1,
                "reason-invalid": 0,
                "reason-other": 4,
            }[change]
        elif change == "stopped":
            environment.thread.stopped = True
        else:
            mutate(environment, change)

    environment.thread.on_register = register
    assert_error(
        send(
            environment,
            "read_registers",
            expected_token=expected,
            thread_id=1,
            registers=["pc"],
        ),
        "state_changed",
    )


@pytest.mark.parametrize(
    "wrong_owner", ["invalid", "unique-id", "stop", "state", "pid"]
)
def test_current_stop_info_must_belong_to_expected_stopped_process_before_frame_access(
    environment: Any, monkeypatch: pytest.MonkeyPatch, wrong_owner: str
) -> None:
    environment.thread.stopped = False
    expected = token(environment)
    owner = Process()
    if wrong_owner == "invalid":
        owner.valid = False
    elif wrong_owner == "unique-id":
        owner.unique_id += 1
    elif wrong_owner == "stop":
        owner.stop_id += 1
    elif wrong_owner == "state":
        owner.state = 2
    else:
        owner.pid += 1
    monkeypatch.setattr(environment.thread, "GetProcess", lambda: owner)
    assert_error(
        send(
            environment,
            "read_registers",
            expected_token=expected,
            thread_id=1,
            registers=["pc"],
        ),
        "state_changed",
    )
    assert environment.thread.frames == 0 and environment.thread.queries == []


def test_thread_becoming_nonstopped_before_resolution_is_rejected_before_frame_access(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = token(environment)

    def lookup(identity: int) -> Thread:
        environment.thread.stopped = False
        return environment.thread

    monkeypatch.setattr(environment.process, "GetThreadByID", lookup)
    assert_error(
        send(
            environment,
            "read_registers",
            expected_token=expected,
            thread_id=1,
            registers=["pc"],
        ),
        "state_changed",
    )
    assert environment.thread.frames == 0 and environment.thread.queries == []


def test_nonstopped_thread_metadata_does_not_grant_arm32_data_context(
    environment: Any,
) -> None:
    environment.target.triple, environment.target.width = "armv7-unknown-linux", 4
    environment.thread.stopped = False
    environment.thread.reason = environment.api.eStopReasonNone
    expected = token(environment)
    threads = send(environment, "list_threads", expected_token=expected)
    assert threads["ok"] and threads["data"]["items"][0]["is_stopped"] is False
    raw = read_memory(environment, expected)
    assert raw["ok"] and raw["data"]["data_byte_order"]["order"] == "unknown"
    assert environment.thread.frames == 0 and environment.thread.queries == []


@pytest.mark.parametrize(
    "triple,width",
    [
        ("arm64_32-apple-watchos", 4),
        ("arm64_32-apple-watchos", 8),
        ("aarch64_32-unknown-linux", 4),
        ("arm64_future-unknown-linux", 4),
        ("aarch64-unknown-linux-gnu_ilp32", 4),
        ("aarch64-unknown-linux-gnu_ilp32", 8),
        ("arm64-unknown-linux", 4),
        ("arm_unknown-unknown-linux", 4),
        ("thumb_unknown-unknown-linux", 4),
        ("armv7-unknown-linux", 8),
        ("armv7m-unknown-linux", 4),
    ],
)
@pytest.mark.parametrize(
    "operation", ["describe_session", "read_registers", "read_memory"]
)
def test_unsupported_arm_variants_never_interpret_pstate_as_cpsr_or_read_memory(
    environment: Any, triple: str, width: int, operation: str
) -> None:
    expected = token(environment)
    environment.target.triple, environment.target.width = triple, width
    environment.thread.registers["cpsr"] = 1 << 9
    if operation == "read_memory":
        response = read_memory(environment, expected, thread_id=1)
    elif operation == "read_registers":
        response = send(
            environment,
            operation,
            expected_token=expected,
            thread_id=1,
            registers=["pc"],
        )
    else:
        response = send(environment, operation, expected_token=expected)
    assert_error(response, "unavailable")
    assert environment.thread.frames == 0 and environment.thread.queries == []
    assert environment.process.reads == environment.process.mapping_queries == []


def test_arm64_32_raw_memory_without_thread_is_also_refused(environment: Any) -> None:
    expected = token(environment)
    environment.target.triple, environment.target.width = "arm64_32-apple-watchos", 4
    assert_error(read_memory(environment, expected), "unavailable")
    assert environment.process.reads == []


@pytest.mark.parametrize(
    "fields",
    [
        {"thread_id": 0},
        {"thread_id": True},
        {"thread_id": 9},
        {"registers": ["x0", "x0"]},
        {"registers": []},
        {"registers": ["rax"]},
        {"registers": ["foo()"]},
        {"registers": ["pc"] * 35},
        {"registers": [{}]},
    ],
)
def test_invalid_register_requests_fail_closed(
    environment: Any, fields: dict[str, Any]
) -> None:
    request = {"thread_id": 1, "registers": ["x0"]} | fields
    assert_error(
        send(
            environment, "read_registers", expected_token=token(environment), **request
        )
    )


@pytest.mark.parametrize("missing", ["pc", "sp", "cpsr", "x0"])
def test_missing_required_or_requested_register_is_not_silently_omitted(
    environment: Any, missing: str
) -> None:
    environment.thread.registers.pop(missing)
    assert_error(
        send(
            environment,
            "read_registers",
            expected_token=token(environment),
            thread_id=1,
            registers=["x0"],
        ),
        "unavailable",
    )


@pytest.mark.parametrize(
    "issue",
    [
        "pc-mismatch",
        "sp-mismatch",
        "status-width",
        "value-width",
        "frame-id",
        "no-frame",
        "read-error",
    ],
)
def test_register_and_frame_context_must_match(
    environment: Any, monkeypatch: pytest.MonkeyPatch, issue: str
) -> None:
    if issue == "pc-mismatch":
        environment.thread.pc_override = 0x1004
    elif issue == "sp-mismatch":
        environment.thread.sp_override = 0x8004
    elif issue == "status-width":
        environment.thread.registers["cpsr"] = 2**32
    elif issue == "value-width":
        environment.thread.registers["x0"] = 2**64
    elif issue == "frame-id":
        environment.thread.frame_id = 1
    elif issue == "no-frame":
        environment.thread.frame_valid = False
    else:

        def failed_register(name: str) -> Any:
            def value(error: Error) -> int:
                error.success = False
                return 0

            return SimpleNamespace(IsValid=lambda: True, GetValueAsUnsigned=value)

        monkeypatch.setattr(environment.thread, "find_register", failed_register)
    assert_error(
        send(
            environment,
            "read_registers",
            expected_token=token(environment),
            thread_id=1,
            registers=["x0"],
        )
    )


@pytest.mark.parametrize(
    "change", ["stop", "membership", "reason", "frame", "pc", "sp", "cpsr", "x0"]
)
def test_register_mutation_is_rejected_with_fresh_reread(
    environment: Any, change: str
) -> None:
    expected = token(environment)
    changed = False

    def register(name: str) -> None:
        nonlocal changed
        if not changed and name == "x0":
            changed = True
            mutate(environment, change)

    environment.thread.on_register = register
    assert_error(
        send(
            environment,
            "read_registers",
            expected_token=expected,
            thread_id=1,
            registers=["x0"],
        ),
        "state_changed",
    )


@pytest.mark.parametrize("status,order", [(0, "little"), (1 << 9, "big")])
def test_arm32_data_order_comes_only_from_selected_fresh_cpsr(
    environment: Any, status: int, order: str
) -> None:
    environment.target.triple, environment.target.width = "armv7-unknown-linux", 4
    environment.thread.registers = {"pc": 0x1000, "sp": 0x8000, "cpsr": status, "r0": 7}
    expected = token(environment)
    raw = read_memory(environment, expected)
    assert raw["ok"] and raw["data"]["data_byte_order"]["order"] == "unknown"
    selected = read_memory(environment, expected, thread_id=1)
    assert selected["ok"] and selected["data"]["data_byte_order"]["order"] == order
    assert selected["data"]["interpretation"] == "raw-bytes-only"


def test_arm32_missing_status_does_not_guess_data_order(environment: Any) -> None:
    environment.target.triple, environment.target.width = "arm-unknown-linux", 4
    environment.thread.registers.pop("cpsr")
    expected = token(environment)
    assert_error(read_memory(environment, expected, thread_id=1), "unavailable")
    assert environment.process.reads == []
    raw = read_memory(environment, expected)
    assert raw["ok"] and raw["data"]["data_byte_order"]["order"] == "unknown"


def test_x86_register_status_and_non_arm_endianness(environment: Any) -> None:
    environment.target.triple = "x86_64-unknown-linux"
    environment.thread.registers = {
        "rip": 0x1000,
        "rsp": 0x8000,
        "rflags": 0x202,
        "rax": 7,
    }
    response = send(
        environment,
        "read_registers",
        expected_token=token(environment),
        thread_id=1,
        registers=["rax"],
    )
    assert response["ok"], response
    assert response["data"]["context"]["registers"]["rflags"] == "0x202"
    assert response["data"]["data_byte_order"]["order"] == "little"


def test_query_callback_is_lazy_and_emits_one_json_message(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    messages: list[str] = []
    result = SimpleNamespace(AppendMessage=messages.append)
    environment.bridge.query(
        environment.debugger, '{"version":1,"operation":"describe_session"}', result, {}
    )
    assert len(messages) == 1 and json.loads(messages[0])["ok"]
    monkeypatch.delitem(sys.modules, "lldb")

    def forbidden_import(name: str) -> None:
        pytest.fail("malformed request loaded LLDB")

    monkeypatch.setattr(environment.bridge.importlib, "import_module", forbidden_import)
    environment.bridge.query(None, "bad JSON", result, {})
    assert_error(json.loads(messages[-1]), "invalid_request")


def test_registration_is_the_only_command_and_queries_never_execute_target_code(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[str] = []
    environment.bridge.__lldb_init_module(
        SimpleNamespace(HandleCommand=commands.append), {}
    )
    assert commands == [
        "command script add -f lldb_bridge.query rampage-query",
        "command script add -f lldb_bridge.serve rampage-query-serve",
    ]

    def forbidden(*arguments: Any, **options: Any) -> None:
        pytest.fail("bridge invoked a non-read-only API")

    for receiver, names in [
        (
            environment.debugger,
            ["HandleCommand", "SetAsync", "GetCommandInterpreter", "SetSelectedTarget"],
        ),
        (
            environment.target,
            ["EvaluateExpression", "Launch", "Attach", "BreakpointCreateByAddress"],
        ),
        (
            environment.process,
            [
                "Continue",
                "Stop",
                "Kill",
                "Detach",
                "WriteMemory",
                "SetSelectedThreadByID",
            ],
        ),
        (environment.thread, ["Resume", "StepInstruction", "Suspend"]),
    ]:
        for name in names:
            monkeypatch.setattr(receiver, name, forbidden, raising=False)
    original_frame = environment.thread.GetFrameAtIndex

    def frame(index: int) -> Any:
        value = original_frame(index)
        value.EvaluateExpression, value.GetValueForVariablePath = forbidden, forbidden
        return value

    monkeypatch.setattr(environment.thread, "GetFrameAtIndex", frame)
    expected = token(environment)
    for operation in ["list_modules", "list_threads", "read_registers"]:
        response = send(
            environment,
            operation,
            expected_token=expected,
            **(
                {"thread_id": 1, "registers": ["x0"]}
                if operation == "read_registers"
                else {}
            ),
        )
        assert response["ok"], response
    assert read_memory(environment, expected, thread_id=1)["ok"]
    assert resolve_address(environment, expected)["ok"]


def test_queries_do_not_publish_to_disk_or_create_network_endpoints(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = token(environment)

    def forbidden(*arguments: Any, **options: Any) -> None:
        pytest.fail("bridge attempted disk publication or network access")

    for receiver, name in [
        (Path, "write_text"),
        (Path, "write_bytes"),
        (Path, "open"),
        (tempfile, "NamedTemporaryFile"),
        (socket, "socket"),
        (environment.bridge._snapshot, "publish_snapshot"),
    ]:
        monkeypatch.setattr(receiver, name, forbidden)
    for operation in [
        "describe_session",
        "list_modules",
        "list_threads",
        "read_registers",
    ]:
        response = send(
            environment,
            operation,
            expected_token=expected,
            **(
                {"thread_id": 1, "registers": ["x0"]}
                if operation == "read_registers"
                else {}
            ),
        )
        assert response["ok"], response
    assert read_memory(environment, expected)["ok"]
    assert resolve_address(environment, expected)["ok"]


@pytest.mark.parametrize(
    "uuid_text", [Module.uuid.upper(), Module.uuid.replace("-", "")]
)
def test_resolution_selects_only_uuid_among_same_basename_modules(
    environment: Any, uuid_text: str
) -> None:
    first, second = Module("same"), Module("same")
    second.uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    second.filespec.path = "/other/same"
    second.sections = [Section(second, 0x100000000, 0x1800, 0x100)]
    environment.target.modules = [second, first]
    response = resolve_address(environment, token(environment), module_uuid=uuid_text)
    assert response["ok"], response
    data = response["data"]
    assert data["module_uuid"] == Module.uuid
    assert data["module"]["index"] == 1 and data["module"]["path"] == "/owned/same"
    assert data["file_address"] == "0x100000004" and data["load_address"] == "0x1004"
    assert data["module_context"]["data_byte_order"]["order"] == "unknown"
    assert data["proven_flow"] is data["proven_layout"] is False
    assert response["observation"]["atomic_snapshot"] is False
    assert first.addresses == [0x100000004] * 2 and second.addresses == []
    assert first.resolutions == second.resolutions == []
    assert environment.process.mapping_queries == [0x1004] * 2
    assert environment.process.reads == [] and environment.thread.frames == 0


def test_resolution_uses_section_mapping_not_header_slide(environment: Any) -> None:
    module = environment.target.modules[0]
    module.sections = [Section(module, module.image + 0x100, 0x1800, 0x80)]
    response = resolve_address(
        environment, token(environment), file_address=module.image + 0x104
    )
    assert response["ok"], response
    assert response["data"]["load_address"] == "0x1804"
    assert response["data"]["section"]["offset"] == "0x4"
    assert response["data"]["load_address"] != hex(module.runtime + 0x104)


def test_resolution_accepts_sdk_build_id_uuid_and_selected_module_context(
    environment: Any,
) -> None:
    module = environment.target.modules[0]
    module.uuid = "01234567-89AB-CDEF-0123-456789ABCDEF-01234567"
    module.order = environment.api.eByteOrderBig
    response = resolve_address(
        environment,
        token(environment),
        module_uuid=module.uuid.replace("-", "").lower(),
    )
    assert response["ok"], response
    assert response["data"]["module_uuid"] == module.uuid.lower()
    assert response["data"]["module_context"]["object_byte_order"] == "big"
    assert response["data"]["module_context"]["data_byte_order"]["order"] == "unknown"
    assert environment.target.order == environment.api.eByteOrderLittle


@pytest.mark.parametrize("wrong", ["file", "load", "offset", "invalid"])
def test_resolution_refuses_inconsistent_resolved_sdk_address(
    environment: Any, monkeypatch: pytest.MonkeyPatch, wrong: str
) -> None:
    module = environment.target.modules[0]
    expected = token(environment)
    resolved = ResolvedAddress(module.sections[0], 4)
    if wrong == "file":
        monkeypatch.setattr(resolved, "GetFileAddress", lambda: module.image + 5)
    elif wrong == "load":
        monkeypatch.setattr(resolved, "GetLoadAddress", lambda target: 0x1005)
    elif wrong == "offset":
        monkeypatch.setattr(resolved, "GetOffset", lambda: 5)
    else:
        resolved.valid = False
    monkeypatch.setattr(environment.api, "SBAddress", lambda section, offset: resolved)
    assert_error(resolve_address(environment, expected), "unavailable")
    assert environment.process.mapping_queries == []


def test_resolution_refuses_file_address_outside_module_width(environment: Any) -> None:
    module = environment.target.modules[0]
    module.width = 4
    assert_error(resolve_address(environment, token(environment)), "invalid_request")
    assert module.resolutions == []


def test_resolution_does_not_coerce_boolean_backend_file_address_at_zero(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = environment.target.modules[0]
    module.sections = [Section(module, 0, 0x1000, 0x100)]
    resolved = ResolvedAddress(module.sections[0], 0)
    monkeypatch.setattr(resolved, "GetFileAddress", lambda: False)
    monkeypatch.setattr(environment.api, "SBAddress", lambda section, offset: resolved)
    assert_error(
        resolve_address(environment, token(environment), file_address=0), "unavailable"
    )
    assert environment.process.mapping_queries == []


def test_nested_leaf_resolution_keeps_explicit_section_bounds(environment: Any) -> None:
    module = environment.target.modules[0]
    parent = module.sections[0]
    parent.children = [Section(module, parent.file, parent.load, 0x20)]
    response = resolve_address(environment, token(environment))
    assert response["ok"], response
    assert response["data"]["section"]["index_path"] == [0, 0]
    assert response["data"]["section"]["file_end"] == hex(parent.file + 0x20)


@pytest.mark.parametrize(
    "fields",
    [
        {"module_uuid": "same"},
        {"module_uuid": "0"},
        {"module_uuid": None},
        {"module_uuid": []},
        {"module_uuid": "urn:uuid:" + Module.uuid},
        {"module_uuid": "{" + Module.uuid + "}"},
        {"module_uuid": "é" * 32},
        {"module_uuid": "a" * 129},
        {"module_uuid": "ab-cd"},
        {"file_address": True},
        {"file_address": -1},
        {"file_address": "100000004"},
        {"file_address": "0xffffffffffffffff"},
        {"file_address": None},
        {"path": "/must/not/open"},
        {"module_id": 0},
        {"thread_id": 1},
        {"response_budget": None},
    ],
)
def test_resolution_invalid_fields_refuse_before_sdk(
    environment: Any, fields: dict[str, Any]
) -> None:
    expected = token(environment)
    assert_error(resolve_address(environment, expected, **fields), "invalid_request")
    assert environment.target.modules[0].resolutions == []
    assert environment.process.mapping_queries == environment.process.reads == []


@pytest.mark.parametrize("selection", ["missing", "duplicate", "empty", "opaque"])
def test_resolution_never_falls_back_from_missing_or_ambiguous_uuid(
    environment: Any, selection: str
) -> None:
    module = environment.target.modules[0]
    if selection == "duplicate":
        duplicate = Module("different")
        duplicate.uuid = module.uuid.upper().replace("-", "")
        environment.target.modules.append(duplicate)
    elif selection == "empty":
        module.uuid = ""
    elif selection == "opaque":
        module.uuid = "same"
    else:
        module.uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert_error(resolve_address(environment, token(environment)), "unavailable")
    assert module.resolutions == [] and environment.process.mapping_queries == []


@pytest.mark.parametrize(
    "issue",
    [
        "gap",
        "container-gap",
        "unloaded",
        "invalid-section",
        "overflow-file",
        "overflow-load",
        "wrong-owner",
        "foreign-section",
        "unknown-order",
        "unknown-width",
    ],
)
def test_resolution_rejects_invalid_section_or_module_evidence(
    environment: Any, monkeypatch: pytest.MonkeyPatch, issue: str
) -> None:
    module = environment.target.modules[0]
    section = module.sections[0]
    if issue == "gap":
        section.size = 2
    elif issue == "container-gap":
        section.children = [Section(module, section.file + 0x10, 0x1010, 0x10)]
    elif issue == "unloaded":
        section.load = environment.api.LLDB_INVALID_ADDRESS
    elif issue == "invalid-section":
        section.valid = False
    elif issue == "overflow-file":
        section.size = 2**64 - 1
    elif issue == "overflow-load":
        section.load = 2**64 - 8
    elif issue == "wrong-owner":
        section.module = Module("other")
    elif issue == "foreign-section":
        foreign = Section(module, section.file, section.load, section.size)
        monkeypatch.setattr(
            environment.api,
            "SBAddress",
            lambda section, offset: ResolvedAddress(foreign, offset),
        )
    elif issue == "unknown-order":
        module.order = 99
    else:
        module.width = 0
    assert_error(resolve_address(environment, token(environment)), "unavailable")
    assert environment.process.mapping_queries == environment.process.reads == []


@pytest.mark.parametrize("permissions", ["---", "-wx", "???", "r??"])
def test_resolution_requires_known_readable_runtime_mapping(
    environment: Any, permissions: str
) -> None:
    environment.process.mappings = [(0x1000, 0x2000, permissions)]
    assert_error(resolve_address(environment, token(environment)), "unavailable")
    assert environment.process.reads == []


def test_resolution_rejects_unmapped_address_and_stale_stop(environment: Any) -> None:
    expected = token(environment)
    environment.process.mappings = []
    assert_error(resolve_address(environment, expected), "unavailable")
    environment.process.mapping_queries.clear()
    environment.process.stop_id += 1
    assert_error(resolve_address(environment, expected), "stale_token")
    assert environment.process.mapping_queries == []


@pytest.mark.parametrize(
    "change",
    [
        "stop",
        "expression-stop",
        "selected-target",
        "module-uuid",
        "module-path",
        "module-order",
        "module-width",
        "mapping-permissions",
        "mapping-bounds",
        "section-load",
        "section-size",
        "section-replaced",
        "module-replaced",
        "same-token-target",
    ],
)
def test_resolution_revalidates_fresh_sdk_objects_after_serialization(
    environment: Any, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    expected = token(environment)
    original_encode = environment.bridge.encode_json

    def encode(value: Any) -> str:
        encoded = original_encode(value)
        if isinstance(value, dict) and value.get("ok") is True:
            module = environment.target.modules[0]
            if change == "section-load":
                module.sections[0].load += 0x10
            elif change == "section-size":
                module.sections[0].size -= 1
            elif change == "section-replaced":
                module.sections = [
                    Section(module, module.image, module.runtime, 0x1000)
                ]
            elif change == "module-replaced":
                environment.target.modules = [Module()]
            elif change == "same-token-target":
                environment.debugger.target = Target()
            else:
                mutate(environment, change)
        return encoded

    monkeypatch.setattr(environment.bridge, "encode_json", encode)
    assert_error(resolve_address(environment, expected), "state_changed")
    assert environment.process.reads == []


def test_resolution_race_during_sdk_resolution_discards_result(
    environment: Any,
) -> None:
    module = environment.target.modules[0]
    expected = token(environment)
    module.on_address = lambda: mutate(environment, "stop")
    assert_error(resolve_address(environment, expected), "state_changed")
    assert environment.process.mapping_queries == []


def test_resolution_detects_same_metadata_module_replaced_after_initial_enumeration(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = token(environment)
    original = environment.target.GetModuleAtIndex
    accesses = 0

    def module_at_index(index: int) -> Module:
        nonlocal accesses
        accesses += 1
        if accesses == 2:
            environment.target.modules = [Module()]
        return original(index)

    monkeypatch.setattr(environment.target, "GetModuleAtIndex", module_at_index)
    assert_error(resolve_address(environment, expected), "state_changed")
    assert environment.target.modules[0].resolutions == []


def test_resolution_shared_work_budget_includes_revalidation_and_failed_inspections(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = token(environment)
    context = environment.bridge.QueryContext(
        environment.debugger, environment.api, expected, "resolve_module_address"
    )
    context.execute(
        {
            "operation": "resolve_module_address",
            "module_uuid": Module.uuid,
            "file_address": "0x100000004",
        }
    )
    consumed = context.resolution_work
    monkeypatch.setattr(environment.bridge, "MAX_RESOLUTION_WORK", consumed)
    with pytest.raises(environment.bridge.QueryError) as raised:
        context.verify()
    assert raised.value.code == "state_changed"
    assert context.resolution_work == consumed
    assert environment.target.modules[0].addresses == [0x100000004]
    assert environment.target.modules[0].resolutions == []
    context = environment.bridge.QueryContext(
        environment.debugger, environment.api, expected
    )
    environment.target.modules[0].valid = False
    with pytest.raises(environment.bridge.QueryError):
        context.resolve_module_address(Module.uuid, 0x100000004)
    assert context.resolution_work == 2


@pytest.mark.parametrize(
    "budget", ["section-count", "section-depth", "mapping", "response"]
)
def test_resolution_limits_fail_without_partial_observations(
    environment: Any, monkeypatch: pytest.MonkeyPatch, budget: str
) -> None:
    expected = token(environment)
    module = environment.target.modules[0]
    fields = {}
    if budget == "section-count":
        monkeypatch.setattr(environment.bridge, "MAX_MODULE_SECTIONS", 1)
        module.sections.append(Section(module, module.image + 0x2000, 0x4000, 0x10))
    elif budget == "section-depth":
        monkeypatch.setattr(environment.bridge, "MAX_SECTION_DEPTH", 1)
        module.sections[0].children = [Section(module, module.image, 0x1000, 0x10)]
    elif budget == "mapping":
        monkeypatch.setattr(environment.bridge, "MAX_MAPPING_QUERIES", 1)
    else:
        fields["response_budget"] = 1024
    assert_error(resolve_address(environment, expected, **fields))
    assert environment.process.reads == []
    if budget in {"section-count", "section-depth"}:
        assert module.resolutions == module.addresses == []


@pytest.mark.parametrize("kind", ["roots", "aggregate", "depth", "unresolved-budget"])
def test_resolution_caps_precede_sdk_address_construction_and_unbounded_native_search(
    environment: Any, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    module = environment.target.modules[0]
    expected = token(environment)
    if kind == "roots":
        module.sections = [
            Section(module, module.image, 0x1000, 0x1000)
            for _ in range(environment.bridge.MAX_MODULE_SECTIONS + 1)
        ]
    elif kind == "aggregate":
        module.sections[0].children = [
            Section(module, module.image, 0x1000, 0x100)
            for _ in range(environment.bridge.MAX_MODULE_SECTIONS)
        ]
    elif kind == "depth":
        parent = module.sections[0]
        for _ in range(environment.bridge.MAX_SECTION_DEPTH):
            child = InheritedSection(parent, 0, 0x100)
            parent.children = [child]
            parent = child
    else:
        monkeypatch.setattr(environment.bridge, "MAX_RESOLUTION_WORK", 6)
    file_address = module.image + (0x1000 if kind == "unresolved-budget" else 4)
    assert_error(
        resolve_address(environment, expected, file_address=file_address),
        "limit_exceeded",
    )
    assert module.resolutions == module.addresses == []
    assert environment.process.mapping_queries == environment.process.reads == []


@pytest.mark.parametrize("kind", ["missing", "container-gap"])
def test_unresolved_file_addresses_still_preflight_structure_without_calling_native_search(
    environment: Any, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    module = environment.target.modules[0]
    expected = token(environment)
    if kind == "container-gap":
        module.sections[0].children = [InheritedSection(module.sections[0], 0x10, 0x10)]
    section_queries = []
    original = module.GetNumSections

    def count() -> int:
        section_queries.append(True)
        return original()

    monkeypatch.setattr(module, "GetNumSections", count)
    file_address = module.image + (0x1000 if kind == "missing" else 4)
    assert_error(
        resolve_address(environment, expected, file_address=file_address), "unavailable"
    )
    assert section_queries
    assert module.resolutions == module.addresses == []


@pytest.mark.parametrize("failure", ["count", "section"])
def test_failed_sdk_hierarchy_preflight_consumes_inspection_work_without_resolving(
    environment: Any, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    module = environment.target.modules[0]
    context = environment.bridge.QueryContext(
        environment.debugger, environment.api, token(environment)
    )

    def broken(*arguments: Any) -> Any:
        raise RuntimeError("SDK hierarchy unavailable")

    monkeypatch.setattr(
        module, "GetNumSections" if failure == "count" else "GetSectionAtIndex", broken
    )
    with pytest.raises(RuntimeError, match="hierarchy unavailable"):
        context.read_section_structure(module)
    assert context.resolution_work == (1 if failure == "count" else 2)
    assert module.resolutions == module.addresses == []


def test_section_metadata_overflow_charges_failed_preflight_before_sdk_address_construction(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = environment.target.modules[0]
    context = environment.bridge.QueryContext(
        environment.debugger, environment.api, token(environment)
    )
    monkeypatch.setattr(environment.bridge, "MAX_METADATA_BYTES", 1)
    with pytest.raises(environment.bridge.QueryError) as raised:
        context.read_section_hierarchy(module, environment.target)
    assert raised.value.code == "limit_exceeded"
    assert context.resolution_work == 3
    assert module.resolutions == module.addresses == []


def test_inherited_sdk_load_wrap_is_refused_even_when_wrapped_leaf_is_readable(
    environment: Any,
) -> None:
    module = environment.target.modules[0]
    parent = Section(module, 0x100000000, 2**64 - 0x1000, 0x4000)
    leaf = InheritedSection(parent, 0x2000, 0x100)
    parent.children = [leaf]
    module.sections = [parent]
    environment.process.mappings = [(0x1000, 0x2000, "r-x")]
    observed = ResolvedAddress(leaf, 4)
    assert observed.GetFileAddress() == 0x100002004
    assert observed.GetLoadAddress(environment.target) == 0x1004
    assert_error(
        resolve_address(environment, token(environment), file_address="0x100002004"),
        "unavailable",
    )
    assert module.resolutions == module.addresses == []
    assert environment.process.mapping_queries == []


def test_inherited_sdk_file_wrap_is_refused_before_address_construction(
    environment: Any,
) -> None:
    module = environment.target.modules[0]
    parent = Section(module, 2**64 - 0x1000, 0x2000, 0x4000)
    leaf = InheritedSection(parent, 0x2000, 0x100)
    parent.children = [leaf]
    module.sections = [parent]
    assert ResolvedAddress(leaf, 4).GetFileAddress() == 0x1004
    assert_error(
        resolve_address(environment, token(environment), file_address="0x1004"),
        "unavailable",
    )
    assert module.resolutions == module.addresses == []


@pytest.mark.parametrize(
    "kind", ["unloaded-parent", "outside-parent", "wrong-parent", "cycle"]
)
def test_resolution_refuses_unsupported_or_inconsistent_ancestor_mapping(
    environment: Any, kind: str
) -> None:
    module = environment.target.modules[0]
    parent = module.sections[0]
    leaf = InheritedSection(parent, 0, 0x100, direct_load=0x1000)
    parent.children = [leaf]
    if kind == "unloaded-parent":
        parent.load = environment.api.LLDB_INVALID_ADDRESS
        assert leaf.GetLoadAddress(environment.target) == 0x1000
    elif kind == "outside-parent":
        leaf.size = parent.size + 1
    elif kind == "wrong-parent":
        leaf.parent = Section(module, parent.file, parent.load, parent.size)
    else:
        parent.children = [parent]
    assert_error(resolve_address(environment, token(environment)), "unavailable")
    assert module.resolutions == module.addresses == []


def test_resolution_publishes_checked_ancestor_bounds_for_valid_inheritance(
    environment: Any,
) -> None:
    module = environment.target.modules[0]
    parent = module.sections[0]
    parent.size = 0x4000
    leaf = InheritedSection(parent, 0x2000, 0x100)
    parent.children = [leaf]
    environment.process.mappings = [(0x3000, 0x4000, "r-x")]
    response = resolve_address(
        environment, token(environment), file_address=module.image + 0x2004
    )
    assert response["ok"], response
    assert response["data"]["load_address"] == "0x3004"
    assert response["data"]["section"]["load_base"] == "0x3000"
    assert response["data"]["section"]["ancestors"][0]["load_base"] == "0x1000"
    assert response["data"]["section"]["ancestors"][0]["file_end"] == hex(
        parent.file + parent.size
    )
    assert module.resolutions == []


def test_hierarchy_replacement_during_preflight_refuses_before_sdk_address_construction(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = environment.target.modules[0]
    parent = module.sections[0]
    parent.children = [InheritedSection(parent, 0, 0x100)]
    expected = token(environment)
    original = parent.GetName

    def changed() -> str:
        parent.children = [InheritedSection(parent, 0, 0x100)]
        return original()

    monkeypatch.setattr(parent, "GetName", changed)
    assert_error(resolve_address(environment, expected), "state_changed")
    assert module.resolutions == module.addresses == []


@pytest.mark.parametrize(
    "change", ["ancestor-size", "ancestor-replaced", "compensated-ancestor-load"]
)
def test_resolution_revalidates_full_ancestor_chain_even_when_leaf_address_stays_the_same(
    environment: Any, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    module = environment.target.modules[0]
    parent = module.sections[0]
    parent.size = 0x4000
    leaf = InheritedSection(parent, 0x2000, 0x100)
    parent.children = [leaf]
    environment.process.mappings = [(0x3000, 0x4000, "r-x")]
    expected = token(environment)
    original_encode = environment.bridge.encode_json

    def encode(value: Any) -> str:
        encoded = original_encode(value)
        if isinstance(value, dict) and value.get("ok") is True:
            if change == "ancestor-size":
                parent.size -= 1
            elif change == "ancestor-replaced":
                replacement = Section(module, parent.file, parent.load, parent.size)
                replacement.children = [leaf]
                module.sections = [replacement]
            else:
                parent.file += 0x100
                parent.load += 0x100
                leaf.relative_file_offset -= 0x100
                assert leaf.GetLoadAddress(environment.target) == 0x3000
                assert leaf.GetFileAddress() == module.image + 0x2000
        return encoded

    monkeypatch.setattr(environment.bridge, "encode_json", encode)
    assert_error(
        resolve_address(environment, expected, file_address=module.image + 0x2004),
        "state_changed",
    )
    assert module.resolutions == []


def test_final_mapping_inspection_cannot_publish_a_changed_ancestor_chain(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = environment.target.modules[0]
    parent = module.sections[0]
    parent.size = 0x4000
    parent.children = [InheritedSection(parent, 0x2000, 0x100)]
    environment.process.mappings = [(0x3000, 0x4000, "r-x")]
    expected = token(environment)
    original = environment.process.GetMemoryRegionInfo

    def changed(address: int, region: Region) -> Error:
        error = original(address, region)
        if len(environment.process.mapping_queries) == 2:
            parent.size -= 1
        return error

    monkeypatch.setattr(environment.process, "GetMemoryRegionInfo", changed)
    assert_error(
        resolve_address(environment, expected, file_address=module.image + 0x2004),
        "state_changed",
    )
    assert len(environment.process.mapping_queries) == 2
    assert module.resolutions == []


def guarded_modules_with_unbounded_nonselected_hierarchy(
    environment: Any,
) -> tuple[GuardedHeaderModule, GuardedHeaderModule]:
    selected, other = GuardedHeaderModule("same"), GuardedHeaderModule("same")
    other.uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    other.filespec.path = "/other/same"
    parent = other.sections[0]
    for _ in range(environment.bridge.MAX_SECTION_DEPTH):
        child = InheritedSection(parent, 0, 0x100)
        parent.children = [child]
        parent = child
    selected.header_allowed = other.header_allowed = False
    environment.target.modules = [other, selected]
    return selected, other


def test_resolution_init_and_publish_never_resolve_headers_in_any_module(
    environment: Any,
) -> None:
    expected = token(environment)
    selected, other = guarded_modules_with_unbounded_nonselected_hierarchy(environment)
    response = resolve_address(environment, expected)
    assert response["ok"], response
    assert response["token"] == expected
    assert response["data"]["module"]["index"] == 1
    assert response["data"]["module"]["path"] == "/owned/same"
    assert "runtime_base" not in response["data"]["module"]
    assert "image_base" not in response["data"]["module"]
    assert response["data"]["load_address"] == "0x1004"
    assert selected.addresses == [0x100000004] * 2
    assert selected.header_calls == other.header_calls == 0
    assert selected.resolutions == other.resolutions == other.addresses == []


@pytest.mark.parametrize(
    "failure",
    [
        "selected-depth",
        "selected-count",
        "unresolved",
        "missing-uuid",
        "duplicate-uuid",
        "budget",
        "sdk-error",
    ],
)
def test_resolution_error_and_unresolved_paths_never_resolve_selected_or_nonselected_headers(
    environment: Any, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    expected = token(environment)
    selected, other = guarded_modules_with_unbounded_nonselected_hierarchy(environment)
    fields = {}
    code = "unavailable"
    if failure == "selected-depth":
        parent = selected.sections[0]
        for _ in range(environment.bridge.MAX_SECTION_DEPTH):
            child = InheritedSection(parent, 0, 0x100)
            parent.children = [child]
            parent = child
        code = "limit_exceeded"
    elif failure == "selected-count":
        selected.sections = [
            Section(selected, selected.image, 0x1000, 0x1000)
            for _ in range(environment.bridge.MAX_MODULE_SECTIONS + 1)
        ]
        code = "limit_exceeded"
    elif failure == "unresolved":
        fields["file_address"] = selected.image + 0x1000
    elif failure == "missing-uuid":
        fields["module_uuid"] = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
    elif failure == "duplicate-uuid":
        other.uuid = selected.uuid.upper()
    elif failure == "budget":
        monkeypatch.setattr(environment.bridge, "MAX_RESOLUTION_WORK", 6)
        code = "limit_exceeded"
    else:

        def failed_sections() -> int:
            raise RuntimeError("selected SDK section enumeration failed")

        monkeypatch.setattr(selected, "GetNumSections", failed_sections)
        code = "backend_error"
    assert_error(resolve_address(environment, expected, **fields), code)
    assert selected.header_calls == other.header_calls == 0
    assert (
        selected.addresses
        == other.addresses
        == selected.resolutions
        == other.resolutions
        == []
    )
    assert environment.process.mapping_queries == environment.process.reads == []


def test_resolution_stop_identity_and_mapping_do_not_depend_on_uninspected_headers(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = token(environment)
    selected, other = guarded_modules_with_unbounded_nonselected_hierarchy(environment)
    original_encode = environment.bridge.encode_json

    def encode(value: Any) -> str:
        encoded = original_encode(value)
        if isinstance(value, dict) and value.get("ok") is True:
            selected.runtime = environment.api.LLDB_INVALID_ADDRESS
            selected.image = 2**64
            other.runtime = -1
            other.image = -1
        return encoded

    monkeypatch.setattr(environment.bridge, "encode_json", encode)
    response = resolve_address(environment, expected)
    assert response["ok"], response
    assert response["token"] == expected
    assert response["data"]["file_address"] == "0x100000004"
    assert response["data"]["load_address"] == "0x1004"
    assert selected.header_calls == other.header_calls == 0


@pytest.mark.parametrize(
    "operation",
    [
        "describe_session",
        "list_modules",
        "list_threads",
        "read_registers",
        "read_memory",
    ],
)
def test_existing_operations_keep_their_original_module_header_observation(
    environment: Any, operation: str
) -> None:
    expected = token(environment)
    module = GuardedHeaderModule()
    environment.target.modules = [module]
    fields = {}
    if operation == "read_registers":
        fields = {"thread_id": 1, "registers": ["x0"]}
    elif operation == "read_memory":
        fields = {"address": "0x1000", "size": 4, "permissions": "r-x"}
    response = send(environment, operation, expected_token=expected, **fields)
    assert response["ok"], response
    assert module.header_calls == 2
    if operation == "list_modules":
        assert response["data"]["items"][0]["runtime_base"] == hex(module.runtime)
        assert response["data"]["items"][0]["image_base"] == hex(module.image)
