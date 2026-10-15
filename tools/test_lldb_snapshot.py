from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


def load_exporter() -> Any:
    spec = importlib.util.spec_from_file_location(
        "lldb_snapshot", Path(__file__).with_name("lldb_snapshot.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Result:
    error: str | None = None
    message: str | None = None

    def SetError(self, text: str) -> None:
        self.error = text

    def AppendMessage(self, text: str) -> None:
        self.message = text


class ReadError:
    def Success(self) -> bool:
        return True


class MemoryRegion:
    base: int = 0x1000
    end: int = 0x2000
    permissions: str = "r-x"
    mapped: bool = True

    def IsMapped(self) -> bool:
        return self.mapped

    def GetRegionBase(self) -> int:
        return self.base

    def GetRegionEnd(self) -> int:
        return self.end

    def IsReadable(self) -> bool:
        return "r" in self.permissions

    def IsWritable(self) -> bool:
        return "w" in self.permissions

    def IsExecutable(self) -> bool:
        return "x" in self.permissions


class Process:
    state: int = 1
    stop_id: int = 1
    expression_stop_id: int = 0
    reads: list[tuple[int, int]]

    def __init__(self) -> None:
        self.reads = []

    def GetState(self) -> int:
        return self.state

    def GetProcessID(self) -> int:
        return 123

    def GetStopID(self, include_expression_stops: bool = False) -> int:
        return self.stop_id + (
            self.expression_stop_id if include_expression_stops else 0
        )

    def GetSelectedThread(self) -> Any:
        return SimpleNamespace(IsValid=lambda: False)

    def GetThreadByID(self, identity: int) -> Any:
        thread = self.GetSelectedThread()
        return (
            thread
            if thread.IsValid() and thread.GetThreadID() == identity
            else SimpleNamespace(IsValid=lambda: False)
        )

    def GetMemoryRegionInfo(self, address: int, region: MemoryRegion) -> ReadError:
        return ReadError()

    def ReadMemory(self, address: int, size: int, error: ReadError) -> bytes:
        self.reads.append((address, size))
        return b"\x55\x48\x89\xe5"[:size]


def debugger(process: Process) -> Any:
    target = SimpleNamespace(
        GetProcess=lambda: process,
        GetTriple=lambda: "x86_64-apple-macosx",
        GetByteOrder=lambda: 0,
        GetAddressByteSize=lambda: 8,
        GetNumModules=lambda: 0,
    )
    return SimpleNamespace(GetSelectedTarget=lambda: target)


def test_export_reads_only_requested_ranges_and_never_overwrites(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()
    output = tmp_path / "capture.json"
    result = Result()
    exporter = load_exporter()
    command = f"{output} --region 0x1000:4:r-x --seed 0x1000"
    exporter.export_snapshot(debugger(process), command, result, {})
    assert result.error is None
    assert process.reads == [(0x1000, 4)]
    snapshot = json.loads(output.read_text())
    assert snapshot["regions"][0]["bytes"] == "554889e5"
    assert snapshot["seeds"] == ["0x1000"]
    assert snapshot["target"] == {"platform": "darwin"}
    assert "software-breakpoint traps normalized" in snapshot["provenance"]
    exporter.export_snapshot(debugger(process), command, result, {})
    assert result.error is not None
    assert json.loads(output.read_text()) == snapshot
    assert process.reads == [(0x1000, 4)]


def test_export_rejects_running_process_without_reading_memory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()
    process.state = 2
    result = Result()
    load_exporter().export_snapshot(
        debugger(process),
        f"{tmp_path / 'capture.json'} --region 0x1000:4:r-x",
        result,
        {},
    )
    assert result.error is not None
    assert process.reads == []
    assert not (tmp_path / "capture.json").exists()


def test_export_records_module_slides_and_register_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
            LLDB_INVALID_ADDRESS=2**64 - 1,
        ),
    )
    process = Process()
    frame = SimpleNamespace(
        IsValid=lambda: True,
        GetFrameID=lambda: 0,
        GetPC=lambda: 0x1000,
        GetSP=lambda: 0x8000,
        FindRegister=lambda name: SimpleNamespace(
            IsValid=lambda: name == "rsp",
            GetValueAsUnsigned=lambda error: 0x8000,
        ),
    )
    thread = SimpleNamespace(
        IsValid=lambda: True,
        GetFrameAtIndex=lambda index: frame,
        GetThreadID=lambda: 1,
        IsStopped=lambda: True,
        GetStopReason=lambda: 3,
    )
    filespec = SimpleNamespace(GetFilename=lambda: "fixture")
    module = SimpleNamespace(
        GetObjectFileHeaderAddress=lambda: SimpleNamespace(
            GetLoadAddress=lambda target: 0x1000,
            GetFileAddress=lambda: 0,
        ),
        GetUUIDString=lambda: "01234567-89ab-cdef-0123-456789abcdef",
        GetFileSpec=lambda: filespec,
    )
    target = SimpleNamespace(
        GetProcess=lambda: SimpleNamespace(
            GetState=process.GetState,
            ReadMemory=process.ReadMemory,
            GetMemoryRegionInfo=process.GetMemoryRegionInfo,
            GetProcessID=process.GetProcessID,
            GetStopID=process.GetStopID,
            GetSelectedThread=lambda: thread,
            GetThreadByID=lambda identity: thread,
        ),
        GetTriple=lambda: "x86_64-apple-macosx",
        GetByteOrder=lambda: 0,
        GetAddressByteSize=lambda: 8,
        GetNumModules=lambda: 1,
        GetModuleAtIndex=lambda index: module,
    )
    output = tmp_path / "metadata.json"
    result = Result()
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} --region 0x1000:4:r-x",
        result,
        {},
    )
    assert result.error is None
    snapshot = json.loads(output.read_text())
    assert snapshot["modules"][0]["runtime_base"] == "0x1000"
    assert snapshot["modules"][0]["image_base"] == "0x0"
    assert snapshot["registers"] == [
        {"thread_id": "0x1", "name": "rsp", "value": "0x8000"}
    ]

    def failed_register(error: Any) -> int:
        error.Success = lambda: False
        return 0

    frame.FindRegister = lambda name: SimpleNamespace(
        IsValid=lambda: name == "rsp",
        GetValueAsUnsigned=failed_register,
    )
    result = Result()
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{tmp_path / 'failed-register.json'} --region 0x1000:4:r-x",
        result,
        {},
    )
    assert result.error is not None
    assert not (tmp_path / "failed-register.json").exists()


@pytest.mark.parametrize(
    "arguments",
    [
        "",
        "--region 0x1000:4:r-x --seed 0x2000",
        "--region 0x1000:4:r-x --region 0x1000:4:r-x",
        "--region 0x1000:4:r-x --thumb",
        "--region 0x1000:4:r-x --compiler ../apple",
    ],
)
def test_export_validation_fails_before_any_memory_read_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: str,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()
    result = Result()
    output = tmp_path / "capture.json"
    command = f"{output} {arguments}" if arguments else ""
    load_exporter().export_snapshot(debugger(process), command, result, {})
    assert result.error is not None
    assert not output.exists()
    assert process.reads == []


def test_explicit_compiler_is_recorded_without_executing_target_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()
    output = tmp_path / "explicit-compiler.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process),
        f"{output} --region 0x1000:4:r-x --compiler apple",
        result,
        {},
    )
    assert result.error is None
    assert json.loads(output.read_text())["target"] == {
        "platform": "darwin",
        "compiler": "apple",
    }


@pytest.mark.parametrize(
    "actual,requested",
    [("rw-", "r--"), ("rwx", "r-x"), ("r--", "r-x"), ("---", "r--"), ("r--", "rw-")],
)
def test_mislabelled_permissions_are_rejected_before_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, actual: str, requested: str
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()

    def mapping(address: int, region: MemoryRegion) -> ReadError:
        region.permissions = actual
        return ReadError()

    monkeypatch.setattr(process, "GetMemoryRegionInfo", mapping)
    result = Result()
    output = tmp_path / "mislabelled.json"
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:{requested}", result, {}
    )
    assert "permission mismatch" in (result.error or "")
    assert process.reads == []
    assert not output.exists()


@pytest.mark.parametrize("gap", [False, True])
def test_every_mapping_in_a_requested_range_is_validated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gap: bool
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()
    queries: list[int] = []

    def mapping(address: int, region: MemoryRegion) -> ReadError:
        queries.append(address)
        region.base, region.end = address, address + 2
        region.mapped = not gap or address == 0x1000
        return ReadError()

    monkeypatch.setattr(process, "GetMemoryRegionInfo", mapping)
    output = tmp_path / "mapping.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x", result, {}
    )
    assert queries == [0x1000, 0x1002] * (1 if gap else 2)
    if gap:
        assert result.error is not None
        assert process.reads == []
        assert not output.exists()
    else:
        assert result.error is None
        assert process.reads == [(0x1000, 4)]


def test_changed_stop_identity_never_publishes_a_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()

    def read(address: int, size: int, error: ReadError) -> bytes:
        process.stop_id += 1
        return b"\x00" * size

    monkeypatch.setattr(process, "ReadMemory", read)
    result = Result()
    output = tmp_path / "changed-stop.json"
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x", result, {}
    )
    assert "changed stop state" in (result.error or "")
    assert not output.exists()


def test_expression_only_stop_changes_are_observed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()

    def read(address: int, size: int, error: ReadError) -> bytes:
        process.expression_stop_id += 1
        return b"\x00" * size

    monkeypatch.setattr(process, "ReadMemory", read)
    result = Result()
    output = tmp_path / "expression-stop.json"
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x", result, {}
    )
    assert "changed stop state" in (result.error or "")
    assert not output.exists()


@pytest.mark.parametrize(
    "base,end", [(0x1001, 0x2000), (0x1000, 0x1000), (0x1000, 2**64)]
)
def test_nonprogressing_or_malformed_mapping_bounds_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base: int, end: int
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()

    def mapping(address: int, region: MemoryRegion) -> ReadError:
        region.base, region.end = base, end
        return ReadError()

    monkeypatch.setattr(process, "GetMemoryRegionInfo", mapping)
    result = Result()
    output = tmp_path / "bad-bounds.json"
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x", result, {}
    )
    assert "invalid memory mapping bounds" in (result.error or "")
    assert process.reads == []
    assert not output.exists()


def test_missing_mapping_api_is_refused_without_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError, eStateStopped=1, eByteOrderBig=1, eByteOrderLittle=0
        ),
    )
    process = Process()
    result = Result()
    load_exporter().export_snapshot(
        debugger(process),
        f"{tmp_path / 'missing.json'} --region 0x1000:4:r-x",
        result,
        {},
    )
    assert "cannot inspect memory permissions" in (result.error or "")
    assert process.reads == []


def test_failed_output_write_cleans_temporary_file_without_publishing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exporter = load_exporter()

    def fail(snapshot: dict[str, Any], stream: Any) -> None:
        stream.write("partial")
        raise OSError("controlled output failure")

    monkeypatch.setattr(exporter.json, "dump", fail)
    with pytest.raises(OSError, match="controlled output failure"):
        exporter.publish_snapshot({}, tmp_path / "capture.json", lambda: None)
    assert list(tmp_path.iterdir()) == []


def test_atomic_publication_refuses_a_destination_created_during_serialization(
    tmp_path: Path,
) -> None:
    output = tmp_path / "capture.json"

    def competing_output() -> None:
        output.write_text("preserved")

    with pytest.raises(FileExistsError):
        load_exporter().publish_snapshot({}, output, competing_output)
    assert output.read_text() == "preserved"
    assert list(tmp_path.iterdir()) == [output]


def test_mapping_query_budget_is_enforced_without_memory_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = Process()
    queries = 0

    def mapping(address: int, region: MemoryRegion) -> ReadError:
        nonlocal queries
        queries += 1
        region.base, region.end = address, address + 1
        return ReadError()

    monkeypatch.setattr(process, "GetMemoryRegionInfo", mapping)
    with pytest.raises(ValueError, match="mapping query limit"):
        load_exporter().validate_memory_permissions(
            process,
            [(0x1000, 16385, "r-x")],
            SimpleNamespace(SBMemoryRegionInfo=MemoryRegion),
        )
    assert queries == 16384
    assert process.reads == []


def test_failed_mapping_query_is_reported_before_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(
            SBError=ReadError,
            SBMemoryRegionInfo=MemoryRegion,
            eStateStopped=1,
            eByteOrderBig=1,
            eByteOrderLittle=0,
        ),
    )
    process = Process()

    def mapping(address: int, region: MemoryRegion) -> Any:
        return SimpleNamespace(Success=lambda: False)

    monkeypatch.setattr(process, "GetMemoryRegionInfo", mapping)
    result = Result()
    load_exporter().export_snapshot(
        debugger(process),
        f"{tmp_path / 'failed.json'} --region 0x1000:4:r-x",
        result,
        {},
    )
    assert "mapping unavailable" in (result.error or "")
    assert process.reads == []


def test_stop_change_during_serialization_is_checked_before_publication(
    tmp_path: Path,
) -> None:
    output = tmp_path / "changed-before-publish.json"

    def changed_stop() -> None:
        raise ValueError("process changed stop state during capture")

    with pytest.raises(ValueError, match="changed stop state"):
        load_exporter().publish_snapshot({}, output, changed_stop)
    assert list(tmp_path.iterdir()) == []


def test_cleanup_failure_after_publication_is_a_warning_not_capture_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "complete.json"
    exporter = load_exporter()

    def failed_cleanup(path: Path) -> None:
        raise OSError("controlled cleanup failure")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", failed_cleanup)
        warning = exporter.publish_snapshot({"complete": True}, output, lambda: None)
    assert "cleanup failure" in (warning or "")
    assert json.loads(output.read_text()) == {"complete": True}
    for temporary in tmp_path.glob(".rampage-capture-*"):
        temporary.unlink()


def test_interrupted_serialization_preserves_interrupt_and_removes_sensitive_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exporter = load_exporter()

    def interrupted(snapshot: dict[str, Any], stream: Any) -> None:
        stream.write("captured bytes")
        raise KeyboardInterrupt()

    monkeypatch.setattr(exporter.json, "dump", interrupted)
    with pytest.raises(KeyboardInterrupt):
        exporter.publish_snapshot({}, tmp_path / "interrupted.json", lambda: None)
    assert list(tmp_path.iterdir()) == []


class FileSpec:
    def GetFilename(self) -> str:
        return "fixture"

    def __str__(self) -> str:
        return "fixture"


def loaded_module(
    runtime: int = 0x1000, machine: str = "x86_64", hole: bool = False
) -> Any:
    def section(image: int, load: int) -> Any:
        return SimpleNamespace(
            GetNumSubSections=lambda: 0,
            GetFileAddress=lambda: image,
            GetLoadAddress=lambda target: load,
            GetByteSize=lambda: 2,
        )

    leaves = [
        section(0x100000100, runtime + 0x100),
        section(
            0x100000103 if hole else 0x100000102, runtime + (0x103 if hole else 0x102)
        ),
    ]
    parent = SimpleNamespace(
        GetNumSubSections=lambda: len(leaves),
        GetSubSectionAtIndex=lambda index: leaves[index],
    )
    return SimpleNamespace(
        GetObjectFileHeaderAddress=lambda: SimpleNamespace(
            GetFileAddress=lambda: 0x100000000, GetLoadAddress=lambda target: runtime
        ),
        GetUUIDString=lambda: "01234567-89ab-cdef-0123-456789abcdef",
        GetFileSpec=FileSpec,
        GetTriple=lambda: f"{machine}-apple-macosx",
        GetByteOrder=lambda: 0,
        GetAddressByteSize=lambda: 8,
        GetNumSections=lambda: 1,
        GetSectionAtIndex=lambda index: parent,
    )


@pytest.mark.parametrize("runtime", [0x1000, 0x200000000])
def test_module_selection_uses_checked_header_slide_and_loaded_section_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime: int
) -> None:
    api = SimpleNamespace(
        SBError=ReadError,
        SBMemoryRegionInfo=MemoryRegion,
        eStateStopped=1,
        eByteOrderBig=1,
        eByteOrderLittle=0,
        LLDB_INVALID_ADDRESS=2**64 - 1,
    )
    monkeypatch.setitem(sys.modules, "lldb", api)
    process = Process()

    def mapping(address: int, region: MemoryRegion) -> ReadError:
        region.base, region.end = runtime, runtime + 0x1000
        return ReadError()

    monkeypatch.setattr(process, "GetMemoryRegionInfo", mapping)
    target = debugger(process).GetSelectedTarget()
    target.GetNumModules = lambda: 1
    target.GetModuleAtIndex = lambda index: loaded_module(runtime)
    output = tmp_path / "module.json"
    result = Result()
    selection = "0123456789ABCDEF0123456789ABCDEF:0x100000100"
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} --module-region {selection}:4:r-x --module-seed {selection}",
        result,
        {},
    )
    assert result.error is None
    assert process.reads == [(runtime + 0x100, 4)]
    snapshot = json.loads(output.read_text())
    assert snapshot["seeds"] == [hex(runtime + 0x100)]
    assert snapshot["modules"][0]["runtime_base"] == hex(runtime)


@pytest.mark.parametrize(
    "issue", ["hole", "architecture", "ambiguous", "unknown", "overflow"]
)
def test_invalid_module_selections_fail_before_target_memory_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, issue: str
) -> None:
    api = SimpleNamespace(
        SBError=ReadError,
        SBMemoryRegionInfo=MemoryRegion,
        eStateStopped=1,
        eByteOrderBig=1,
        eByteOrderLittle=0,
        LLDB_INVALID_ADDRESS=2**64 - 1,
    )
    monkeypatch.setitem(sys.modules, "lldb", api)
    process = Process()
    target = debugger(process).GetSelectedTarget()
    target.GetNumModules = lambda: 2 if issue == "ambiguous" else 1
    target.GetModuleAtIndex = lambda index: loaded_module(
        2**64 - 2 if issue == "overflow" else 0x1000,
        "arm64" if issue == "architecture" else "x86_64",
        issue == "hole",
    )
    identity = "0" * 32 if issue == "unknown" else "0123456789abcdef0123456789abcdef"
    result = Result()
    output = tmp_path / "invalid-module.json"
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} --module-region {identity}:0x100000100:4:r-x",
        result,
        {},
    )
    assert result.error is not None
    assert process.reads == []
    assert not output.exists()


def test_opaque_module_identifiers_do_not_prevent_explicit_runtime_range_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = SimpleNamespace(
        SBError=ReadError,
        SBMemoryRegionInfo=MemoryRegion,
        eStateStopped=1,
        eByteOrderBig=1,
        eByteOrderLittle=0,
        LLDB_INVALID_ADDRESS=2**64 - 1,
    )
    monkeypatch.setitem(sys.modules, "lldb", api)
    process = Process()
    target = debugger(process).GetSelectedTarget()
    module = loaded_module()
    opaque = "0123456789abcdef0123456789abcdef01234567"
    module.GetUUIDString = lambda: opaque
    target.GetNumModules = lambda: 1
    target.GetModuleAtIndex = lambda index: module
    result = Result()
    output = tmp_path / "opaque.json"
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} --region 0x1000:4:r-x",
        result,
        {},
    )
    assert result.error is None
    assert json.loads(output.read_text())["modules"][0]["uuid"] == opaque


def test_contained_overlapping_section_cannot_hide_a_contradictory_slide() -> None:
    exporter = load_exporter()
    target = SimpleNamespace(
        GetTriple=lambda: "x86_64-apple-macosx",
        GetByteOrder=lambda: 0,
        GetAddressByteSize=lambda: 8,
    )
    module = loaded_module()
    metadata = {
        "uuid": "0123456789abcdef0123456789abcdef",
        "image_base": "0x100000000",
        "runtime_base": "0x1000",
    }
    ranges = {metadata["uuid"]: [(0x100000100, 0x1100, 4), (0x100000101, 0x9101, 1)]}
    with pytest.raises(ValueError, match="header slide"):
        exporter.resolve_module_range(
            f"{metadata['uuid']}:0x100000100",
            [(module, metadata)],
            target,
            SimpleNamespace(),
            ranges,
            4,
        )


def test_runtime_aliases_of_unselected_sections_are_rejected() -> None:
    exporter = load_exporter()
    target = SimpleNamespace(
        GetTriple=lambda: "x86_64-apple-macosx",
        GetByteOrder=lambda: 0,
        GetAddressByteSize=lambda: 8,
    )
    metadata = {
        "uuid": "0123456789abcdef0123456789abcdef",
        "image_base": "0x100000000",
        "runtime_base": "0x1000",
    }
    ranges = {metadata["uuid"]: [(0x100000100, 0x1100, 4), (0x100000200, 0x1100, 4)]}
    with pytest.raises(ValueError, match="header slide"):
        exporter.resolve_module_range(
            f"{metadata['uuid']}:0x100000100",
            [(loaded_module(), metadata)],
            target,
            SimpleNamespace(),
            ranges,
            4,
        )


def test_section_inspection_budget_is_shared_across_selected_modules() -> None:
    api = SimpleNamespace(LLDB_INVALID_ADDRESS=2**64 - 1)
    exporter = load_exporter()
    budget = [3]
    assert (
        len(exporter.module_ranges(loaded_module(), SimpleNamespace(), api, budget))
        == 2
    )
    assert budget == [0]
    with pytest.raises(ValueError, match="inspection limit"):
        exporter.module_ranges(loaded_module(), SimpleNamespace(), api, budget)


class CaptureThread:
    valid: bool = True
    stopped: bool = True
    reason: int = 3
    frame_valid: bool = True
    identity: int
    registers: dict[str, int]
    register_queries: list[str]

    def __init__(self, identity: int) -> None:
        self.identity = identity
        self.registers = {
            "rip": 0x1100,
            "rsp": 0x8000 + identity * 0x100,
            "rax": identity,
        }
        self.register_queries = []

    def IsValid(self) -> bool:
        return self.valid

    def IsStopped(self) -> bool:
        return self.stopped

    def GetThreadID(self) -> int:
        return self.identity

    def GetStopReason(self) -> int:
        return self.reason

    def GetFrameAtIndex(self, index: int) -> Any:
        assert index == 0
        return SimpleNamespace(
            IsValid=lambda: self.frame_valid,
            FindRegister=self.find_register,
            GetFrameID=lambda: 0,
            GetPC=lambda: self.registers.get("pc", self.registers.get("rip", 0x1100)),
            GetSP=lambda: self.registers.get("sp", self.registers.get("rsp", 0x8000)),
        )

    def find_register(self, name: str) -> Any:
        self.register_queries.append(name)
        return SimpleNamespace(
            IsValid=lambda: name in self.registers,
            GetValueAsUnsigned=lambda error: self.registers[name],
        )


class ThreadProcess(Process):
    threads: list[CaptureThread]
    thread_lookups: list[int]
    thread_indices: list[int]
    count_queries: int

    def __init__(self, threads: list[CaptureThread]) -> None:
        super().__init__()
        self.threads = threads
        self.thread_lookups = []
        self.thread_indices = []
        self.count_queries = 0

    def GetSelectedThread(self) -> Any:
        return self.threads[0] if self.threads else super().GetSelectedThread()

    def GetNumThreads(self) -> int:
        self.count_queries += 1
        return len(self.threads)

    def GetThreadAtIndex(self, index: int) -> CaptureThread:
        self.thread_indices.append(index)
        return self.threads[index]

    def GetThreadByID(self, identity: int) -> Any:
        self.thread_lookups.append(identity)
        return next(
            (thread for thread in self.threads if thread.identity == identity),
            SimpleNamespace(IsValid=lambda: False),
        )


@pytest.fixture
def capture_api(monkeypatch: pytest.MonkeyPatch) -> Any:
    api = SimpleNamespace(
        SBError=ReadError,
        SBMemoryRegionInfo=MemoryRegion,
        eStateStopped=1,
        eByteOrderBig=1,
        eByteOrderLittle=0,
        LLDB_INVALID_ADDRESS=2**64 - 1,
    )
    monkeypatch.setitem(sys.modules, "lldb", api)
    return api


@pytest.mark.parametrize("machine", ["arm64", "arm64e", "aarch64", "aarch64_be"])
@pytest.mark.parametrize("selection", ["", "--thread 1", "--all-threads"])
@pytest.mark.parametrize("status", [0, 1 << 9])
@pytest.mark.parametrize("byte_order", [0, 1])
def test_arm64_export_refuses_unknown_data_order_before_reads_or_files(
    tmp_path: Path,
    capture_api: Any,
    monkeypatch: pytest.MonkeyPatch,
    machine: str,
    selection: str,
    status: int,
    byte_order: int,
) -> None:
    exporter = load_exporter()
    thread = CaptureThread(1)
    thread.registers = {"pc": 0x1100, "sp": 0x8100, "x0": 1, "cpsr": status}
    process = ThreadProcess([thread])
    target = debugger(process).GetSelectedTarget()
    target.GetTriple = lambda: f"{machine}-apple-macosx14.0.0"
    target.GetByteOrder = lambda: byte_order
    monkeypatch.setattr(process, "GetByteOrder", target.GetByteOrder, raising=False)
    before = (process.state, process.stop_id, thread.identity, thread.registers.copy())

    def forbidden(*arguments: Any, **options: Any) -> Any:
        pytest.fail(
            "unknown ARM64 DATA order must refuse before reads or filesystem writes"
        )

    monkeypatch.setattr(process, "ReadMemory", forbidden)
    monkeypatch.setattr(process, "GetMemoryRegionInfo", forbidden)
    monkeypatch.setattr(exporter.tempfile, "NamedTemporaryFile", forbidden)
    monkeypatch.setattr(exporter.os, "link", forbidden)
    monkeypatch.setattr(exporter, "publish_snapshot", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    output = tmp_path / "capture.json"
    result = Result()
    exporter.export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} --region 0x1000:4:r-x {selection}",
        result,
        {},
    )
    assert "current LLDB SDK cannot affirm runtime DATA endianness" in (
        result.error or ""
    )
    assert result.message is None
    assert process.reads == process.thread_indices == process.thread_lookups == []
    assert thread.register_queries == []
    assert before == (process.state, process.stop_id, thread.identity, thread.registers)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("selection", ["", "--thread 0x2 --thread 1", "--all-threads"])
def test_thread_selection_preserves_default_and_flattened_register_provenance(
    tmp_path: Path, capture_api: Any, selection: str
) -> None:
    threads = [CaptureThread(1), CaptureThread(2)]
    threads[1].reason = 0
    threads[1].stopped = False
    process = ThreadProcess(threads)
    output = tmp_path / "threads.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x {selection}", result, {}
    )
    assert result.error is None
    snapshot = json.loads(output.read_text())
    wanted = (
        [threads[1], threads[0]]
        if selection.startswith("--thread")
        else threads
        if selection
        else threads[:1]
    )
    assert snapshot["registers"] == [
        {
            "thread_id": hex(thread.identity),
            "name": name,
            "value": hex(thread.registers[name]),
        }
        for thread in wanted
        for name in ("rax", "rsp", "rip")
    ]
    for thread in wanted:
        assert (
            f"{thread.identity:#x} (stop reason {thread.reason})"
            in snapshot["provenance"]
        )
    if not selection:
        assert threads[1].register_queries == []
    assert process.thread_lookups == (
        [2, 1] * 2 if selection.startswith("--thread") else [] if selection else [1]
    )
    assert process.thread_indices == (
        [0, 1] * 2 if selection == "--all-threads" else []
    )
    assert process.count_queries == (2 if selection == "--all-threads" else 0)
    assert process.reads == [(0x1000, 4)]


@pytest.mark.parametrize(
    "selection,expected",
    [
        ("--thread 1 --thread 0x1", "duplicate requested"),
        ("--thread 0", "invalid requested"),
        ("--thread -1", "invalid requested"),
        ("--thread 0xffffffffffffffff", "invalid requested"),
        ("--thread invalid", "invalid literal"),
        ("--thread 9", "not valid"),
        ("--all-threads --thread 1", "not allowed"),
    ],
)
def test_invalid_thread_selection_is_rejected_before_memory_reads(
    tmp_path: Path, capture_api: Any, selection: str, expected: str
) -> None:
    process = ThreadProcess([CaptureThread(1)])
    output = tmp_path / "invalid-thread.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x {selection}", result, {}
    )
    assert expected in (result.error or "")
    assert process.reads == []
    assert not output.exists()


@pytest.mark.parametrize("all_threads", [False, True])
def test_thread_budget_refuses_excess_without_enumeration_or_partial_capture(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch, all_threads: bool
) -> None:
    exporter = load_exporter()
    monkeypatch.setattr(exporter, "MAX_CAPTURE_THREADS", 2)
    process = ThreadProcess([CaptureThread(index) for index in (1, 2, 3)])
    selection = "--all-threads" if all_threads else "--thread 1 --thread 2 --thread 3"
    output = tmp_path / "bounded.json"
    result = Result()
    exporter.export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x {selection}", result, {}
    )
    assert "thread limit" in (result.error or "")
    assert process.thread_indices == process.thread_lookups == process.reads == []
    assert not output.exists()
    process.threads.pop()
    result = Result()
    exporter.export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x --all-threads", result, {}
    )
    assert result.error is None
    assert {
        row["thread_id"] for row in json.loads(output.read_text())["registers"]
    } == {"0x1", "0x2"}


@pytest.mark.parametrize("selection", ["", "--all-threads"])
def test_no_selected_thread_preserves_default_but_all_requires_threads(
    tmp_path: Path, capture_api: Any, selection: str
) -> None:
    process = ThreadProcess([])
    output = tmp_path / "no-threads.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x {selection}", result, {}
    )
    if selection:
        assert "thread count is empty" in (result.error or "")
        assert process.reads == []
        assert not output.exists()
    else:
        assert result.error is None
        assert json.loads(output.read_text())["registers"] == []
        assert process.count_queries == 0


def test_default_without_a_valid_selected_top_frame_still_captures_memory(
    tmp_path: Path, capture_api: Any
) -> None:
    thread = CaptureThread(1)
    thread.frame_valid = False
    process = ThreadProcess([thread])
    output = tmp_path / "no-selected-frame.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x", result, {}
    )
    assert result.error is None
    assert process.reads == [(0x1000, 4)]
    assert json.loads(output.read_text())["registers"] == []
    assert thread.register_queries == []


@pytest.mark.parametrize(
    "issue",
    ["invalid", "frame", "identity", "reason", "duplicate", "wrong-id"],
)
def test_thread_context_validation_cannot_silently_omit_requested_threads(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch, issue: str
) -> None:
    threads = [CaptureThread(1), CaptureThread(2)]
    process = ThreadProcess(threads)
    if issue == "invalid":
        threads[1].valid = False
    elif issue == "frame":
        threads[1].frame_valid = False
    elif issue == "identity":
        threads[1].identity = 0
    elif issue == "reason":
        threads[1].reason = -1
    elif issue == "duplicate":
        threads[1].identity = 1
    else:
        monkeypatch.setattr(process, "GetThreadByID", lambda identity: threads[0])
    selection = "--thread 2" if issue == "wrong-id" else "--all-threads"
    output = tmp_path / "bad-context.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x {selection}", result, {}
    )
    assert result.error is not None
    assert process.reads == []
    assert not output.exists()
    assert all(not thread.register_queries for thread in threads)


@pytest.mark.parametrize("stage", ["memory", "registers", "publication"])
@pytest.mark.parametrize("change", ["reason", "identity", "stopped", "frame"])
def test_thread_context_changes_never_publish_partial_or_mislabelled_registers(
    tmp_path: Path,
    capture_api: Any,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    change: str,
) -> None:
    exporter = load_exporter()
    thread = CaptureThread(1)
    process = ThreadProcess([thread])

    def mutate() -> None:
        if change == "reason":
            thread.reason += 1
        elif change == "identity":
            thread.identity += 1
        elif change == "stopped":
            thread.stopped = False
        else:
            thread.frame_valid = False

    if stage == "memory":

        def read(address: int, size: int, error: ReadError) -> bytes:
            mutate()
            return b"\x00" * size

        monkeypatch.setattr(process, "ReadMemory", read)
    elif stage == "registers":
        original_register = thread.find_register

        def register(name: str) -> Any:
            value = original_register(name)
            mutate()
            return value

        monkeypatch.setattr(thread, "find_register", register)
    else:
        original_dump = exporter.json.dump

        def dump(snapshot: dict[str, Any], stream: Any) -> None:
            original_dump(snapshot, stream)
            mutate()

        monkeypatch.setattr(exporter.json, "dump", dump)
    result = Result()
    output = tmp_path / "changed-thread.json"
    exporter.export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x --thread 1", result, {}
    )
    assert result.error is not None
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "byte_order,address_size,machine",
    [
        (2, 8, "x86_64"),
        (0, 4, "x86_64"),
        (1, 4, "arm"),
        (1, 8, "x86_64"),
    ],
)
def test_unrepresentable_target_context_is_rejected_before_memory_reads(
    tmp_path: Path, capture_api: Any, byte_order: int, address_size: int, machine: str
) -> None:
    process = Process()
    target = debugger(process).GetSelectedTarget()
    target.GetByteOrder = lambda: byte_order
    target.GetAddressByteSize = lambda: address_size
    target.GetTriple = lambda: f"{machine}-unknown-linux"
    result = Result()
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{tmp_path / 'invalid-target.json'} --region 0x1000:4:r-x",
        result,
        {},
    )
    assert result.error is not None
    assert process.reads == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("change", ["byte-order", "address-size", "triple"])
def test_target_context_change_during_capture_is_not_published(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    process = Process()
    target = debugger(process).GetSelectedTarget()

    def read(address: int, size: int, error: ReadError) -> bytes:
        if change == "byte-order":
            target.GetByteOrder = lambda: 1
        elif change == "address-size":
            target.GetAddressByteSize = lambda: 4
        else:
            target.GetTriple = lambda: "arm64-unknown-linux"
        return b"\x00" * size

    monkeypatch.setattr(process, "ReadMemory", read)
    result = Result()
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{tmp_path / 'changed-target.json'} --region 0x1000:4:r-x",
        result,
        {},
    )
    assert "target context changed" in (result.error or "")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "issue", [None, "byte-order", "address-size", "architecture", "permissions"]
)
def test_multiple_modules_and_threads_keep_uuid_slides_and_context_separate(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch, issue: str | None
) -> None:
    process = ThreadProcess([CaptureThread(1), CaptureThread(2)])
    modules = [loaded_module(0x1000), loaded_module(0x3000)]
    uuids = ["0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"]
    modules[1].GetUUIDString = lambda: uuids[1]
    if issue == "byte-order":
        modules[1].GetByteOrder = lambda: 1
    elif issue == "address-size":
        modules[1].GetAddressByteSize = lambda: 4
    elif issue == "architecture":
        modules[1].GetTriple = lambda: "arm64-apple-macosx"

    def mapping(address: int, region: MemoryRegion) -> ReadError:
        region.base = address & ~0xFFF
        region.end = region.base + 0x1000
        if issue == "permissions" and address >= 0x3000:
            region.permissions = "rw-"
        return ReadError()

    monkeypatch.setattr(process, "GetMemoryRegionInfo", mapping)
    target = debugger(process).GetSelectedTarget()
    target.GetNumModules = lambda: len(modules)
    target.GetModuleAtIndex = lambda index: modules[index]
    selections = " ".join(
        f"--module-region {uuid}:0x100000100:4:r-x --module-seed {uuid}:0x100000100"
        for uuid in uuids
    )
    output = tmp_path / "multi-module.json"
    result = Result()
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} {selections} --all-threads",
        result,
        {},
    )
    if issue is not None:
        assert result.error is not None
        assert process.reads == []
        assert not output.exists()
        return
    assert result.error is None
    assert process.reads == [(0x1100, 4), (0x3100, 4)]
    snapshot = json.loads(output.read_text())
    assert snapshot["seeds"] == ["0x1100", "0x3100"]
    assert [metadata["runtime_base"] for metadata in snapshot["modules"]] == [
        "0x1000",
        "0x3000",
    ]
    assert [
        load_exporter().module_identity(metadata["uuid"])
        for metadata in snapshot["modules"]
    ] == uuids
    assert {row["thread_id"] for row in snapshot["registers"]} == {"0x1", "0x2"}
    assert "byte_order" not in snapshot["modules"][0]


@pytest.mark.parametrize("stage", ["memory", "publication"])
@pytest.mark.parametrize(
    "change", ["uuid", "slide", "byte-order", "address-size", "architecture"]
)
def test_changed_module_provenance_is_not_published(
    tmp_path: Path,
    capture_api: Any,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    change: str,
) -> None:
    exporter = load_exporter()
    process = Process()
    target = debugger(process).GetSelectedTarget()
    module = loaded_module()
    target.GetNumModules = lambda: 1
    target.GetModuleAtIndex = lambda index: module

    def mutate() -> None:
        if change == "uuid":
            module.GetUUIDString = lambda: "fedcba9876543210fedcba9876543210"
        elif change == "slide":
            module.GetObjectFileHeaderAddress = lambda: SimpleNamespace(
                GetFileAddress=lambda: 0x100000000, GetLoadAddress=lambda target: 0x2000
            )
        elif change == "byte-order":
            module.GetByteOrder = lambda: 1
        elif change == "address-size":
            module.GetAddressByteSize = lambda: 4
        else:
            module.GetTriple = lambda: "arm64-apple-macosx"

    if stage == "memory":

        def read(address: int, size: int, error: ReadError) -> bytes:
            mutate()
            return b"\x00" * size

        monkeypatch.setattr(process, "ReadMemory", read)
    else:
        original_dump = exporter.json.dump

        def dump(snapshot: dict[str, Any], stream: Any) -> None:
            original_dump(snapshot, stream)
            mutate()

        monkeypatch.setattr(exporter.json, "dump", dump)
    output = tmp_path / "changed-module.json"
    result = Result()
    exporter.export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} --module-region 0123456789abcdef0123456789abcdef:0x100000100:4:r-x",
        result,
        {},
    )
    assert "module" in (result.error or "")
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("selection", ["--all-threads", "--thread 1"])
def test_changed_thread_membership_is_not_published(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch, selection: str
) -> None:
    process = ThreadProcess([CaptureThread(1)])

    def read(address: int, size: int, error: ReadError) -> bytes:
        if selection == "--all-threads":
            process.threads.append(CaptureThread(2))
        else:
            process.threads.clear()
        return b"\x00" * size

    monkeypatch.setattr(process, "ReadMemory", read)
    output = tmp_path / "changed-thread-set.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x {selection}", result, {}
    )
    assert "thread" in (result.error or "")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("issue", ["missing", "failed", "overflow"])
def test_bad_registers_in_a_later_thread_refuse_the_entire_capture(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch, issue: str
) -> None:
    threads = [CaptureThread(1), CaptureThread(2)]
    process = ThreadProcess(threads)
    if issue == "missing":
        threads[1].registers.clear()
    elif issue == "overflow":
        threads[1].registers["rax"] = 2**64
    else:

        def register(name: str) -> Any:
            def value(error: Any) -> int:
                error.Success = lambda: False
                return 0

            return SimpleNamespace(
                IsValid=lambda: name == "rsp", GetValueAsUnsigned=value
            )

        monkeypatch.setattr(threads[1], "find_register", register)
    output = tmp_path / "failed-registers.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x --all-threads", result, {}
    )
    assert result.error is not None
    assert threads[0].register_queries
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "machine,registers",
    [
        ("arm", {"r0": 1, "sp": 0x8000, "pc": 0x1000, "cpsr": 0}),
        ("x86_64", {"rax": 2, "rsp": 0x9000, "rip": 0x1000}),
    ],
)
def test_other_supported_architectures_capture_bounded_named_registers(
    tmp_path: Path, capture_api: Any, machine: str, registers: dict[str, int]
) -> None:
    thread = CaptureThread(1)
    thread.registers = registers
    process = ThreadProcess([thread])
    target = debugger(process).GetSelectedTarget()
    target.GetTriple = lambda: f"{machine}-unknown-linux"
    target.GetAddressByteSize = lambda: 4 if machine == "arm" else 8
    output = tmp_path / "other-registers.json"
    result = Result()
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} --region 0x1000:4:r-x --thread 1",
        result,
        {},
    )
    assert result.error is None
    snapshot = json.loads(output.read_text())
    assert {
        row["name"]: int(row["value"], 16) for row in snapshot["registers"]
    } == registers
    assert all(row["thread_id"] == "0x1" for row in snapshot["registers"])
    assert len(thread.register_queries) <= 34 + 5


def test_multi_thread_export_never_launches_attaches_executes_or_changes_selection(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    threads = [CaptureThread(1), CaptureThread(2)]
    process = ThreadProcess(threads)
    selected_debugger = debugger(process)
    target = selected_debugger.GetSelectedTarget()

    def forbidden(*arguments: Any, **options: Any) -> None:
        pytest.fail("exporter attempted an operation outside stopped read-only capture")

    for receiver, names in [
        (selected_debugger, ["HandleCommand", "SetAsync"]),
        (
            target,
            [
                "Launch",
                "LaunchSimple",
                "Attach",
                "AttachToProcessWithID",
                "EvaluateExpression",
            ],
        ),
        (
            process,
            [
                "Continue",
                "Stop",
                "Kill",
                "Detach",
                "SetSelectedThread",
                "SetSelectedThreadByID",
            ],
        ),
    ]:
        for name in names:
            monkeypatch.setattr(receiver, name, forbidden, raising=False)
    for thread in threads:
        for name in [
            "StepInto",
            "StepOver",
            "StepInstruction",
            "RunToAddress",
            "Resume",
            "Suspend",
        ]:
            monkeypatch.setattr(thread, name, forbidden, raising=False)
        frame = thread.GetFrameAtIndex(0)
        frame.EvaluateExpression = forbidden
        frame.GetValueForVariablePath = forbidden
        monkeypatch.setattr(thread, "GetFrameAtIndex", lambda index, frame=frame: frame)
    output = tmp_path / "readonly.json"
    result = Result()
    load_exporter().export_snapshot(
        selected_debugger, f"{output} --region 0x1000:4:r-x --all-threads", result, {}
    )
    assert result.error is None
    assert process.reads == [(0x1000, 4)]
    assert len(
        {row["thread_id"] for row in json.loads(output.read_text())["registers"]}
    ) == len(threads)


def change_during_publication(
    exporter: Any, monkeypatch: pytest.MonkeyPatch, change: Callable[[], None]
) -> None:
    original_dump = exporter.json.dump

    def dump(snapshot: dict[str, Any], stream: Any) -> None:
        original_dump(snapshot, stream)
        change()

    monkeypatch.setattr(exporter.json, "dump", dump)


@pytest.mark.parametrize("selection", ["", "--thread 1", "--all-threads"])
@pytest.mark.parametrize("status", [None, 1 << 9, 2**32])
def test_arm32_unknown_or_big_endian_cpsr_refuses_capture_before_memory_reads(
    tmp_path: Path, capture_api: Any, selection: str, status: int | None
) -> None:
    thread = CaptureThread(1)
    thread.registers = {"pc": 0x1100, "sp": 0x8100, "r0": 1}
    if status is not None:
        thread.registers["cpsr"] = status
    process = ThreadProcess([thread])
    target = debugger(process).GetSelectedTarget()
    target.GetTriple = lambda: "arm-unknown-linux"
    target.GetAddressByteSize = lambda: 4
    result = Result()
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{tmp_path / 'endian.json'} --region 0x1000:4:r-x {selection}",
        result,
        {},
    )
    assert "CPSR" in (result.error or "")
    assert process.reads == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("missing", ["thread", "frame", "unreadable"])
def test_arm32_default_cannot_guess_data_byte_order_without_readable_status(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    thread = CaptureThread(1)
    thread.registers = {"pc": 0x1100, "sp": 0x8100, "r0": 1}
    thread.registers["cpsr"] = 0
    process = ThreadProcess([] if missing == "thread" else [thread])
    if missing == "frame":
        thread.frame_valid = False
    elif missing == "unreadable":

        def register(name: str) -> Any:
            def value(error: Any) -> int:
                error.Success = lambda: False
                return 0

            return SimpleNamespace(
                IsValid=lambda: name == "cpsr", GetValueAsUnsigned=value
            )

        monkeypatch.setattr(thread, "find_register", register)
    target = debugger(process).GetSelectedTarget()
    target.GetTriple = lambda: "arm-unknown-linux"
    target.GetAddressByteSize = lambda: 4
    result = Result()
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{tmp_path / 'unknown-endian.json'} --region 0x1000:4:r-x",
        result,
        {},
    )
    assert "cpsr" in (result.error or "").lower()
    assert process.reads == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("change", [None, 1 << 9, 1])
def test_arm32_status_changes_at_publication_are_rejected_without_guessing_be8(
    tmp_path: Path,
    capture_api: Any,
    monkeypatch: pytest.MonkeyPatch,
    change: int | None,
) -> None:
    exporter = load_exporter()
    thread = CaptureThread(1)
    thread.registers = {"pc": 0x1100, "sp": 0x8100, "r0": 1}
    thread.registers["cpsr"] = 0
    process = ThreadProcess([thread])
    target = debugger(process).GetSelectedTarget()
    target.GetTriple = lambda: "arm-unknown-linux"
    target.GetAddressByteSize = lambda: 4

    def mutate() -> None:
        if change is None:
            thread.registers.pop("cpsr")
        else:
            thread.registers["cpsr"] = change

    change_during_publication(exporter, monkeypatch, mutate)
    result = Result()
    exporter.export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{tmp_path / 'changed-endian.json'} --region 0x1000:4:r-x --thread 1",
        result,
        {},
    )
    assert result.error is not None
    assert process.reads == [(0x1000, 4)]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("selection", ["--thread 1", "--all-threads"])
@pytest.mark.parametrize("registers", [{"rax": 1}, {"rip": 0x1100}, {"rsp": 0x8100}])
def test_explicit_thread_capture_requires_pc_and_sp_not_any_single_register(
    tmp_path: Path, capture_api: Any, selection: str, registers: dict[str, int]
) -> None:
    thread = CaptureThread(1)
    thread.registers = registers
    process = ThreadProcess([thread])
    result = Result()
    load_exporter().export_snapshot(
        debugger(process),
        f"{tmp_path / 'partial.json'} --region 0x1000:4:r-x {selection}",
        result,
        {},
    )
    assert "missing required core registers" in (result.error or "")
    assert list(tmp_path.iterdir()) == []


def test_legacy_default_still_skips_unsupported_named_registers(
    tmp_path: Path, capture_api: Any
) -> None:
    thread = CaptureThread(1)
    thread.registers = {"rax": 1}
    process = ThreadProcess([thread])
    output = tmp_path / "partial-default.json"
    result = Result()
    load_exporter().export_snapshot(
        debugger(process), f"{output} --region 0x1000:4:r-x", result, {}
    )
    assert result.error is None
    assert json.loads(output.read_text())["registers"] == [
        {"thread_id": "0x1", "name": "rax", "value": "0x1"}
    ]


@pytest.mark.parametrize("selection", ["", "--thread 1", "--all-threads"])
def test_arm32_sparse_default_requires_only_endian_status_but_explicit_capture_needs_core(
    tmp_path: Path, capture_api: Any, selection: str
) -> None:
    thread = CaptureThread(1)
    thread.registers = {"r0": 2, "cpsr": 0}
    process = ThreadProcess([thread])
    target = debugger(process).GetSelectedTarget()
    target.GetTriple = lambda: "arm-unknown-linux"
    target.GetAddressByteSize = lambda: 4
    output = tmp_path / "arm-sparse.json"
    result = Result()
    load_exporter().export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} --region 0x1000:4:r-x {selection}",
        result,
        {},
    )
    if selection:
        assert "missing required core registers" in (result.error or "")
        assert list(tmp_path.iterdir()) == []
    else:
        assert result.error is None
        snapshot = json.loads(output.read_text())
        assert snapshot["big_endian"] is snapshot["data_big_endian"] is False
        assert {row["name"] for row in snapshot["registers"]} == {"r0", "cpsr"}


@pytest.mark.parametrize("change", ["load", "coverage", "image", "unloaded"])
def test_publication_recrawls_selected_sections_even_when_uuid_header_and_stop_are_unchanged(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    exporter = load_exporter()
    process = Process()
    target = debugger(process).GetSelectedTarget()
    module = loaded_module()
    target.GetNumModules = lambda: 1
    target.GetModuleAtIndex = lambda index: module
    section = module.GetSectionAtIndex(0).GetSubSectionAtIndex(0)

    def mutate() -> None:
        if change == "load":
            section.GetLoadAddress = lambda target: 0x9100
        elif change == "coverage":
            section.GetByteSize = lambda: 1
        elif change == "image":
            section.GetFileAddress = lambda: 0x100000200
        else:
            section.GetLoadAddress = lambda target: capture_api.LLDB_INVALID_ADDRESS

    change_during_publication(exporter, monkeypatch, mutate)
    result = Result()
    exporter.export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{tmp_path / 'changed-sections.json'} --module-region 0123456789abcdef0123456789abcdef:0x100000100:4:r-x",
        result,
        {},
    )
    assert "section ranges changed" in (result.error or "")
    assert process.stop_id == 1
    assert process.reads == [(0x1100, 4)]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("budget,accepted", [(3, False), (6, True)])
def test_initial_and_publication_section_inspection_share_one_budget(
    tmp_path: Path,
    capture_api: Any,
    monkeypatch: pytest.MonkeyPatch,
    budget: int,
    accepted: bool,
) -> None:
    exporter = load_exporter()
    monkeypatch.setattr(exporter, "MAX_MODULE_SECTIONS", budget)
    process = Process()
    target = debugger(process).GetSelectedTarget()
    module = loaded_module()
    target.GetNumModules = lambda: 1
    target.GetModuleAtIndex = lambda index: module
    output = tmp_path / "section-budget.json"
    result = Result()
    exporter.export_snapshot(
        SimpleNamespace(GetSelectedTarget=lambda: target),
        f"{output} --module-region 0123456789abcdef0123456789abcdef:0x100000100:4:r-x",
        result,
        {},
    )
    assert output.exists() == accepted
    if not accepted:
        assert "inspection limit" in (result.error or "")
        assert list(tmp_path.iterdir()) == []
    else:
        assert result.error is None


@pytest.mark.parametrize("selection", ["", "--thread 1", "--all-threads"])
@pytest.mark.parametrize("change", ["pc", "sp", "frame-id", "invalid", "core-register"])
def test_publication_uses_fresh_resolved_thread_top_frame_not_retained_valid_objects(
    tmp_path: Path,
    capture_api: Any,
    monkeypatch: pytest.MonkeyPatch,
    selection: str,
    change: str,
) -> None:
    exporter = load_exporter()
    original = CaptureThread(1)
    process = ThreadProcess([original])
    original_frame = original.GetFrameAtIndex(0)

    def mutate() -> None:
        replacement = CaptureThread(1)
        if change == "pc":
            replacement.registers["rip"] = 0x9900
        elif change == "sp":
            replacement.registers["rsp"] = 0xA000
        elif change == "invalid":
            replacement.frame_valid = False
        else:
            frame = replacement.GetFrameAtIndex(0)
            if change == "frame-id":
                frame.GetFrameID = lambda: 1
            else:
                frame.FindRegister = lambda name: SimpleNamespace(
                    IsValid=lambda: True, GetValueAsUnsigned=lambda error: 0x9900
                )
            monkeypatch.setattr(replacement, "GetFrameAtIndex", lambda index: frame)
        process.threads[0] = replacement

    change_during_publication(exporter, monkeypatch, mutate)
    result = Result()
    exporter.export_snapshot(
        debugger(process),
        f"{tmp_path / 'fresh-frame.json'} --region 0x1000:4:r-x {selection}",
        result,
        {},
    )
    assert result.error is not None
    assert original.IsValid() and original_frame.IsValid()
    assert original.GetThreadID() == process.threads[0].GetThreadID() == 1
    assert original.GetStopReason() == process.threads[0].GetStopReason()
    assert process.stop_id == 1
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("change", ["permissions", "unmapped", "unavailable", "bounds"])
def test_publication_revalidates_every_actual_memory_mapping_without_a_stop_change(
    tmp_path: Path, capture_api: Any, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    exporter = load_exporter()
    process = Process()
    final_queries: list[int] = []

    def mutate() -> None:
        def mapping(address: int, region: MemoryRegion) -> Any:
            final_queries.append(address)
            if address == 0x1008:
                if change == "permissions":
                    region.permissions = "r--"
                elif change == "unmapped":
                    region.mapped = False
                elif change == "bounds":
                    region.end = address
                else:
                    return SimpleNamespace(Success=lambda: False)
            return ReadError()

        monkeypatch.setattr(process, "GetMemoryRegionInfo", mapping)

    change_during_publication(exporter, monkeypatch, mutate)
    result = Result()
    exporter.export_snapshot(
        debugger(process),
        f"{tmp_path / 'late-permissions.json'} --region 0x1000:4:r-x --region 0x1008:4:r-x",
        result,
        {},
    )
    assert result.error is not None
    assert process.reads == [(0x1000, 4), (0x1008, 4)]
    assert final_queries == [0x1000, 0x1008]
    assert process.stop_id == 1
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("budget,accepted", [(3, False), (4, True)])
def test_initial_and_publication_mapping_queries_share_one_capture_budget(
    tmp_path: Path,
    capture_api: Any,
    monkeypatch: pytest.MonkeyPatch,
    budget: int,
    accepted: bool,
) -> None:
    exporter = load_exporter()
    monkeypatch.setattr(exporter, "MAX_MEMORY_MAPPING_QUERIES", budget)
    process = Process()
    queries: list[int] = []

    def mapping(address: int, region: MemoryRegion) -> ReadError:
        queries.append(address)
        return ReadError()

    monkeypatch.setattr(process, "GetMemoryRegionInfo", mapping)
    output = tmp_path / "mapping-budget.json"
    result = Result()
    exporter.export_snapshot(
        debugger(process),
        f"{output} --region 0x1000:4:r-x --region 0x1008:4:r-x",
        result,
        {},
    )
    assert len(queries) == budget
    assert queries[:2] == [0x1000, 0x1008]
    assert output.exists() == accepted
    if not accepted:
        assert "mapping query limit" in (result.error or "")
        assert list(tmp_path.iterdir()) == []
    else:
        assert result.error is None
