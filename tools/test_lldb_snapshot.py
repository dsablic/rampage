from __future__ import annotations

import importlib.util
import json
import sys
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

    def GetMemoryRegionInfo(self, address: int, region: MemoryRegion) -> ReadError:
        return ReadError()

    def ReadMemory(self, address: int, size: int, error: ReadError) -> bytes:
        self.reads.append((address, size))
        return b"\xc0\x03\x5f\xd6"[:size]


def debugger(process: Process) -> Any:
    target = SimpleNamespace(
        GetProcess=lambda: process,
        GetTriple=lambda: "arm64-apple-macosx",
        GetByteOrder=lambda: 0,
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
    assert snapshot["regions"][0]["bytes"] == "c0035fd6"
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
            LLDB_INVALID_ADDRESS=2**64 - 1,
        ),
    )
    process = Process()
    frame = SimpleNamespace(
        IsValid=lambda: True,
        FindRegister=lambda name: SimpleNamespace(
            IsValid=lambda: name == "sp",
            GetValueAsUnsigned=lambda error: 0x8000,
        ),
    )
    thread = SimpleNamespace(
        IsValid=lambda: True,
        GetFrameAtIndex=lambda index: frame,
        GetThreadID=lambda: 1,
    )
    filespec = SimpleNamespace(GetFilename=lambda: "fixture")
    module = SimpleNamespace(
        GetObjectFileHeaderAddress=lambda: SimpleNamespace(
            GetLoadAddress=lambda target: 0x1000,
            GetFileAddress=lambda: 0,
        ),
        GetUUIDString=lambda: "fixture-uuid",
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
        ),
        GetTriple=lambda: "arm64-apple-macosx",
        GetByteOrder=lambda: 0,
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
        {"thread_id": "0x1", "name": "sp", "value": "0x8000"}
    ]

    def failed_register(error: Any) -> int:
        error.Success = lambda: False
        return 0

    frame.FindRegister = lambda name: SimpleNamespace(
        IsValid=lambda: name == "sp",
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
    assert queries == [0x1000, 0x1002]
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
        SimpleNamespace(SBError=ReadError, eStateStopped=1, eByteOrderBig=1),
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
