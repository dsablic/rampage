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


class Process:
    state: int = 1
    reads: list[tuple[int, int]]

    def __init__(self) -> None:
        self.reads = []

    def GetState(self) -> int:
        return self.state

    def GetProcessID(self) -> int:
        return 123

    def GetSelectedThread(self) -> Any:
        return SimpleNamespace(IsValid=lambda: False)

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
        SimpleNamespace(SBError=ReadError, eStateStopped=1, eByteOrderBig=1),
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
    exporter.export_snapshot(debugger(process), command, result, {})
    assert result.error is not None
    assert json.loads(output.read_text()) == snapshot


def test_export_rejects_running_process_without_reading_memory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(SBError=ReadError, eStateStopped=1, eByteOrderBig=1),
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
            GetProcessID=process.GetProcessID,
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
        SimpleNamespace(SBError=ReadError, eStateStopped=1, eByteOrderBig=1),
    )
    process = Process()
    result = Result()
    output = tmp_path / "capture.json"
    command = f"{output} {arguments}" if arguments else ""
    load_exporter().export_snapshot(debugger(process), command, result, {})
    assert result.error is not None
    assert not output.exists()
    assert process.reads == []
