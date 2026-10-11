from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
from pathlib import Path
from typing import Any

import pytest


def run_lldb(arguments: list[str]) -> tuple[int, str]:
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
    assert process.returncode is not None
    return process.returncode, output


@pytest.mark.skipif(
    os.environ.get("RAMPAGE_LLDB_LIVE") != "1",
    reason="opt-in debugger integration on a controlled local ARM64 fixture",
)
def test_stopped_fixture_exports_runtime_metadata_and_correlates_original(
    tmp_path: Path,
) -> None:
    source = tmp_path / "fixture.c"
    executable = tmp_path / "fixture"
    source.write_text("int main(void) { return 42; }\n")
    subprocess.run(
        ["clang", "-g", "-O0", str(source), "-o", str(executable)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    root = Path(__file__).resolve().parents[1]
    snapshot_path = tmp_path / "capture.json"
    capture = tmp_path / "capture_fixture.py"
    export_command = f"rampage-snapshot {shlex.quote(str(snapshot_path))} "
    capture.write_text(
        "from typing import Any\n"
        "def capture(\n"
        "    debugger: Any, command: str, result: Any, internal: dict[str, Any]\n"
        ") -> None:\n"
        "    target = debugger.GetSelectedTarget()\n"
        "    context = target.FindFunctions('main').GetContextAtIndex(0)\n"
        "    function = context.GetFunction()\n"
        "    start = function.GetStartAddress().GetLoadAddress(target)\n"
        "    end = function.GetEndAddress().GetLoadAddress(target)\n"
        f"    destination = {export_command!r}\n"
        "    region = f'--region {start:#x}:{end-start}:r-x --seed {start:#x}'\n"
        "    debugger.HandleCommand(destination + region)\n"
        "def __lldb_init_module(debugger: Any, internal: dict[str, Any]) -> None:\n"
        "    debugger.HandleCommand(\n"
        "        'command script add -f capture_fixture.capture capture-fixture')\n"
    )
    commands = [
        "settings set target.disable-aslr false",
        "breakpoint set -n main",
        "run",
        f"command script import {shlex.quote(str(root / 'tools/lldb_snapshot.py'))}",
        f"command script import {shlex.quote(str(capture))}",
        "capture-fixture",
        "process kill",
    ]
    status, output = run_lldb(
        [
            "lldb",
            "--batch",
            *[part for command in commands for part in ("-o", command)],
            str(executable),
        ],
    )
    assert status == 0, output
    assert snapshot_path.is_file(), output
    snapshot = json.loads(snapshot_path.read_text())
    assert snapshot["arch"] == "aarch64"
    assert snapshot["target"]["platform"] == "darwin"
    seed = snapshot["seeds"][0]
    registers = {
        register["name"]: int(register["value"], 16)
        for register in snapshot["registers"]
    }
    assert (
        int(seed, 16)
        <= registers["pc"]
        < int(seed, 16) + len(bytes.fromhex(snapshot["regions"][0]["bytes"]))
    )
    assert registers["sp"] != 0
    module = next(
        module for module in snapshot["modules"] if module["name"] == "fixture"
    )
    cli = os.environ.get("RAMPAGE_CLI", str(root / "target/debug/rampage"))
    summary_output = subprocess.run(
        [str(cli), "--json", "summarize", str(snapshot_path), "--at", seed],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    summary = json.loads(summary_output.stdout)
    assert summary["ir"] and all(
        instruction["complete"] for instruction in summary["ir"]
    )
    assert summary["ssa"]["blocks"]
    correlation_output = subprocess.run(
        [
            str(cli),
            "--json",
            "correlate",
            str(snapshot_path),
            "--original",
            str(executable),
            "--module",
            module["uuid"],
            "--at",
            seed,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    correlation = json.loads(correlation_output.stdout)
    assert int(correlation["image_address"], 16) == int(seed, 16) - int(
        module["runtime_base"], 16
    ) + int(module["image_base"], 16)


@pytest.mark.parametrize("failure", [KeyboardInterrupt, subprocess.TimeoutExpired])
def test_lldb_failures_terminate_and_reap_the_session(
    monkeypatch: pytest.MonkeyPatch,
    failure: type[BaseException],
) -> None:
    class Process:
        pid = 123
        returncode: int | None = None
        calls = 0

        def communicate(self, timeout: int | None = None) -> tuple[str, None]:
            self.calls += 1
            if self.calls == 1:
                if failure is subprocess.TimeoutExpired:
                    assert timeout is not None
                    raise subprocess.TimeoutExpired("lldb", timeout)
                raise KeyboardInterrupt()
            self.returncode = -9
            return "", None

        def poll(self) -> int | None:
            return self.returncode

    process = Process()
    terminated: list[int] = []

    def launch(*arguments: Any, **options: Any) -> Process:
        return process

    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(os, "killpg", lambda pid, sig: terminated.append(pid))
    with pytest.raises(failure):
        run_lldb(["lldb"])
    assert terminated == [process.pid]
    assert process.calls == 2
    assert process.returncode == -9
