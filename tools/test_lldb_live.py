from __future__ import annotations

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


def refusal_script(destination: Path, minimum_threads: int, modules: list[Path]) -> str:
    return (
        "from pathlib import Path\n"
        "from typing import Any\n"
        "import shlex\n"
        "import lldb\n"
        "import lldb_snapshot\n"
        "class Guard:\n"
        "    def __init__(self, methods: dict[str, Any]) -> None:\n"
        "        self.methods = methods\n"
        "    def __getattr__(self, name: str) -> Any:\n"
        "        assert name in self.methods, f'exporter attempted forbidden SDK access: {name}'\n"
        "        return self.methods[name]\n"
        "def capture(debugger: Any, command: str, result: Any, internal: dict[str, Any]) -> None:\n"
        "    target = debugger.GetSelectedTarget()\n"
        "    process = target.GetProcess()\n"
        "    assert target.GetTriple().split('-')[0] == 'arm64'\n"
        "    assert target.GetByteOrder() == lldb.eByteOrderLittle\n"
        f"    assert process.GetNumThreads() >= {minimum_threads}\n"
        "    paths = {str(target.GetModuleAtIndex(index).GetFileSpec())\n"
        "             for index in range(target.GetNumModules())}\n"
        f"    assert set({[str(module) for module in modules]!r}) <= paths\n"
        "    def context() -> tuple[Any, ...]:\n"
        "        thread = process.GetSelectedThread()\n"
        "        frame = thread.GetFrameAtIndex(0)\n"
        "        error = lldb.SBError()\n"
        "        status = frame.FindRegister('cpsr').GetValueAsUnsigned(error)\n"
        "        assert error.Success()\n"
        "        return (debugger.GetIndexOfTarget(debugger.GetSelectedTarget()),\n"
        "                process.GetUniqueID(), process.GetProcessID(), process.GetState(),\n"
        "                process.GetStopID(True), process.GetNumThreads(), thread.GetThreadID(),\n"
        "                thread.GetStopReason(), frame.GetPC(), frame.GetSP(), status)\n"
        "    before = context()\n"
        "    assert process.GetState() == lldb.eStateStopped\n"
        "    guarded_process = Guard({'GetState': process.GetState, 'GetStopID': process.GetStopID})\n"
        "    guarded_target = Guard({'GetProcess': lambda: guarded_process,\n"
        "                            'GetTriple': target.GetTriple, 'GetByteOrder': target.GetByteOrder,\n"
        "                            'GetAddressByteSize': target.GetAddressByteSize})\n"
        "    guarded_debugger = Guard({'GetSelectedTarget': lambda: guarded_target})\n"
        f"    destination = Path({str(destination)!r})\n"
        "    files_before = set(destination.parent.iterdir())\n"
        "    def forbidden(*args: Any, **kwargs: Any) -> Any:\n"
        "        raise AssertionError('ARM64 refusal attempted publication')\n"
        "    original_publish = lldb_snapshot.publish_snapshot\n"
        "    lldb_snapshot.publish_snapshot = forbidden\n"
        "    refusal = lldb.SBCommandReturnObject()\n"
        "    try:\n"
        "        lldb_snapshot.export_snapshot(guarded_debugger,\n"
        "            f'{shlex.quote(str(destination))} --region 0x1000:4:r-x --all-threads', refusal, {})\n"
        "    finally:\n"
        "        lldb_snapshot.publish_snapshot = original_publish\n"
        "    assert not refusal.Succeeded()\n"
        "    assert 'current LLDB SDK cannot affirm runtime DATA endianness' in refusal.GetError()\n"
        "    assert not destination.exists()\n"
        "    assert set(destination.parent.iterdir()) == files_before\n"
        "    assert context() == before\n"
        "    result.AppendMessage('ARM64 export refused without reads, publication, or state changes')\n"
        "def __lldb_init_module(debugger: Any, internal: dict[str, Any]) -> None:\n"
        "    debugger.HandleCommand('command script add -f capture_fixture.capture capture-fixture')\n"
    )


@pytest.mark.skipif(
    os.environ.get("RAMPAGE_LLDB_LIVE") != "1",
    reason="opt-in debugger integration on a controlled local ARM64 fixture",
)
def test_stopped_arm64_fixture_refuses_export_without_reads_publication_or_state_changes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "fixture.c"
    executable = tmp_path / "fixture"
    source.write_text("int main(void) { return 42; }\n")
    subprocess.run(
        ["clang", "-arch", "arm64", "-g", "-O0", str(source), "-o", str(executable)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    root = Path(__file__).resolve().parents[1]
    snapshot_path = tmp_path / "capture.json"
    capture = tmp_path / "capture_fixture.py"
    capture.write_text(refusal_script(snapshot_path, 1, [executable]))
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
    assert "ARM64 export refused without reads, publication, or state changes" in output
    assert not snapshot_path.exists(), output


@pytest.mark.skipif(
    os.environ.get("RAMPAGE_LLDB_LIVE") != "1",
    reason="opt-in debugger integration on a controlled local ARM64 fixture",
)
def test_stopped_owned_arm64_two_module_fixture_refuses_export_with_all_threads(
    tmp_path: Path,
) -> None:
    library_source = tmp_path / "fixture_library.c"
    library = tmp_path / "libfixture.dylib"
    library_source.write_text(
        "__attribute__((noinline)) int capture_ready(void) { return 42; }\n"
    )
    source = tmp_path / "fixture_multi.c"
    executable = tmp_path / "fixture_multi"
    source.write_text(
        "#include <pthread.h>\n"
        "#include <stdatomic.h>\n"
        "extern int capture_ready(void);\n"
        "static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;\n"
        "static atomic_int ready;\n"
        "static void *worker(void *unused) {\n"
        "    atomic_store(&ready, 1);\n"
        "    pthread_mutex_lock(&gate);\n"
        "    pthread_mutex_unlock(&gate);\n"
        "    return 0;\n"
        "}\n"
        "int main(void) {\n"
        "    pthread_t thread;\n"
        "    pthread_mutex_lock(&gate);\n"
        "    if (pthread_create(&thread, 0, worker, 0)) return 1;\n"
        "    while (!atomic_load(&ready)) {}\n"
        "    int value = capture_ready();\n"
        "    pthread_mutex_unlock(&gate);\n"
        "    pthread_join(thread, 0);\n"
        "    return value;\n"
        "}\n"
    )
    subprocess.run(
        [
            "clang",
            "-arch",
            "arm64",
            "-g",
            "-O0",
            "-dynamiclib",
            str(library_source),
            "-install_name",
            str(library),
            "-o",
            str(library),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        [
            "clang",
            "-arch",
            "arm64",
            "-g",
            "-O0",
            "-pthread",
            str(source),
            str(library),
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    root = Path(__file__).resolve().parents[1]
    output_path = tmp_path / "multi-capture.json"
    capture = tmp_path / "capture_fixture.py"
    capture.write_text(refusal_script(output_path, 2, [executable, library]))
    commands = [
        "settings set target.disable-aslr false",
        "breakpoint set -n capture_ready",
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
        ]
    )
    assert status == 0, output
    assert "ARM64 export refused without reads, publication, or state changes" in output
    assert not output_path.exists(), output


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
