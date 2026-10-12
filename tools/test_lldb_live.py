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
        "    module = context.GetModule()\n"
        "    uuid = module.GetUUIDString()\n"
        "    image = function.GetStartAddress().GetFileAddress()\n"
        f"    destination = {export_command!r}\n"
        "    region = f'--module-region {uuid}:{image:#x}:{end-start}:r-x --module-seed {uuid}:{image:#x}'\n"
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
    comparison_output = subprocess.run(
        [
            str(cli),
            "--json",
            "compare-runtime",
            str(snapshot_path),
            "--original",
            str(executable),
            "--module",
            module["uuid"],
            "--range",
            f"{seed}:4",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    comparison = json.loads(comparison_output.stdout)
    assert comparison["requested_bytes"] == comparison["equal_bytes"] == 4
    assert comparison["changed_bytes"] == comparison["unavailable_bytes"] == 0
    assert comparison["original_image_sha256"]


@pytest.mark.skipif(
    os.environ.get("RAMPAGE_LLDB_LIVE") != "1",
    reason="opt-in debugger integration on a controlled local ARM64 fixture",
)
def test_stopped_owned_fixture_captures_two_modules_and_all_threads(
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
    expected_path = tmp_path / "expected-context.json"
    capture = tmp_path / "capture_multi.py"
    destination = f"rampage-snapshot {shlex.quote(str(output_path))} --all-threads"
    capture.write_text(
        "import json\n"
        "from pathlib import Path\n"
        "from typing import Any\n"
        "def capture(debugger: Any, command: str, result: Any, internal: dict[str, Any]) -> None:\n"
        "    target = debugger.GetSelectedTarget()\n"
        f"    arguments = [{destination!r}]\n"
        "    seeds = []\n"
        "    for name in ('main', 'capture_ready'):\n"
        "        context = target.FindFunctions(name).GetContextAtIndex(0)\n"
        "        function = context.GetFunction()\n"
        "        image = function.GetStartAddress().GetFileAddress()\n"
        "        size = function.GetEndAddress().GetFileAddress() - image\n"
        "        uuid = context.GetModule().GetUUIDString()\n"
        "        seeds.append(hex(function.GetStartAddress().GetLoadAddress(target)))\n"
        "        arguments.append(f'--module-region {uuid}:{image:#x}:{size}:r-x')\n"
        "        arguments.append(f'--module-seed {uuid}:{image:#x}')\n"
        "    process = target.GetProcess()\n"
        "    threads = [hex(process.GetThreadAtIndex(index).GetThreadID())\n"
        "               for index in range(process.GetNumThreads())]\n"
        f"    Path({str(expected_path)!r}).write_text(json.dumps({{'seeds': seeds, 'threads': threads}}))\n"
        "    debugger.HandleCommand(' '.join(arguments))\n"
        "def __lldb_init_module(debugger: Any, internal: dict[str, Any]) -> None:\n"
        "    debugger.HandleCommand('command script add -f capture_multi.capture capture-multi')\n"
    )
    commands = [
        "settings set target.disable-aslr false",
        "breakpoint set -n capture_ready",
        "run",
        f"command script import {shlex.quote(str(root / 'tools/lldb_snapshot.py'))}",
        f"command script import {shlex.quote(str(capture))}",
        "capture-multi",
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
    assert output_path.is_file(), output
    snapshot = json.loads(output_path.read_text())
    expected = json.loads(expected_path.read_text())
    assert snapshot["arch"] == "aarch64"
    assert len(snapshot["regions"]) == len(snapshot["seeds"]) == 2
    assert snapshot["seeds"] == expected["seeds"]
    owned_modules = [
        module
        for module in snapshot["modules"]
        if module["path"] in {str(executable), str(library)}
    ]
    assert len(owned_modules) == 2
    assert len({module["uuid"] for module in owned_modules}) == 2
    for seed in snapshot["seeds"]:
        assert (
            sum(
                int(region["address"], 16)
                <= int(seed, 16)
                < int(region["address"], 16) + len(bytes.fromhex(region["bytes"]))
                for region in snapshot["regions"]
            )
            == 1
        )
    threads = {register["thread_id"] for register in snapshot["registers"]}
    assert len(threads) == 2
    assert threads == set(expected["threads"])
    for thread in threads:
        registers = {
            register["name"]: int(register["value"], 16)
            for register in snapshot["registers"]
            if register["thread_id"] == thread
        }
        assert registers["pc"] != 0 and registers["sp"] != 0
        assert f"{thread} (stop reason " in snapshot["provenance"]
    assert "software-breakpoint traps normalized" in snapshot["provenance"]


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
