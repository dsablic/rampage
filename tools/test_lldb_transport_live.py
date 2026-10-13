from __future__ import annotations

import json
import os
import shlex
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from test_lldb_transport import exchange, receive_response, request

pytestmark = pytest.mark.skipif(
    os.environ.get("RAMPAGE_LLDB_TRANSPORT_LIVE") != "1",
    reason="opt-in local LLDB transport integration using only a freshly compiled owned native fixture",
)


def initial_query(path: Path, process: subprocess.Popen[str]) -> dict[str, Any]:
    deadline = time.monotonic() + 15
    pause = threading.Event()
    while True:
        if process.poll() is not None:
            output, _ = process.communicate(timeout=1)
            pytest.fail(f"owned fixture LLDB exited before binding: {output}")
        if time.monotonic() >= deadline:
            pytest.fail(
                "owned fixture LLDB did not accept the initial query within startup deadline"
            )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(min(5, deadline - time.monotonic()))
            try:
                connection.connect(str(path))
            except (FileNotFoundError, ConnectionRefusedError):
                pause.wait(0.01)
                continue
            connection.sendall(request())
            connection.shutdown(socket.SHUT_WR)
            return receive_response(connection)


def test_owned_stopped_native_fixture_serves_queries_closes_listener_and_retains_endpoint(
    tmp_path: Path,
) -> None:
    source = tmp_path / "transport_fixture.c"
    executable = tmp_path / "transport_fixture"
    source.write_text(
        "volatile unsigned char transport_bytes[4] = {0x12, 0x34, 0x56, 0x78};\n"
        "int main(void) { return transport_bytes[0]; }\n"
    )
    subprocess.run(
        ["clang", "-g", "-O0", str(source), "-o", str(executable)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    checks = tmp_path / "transport_checks.py"
    metadata_path = tmp_path / "metadata.json"
    checks.write_text(
        "import json\n"
        "import os\n"
        "import signal\n"
        "import subprocess\n"
        "from types import SimpleNamespace\n"
        "import lldb\n"
        "import lldb_bridge\n"
        "before = None\n"
        "def identity(debugger):\n"
        "    process = debugger.GetSelectedTarget().GetProcess()\n"
        "    return process.GetUniqueID(), process.GetStopID(True), process.GetState()\n"
        "def record(debugger, command, result, internal):\n"
        "    global before\n"
        "    before = identity(debugger)\n"
        "    assert before[2] == lldb.eStateStopped\n"
        "    target = debugger.GetSelectedTarget()\n"
        "    process = target.GetProcess()\n"
        "    metadata = dict(thread_id=process.GetSelectedThread().GetThreadID(),\n"
        "                    address=hex(target.FindFirstGlobalVariable('transport_bytes').GetLoadAddress()))\n"
        f"    with open({str(metadata_path)!r}, 'w') as destination:\n"
        "        json.dump(metadata, destination)\n"
        "def verify(debugger, command, result, internal):\n"
        "    assert before == identity(debugger), (before, identity(debugger))\n"
        "    result.AppendMessage('owned transport identity unchanged')\n"
        "def interrupted_launch(debugger, command, result, internal):\n"
        "    original_spawn = subprocess.Popen\n"
        "    original_handler = signal.getsignal(signal.SIGINT)\n"
        "    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())\n"
        "    helpers, messages, errors = [], [], []\n"
        "    def spawn(*arguments, **options):\n"
        "        process = original_spawn(*arguments, **options)\n"
        "        helpers.append(process)\n"
        "        os.kill(os.getpid(), signal.SIGINT)\n"
        "        return process\n"
        "    subprocess.Popen = spawn\n"
        "    try:\n"
        "        response = SimpleNamespace(AppendMessage=messages.append, SetError=errors.append)\n"
        "        lldb_bridge.serve(debugger, command, response, {})\n"
        "    finally:\n"
        "        subprocess.Popen = original_spawn\n"
        "    assert len(messages) == 1 and 'interrupted' in messages[0] and not errors, (messages, errors)\n"
        "    assert len(helpers) == 1 and helpers[0].poll() is not None\n"
        "    try:\n"
        "        os.waitpid(helpers[0].pid, os.WNOHANG)\n"
        "    except ChildProcessError:\n"
        "        pass\n"
        "    else:\n"
        "        raise AssertionError('interrupted helper was not reaped')\n"
        "    assert signal.getsignal(signal.SIGINT) is original_handler\n"
        "    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask\n"
        "    assert before == identity(debugger)\n"
        "    result.AppendMessage('owned transport interrupted launch reaped and signal policy restored')\n"
        "def __lldb_init_module(debugger, internal):\n"
        "    debugger.HandleCommand('command script add -f transport_checks.record transport-before')\n"
        "    debugger.HandleCommand('command script add -f transport_checks.verify transport-after')\n"
        "    debugger.HandleCommand('command script add -f transport_checks.interrupted_launch transport-interrupt')\n"
    )
    root = Path(tempfile.gettempdir()).resolve()
    if (root / "opencode").is_dir():
        root /= "opencode"
    with tempfile.TemporaryDirectory(prefix="rq-", dir=root) as directory:
        private = Path(directory)
        private.chmod(0o700)
        path = private / "q.sock"
        bridge_path = Path(__file__).with_name("lldb_bridge.py").resolve()
        commands = [
            "settings set target.disable-aslr false",
            "breakpoint set -n main",
            "run",
            f"command script import {shlex.quote(str(bridge_path))}",
            f"command script import {shlex.quote(str(checks))}",
            "transport-before",
            f"rampage-query-serve --socket {shlex.quote(str(path))} --max-requests 8 --idle-timeout-ms 5000",
            (
                f"rampage-query-serve --socket {shlex.quote(str(private / 'idle.sock'))} "
                "--max-requests 1 --idle-timeout-ms 1"
            ),
            f"transport-interrupt --socket {shlex.quote(str(private / 'int.sock'))} --idle-timeout-ms 1",
            "transport-after",
            "process kill",
        ]
        process = subprocess.Popen(
            [
                "lldb",
                "--batch",
                *[part for command in commands for part in ("-o", command)],
                str(executable),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            session = initial_query(path, process)
            metadata: dict[str, Any] = json.loads(metadata_path.read_text())
            assert session["ok"], session
            expected = session["token"]
            thread_id = metadata["thread_id"]
            for operation, fields in (
                ("list_modules", {"limit": 1}),
                ("list_threads", {"limit": 1}),
                (
                    "read_registers",
                    {
                        "thread_id": thread_id,
                        "registers": [
                            "rip"
                            if session["data"]["architecture"] == "x86_64"
                            else "pc"
                        ],
                    },
                ),
                (
                    "read_memory",
                    {"address": metadata["address"], "size": 4, "permissions": "rw-"},
                ),
            ):
                response = exchange(
                    path, request(operation, expected_token=expected, **fields)
                )
                assert response["ok"] and response["token"] == expected, response
                assert response["observation"]["atomic_snapshot"] is False
                if operation == "read_memory":
                    assert response["data"]["bytes_hex"] == "12345678"
            stale = dict(expected, stop_id=expected["stop_id"] + 1)
            failure = exchange(path, request("list_threads", expected_token=stale))
            assert failure["ok"] is False and failure["error"]["code"] == "stale_token"
            assert exchange(path, request("continue"))["ok"] is False
            assert exchange(path, request() + request())["ok"] is False
            output, _ = process.communicate(timeout=15)
            assert process.returncode == 0, output
            assert "owned transport identity unchanged" in output, output
            assert (
                "owned transport interrupted launch reaped and signal policy restored"
                in output
            ), output
            assert "8 accepted connections" in output, output
            assert "0 accepted connections" in output, output
            assert path.exists()
            assert (private / "idle.sock").exists()
            assert "endpoint retained for operator cleanup" in output, output
            for endpoint in (path, private / "idle.sock", private / "int.sock"):
                assert stat.S_IMODE(endpoint.lstat().st_mode) == 0o600
                with (
                    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection,
                    pytest.raises(ConnectionRefusedError),
                ):
                    connection.connect(str(endpoint))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
