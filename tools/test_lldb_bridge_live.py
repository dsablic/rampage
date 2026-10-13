from __future__ import annotations

import os
import shlex
import signal
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RAMPAGE_LLDB_BRIDGE_LIVE") != "1",
    reason="opt-in LLDB bridge integration using only a freshly compiled owned fixture",
)


def run_lldb(arguments: list[str]) -> tuple[int, str]:
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    try:
        output, _ = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
    assert process.returncode is not None
    return process.returncode, output


def test_owned_stopped_fixture_registered_json_operations(tmp_path: Path) -> None:
    source, executable = tmp_path / "bridge_fixture.c", tmp_path / "bridge_fixture"
    source.write_text(
        "volatile unsigned char bridge_bytes[4] = {0x12, 0x34, 0x56, 0x78};\n"
        "int main(void) { return bridge_bytes[0]; }\n"
    )
    subprocess.run(
        ["clang", "-g", "-O0", str(source), "-o", str(executable)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    bridge_path = Path(__file__).with_name("lldb_bridge.py").resolve()
    checks = tmp_path / "bridge_checks.py"
    checks.write_text(
        "import json\n"
        "import lldb\n"
        "import lldb_bridge\n"
        "def checks(debugger, command, result, internal):\n"
        "    interpreter = debugger.GetCommandInterpreter()\n"
        "    def send(operation, **fields):\n"
        "        response = lldb.SBCommandReturnObject()\n"
        "        request = json.dumps(dict(version=1, operation=operation, **fields))\n"
        "        interpreter.HandleCommand('rampage-query ' + request, response)\n"
        "        assert response.Succeeded(), response.GetError()\n"
        "        return json.loads(response.GetOutput())\n"
        "    session = send('describe_session')\n"
        "    assert session['ok'], session\n"
        "    token = session['token']\n"
        "    process = debugger.GetSelectedTarget().GetProcess()\n"
        "    before = (process.GetUniqueID(), process.GetStopID(True), process.GetState())\n"
        "    assert token['process_unique_id'] == before[0]\n"
        "    assert token['stop_id'] == before[1]\n"
        "    modules = send('list_modules', expected_token=token, limit=1)\n"
        "    assert modules['ok'] and len(modules['data']['items']) == 1, modules\n"
        "    threads = send('list_threads', expected_token=token, limit=1)\n"
        "    assert threads['ok'] and threads['data']['items'], threads\n"
        "    thread = process.GetSelectedThread()\n"
        "    registers = send('read_registers', expected_token=token, thread_id=thread.GetThreadID(),\n"
        "                     registers=['pc'] if session['data']['architecture'] != 'x86_64' else ['rip'])\n"
        "    assert thread.GetStopReason() == lldb.eStopReasonBreakpoint\n"
        "    assert registers['ok'], registers\n"
        "    evidence = registers['data']['context']['stop_evidence']\n"
        "    assert evidence['is_stopped'] == thread.IsStopped()\n"
        "    assert evidence['stop_reason'] == lldb.eStopReasonBreakpoint\n"
        "    assert evidence['source'] == ('SBThread.IsStopped' if thread.IsStopped() else\n"
        "                                  'SBThread.GetStopReason/current-process-stop')\n"
        "    frame = thread.GetFrameAtIndex(0)\n"
        "    context = registers['data']['context']\n"
        "    assert int(context['pc'], 16) == frame.GetPC()\n"
        "    assert int(context['sp'], 16) == frame.GetSP()\n"
        "    assert all(name in context['registers'] for name in registers['data']['required_registers'])\n"
        "    target = debugger.GetSelectedTarget()\n"
        "    location = target.FindFirstGlobalVariable('bridge_bytes').GetLoadAddress()\n"
        "    lldb_bridge.require_permission_description_support(lldb)\n"
        "    unknown = lldb.SBMemoryRegionInfo()\n"
        "    denied = lldb.SBMemoryRegionInfo('owned SDK check', 0x1000, 0x2000,\n"
        "                                      lldb.ePermissionsReadable, True)\n"
        "    assert not unknown.IsWritable() and not denied.IsWritable()\n"
        "    assert not unknown.IsExecutable() and not denied.IsExecutable()\n"
        "    assert lldb_bridge.known_permissions(denied, lldb) == 'r--'\n"
        "    try:\n"
        "        lldb_bridge.known_permissions(unknown, lldb)\n"
        "    except lldb_bridge.QueryError as error:\n"
        "        assert error.code == 'unavailable'\n"
        "    else:\n"
        "        raise AssertionError('SDK unknown permissions were accepted as known No')\n"
        "    region = lldb.SBMemoryRegionInfo()\n"
        "    assert process.GetMemoryRegionInfo(location, region).Success()\n"
        "    assert lldb_bridge.known_permissions(region, lldb) == 'rw-'\n"
        "    memory = send('read_memory', expected_token=token, address=hex(location), size=4, permissions='rw-')\n"
        "    assert memory['ok'] and memory['data']['bytes_hex'] == '12345678', memory\n"
        "    assert memory['observation']['atomic_snapshot'] is False\n"
        "    contextual = send('read_memory', expected_token=token, address=hex(location), size=4,\n"
        "                      permissions='rw-', thread_id=thread.GetThreadID())\n"
        "    assert contextual['ok'] and contextual['data']['bytes_hex'] == '12345678', contextual\n"
        "    assert contextual['data']['stop_evidence'] == evidence\n"
        "    stale = dict(token, stop_id=token['stop_id'] + 1)\n"
        "    failure = send('read_memory', expected_token=stale, address=hex(location), size=4, permissions='rw-')\n"
        "    assert not failure['ok'] and failure['error']['code'] == 'stale_token', failure\n"
        "    failure = send('continue', expected_token=token)\n"
        "    assert not failure['ok'] and failure['error']['code'] == 'invalid_request', failure\n"
        "    assert before == (process.GetUniqueID(), process.GetStopID(True), process.GetState())\n"
        "    result.AppendMessage('owned bridge checks passed')\n"
        "    result.AppendMessage('owned bridge stop evidence: ' + json.dumps(evidence))\n"
        "def __lldb_init_module(debugger, internal):\n"
        "    debugger.HandleCommand('command script add -f bridge_checks.checks bridge-checks')\n"
    )
    commands = [
        "settings set target.disable-aslr false",
        "breakpoint set -n main",
        "run",
        f"command script import {shlex.quote(str(bridge_path))}",
        f"command script import {shlex.quote(str(checks))}",
        "bridge-checks",
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
    assert "owned bridge checks passed" in output, output
    evidence = next(
        line
        for line in output.splitlines()
        if line.startswith("owned bridge stop evidence: ")
    )
    print(evidence)
