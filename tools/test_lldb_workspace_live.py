from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import textwrap
from pathlib import Path

import pytest
from test_lldb_live import run_lldb


@pytest.mark.skipif(
    os.environ.get("RAMPAGE_LLDB_WORKSPACE_LIVE") != "1",
    reason="opt-in owned x86_64 Darwin fixture and real offscreen debugger workspace controls",
)
def test_owned_x86_64_stopped_fixture_through_workspace_controls(
    tmp_path: Path,
) -> None:
    ui_test = Path(os.environ["RAMPAGE_UI_LIVE_TEST_BIN"]).resolve(strict=True)
    assert ui_test.is_file() and os.access(ui_test, os.X_OK)
    source = tmp_path / "transport_fixture.c"
    executable = tmp_path / "transport_fixture"
    source.write_text(
        "volatile unsigned char transport_bytes[4] = {0x12, 0x34, 0x56, 0x78};\n"
        "int main(void) { return transport_bytes[0]; }\n"
    )
    subprocess.run(
        ["clang", "-arch", "x86_64", "-g", "-O0", str(source), "-o", str(executable)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    temporary_root = Path(tempfile.gettempdir()).resolve()
    if (temporary_root / "opencode").is_dir():
        temporary_root /= "opencode"
    with tempfile.TemporaryDirectory(prefix="rw-", dir=temporary_root) as directory:
        private = Path(directory)
        private.chmod(0o700)
        endpoint = private / "q.sock"
        output = private / "workspace.capture.json"
        checks = tmp_path / "workspace_checks.py"
        checks.write_text(
            "import json\nimport os\nimport subprocess\nimport threading\n"
            "from pathlib import Path\nimport lldb\nimport lldb_bridge\n"
            "import lldb_transport\n"
            + textwrap.dedent(
                f"""
                def exercise(debugger, command, result, internal):
                    target = debugger.GetSelectedTarget()
                    process = target.GetProcess()
                    try:
                        assert process.IsValid() and process.GetState() == lldb.eStateStopped, (
                            'Owned x86_64 fixture did not stop; Rosetta/debugserver availability is required')
                        assert target.GetTriple().split('-')[0] == 'x86_64'
                        assert target.GetByteOrder() == lldb.eByteOrderLittle
                        before = (process.GetUniqueID(), process.GetStopID(True), process.GetState())
                        context = target.FindFunctions('main').GetContextAtIndex(0)
                        function = context.GetFunction()
                        address = function.GetStartAddress()
                        size = function.GetEndAddress().GetFileAddress() - address.GetFileAddress()
                        assert 4 <= size <= 4096
                        module = context.GetModule()
                        assert module.IsValid() and module.GetUUIDString()
                        assert module.GetByteOrder() == lldb.eByteOrderLittle
                        assert module.GetAddressByteSize() == target.GetAddressByteSize() == 8
                        thread = process.GetSelectedThread()
                        error = lldb.SBError()
                        expected_bytes = process.ReadMemory(address.GetLoadAddress(target), 4, error)
                        assert error.Success() and len(expected_bytes) == 4
                        module_index = next(index for index in range(target.GetNumModules())
                                            if target.GetModuleAtIndex(index) == module)
                        assert module_index < 32, 'Owned executable must be in the explicitly requested first page'
                        header = module.GetObjectFileHeaderAddress()
                        metadata = dict(
                            source={str(executable)!r}, socket={str(endpoint)!r}, output={str(output)!r},
                            module_index=module_index, module_name=module.GetFileSpec().GetFilename(),
                            module_uuid=module.GetUUIDString(), module_triple=module.GetTriple(),
                            runtime_base=hex(header.GetLoadAddress(target)),
                            image_base=hex(header.GetFileAddress()),
                            file_address=hex(address.GetFileAddress()),
                            load_address=hex(address.GetLoadAddress(target)), bytes_hex=expected_bytes.hex(),
                            thread_id=thread.GetThreadID(), stop_reason=thread.GetStopReason(),
                            is_stopped=thread.IsStopped(), stop_id=process.GetStopID(True))
                        requests, outcomes = [], []
                        def query(encoded):
                            requests.append(json.loads(encoded))
                            return lldb_bridge.query_json(debugger, encoded, lldb)
                        def preflight():
                            lldb_bridge.QueryContext(debugger, lldb, None).verify()
                        def client():
                            try:
                                outcomes.append(subprocess.run(
                                    [{str(ui_test)!r}, '--ignored', '--exact',
                                     'owned_lldb_workspace_connect_inspect_prepare_compare_save_open',
                                     '--nocapture', '--test-threads=1'],
                                    env={{**os.environ, 'RAMPAGE_LLDB_WORKSPACE_LIVE': '1',
                                         'RAMPAGE_LLDB_WORKSPACE_METADATA': json.dumps(metadata)}},
                                    capture_output=True, text=True, timeout=15))
                            except Exception as error:
                                outcomes.append(error)
                        worker = threading.Thread(target=client)
                        try:
                            accepted = lldb_transport.run_server(
                                {str(endpoint)!r}, query, preflight, max_requests=128,
                                idle_timeout_ms=5000, ready=worker.start)
                        finally:
                            if worker.ident is not None:
                                worker.join(16)
                        assert not worker.is_alive() and len(outcomes) == 1
                        outcome = outcomes[0]
                        assert isinstance(outcome, subprocess.CompletedProcess), repr(outcome)
                        assert outcome.returncode == 0, outcome.stdout + outcome.stderr
                        assert '1 passed' in outcome.stdout, outcome.stdout
                        assert before == (process.GetUniqueID(), process.GetStopID(True), process.GetState())
                        inspection = ['describe_session', 'list_modules', 'list_threads',
                                      'read_registers', 'read_memory', 'resolve_module_address']
                        prepared = ['describe_session', 'list_modules', 'resolve_module_address',
                                    'read_registers', 'read_memory', 'read_registers',
                                    'resolve_module_address', 'list_modules', 'describe_session']
                        assert [request['operation'] for request in requests] == inspection + prepared, requests
                        assert accepted == 15
                        token = requests[1]['expected_token']
                        assert all(request['expected_token'] == token for request in requests[1:])
                        assert all('output' not in request and 'path' not in request for request in requests)
                        assert Path({str(output)!r}).is_file()
                        result.AppendMessage(outcome.stdout)
                    finally:
                        if process.IsValid() and process.GetState() == lldb.eStateStopped:
                            killed = process.Kill()
                            assert killed.Success(), str(killed)
                    result.AppendMessage('owned workspace UI: 15 real SDK queries; unchanged stopped identity')
                def __lldb_init_module(debugger, internal):
                    debugger.HandleCommand('command script add -f workspace_checks.exercise workspace-live')
                """
            )
        )
        bridge = Path(__file__).with_name("lldb_bridge.py").resolve()
        commands = [
            "settings set target.disable-aslr false",
            "breakpoint set -n main",
            "run",
            f"command script import {shlex.quote(str(bridge))}",
            f"command script import {shlex.quote(str(checks))}",
            "workspace-live",
        ]
        status, transcript = run_lldb(
            [
                "lldb",
                "--no-lldbinit",
                "--batch",
                *[part for command in commands for part in ("-o", command)],
                str(executable),
            ]
        )
        assert status == 0, transcript
        assert (
            "owned workspace UI: 15 real SDK queries; unchanged stopped identity"
            in transcript
        ), transcript
