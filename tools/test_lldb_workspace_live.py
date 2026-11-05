from __future__ import annotations

import os
import platform
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
    exercise_workspace(tmp_path, "x86_64")


@pytest.mark.skipif(
    os.environ.get("RAMPAGE_LLDB_ARM64_WORKSPACE_LIVE") != "1",
    reason="opt-in owned native ARM64 Darwin fixture; read-only inspection, not capture",
)
def test_native_arm64_stopped_fixture_through_workspace_inspection(
    tmp_path: Path,
) -> None:
    assert platform.system() == "Darwin" and platform.machine() == "arm64", (
        "requires native ARM64 Darwin"
    )
    exercise_workspace(tmp_path, "arm64")


def exercise_workspace(tmp_path: Path, architecture: str) -> None:
    """Use SDK Kill on normal unwinding; the outer LLDB timeout is not descendant-cleanup proof."""
    native_arm64 = architecture == "arm64"
    test_name = (
        "debugger_workspace_live::owned_lldb_native_arm64_workspace_readonly_inspection"
        if native_arm64
        else "debugger_workspace_live::owned_lldb_workspace_connect_inspect_prepare_compare_save_open"
    )
    opt_in = (
        "RAMPAGE_LLDB_ARM64_WORKSPACE_LIVE"
        if native_arm64
        else "RAMPAGE_LLDB_WORKSPACE_LIVE"
    )
    query_count = 6 if native_arm64 else 15
    success = f"owned workspace UI: {query_count} real SDK queries; unchanged stopped identity"
    ui_test = Path(os.environ["RAMPAGE_UI_LIVE_TEST_BIN"]).resolve(strict=True)
    assert ui_test.is_file() and os.access(ui_test, os.X_OK)
    source = tmp_path / "transport_fixture.c"
    executable = tmp_path / "transport_fixture"
    source.write_text(
        "volatile unsigned char transport_bytes[4] = {0x12, 0x34, 0x56, 0x78};\n"
        "int main(void) { return transport_bytes[0]; }\n"
    )
    subprocess.run(
        [
            "clang",
            "-arch",
            architecture,
            "-g",
            "-O0",
            str(source),
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="rw-", dir=temporary_root) as directory:
        private = Path(directory)
        private.chmod(0o700)
        endpoint = private / "q.sock"
        output = private / "workspace.capture.json"
        bridge = Path(__file__).with_name("lldb_bridge.py").resolve()
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
                        native_arm64 = {native_arm64!r}
                        assert process.IsValid() and process.GetState() == lldb.eStateStopped, (
                            'Owned ARM64 fixture did not stop; native debugserver access is required'
                            if native_arm64 else
                            'Owned x86_64 fixture did not stop; Rosetta/debugserver availability is required')
                        machines = ('arm64', 'aarch64') if native_arm64 else ('x86_64',)
                        assert target.GetTriple().split('-')[0] in machines
                        assert target.GetByteOrder() == lldb.eByteOrderLittle
                        before = (process.GetUniqueID(), process.GetStopID(True), process.GetState())
                        context = target.FindFunctions('main').GetContextAtIndex(0)
                        function = context.GetFunction()
                        address = function.GetStartAddress()
                        size = function.GetEndAddress().GetFileAddress() - address.GetFileAddress()
                        assert 4 <= size <= 4096
                        module = context.GetModule()
                        assert module.IsValid() and module.GetUUIDString()
                        if native_arm64:
                            assert module.GetTriple().split('-')[0] in machines
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
                        if native_arm64:
                            assert Path(lldb_bridge.__file__).resolve() == Path({str(bridge)!r})
                            assert header.IsValid()
                            assert header.GetLoadAddress(target) != lldb.LLDB_INVALID_ADDRESS
                            assert header.GetFileAddress() != lldb.LLDB_INVALID_ADDRESS
                            frame = thread.GetFrameAtIndex(0)
                            assert frame.IsValid()
                            registers = {{}}
                            for name in ('pc', 'sp', 'cpsr'):
                                register = frame.FindRegister(name)
                                assert register.IsValid() and register.GetError().Success(), name
                                value = register.GetValueAsUnsigned()
                                assert register.GetError().Success(), name
                                registers[name] = hex(value)
                            metadata['registers'] = registers
                        requests, responses, outcomes = [], [], []
                        def query(encoded):
                            requests.append(json.loads(encoded))
                            response = lldb_bridge.query_json(debugger, encoded, lldb)
                            responses.append(json.loads(response))
                            return response
                        def preflight():
                            lldb_bridge.QueryContext(debugger, lldb, None).verify()
                        def client():
                            try:
                                outcomes.append(subprocess.run(
                                    [{str(ui_test)!r}, '--ignored', '--exact',
                                     {test_name!r},
                                     '--nocapture', '--test-threads=1'],
                                    env={{**os.environ, {opt_in!r}: '1',
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
                        expected = inspection if native_arm64 else inspection + prepared
                        assert [request['operation'] for request in requests] == expected, requests
                        assert accepted == {query_count}
                        token = requests[1]['expected_token']
                        assert all(request['expected_token'] == token for request in requests[1:])
                        assert all('output' not in request and 'path' not in request for request in requests)
                        if native_arm64:
                            assert not Path({str(output)!r}).exists()
                            assert all(response['ok'] is True for response in responses), responses
                            assert all(response['token'] == token for response in responses)
                            assert token['process_unique_id'] == before[0] and token['stop_id'] == before[1]
                            assert token['target_index'] == debugger.GetIndexOfTarget(target)
                            assert all(response['observation']['atomic_snapshot'] is False
                                       for response in responses)
                            session = responses[0]['data']
                            assert session['architecture'] == 'aarch64'
                            assert session['target_byte_order'] == 'little'
                            rows = responses[1]['data']['items']
                            row = next(row for row in rows if row['index'] == module_index)
                            for field in ('runtime_base', 'image_base'):
                                assert row[field] == metadata[field]
                            assert row['uuid'] == metadata['module_uuid']
                            assert row['triple'] == metadata['module_triple']
                            assert row['target_byte_order'] == 'little'
                            assert row['address_byte_size'] == 8
                            raw = responses[3]['data']
                            assert set(raw['required_registers']) == set(metadata['registers'])
                            assert 'registers' not in requests[3]
                            for name in raw['required_registers']:
                                assert raw['context']['registers'][name] == metadata['registers'][name]
                            memory = responses[4]['data']
                            assert memory['bytes_hex'] == metadata['bytes_hex']
                            assert memory['address'] == metadata['load_address']
                            assert memory['size'] == 4 and memory['permissions'] == 'r-x'
                            assert memory['interpretation'] == 'raw-bytes-only'
                            assert 'may normalize' in memory['read_semantics']
                            for data in (session, raw, memory):
                                assert data['data_byte_order']['order'] == 'unknown'
                                assert 'does not establish' in data['data_byte_order']['source']
                            resolved = responses[5]['data']
                            assert resolved['load_address'] == metadata['load_address']
                            assert resolved['file_address'] == metadata['file_address']
                            assert resolved['module_context']['data_byte_order']['order'] == 'unknown'
                            assert resolved['proven_flow'] is False and resolved['proven_layout'] is False
                        else:
                            assert Path({str(output)!r}).is_file()
                        result.AppendMessage(outcome.stdout)
                    finally:
                        state = process.GetState()
                        terminal = (lldb.eStateExited, lldb.eStateDetached, lldb.eStateInvalid, lldb.eStateUnloaded)
                        should_kill = state not in terminal if {native_arm64!r} else state == lldb.eStateStopped
                        if process.IsValid() and should_kill:
                            killed = process.Kill()
                            assert killed.Success(), str(killed)
                    result.AppendMessage({success!r})
                def __lldb_init_module(debugger, internal):
                    debugger.HandleCommand('command script add -f workspace_checks.exercise workspace-live')
                """
            )
        )
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
        assert success in transcript, transcript
