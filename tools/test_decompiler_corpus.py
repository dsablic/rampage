"""Stdlib-only corpus runner tests with a real, controlled CLI subprocess."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from tools import decompiler_corpus as corpus

RESULT: dict[str, Any] = {
    "address": "0x1000",
    "name": "example",
    "language_id": "x86:LE:64:default:gcc",
    "code": 'int example(int value) { /* WARNING: test */ puts("hello"); return value; }\n',
    "tokens": [{"kind": "type", "text": "int"}, {"kind": "call", "text": "puts"}],
    "structure": {
        "provenance": "engine_recovered",
        "signature": {
            "return_type": {"name": "int", "size": 4},
            "calling_convention": "__cdecl",
            "variadic": False,
            "parameters": [
                {
                    "name": "value",
                    "data_type": {"name": "int", "size": 4},
                    "storage": {},
                }
            ],
        },
        "blocks": [{"index": 0, "start": "0x1000", "end": "0x1005", "successors": []}],
        "calls": [
            {"name": "puts", "source": "0x1003", "target": "0x2000", "indirect": False}
        ],
        "jump_tables": [
            {
                "switch_address": "0x1004",
                "partial": False,
                "targets": ["0x3000", "0x3010"],
                "case_values": [1, None],
            },
        ],
    },
}

FAKE_BODY = """
import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

mode = sys.argv[sys.argv.index("--at") + 1]
payload = json.loads(Path(__file__).with_suffix(".json").read_text())
if mode == "timeout":
    threading.Event().wait(60)
elif mode == "crash":
    os.kill(os.getpid(), signal.SIGTERM)
elif mode == "nonzero":
    print("failed", file=sys.stderr)
    raise SystemExit(7)
elif mode == "malformed":
    print("not JSON")
elif mode == "invalid-shape":
    print(json.dumps({"code": "C"}))
elif mode == "invalid-utf8":
    os.write(1, b"\\xff")
elif mode == "nonfinite":
    print(json.dumps(payload)[:-1] + ', "extra": 1e999}')
elif mode == "stdout-limit":
    os.write(1, b"x" * (1024 * 1024))
elif mode == "stdout-limit-hold":
    os.write(1, b"x" * 2048)
    threading.Event().wait(60)
elif mode == "stderr-limit":
    os.write(2, b"x" * (1024 * 1024))
elif mode == "both-streams":
    def write_stderr():
        os.write(2, b"e" * (1024 * 1024))
    threading.Thread(target=write_stderr).start()
    os.write(1, b"o" * (1024 * 1024))
elif mode == "descendant":
    subprocess.Popen([sys.executable, "-c", "import threading; threading.Event().wait(60)"])
else:
    Path(__file__).with_suffix(".args").write_text(json.dumps(sys.argv[1:]))
    print(json.dumps(payload))
"""


class CorpusTests(unittest.TestCase):
    directory: tempfile.TemporaryDirectory[str]
    root: Path
    executable: Path
    image: Path

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="decompiler-corpus-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.executable = self.root / "fake-rampage"
        self.executable.write_text(
            f"#!{sys.executable}\n" + FAKE_BODY, encoding="utf-8"
        )
        self.executable.chmod(0o755)
        self.executable.with_suffix(".json").write_text(
            json.dumps(RESULT), encoding="utf-8"
        )
        self.image = self.root / "image with spaces.elf"
        self.image.write_bytes(b"controlled image")

    def test_successful_output_does_not_hide_incomplete_recovery(self) -> None:
        result = json.loads(json.dumps(RESULT))
        result["structure"]["diagnostics"] = {
            "bad_data": True,
            "unimplemented": False,
            "unresolved_calls": 0,
            "unresolved_indirect_jumps": 0,
            "partial_jump_tables": 0,
            "warnings": [
                {"kind": "body", "address": "0x1000", "message": "bad instruction"}
            ],
        }
        result["recovery_status"] = "incomplete"
        self.executable.with_suffix(".json").write_text(json.dumps(result))
        record = corpus.run_case(
            str(self.executable),
            corpus.Case("bad", self.image, "example"),
            5,
            65536,
            False,
        )
        self.assertTrue(record["success"])
        self.assertEqual(record["metrics"]["recovery_status"], "incomplete")
        self.assertEqual(
            corpus.aggregate([record])["recovery_status_counts"], {"incomplete": 1}
        )

    def test_legacy_results_are_unassessed_not_issue_free(self) -> None:
        self.assertEqual(
            corpus.recovery_status(
                corpus.validate_result(RESULT)["structure"].get("diagnostics")
            ),
            "unavailable",
        )

    def test_malformed_or_conflicting_recovery_diagnostics_are_rejected(self) -> None:
        diagnostics = {
            "bad_data": False,
            "unimplemented": False,
            "unresolved_calls": 1,
            "unresolved_indirect_jumps": 0,
            "partial_jump_tables": 0,
            "warnings": [],
        }
        for key, value in [
            ("unresolved_calls", True),
            ("bad_data", "false"),
            ("warnings", [{}]),
            ("warnings", [{"kind": [], "message": "bad", "address": None}]),
            ("warnings", [{"kind": {}, "message": "bad", "address": None}]),
        ]:
            result = json.loads(json.dumps(RESULT))
            result["structure"]["diagnostics"] = diagnostics | {key: value}
            with self.assertRaises(corpus.CorpusError):
                corpus.validate_result(result)
        result["structure"]["diagnostics"] = diagnostics
        result["recovery_status"] = "no_reported_issues"
        with self.assertRaises(corpus.CorpusError):
            corpus.validate_result(result)

    def case(
        self, function: str = "example", assertions: dict[str, Any] | None = None
    ) -> corpus.Case:
        return corpus.Case("example", self.image, function, assertions=assertions or {})

    def run_case(
        self, case: corpus.Case, baseline: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return corpus.run_case(
            str(self.executable), case, 2.0, 64 * 1024, False, baseline
        )

    def baseline_case(self, case: corpus.Case) -> dict[str, Any]:
        return {
            "id": case.case_id,
            "image_sha256": corpus.hash_file(self.image),
            "function": case.function,
            "address": RESULT["address"],
            "arch": case.arch,
            "compiler": case.compiler,
            "language_id": RESULT["language_id"],
            "expected_params": 1,
        }

    def test_recovers_metrics_and_checks_only_explicit_assertions(self) -> None:
        case = self.case(
            assertions={
                "expected_contains": ["return value"],
                "expected_not_contains": ["goto"],
                "expected_params": [{"type": "int"}],
                "expected_signature": {"return_type": "int", "variadic": False},
                "expected_calls": [{"name": "puts", "target": 8192, "indirect": False}],
                "expected_strings": ['"hello"'],
                "expected_switch_targets": ["0x3010"],
                "expected_switch_case_values": [1],
            }
        )
        record = self.run_case(case)
        self.assertTrue(record["success"])
        self.assertTrue(record["case_passed"])
        self.assertEqual(record["image_sha256"], corpus.hash_file(self.image))
        self.assertEqual(record["actual_address"], "0x1000")
        metrics = record["metrics"]
        self.assertEqual(metrics["parameter_count"], 1)
        self.assertEqual(metrics["warning_lines"], 1)
        self.assertEqual(metrics["compiler_id"], "gcc")
        self.assertEqual(metrics["call_count"], 1)
        self.assertIsNone(metrics["typed_call_count"])
        self.assertEqual(metrics["token_counts_by_kind"], {"type": 1, "call": 1})
        self.assertEqual(metrics["recovered_block_count"], 1)
        self.assertEqual(metrics["switch_target_count"], 2)
        self.assertGreater(record["elapsed_seconds"], 0)
        self.assertGreater(record["stdout_bytes"], metrics["code_bytes"])

    def test_parameter_count_and_order_mismatch_fail_without_cli_failure(self) -> None:
        for expected in (0, [{"type": "long"}], [{"name": "value"}, {"name": "other"}]):
            with self.subTest(expected=expected):
                record = self.run_case(
                    self.case(assertions={"expected_params": expected})
                )
                self.assertTrue(record["success"])
                self.assertFalse(record["case_passed"])
                self.assertFalse(record["checks"][0]["passed"])

    def test_expected_mismatch_does_not_become_semantic_equality(self) -> None:
        record = self.run_case(self.case(assertions={"expected_strings": ["absent"]}))
        self.assertTrue(record["success"])
        self.assertFalse(record["case_passed"])
        self.assertFalse(record["checks"][0]["passed"])

    def test_signal_exit_and_malformed_outputs_are_recorded(self) -> None:
        for mode, failure in (
            ("crash", "signal"),
            ("nonzero", "nonzero_exit"),
            ("malformed", "malformed_json"),
            ("invalid-shape", "malformed_json"),
            ("invalid-utf8", "malformed_json"),
            ("nonfinite", "malformed_json"),
        ):
            with self.subTest(mode=mode):
                record = self.run_case(
                    self.case(mode, {"expected_not_contains": ["bad"]})
                )
                self.assertFalse(record["success"])
                self.assertTrue(record["failure"].startswith(failure))
                self.assertIsNone(record["checks"][0]["passed"])

    def test_timeout_kills_child_and_keeps_assertions_unavailable(self) -> None:
        record = corpus.run_case(
            str(self.executable), self.case("timeout"), 0.2, 65536, False
        )
        self.assertEqual(record["failure"], "timeout")
        self.assertFalse(record["success"])
        self.assertIsNotNone(record["returncode"])
        self.assertLess(record["elapsed_seconds"], 3)

    @unittest.skipUnless(os.name == "posix", "process group cleanup is POSIX-specific")
    def test_descendant_holding_output_pipe_does_not_hang(self) -> None:
        record = corpus.run_case(
            str(self.executable), self.case("descendant"), 0.3, 65536, False
        )
        self.assertEqual(record["failure"], "timeout")
        self.assertLess(record["elapsed_seconds"], 3)

    def test_large_outputs_are_bounded_and_concurrently_drained(self) -> None:
        for mode in ("stdout-limit", "stderr-limit", "both-streams"):
            with self.subTest(mode=mode):
                execution = corpus.run_process(
                    [
                        str(self.executable),
                        "--json",
                        "decompile",
                        str(self.image),
                        "--at",
                        mode,
                    ],
                    2,
                    1024,
                )
                self.assertEqual(execution["failure"], "output_limit")
                self.assertLessEqual(len(execution["stdout"]), 1024)
                self.assertLessEqual(len(execution["stderr"].encode()), 1024)
                self.assertGreater(
                    max(execution["stdout_bytes"], execution["stderr_bytes"]), 1024
                )

    def test_missing_image_and_spawn_error_are_reported(self) -> None:
        self.image.unlink()
        record = self.run_case(self.case(assertions={"expected_params": 1}))
        self.assertTrue(record["failure"].startswith("image_error"))
        self.assertIsNone(record["checks"][0]["passed"])
        execution = corpus.run_process([str(self.root / "absent")], 1, 1024)
        self.assertTrue(execution["failure"].startswith("spawn_error"))

    def test_output_limit_is_enforced_without_waiting_for_large_read_or_eof(
        self,
    ) -> None:
        execution = corpus.run_process(
            [str(self.executable), "--at", "stdout-limit-hold"], 2, 1024
        )
        self.assertEqual(execution["failure"], "output_limit")
        self.assertLess(execution["elapsed_seconds"], 1)

    @unittest.skipUnless(os.name == "posix", "process group cleanup is POSIX-specific")
    def test_output_limit_group_permission_error_uses_child_kill_without_thread_exception(
        self,
    ) -> None:
        with (
            mock.patch.object(
                corpus.os, "killpg", side_effect=PermissionError("group denied")
            ),
            mock.patch.object(threading, "excepthook") as thread_errors,
        ):
            execution = corpus.run_process(
                [str(self.executable), "--at", "stdout-limit-hold"], 2, 1024
            )
        self.assertEqual(execution["failure"], "output_limit")
        self.assertIsNotNone(execution["returncode"])
        self.assertEqual(execution["cleanup_errors"], [])
        thread_errors.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "process group cleanup is POSIX-specific")
    def test_stop_process_handles_group_disappearance_and_permission_denial(
        self,
    ) -> None:
        for group_error in (ProcessLookupError("gone"), PermissionError("denied")):
            for returncode in (None, 0):
                with self.subTest(group_error=group_error, returncode=returncode):
                    process = mock.Mock(
                        pid=123, poll=mock.Mock(return_value=returncode)
                    )
                    with mock.patch.object(
                        corpus.os, "killpg", side_effect=group_error
                    ):
                        self.assertIsNone(corpus.stop_process(process))
                    self.assertEqual(process.kill.call_count, int(returncode is None))

    @unittest.skipUnless(os.name == "posix", "process group cleanup is POSIX-specific")
    def test_reader_reports_denied_live_child_cleanup_without_thread_exception(
        self,
    ) -> None:
        process = mock.Mock(
            pid=123,
            poll=mock.Mock(return_value=None),
            kill=mock.Mock(side_effect=PermissionError("child denied")),
        )
        capture = corpus.Capture()
        with (
            mock.patch.object(
                corpus.os, "killpg", side_effect=PermissionError("group denied")
            ),
            mock.patch.object(threading, "excepthook") as thread_errors,
        ):
            reader = threading.Thread(
                target=corpus.drain_output,
                args=(io.BytesIO(b"oversized"), capture, 1, process),
            )
            reader.start()
            reader.join()
        self.assertTrue(capture.exceeded)
        self.assertIn(
            "cannot terminate live subprocess 123", capture.cleanup_error or ""
        )
        self.assertIn("child denied", capture.cleanup_error or "")
        thread_errors.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "process group cleanup is POSIX-specific")
    def test_stop_process_suppresses_denial_if_child_exits_during_fallback(
        self,
    ) -> None:
        process = mock.Mock(
            pid=123,
            poll=mock.Mock(side_effect=[None, 0]),
            kill=mock.Mock(side_effect=ProcessLookupError("gone")),
        )
        with mock.patch.object(
            corpus.os, "killpg", side_effect=PermissionError("denied")
        ):
            self.assertIsNone(corpus.stop_process(process))

    def test_reader_closed_stream_cleanup_does_not_leak_thread_exception(self) -> None:
        stream = io.BytesIO(b"output")
        stream.close()
        capture = corpus.Capture()
        process = mock.Mock(pid=123, poll=mock.Mock(return_value=0))
        with (
            mock.patch.object(corpus, "stop_process", return_value=None),
            mock.patch.object(threading, "excepthook") as thread_errors,
        ):
            reader = threading.Thread(
                target=corpus.drain_output, args=(stream, capture, 1, process)
            )
            reader.start()
            reader.join()
        self.assertIn("cannot drain subprocess output", capture.error or "")
        thread_errors.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "process group cleanup is POSIX-specific")
    def test_timeout_reports_live_child_cleanup_failure_without_unbounded_communicate(
        self,
    ) -> None:
        process = mock.Mock(
            pid=123,
            returncode=None,
            poll=mock.Mock(return_value=None),
            kill=mock.Mock(side_effect=PermissionError("child denied")),
            communicate=mock.Mock(side_effect=subprocess.TimeoutExpired(["fake"], 1)),
        )
        with (
            mock.patch.object(corpus.subprocess, "Popen", return_value=process),
            mock.patch.object(
                corpus.os, "killpg", side_effect=PermissionError("group denied")
            ),
            mock.patch.object(threading, "excepthook") as thread_errors,
        ):
            execution = corpus.run_process(["fake"], 2, 1024)
        self.assertEqual(execution["failure"], "timeout")
        self.assertIsNone(execution["returncode"])
        self.assertTrue(
            any(
                "cannot terminate live subprocess" in error
                for error in execution["cleanup_errors"]
            )
        )
        self.assertTrue(
            any("still alive" in error for error in execution["cleanup_errors"])
        )
        self.assertTrue(
            all(
                call.kwargs.get("timeout") is not None
                for call in process.communicate.call_args_list
            )
        )
        thread_errors.assert_not_called()

    def test_baseline_hash_function_arch_compiler_and_language_scope(self) -> None:
        case = self.case()
        baseline = self.baseline_case(case)
        matched = self.run_case(case, baseline)
        self.assertEqual(matched["baseline_status"], "matched")
        self.assertTrue(matched["checks"][0]["passed"])
        for field, value in (
            ("image_sha256", "0" * 64),
            ("function", "other"),
            ("arch", "arm"),
            ("compiler", "windows"),
            ("language_id", "other:gcc"),
            ("address", "0x9999"),
        ):
            with self.subTest(field=field):
                record = self.run_case(case, baseline | {field: value})
                self.assertEqual(record["baseline_status"], "identity_mismatch")
                self.assertIn(field, record["baseline_identity_mismatches"])
                self.assertIsNone(record["checks"][0]["passed"])
                self.assertFalse(record["case_passed"])

    def test_changing_image_invalidates_existing_baseline(self) -> None:
        case = self.case()
        baseline = self.baseline_case(case)
        self.image.write_bytes(b"changed image")
        record = self.run_case(case, baseline)
        self.assertEqual(record["baseline_status"], "identity_mismatch")
        self.assertIn("image_sha256", record["baseline_identity_mismatches"])

    def test_baseline_failure_preserves_reference_assertion_denominator(self) -> None:
        case = self.case("crash")
        record = self.run_case(case, self.baseline_case(case))
        self.assertEqual(record["baseline_status"], "unavailable")
        summary = corpus.aggregate([record])["assertions_by_source"]["baseline"]
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["unavailable"], 1)
        self.assertEqual(summary["passed_over_total"], 0)
        self.assertIsNone(summary["passed_over_evaluated"])

    def test_malformed_nested_result_is_not_treated_as_missing_recovery(self) -> None:
        invalid_values = [
            ("signature", {"parameters": []}),
            ("calls", [{"target": [], "indirect": False}]),
            (
                "jump_tables",
                [
                    RESULT["structure"]["jump_tables"][0]
                    | {"targets": ["bad"], "case_values": []}
                ],
            ),
            (
                "jump_tables",
                [RESULT["structure"]["jump_tables"][0] | {"case_values": [True, None]}],
            ),
        ]
        for key, invalid in invalid_values:
            with self.subTest(key=key, invalid=invalid):
                payload = json.loads(json.dumps(RESULT))
                payload["structure"][key] = invalid
                self.executable.with_suffix(".json").write_text(json.dumps(payload))
                record = self.run_case(self.case(assertions={"expected_params": 1}))
                self.assertTrue(record["failure"].startswith("malformed_json"))
                self.assertIsNone(record["checks"][0]["passed"])

    def test_result_requires_a_valid_returned_function_address(self) -> None:
        for address in (None, True, -1, [], "invalid", "0xnothex"):
            with self.subTest(address=address):
                payload = json.loads(json.dumps(RESULT))
                payload["address"] = address
                self.executable.with_suffix(".json").write_text(json.dumps(payload))
                record = self.run_case(self.case(assertions={"expected_params": 1}))
                self.assertFalse(record["success"])
                self.assertTrue(record["failure"].startswith("malformed_json"))
                self.assertIsNone(record["actual_address"])
        payload.pop("address")
        self.executable.with_suffix(".json").write_text(json.dumps(payload))
        record = self.run_case(self.case())
        self.assertTrue(record["failure"].startswith("malformed_json"))

    def test_numeric_selectors_require_exact_entry_address_with_or_without_baseline(
        self,
    ) -> None:
        for selector in ("0x1000", "0X00001000", "4096", "04096", " 4096 "):
            with self.subTest(selector=selector):
                case = self.case(selector, {"expected_params": 1})
                record = self.run_case(case, self.baseline_case(case))
                self.assertTrue(record["case_passed"])
                self.assertEqual(record["baseline_status"], "matched")
                self.assertEqual(record["actual_address"], "0x1000")
        payload = json.loads(json.dumps(RESULT))
        payload["address"] = "0x9999"
        self.executable.with_suffix(".json").write_text(json.dumps(payload))
        case = self.case("0x1000", {"expected_params": 1})
        for baseline in (None, self.baseline_case(case)):
            with self.subTest(baseline=baseline):
                record = self.run_case(case, baseline)
                self.assertEqual(record["actual_address"], "0x9999")
                self.assertFalse(record["success"])
                self.assertFalse(record["case_passed"])
                self.assertTrue(record["failure"].startswith("address_mismatch"))
                self.assertTrue(
                    all(check["passed"] is None for check in record["checks"])
                )
                if baseline:
                    self.assertEqual(record["baseline_status"], "identity_mismatch")
                    self.assertIn("address", record["baseline_identity_mismatches"])

    def test_interior_selector_is_rejected_even_when_baseline_matches_entry(
        self,
    ) -> None:
        case = self.case("0x1003", {"expected_params": 1})
        record = self.run_case(case, self.baseline_case(case))
        self.assertFalse(record["case_passed"])
        self.assertTrue(record["failure"].startswith("address_mismatch"))
        self.assertEqual(record["baseline_status"], "unavailable")
        self.assertIsNone(record["checks"][1]["passed"])

    def test_invalid_numeric_selector_does_not_escape_case_failure_handling(
        self,
    ) -> None:
        for selector in ("0xnothex", "-1"):
            with self.subTest(selector=selector):
                record = self.run_case(self.case(selector, {"expected_params": 1}))
                self.assertFalse(record["case_passed"])
                self.assertTrue(record["failure"].startswith("selector_error"))
                self.assertIsNone(record["checks"][0]["passed"])

    def test_blocks_require_fields_valid_indices_addresses_and_successor_references(
        self,
    ) -> None:
        invalid_blocks = [
            {},
            {"index": -1},
            {"index": True},
            {"start": "bad"},
            {"end": -1},
            {"end": "0xfff"},
            {"successors": [True]},
            {"successors": [-1]},
            {"successors": [99]},
            {"successors": ["0"]},
            {"successors": None},
        ]
        for invalid in invalid_blocks:
            with self.subTest(invalid=invalid):
                payload = json.loads(json.dumps(RESULT))
                original = payload["structure"]["blocks"][0]
                payload["structure"]["blocks"] = [original | invalid if invalid else {}]
                self.executable.with_suffix(".json").write_text(json.dumps(payload))
                record = self.run_case(self.case(assertions={"expected_params": 1}))
                self.assertTrue(record["failure"].startswith("malformed_json"))
                self.assertIsNone(record["metrics"])
                self.assertIsNone(record["checks"][0]["passed"])
        for field in ("start", "end", "successors"):
            with self.subTest(missing=field):
                payload = json.loads(json.dumps(RESULT))
                payload["structure"]["blocks"][0].pop(field)
                with self.assertRaises(corpus.CorpusError):
                    corpus.validate_result(payload)
        payload = json.loads(json.dumps(RESULT))
        payload["structure"]["blocks"] *= 2
        with self.assertRaisesRegex(corpus.CorpusError, "unique"):
            corpus.validate_result(payload)

    def test_valid_noncontiguous_block_indices_and_nullable_ranges_are_accepted(
        self,
    ) -> None:
        payload = json.loads(json.dumps(RESULT))
        payload["structure"]["blocks"] = [
            {"index": 5, "start": None, "end": None, "successors": [9]},
            {"index": 9, "start": 4096, "end": "0x1005", "successors": [5]},
        ]
        self.executable.with_suffix(".json").write_text(json.dumps(payload))
        record = self.run_case(self.case())
        self.assertTrue(record["case_passed"])
        self.assertEqual(record["metrics"]["recovered_block_count"], 2)

    def test_jump_tables_require_metadata_and_aligned_case_values(self) -> None:
        invalid_tables: list[dict[str, Any]] = [
            {"switch_address": "bad"},
            {"partial": None},
            {"partial": 0},
            {"targets": [None]},
            {"targets": [-1]},
            {"targets": [], "case_values": [1]},
            {"case_values": [1]},
            {"case_values": [1, 2, 3]},
        ]
        for invalid in invalid_tables:
            with self.subTest(invalid=invalid):
                payload = json.loads(json.dumps(RESULT))
                payload["structure"]["jump_tables"][0].update(invalid)
                self.executable.with_suffix(".json").write_text(json.dumps(payload))
                record = self.run_case(
                    self.case(assertions={"expected_switch_case_values": [1]})
                )
                self.assertTrue(record["failure"].startswith("malformed_json"))
                self.assertFalse(record["case_passed"])
                self.assertIsNone(record["checks"][0]["passed"])
        for field in ("switch_address", "partial", "targets"):
            with self.subTest(missing=field):
                payload = json.loads(json.dumps(RESULT))
                payload["structure"]["jump_tables"][0].pop(field)
                with self.assertRaises(corpus.CorpusError):
                    corpus.validate_result(payload)

    def test_missing_or_empty_switch_labels_remain_unavailable(self) -> None:
        for missing in (False, True):
            with self.subTest(missing=missing):
                payload = json.loads(json.dumps(RESULT))
                table = payload["structure"]["jump_tables"][0]
                table["switch_address"] = None
                if missing:
                    table.pop("case_values")
                else:
                    table["case_values"] = []
                self.executable.with_suffix(".json").write_text(json.dumps(payload))
                record = self.run_case(
                    self.case(assertions={"expected_switch_case_values": [1]})
                )
                self.assertTrue(record["success"])
                self.assertFalse(record["case_passed"])
                self.assertIsNone(record["checks"][0]["passed"])
                self.assertEqual(
                    record["checks"][0]["unavailable_reason"],
                    "switch_case_values_unavailable",
                )

    def test_empty_jump_table_and_integer_function_address_are_valid(self) -> None:
        payload = json.loads(json.dumps(RESULT))
        payload["address"] = 4096
        payload["structure"]["jump_tables"] = [
            {
                "switch_address": None,
                "targets": [],
                "case_values": [],
                "partial": True,
            }
        ]
        self.executable.with_suffix(".json").write_text(json.dumps(payload))
        case = self.case("0x1000")
        baseline = self.baseline_case(case) | {"address": 4096}
        record = self.run_case(case, baseline)
        self.assertTrue(record["case_passed"])
        self.assertEqual(record["actual_address"], "0x1000")
        self.assertEqual(record["metrics"]["switch_target_count"], 0)

    def test_aggregate_keeps_failures_and_unavailable_assertions_in_denominator(
        self,
    ) -> None:
        records = [
            self.run_case(self.case(assertions={"expected_params": 1})),
            self.run_case(self.case(assertions={"expected_params": 0})),
            self.run_case(self.case("crash", {"expected_params": 1})),
        ]
        summary = corpus.aggregate(records)
        self.assertEqual(summary["case_count"], 3)
        self.assertEqual(summary["success_rate"], 2 / 3)
        self.assertEqual(summary["assertions"]["passed_over_total"], 1 / 3)
        self.assertEqual(summary["assertions"]["passed_over_evaluated"], 1 / 2)
        self.assertEqual(summary["assertions"]["unavailable"], 1)
        self.assertEqual(summary["warning_lines_case_denominator"], 2)
        self.assertIsNone(
            summary["assertions_by_category"]["switch"]["passed_over_total"]
        )
        empty = corpus.aggregate([])
        self.assertIsNone(empty["success_rate"])
        self.assertIsNone(empty["assertions"]["passed_over_total"])

    def test_manifest_relative_images_metadata_and_validation(self) -> None:
        path = self.root / "manifest.json"
        manifest: dict[str, Any] = {
            "schema": corpus.MANIFEST_SCHEMA,
            "metadata": {
                "compiler": "clang",
                "optimization": "-O2",
                "target": "x86_64-linux-gnu",
            },
            "cases": [
                {
                    "id": "one",
                    "image": self.image.name,
                    "function": "example",
                    "expected_params": 1,
                    "metadata": {"coverage": ["integer parameters"]},
                    "reference_source": "source.c:example",
                }
            ],
        }
        path.write_text(json.dumps(manifest))
        cases, metadata = corpus.load_manifest(path)
        self.assertEqual(cases[0].image, self.image)
        self.assertEqual(metadata["optimization"], "-O2")
        self.assertEqual(cases[0].reference_source, "source.c:example")
        invalid_cases: list[dict[str, Any]] = [
            {"expected_params": -1},
            {"expected_typo": []},
            {"expected_calls": [{"type": "int"}]},
        ]
        for changes in invalid_cases:
            with self.subTest(changes=changes):
                manifest["cases"][0].update(changes)
                path.write_text(json.dumps(manifest))
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_manifest(path)
                for key in changes:
                    manifest["cases"][0].pop(key)
        manifest["cases"] *= 2
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(corpus.CorpusError, "unique"):
            corpus.load_manifest(path)

    def test_baseline_requires_version_settings_and_valid_hash(self) -> None:
        path = self.root / "baseline.json"
        baseline = {
            "schema": corpus.BASELINE_SCHEMA,
            "reference": {"tool": "fixture-source", "version": "1"},
            "settings": {"types": "source declarations"},
            "cases": [self.baseline_case(self.case())],
        }
        path.write_text(json.dumps(baseline))
        self.assertEqual(corpus.load_baseline(path)["reference"]["version"], "1")
        for field in ("reference", "settings"):
            with self.subTest(field=field):
                invalid = dict(baseline)
                invalid.pop(field)
                path.write_text(json.dumps(invalid))
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_baseline(path)
        baseline["cases"][0]["image_sha256"] = "wrong"
        path.write_text(json.dumps(baseline))
        with self.assertRaises(corpus.CorpusError):
            corpus.load_baseline(path)

    def test_baseline_requires_valid_actual_address_even_for_symbol_selectors(
        self,
    ) -> None:
        path = self.root / "baseline.json"
        baseline_case = self.baseline_case(self.case())
        baseline = {
            "schema": corpus.BASELINE_SCHEMA,
            "reference": {"tool": "fixture-source", "version": "1"},
            "settings": {},
            "cases": [baseline_case],
        }
        for address in (None, True, -1, "invalid"):
            with self.subTest(address=address):
                baseline_case["address"] = address
                path.write_text(json.dumps(baseline))
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_baseline(path)
        baseline_case.pop("address")
        path.write_text(json.dumps(baseline))
        with self.assertRaises(corpus.CorpusError):
            corpus.load_baseline(path)

    def test_cli_repeated_cases_flags_and_failure_exit_status(self) -> None:
        output = self.root / "report.json"
        status = corpus.main(
            [
                str(self.executable),
                "--case",
                str(self.image),
                "example",
                "--case",
                str(self.image),
                "malformed",
                "--isolated",
                "--arch",
                "x86_64",
                "--compiler",
                "gcc",
                "--output",
                str(output),
            ]
        )
        self.assertEqual(status, 1)
        report = json.loads(output.read_text())
        self.assertEqual(report["schema"], corpus.REPORT_SCHEMA)
        self.assertEqual(report["aggregate"]["case_count"], 2)
        self.assertTrue(report["settings"]["process_per_case"])
        actual = json.loads(self.executable.with_suffix(".args").read_text())
        self.assertIn("--isolated", actual)
        self.assertEqual(actual[actual.index("--arch") + 1], "x86_64")
        self.assertEqual(actual[actual.index("--compiler") + 1], "gcc")

    def test_cli_success_stdout_and_invalid_timeout(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            status = corpus.main(
                [str(self.executable), "--case", str(self.image), "example"]
            )
        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(captured.getvalue())["aggregate"]["successful_cases"], 1
        )
        for timeout in ("nan", "inf", "0", "-1"):
            with (
                self.subTest(timeout=timeout),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as raised:
                    corpus.main([str(self.executable), "--timeout", timeout])
                self.assertEqual(raised.exception.code, 2)

    def test_cli_cannot_overwrite_its_input_image_or_executable(self) -> None:
        for path in (self.image, self.executable):
            with self.subTest(path=path), contextlib.redirect_stderr(io.StringIO()):
                before = path.read_bytes()
                with self.assertRaises(SystemExit) as raised:
                    corpus.main(
                        [
                            str(self.executable),
                            "--case",
                            str(self.image),
                            "example",
                            "--output",
                            str(path),
                        ]
                    )
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(path.read_bytes(), before)

    def test_hardlinked_output_cannot_overwrite_any_protected_input(self) -> None:
        manifest = self.root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": corpus.MANIFEST_SCHEMA,
                    "cases": [
                        {
                            "id": "example",
                            "image": str(self.image),
                            "function": "example",
                        }
                    ],
                }
            )
        )
        baseline = self.root / "baseline.json"
        baseline.write_text(
            json.dumps(
                {
                    "schema": corpus.BASELINE_SCHEMA,
                    "reference": {"tool": "fixture-source", "version": "1"},
                    "settings": {},
                    "cases": [self.baseline_case(self.case())],
                }
            )
        )
        output = self.root / "linked-report.json"
        for protected in (self.image, self.executable, manifest, baseline):
            with (
                self.subTest(protected=protected),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                os.link(protected, output)
                before = protected.read_bytes()
                try:
                    with self.assertRaises(SystemExit) as raised:
                        corpus.main(
                            [
                                str(self.executable),
                                "--manifest",
                                str(manifest),
                                "--baseline",
                                str(baseline),
                                "--output",
                                str(output),
                            ]
                        )
                    self.assertEqual(raised.exception.code, 2)
                    self.assertEqual(protected.read_bytes(), before)
                finally:
                    output.unlink()

    def test_output_identity_is_rechecked_before_write(self) -> None:
        output = self.root / "late-linked-report.json"
        original = corpus.run_case

        def link_output_after_case(*args: Any, **kwargs: Any) -> dict[str, Any]:
            record = original(*args, **kwargs)
            os.link(self.image, output)
            return record

        before = self.image.read_bytes()
        with (
            mock.patch.object(corpus, "run_case", side_effect=link_output_after_case),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            corpus.main(
                [
                    str(self.executable),
                    "--case",
                    str(self.image),
                    "example",
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(self.image.read_bytes(), before)

    def test_cli_numeric_address_mismatch_fails_and_continues_next_case(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            status = corpus.main(
                [
                    str(self.executable),
                    "--case",
                    str(self.image),
                    "0x9999",
                    "--case",
                    str(self.image),
                    "example",
                ]
            )
        self.assertEqual(status, 1)
        report = json.loads(captured.getvalue())
        self.assertFalse(report["cases"][0]["case_passed"])
        self.assertEqual(report["cases"][0]["actual_address"], "0x1000")
        self.assertTrue(report["cases"][1]["case_passed"])
        self.assertEqual(report["aggregate"]["failed_cases"], 1)


if __name__ == "__main__":
    unittest.main()
