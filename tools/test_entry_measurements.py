"""Source-only measurement wrapper tests; native runs belong to the parent gate."""

from __future__ import annotations

import argparse
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from tools import entry_measurements as measurements


def response(case: dict[str, Any], mode: str = "exact") -> bytes:
    result: dict[str, Any] = {
        "address": "0x1000",
        "language_id": "x86:LE:64:default:" + case["compiler"],
        "code": 'int main(void) { puts("rampage fixture greeting"); return 5; }',
        "structure": {
            "signature": {"parameters": [{"name": "param_1"}, {"name": "param_2"}]}
        },
    }
    if case["oracle"] == "two_argument_sum":
        result["code"] = (
            "int add(int param_1, int param_2) { return param_1 + param_2; }"
        )
    if mode == "exact":
        result["context"] = {
            "scope": "exact_entry",
            "validation": "analyst_asserted",
            "full_image_mapping": True,
            "mapped_backing_checked": True,
            "execution": "in_process_native",
            "mapped_regions": 2,
            "mapped_backed_bytes": 128,
            "counts": {
                "retained_symbols": 1,
                "retained_imports": 1,
                "references": 2,
                "decoded_instructions": 8,
                "decoded_bytes": 32,
                "walk_blocks": 1,
                "stub_aliases": 1,
                "context_budget_exhausted": False,
            },
            "omissions": ["No whole-program context."],
            "timings": {
                "configuration_ms": 1,
                "metadata_ms": 2,
                "replay_ms": 3,
                "mapping_ms": 4,
                "execution_ms": 5,
                "total_ms": 15,
            },
        }
    return json.dumps(result).encode()


def minimal_images() -> dict[str, bytes]:
    elf = bytearray(128)
    elf[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into(
        "<HHIQQQIHHHHHH", elf, 16, 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0
    )
    struct.pack_into("<IIQQQQQQ", elf, 64, 1, 5, 0, 0x1000, 0x1000, 128, 128, 8)
    pe = bytearray(400)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 60, 64)
    pe[64:68] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 68, 0x8664, 1, 0, 0, 0, 240, 2)
    struct.pack_into("<H", pe, 88, 0x20B)
    struct.pack_into("<I", pe, 148, 384)
    struct.pack_into("<I", pe, 196, 16)
    struct.pack_into("<II", pe, 344, 16, 384)
    macho = bytearray(48)
    struct.pack_into("<IIIIIIII", macho, 0, 0xFEEDFACF, 0x1000007, 3, 2, 1, 16, 0, 0)
    struct.pack_into("<IIII", macho, 32, 0x24, 16, 0, 0)
    return {
        "hello-x64-dyn.elf": bytes(elf),
        "hello-x64.exe": bytes(pe),
        "hello-x64.macho": bytes(macho),
    }


def process_result(
    stdout: bytes = b"", failure: str | None = None
) -> measurements.supervisor.ProcessResult:
    return measurements.supervisor.ProcessResult(
        command=["private-cli"],
        returncode=0,
        stdout=stdout,
        stderr=b"private-path-in-stderr",
        wall_seconds=0.125,
        failure=failure,
        max_observed_summed_rss_bytes=4096,
        rss_samples=2,
    )


class MeasurementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name)
        self.root = self.scratch / "repository"
        (self.root / "tests/fixtures/bin").mkdir(parents=True)
        (self.root / "tests/fixtures/src").mkdir()
        (self.root / "tests/fixtures/src/hello.c").write_text("owned-source")
        for name, content in minimal_images().items():
            (self.root / "tests/fixtures/bin" / name).write_bytes(content)
        self.cli = self.scratch / "original-cli"
        self.worker = self.scratch / "original-worker"
        for executable in (self.cli, self.worker):
            executable.write_bytes(b"fake-executable-never-run")
            executable.chmod(0o700)
        self.arguments = argparse.Namespace(
            cli=self.cli,
            worker=self.worker,
            output=self.scratch / "report.json",
            backend="inline",
            repeats=1,
            include_arm64=False,
        )
        patcher = mock.patch.object(measurements, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_preflight_failure_and_unknown_arguments_do_not_change_files(self) -> None:
        before = set(self.scratch.rglob("*"))
        with self.assertRaises(SystemExit):
            measurements.parse_arguments(
                [
                    "--cli",
                    str(self.cli),
                    "--worker",
                    str(self.worker),
                    "--output",
                    str(self.arguments.output),
                    "--unknown",
                ]
            )
        self.arguments.worker = self.scratch / "missing-worker"
        with mock.patch.object(measurements, "prepare_inputs") as prepare:
            self.assertEqual(
                measurements.main(
                    [
                        "--cli",
                        str(self.cli),
                        "--worker",
                        str(self.arguments.worker),
                        "--output",
                        str(self.arguments.output),
                    ]
                ),
                2,
            )
            prepare.assert_not_called()
        self.assertEqual(before, set(self.scratch.rglob("*")))

    def test_hashes_are_reproducible_and_changes_are_detected(self) -> None:
        manifest = measurements.preflight(self.arguments)
        self.assertEqual(
            measurements.fingerprint(manifest),
            measurements.fingerprint(measurements.preflight(self.arguments)),
        )
        self.cli.write_bytes(b"changed-after-preflight")
        workspace = self.scratch / "workspace"
        workspace.mkdir()
        with self.assertRaisesRegex(measurements.MeasurementError, "CLI changed"):
            measurements.prepare_inputs(self.arguments, workspace, manifest)

    def test_inline_is_a_physical_copy_without_worker(self) -> None:
        manifest = measurements.preflight(self.arguments)
        workspace = self.scratch / "workspace"
        workspace.mkdir()
        copied = measurements.prepare_inputs(self.arguments, workspace, manifest)
        self.assertNotEqual(copied.stat().st_ino, self.cli.stat().st_ino)
        self.assertFalse((copied.parent / "rampage-worker").exists())
        with mock.patch.dict(os.environ, {"RAMPAGE_WORKER": "unowned-worker"}):
            command, environment = measurements.invocation(
                copied,
                workspace / "hello-x64.exe",
                manifest["fixtures"][1],
                "inline",
                "legacy",
            )
            self.assertNotIn("RAMPAGE_WORKER", environment)
            self.assertNotIn("--isolated", command)
            self.assertNotIn("--exact-entry", command)
            exact, environment = measurements.invocation(
                copied,
                workspace / "hello-x64.exe",
                manifest["fixtures"][1],
                "inline",
                "exact",
            )
            self.assertNotIn("RAMPAGE_WORKER", environment)
            self.assertNotIn("--isolated", exact)
            self.assertIn("--exact-entry", exact)

    def test_isolated_request_is_rejected_before_writes_or_children(self) -> None:
        before = set(self.scratch.rglob("*"))
        with (
            mock.patch.object(measurements, "prepare_inputs") as prepare,
            mock.patch.object(measurements.supervisor, "run_process") as run,
        ):
            with self.assertRaises(SystemExit) as rejected:
                measurements.main(
                    [
                        "--cli",
                        str(self.cli),
                        "--worker",
                        str(self.worker),
                        "--output",
                        str(self.arguments.output),
                        "--backend",
                        "isolated",
                    ]
                )
            self.assertEqual(rejected.exception.code, 2)
            self.arguments.backend = "isolated"
            with self.assertRaisesRegex(measurements.MeasurementError, "unsupported"):
                measurements.preflight(self.arguments)
            prepare.assert_not_called()
            run.assert_not_called()
        self.assertEqual(before, set(self.scratch.rglob("*")))

    def test_manifest_worker_is_provenance_only_and_isolated_metrics_are_null(
        self,
    ) -> None:
        manifest = measurements.preflight(self.arguments)
        self.assertEqual(manifest["settings"]["backend"], "inline")
        self.assertIn("never executed", manifest["settings"]["backend_scope"])
        self.assertIsNone(manifest["settings"]["isolated_wall_seconds"])
        self.assertIsNone(manifest["settings"]["isolated_rss_bytes"])
        self.assertIn("worker", manifest["executables_sha256"])

    def test_semantic_oracles_reject_shared_wrong_output_and_wrong_context(
        self,
    ) -> None:
        case = measurements.preflight(self.arguments)["fixtures"][0]
        for mode in ("exact", "legacy"):
            good = response(case, mode)
            measurements.validate_result(good, case, "inline", mode)
            for wrong in (
                good.replace(b"return 5", b"return 0"),
                good.replace(b"greeting", b"wrong"),
            ):
                with self.assertRaises(measurements.MeasurementError):
                    measurements.validate_result(wrong, case, "inline", mode)
        for field, wrong_value in (
            ("full_image_mapping", False),
            ("execution", "supervised_worker"),
        ):
            wrong = json.loads(response(case))
            wrong["context"][field] = wrong_value
            with self.assertRaises(measurements.MeasurementError):
                measurements.validate_result(
                    json.dumps(wrong).encode(), case, "inline", "exact"
                )
        with self.assertRaises(measurements.MeasurementError):
            measurements.validate_result(response(case), case, "inline", "legacy")

    def test_pe_oracle_rejects_wrong_operation_even_when_argument_count_matches(
        self,
    ) -> None:
        case = measurements.preflight(self.arguments)["fixtures"][1]
        good = response(case)
        measurements.validate_result(good, case, "inline", "exact")
        with self.assertRaisesRegex(measurements.MeasurementError, "addition"):
            measurements.validate_result(
                good.replace(b" + ", b" - "), case, "inline", "exact"
            )

    def test_malformed_response_fields_raise_measurement_errors(self) -> None:
        cases = measurements.preflight(self.arguments)["fixtures"]
        mutations = (
            (("language_id",), ""),
            (("language_id",), None),
            (("language_id",), []),
            (("code",), None),
            (("code",), {}),
            (("address",), ""),
            (("address",), "0x10000000000000000"),
            (("address",), "0x001000"),
            (("language_id",), "x86:LE:64:arbitrary:gcc"),
            (("context",), []),
            (("context", "timings"), None),
            (("context", "timings", "execution_ms"), "5"),
            (("context", "timings", "execution_ms"), True),
            (("context", "counts", "retained_symbols"), True),
            (("context", "counts", "retained_symbols"), -1),
            (("context", "counts", "retained_symbols"), 1 << 64),
            (("context", "counts", "context_budget_exhausted"), 1),
            (("context", "mapped_backed_bytes"), -1),
            (("context", "mapped_regions"), "two"),
            (("context", "omissions"), [{}]),
            (("structure",), None),
            (("structure", "signature"), []),
            (("structure", "signature", "parameters"), None),
            (("structure", "signature", "parameters"), "two"),
            (("structure", "signature", "parameters"), [None, {}]),
            (
                ("structure", "signature", "parameters"),
                [{"name": "param_1"}, {"name": None}],
            ),
        )
        for path, value in mutations:
            with self.subTest(path=path, value=value):
                case = cases[1] if path[0] == "structure" else cases[0]
                result = json.loads(response(case))
                parent = result
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = value
                with self.assertRaises(measurements.MeasurementError):
                    measurements.validate_result(
                        json.dumps(result).encode(), case, "inline", "exact"
                    )

    def test_pe_admission_rejects_an_elf_with_a_pe_filename(self) -> None:
        elf = (self.root / "tests/fixtures/bin/hello-x64-dyn.elf").read_bytes()
        (self.root / "tests/fixtures/bin/hello-x64.exe").write_bytes(elf)
        with self.assertRaisesRegex(measurements.MeasurementError, "not x86-64 PE"):
            measurements.preflight(self.arguments)
        self.assertFalse(self.arguments.output.exists())

    def test_header_admission_rejects_every_truncated_fixture_prefix(self) -> None:
        for case in measurements.CASES:
            data = minimal_images()[case.fixture]
            measurements.validate_image(data, case)
            for length in range(len(data)):
                with (
                    self.subTest(fixture=case.fixture, length=length),
                    self.assertRaises(measurements.MeasurementError),
                ):
                    measurements.validate_image(data[:length], case)

    def test_header_admission_checks_declared_table_and_command_bounds(self) -> None:
        mutations = (
            (0, 52, "<H", 0),
            (0, 32, "<Q", 1000),
            (0, 96, "<Q", 1000),
            (1, 84, "<H", 96),
            (1, 70, "<H", 100),
            (1, 196, "<I", 100),
            (1, 348, "<I", 1000),
            (2, 16, "<I", 2),
            (2, 20, "<I", 1000),
            (2, 36, "<I", 4),
        )
        for index, offset, layout, value in mutations:
            with self.subTest(index=index, offset=offset):
                case = measurements.CASES[index]
                data = bytearray(minimal_images()[case.fixture])
                struct.pack_into(layout, data, offset, value)
                with self.assertRaises(measurements.MeasurementError):
                    measurements.validate_image(bytes(data), case)

    def test_report_never_copies_sensitive_response_text_or_nested_values(self) -> None:
        manifest = measurements.preflight(self.arguments)
        marker = "/private/sensitive_measurement_marker"
        variants = (
            "omissions",
            "counts",
            "count_key",
            "mapped_regions",
            "address",
            "language_id",
        )
        for variant in variants:
            with self.subTest(variant=variant):

                def fake_run(
                    command: list[str],
                    *_args: Any,
                    selected_variant: str = variant,
                    **_kwargs: Any,
                ) -> measurements.supervisor.ProcessResult:
                    case = next(
                        case
                        for case in manifest["fixtures"]
                        if case["fixture"] == Path(command[3]).name
                    )
                    mode = "exact" if "--exact-entry" in command else "legacy"
                    result = json.loads(response(case, mode))
                    result["code"] += " /* " + marker + " */"
                    result["ignored_metadata"] = {marker: [marker]}
                    if selected_variant in ("address", "language_id"):
                        result[selected_variant] += marker
                    elif mode == "exact":
                        context = result["context"]
                        context["omissions"] = [marker]
                        if selected_variant == "counts":
                            context["counts"]["retained_symbols"] = {"path": marker}
                        elif selected_variant == "count_key":
                            context["counts"][marker] = 1
                        elif selected_variant == "mapped_regions":
                            context["mapped_regions"] = marker
                    return process_result(json.dumps(result).encode())

                with mock.patch.object(
                    measurements.supervisor, "run_process", side_effect=fake_run
                ):
                    report = measurements.measure(self.arguments, manifest)
                self.assertNotIn(marker, json.dumps(report))
                if variant == "omissions":
                    self.assertTrue(
                        all(row["status"] == "passed" for row in report["records"])
                    )
                    exact = next(
                        row for row in report["records"] if row["mode"] == "exact"
                    )
                    self.assertEqual(
                        exact["evidence"]["exact_context"]["omission_count"], 1
                    )
                    self.assertNotIn("omissions", exact["evidence"]["exact_context"])
                else:
                    self.assertTrue(
                        any(row["status"] == "failed" for row in report["records"])
                    )

    def test_missing_positive_rss_fails_measurement_but_keeps_source_evidence(
        self,
    ) -> None:
        manifest = measurements.preflight(self.arguments)
        for resident, samples in ((None, 1), (0, 1), (None, 0)):
            with self.subTest(resident=resident, samples=samples):

                def fake_run(
                    command: list[str],
                    *_args: Any,
                    resident_bytes: int | None = resident,
                    sample_count: int = samples,
                    **_kwargs: Any,
                ) -> measurements.supervisor.ProcessResult:
                    case = next(
                        case
                        for case in manifest["fixtures"]
                        if case["fixture"] == Path(command[3]).name
                    )
                    mode = "exact" if "--exact-entry" in command else "legacy"
                    result = process_result(response(case, mode))
                    result.max_observed_summed_rss_bytes = resident_bytes
                    result.rss_samples = sample_count
                    result.failure = (
                        "rss_sampling_unavailable" if sample_count == 0 else None
                    )
                    return result

                with mock.patch.object(
                    measurements.supervisor, "run_process", side_effect=fake_run
                ):
                    report = measurements.measure(self.arguments, manifest)
                for row in report["records"]:
                    self.assertEqual(row["status"], "failed")
                    self.assertEqual(row["failure"], "failed_missing_rss")
                    self.assertEqual(row["evidence"]["source_oracle"], "passed")
                    self.assertIsNone(row["rss"]["max_observed_summed_bytes"])

    def test_missing_and_zero_rss_are_null_not_a_fake_zero_peak(self) -> None:
        for resident, samples in ((None, 0), (0, 1), (4096, 0)):
            result = process_result()
            result.max_observed_summed_rss_bytes = resident
            result.rss_samples = samples
            row = measurements.observation(result)
            self.assertIsNone(row["rss"]["max_observed_summed_bytes"])
            self.assertEqual(row["rss"]["status"], "unavailable")
            self.assertNotIn("private-path", json.dumps(row))
        failure = measurements.observation(
            process_result(failure="guardian_exception: private-path")
        )
        self.assertEqual(failure["supervision_failure"], "supervision_error")
        self.assertNotIn("private-path", json.dumps(failure))

    def test_timeout_attempts_are_bounded_recorded_and_never_retried(self) -> None:
        manifest = measurements.preflight(self.arguments)
        with mock.patch.object(
            measurements.supervisor,
            "run_process",
            return_value=process_result(failure="external_deadline"),
        ) as run:
            report = measurements.measure(self.arguments, manifest)
        self.assertEqual(run.call_count, 6)
        self.assertEqual(len(report["records"]), 6)
        self.assertTrue(all(row["backend"] == "inline" for row in report["records"]))
        self.assertTrue(all(row["status"] == "failed" for row in report["records"]))
        for call in run.call_args_list:
            self.assertGreater(call.args[2], 0)
            self.assertLessEqual(call.args[2], 30)
            self.assertGreaterEqual(call.kwargs["stderr_limit"], 60000)
        self.assertEqual(sum(row["failed"] for row in report["summary"]), 6)
        self.assertNotIn("private-path", json.dumps(report))
        self.assertFalse(any(self.scratch.glob("entry-measurements-*")))

    def test_exhausted_budget_launches_no_child(self) -> None:
        manifest = measurements.preflight(self.arguments)
        with (
            mock.patch.object(
                measurements.time, "monotonic", side_effect=[0, *([121] * 7)]
            ),
            mock.patch.object(measurements.supervisor, "run_process") as run,
        ):
            report = measurements.measure(self.arguments, manifest)
        run.assert_not_called()
        self.assertTrue(all(row["status"] == "not_run" for row in report["records"]))

    def test_supervisor_exception_is_recorded_and_stops_further_launches(self) -> None:
        manifest = measurements.preflight(self.arguments)
        with mock.patch.object(
            measurements.supervisor, "run_process", side_effect=OSError("private-path")
        ) as run:
            report = measurements.measure(self.arguments, manifest)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(report["records"][0]["failure"], "supervision_exception")
        self.assertTrue(
            all(row["status"] == "not_run" for row in report["records"][1:])
        )
        self.assertNotIn("private-path", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
