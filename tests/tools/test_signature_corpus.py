"""Offline runner regressions; real compiler/evaluator measurements belong to the parent gate."""

from __future__ import annotations

import contextlib
import gzip
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any, BinaryIO
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[2] / "tools/signature-corpus.py"
SPEC = importlib.util.spec_from_file_location("signature_corpus_runner", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
corpus = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = corpus
SPEC.loader.exec_module(corpus)


def make_archive(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in entries:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))


def refresh_starter(path: Path, arch: str) -> None:
    shell = MODULE_PATH.with_name("gen-signatures.sh").read_text(encoding="utf-8")
    inline = shell.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    try:
        subprocess.run(
            [sys.executable, "-I", "-", str(path), arch],
            input=inline,
            text=True,
            capture_output=True,
            check=True,
            timeout=15,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError(error.stderr) from error


class FakeProducers:
    def __init__(
        self,
        version: str = "0.17.0",
        arch: str = "x86_64",
        fail_compile: bool = False,
        passed: bool = True,
        baseline_available: bool = True,
    ) -> None:
        self.version = version
        self.arch = arch
        self.fail_compile = fail_compile
        self.passed = passed
        self.baseline_available = baseline_available
        self.report_updates: dict[str, Any] = {}
        self.calls: list[list[str]] = []

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        stdout: BinaryIO,
        stderr: BinaryIO,
        check: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(argv)
        tool = Path(argv[0]).name
        code = 0
        text = ""
        if tool == "zig" and argv[1:] == ["version"]:
            text = self.version
        elif tool == "zig" and argv[1] == "cc":
            if self.fail_compile:
                code = 3
                stderr.write(b"fake compilation rejected\n")
            else:
                Path(argv[argv.index("-o") + 1]).write_bytes(" ".join(argv).encode())
        elif tool == "zig" and argv[1] == "ar":
            Path(argv[3]).write_bytes(b"fake library archive")
        elif tool == "eval" and argv[1] == "artifact-info":
            stripped = "stripped" in argv[2]
            text = json.dumps(
                {
                    "format": "elf",
                    "arch": self.arch,
                    "static_function_symbols": 0 if stripped else 10,
                    "dynamic_function_symbols": 0,
                    "debug_sections": [],
                }
            )
        elif tool == "eval" and argv[1] == "strip":
            Path(argv[3]).write_bytes(Path(argv[2]).read_bytes())
        elif tool == "builder":
            database = Path(argv[argv.index("--output") + 1])
            database.write_text('{"fake": true}', encoding="utf-8")
            database.with_suffix(".json.gz").write_bytes(
                gzip.compress(database.read_bytes(), mtime=0)
            )
            truth = {
                f"0x{0x401000 + index * 16:x}": f"public_library_{index}"
                for index in range(10)
            }
            baseline = {
                "correct": 0,
                "wrong": 0,
                "missed": 10,
                "spurious": 0,
                "recall": 0.0,
                "precision": 0.0,
            }
            after = {
                "correct": 10 if self.passed else 7,
                "wrong": 0,
                "missed": 0 if self.passed else 3,
                "spurious": 0,
                "recall": 1.0 if self.passed else 0.7,
                "precision": 1.0,
            }
            report = {
                "schema_version": 1,
                "measurement": "phase2-1-library-signatures",
                "arch": self.arch,
                "baseline_available": self.baseline_available,
                "passed": self.passed,
                "baseline": baseline,
                "after": after,
                "library_truth": truth,
                "truth_functions": len(truth),
                "ownership_scope": "unique strong global definitions only; local/weak functions excluded",
                "matched_version_recall_gate": 0.8,
                "target_executed": False,
                "load_image_equivalent_stripped_twin": True,
                "reference_sha256": corpus.sha256(
                    Path(argv[argv.index("--reference") + 1])
                ),
                "symbolized_target_sha256": corpus.sha256(
                    Path(argv[argv.index("--target") + 1])
                ),
                "stripped_target_sha256": corpus.sha256(
                    Path(argv[argv.index("--stripped") + 1])
                ),
                "database_sha256": corpus.sha256(database),
                "compressed_database_sha256": corpus.sha256(
                    database.with_suffix(".json.gz")
                ),
            }
            report.update(self.report_updates)
            corpus.write_json(Path(argv[argv.index("--report") + 1]), report)
            code = 0 if self.passed else 1
        else:
            raise AssertionError(
                f"unexpected command, possibly target execution: {argv}"
            )
        stdout.write(text.encode())
        return subprocess.CompletedProcess(argv, code)


class SignatureCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="signature-corpus-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def fixture(self) -> tuple[dict[str, Any], Any, Path]:
        recipe = dict(corpus.load_manifest()["libraries"]["zlib"])
        recipe["sources"] = ["adler32.c", "crc32.c"]
        archive = self.base / recipe["archive"]
        make_archive(
            archive,
            [
                (f"{recipe['root']}/adler32.c", b"int library_one(void) { return 1; }"),
                (f"{recipe['root']}/crc32.c", b"int library_two(void) { return 2; }"),
                (f"{recipe['root']}/LICENSE", b"test license"),
            ],
        )
        recipe["sha256"] = corpus.sha256(archive)
        paths: dict[str, str] = {}
        for name in ("zig", "eval", "builder"):
            tool = self.base / name
            tool.write_text(f"fake {name}", encoding="utf-8")
            paths[name] = str(tool)
        args = corpus.parser().parse_args(
            [
                "--source-cache",
                str(self.base),
                "--zig",
                paths["zig"],
                "--eval",
                paths["eval"],
                "--builder",
                paths["builder"],
            ]
        )
        return recipe, args, self.base / "slice"

    def test_manifest_rejects_version_and_path_changes(self) -> None:
        for field, value in (("version", "future"), ("sources", ["../outside.c"])):
            with self.subTest(field=field):
                manifest = corpus.load_manifest()
                manifest["libraries"]["zlib"][field] = value
                path = self.base / "recipes.json"
                corpus.write_json(path, manifest)
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_manifest(path)

    def test_list_has_no_outputs_or_tool_invocations(self) -> None:
        output = self.base / "target/signature-corpus/list"
        with (
            contextlib.redirect_stdout(io.StringIO()),
            mock.patch.object(corpus.subprocess, "run") as run,
        ):
            code = corpus.main(["--list", "--output-dir", str(output)])
        self.assertEqual(code, 0)
        self.assertFalse(output.exists())
        run.assert_not_called()

    def test_selection_is_explicit_deduplicated_and_bounded(self) -> None:
        args = corpus.parser().parse_args(
            [
                "--only",
                "lz4",
                "--only",
                "lua",
                "--only",
                "lz4",
                "--target",
                "aarch64-linux-musl",
                "--optimization",
                "O2",
            ]
        )
        rows = corpus.select(args)
        self.assertEqual([row.library for row in rows], ["lz4", "lua"])
        self.assertTrue(
            all(
                row.target == "aarch64-linux-musl" and row.optimization == "O2"
                for row in rows
            )
        )
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            corpus.parser().parse_args(["--only", "untrusted"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            corpus.parser().parse_args(["--baseline-db", "custom.json"])

    def test_output_refuses_nonempty_and_fixture_paths(self) -> None:
        with self.assertRaises(corpus.CorpusError):
            corpus.prepare_output(self.base / "fixtures")
        output = self.base / "target/signature-corpus/pilot"
        corpus.prepare_output(output)
        marker = output / "user-work"
        marker.write_text("keep", encoding="utf-8")
        with self.assertRaises(corpus.CorpusError):
            corpus.prepare_output(output)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_missing_pin_and_corruption_fail_before_any_producer(self) -> None:
        for pin in (None, "0" * 64):
            with self.subTest(pin=pin):
                recipe, args, directory = self.fixture()
                recipe["sha256"] = pin
                with mock.patch.object(corpus.subprocess, "run") as run:
                    result = corpus.build_slice(
                        corpus.Selection("zlib", corpus.TARGETS[0], "O1"),
                        recipe,
                        args,
                        directory,
                    )
                self.assertEqual(result["status"], "failed")
                run.assert_not_called()
                directory.rename(self.base / f"failed-{pin}")

    def test_archive_preflight_refuses_traversal_and_links(self) -> None:
        for name in ("root/../../escape", "/absolute", "other/file"):
            with self.subTest(name=name):
                archive = self.base / "unsafe.tar.gz"
                make_archive(archive, [(name, b"not extracted")])
                with self.assertRaises(corpus.CorpusError):
                    corpus.extract_archive(archive, self.base / "extraction", "root")
                self.assertFalse((self.base / "extraction").exists())
        archive = self.base / "link.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            link = tarfile.TarInfo("root/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../escape"
            stream.addfile(link)
        with self.assertRaises(corpus.CorpusError):
            corpus.extract_archive(archive, self.base / "extraction", "root")

    def test_fake_pipeline_uses_only_builder_public_truth_and_measurements(
        self,
    ) -> None:
        recipe, args, directory = self.fixture()
        fake = FakeProducers()
        with (
            mock.patch.object(corpus, "executable", side_effect=lambda value: value),
            mock.patch.object(
                corpus.subprocess,
                "run",
                side_effect=fake.run,
            ),
        ):
            result = corpus.build_slice(
                corpus.Selection("zlib", corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "measured", result)
        self.assertEqual(result["link_policy"], "full_library_gc_disabled")
        links = [call for call in fake.calls if call[1] == "cc" and "-c" not in call]
        self.assertEqual(len(links), 2)
        for link in links:
            self.assertIn("-Wl,--no-gc-sections", link)
            self.assertNotIn("-Wl,--gc-sections", link)
            archive_start = link.index("-Wl,--whole-archive")
            self.assertTrue(link[archive_start + 1].endswith("libzlib.a"))
            self.assertEqual(link[archive_start + 2], "-Wl,--no-whole-archive")
        builder = next(call for call in fake.calls if Path(call[0]).name == "builder")
        owned = [
            builder[index + 1]
            for index, flag in enumerate(builder)
            if flag == "--object"
        ]
        self.assertEqual(len(owned), 2)
        self.assertTrue(all(Path(path).name.startswith("library-") for path in owned))
        self.assertNotIn("main", builder)
        strip_index = next(
            index for index, call in enumerate(fake.calls) if call[1] == "strip"
        )
        self.assertLess(strip_index, fake.calls.index(builder))
        self.assertFalse(any(call[1] in ("truth", "run") for call in fake.calls))
        builder_report = result["builder_report"]
        self.assertEqual(
            result["measurements"]["baseline"]["evaluation"], builder_report["baseline"]
        )
        self.assertEqual(
            result["measurements"]["new"]["evaluation"], builder_report["after"]
        )
        self.assertEqual(
            json.loads((directory / "truth.json").read_text(encoding="utf-8")),
            builder_report["library_truth"],
        )
        self.assertTrue(result["measurements"]["new"]["gate_passed"])
        self.assertIn("db.json.gz", result["artifacts"])
        commands = json.loads((directory / "commands.json").read_text(encoding="utf-8"))
        self.assertTrue(
            all(
                "returncode" in command and "environment" in command
                for command in commands
            )
        )

    def test_wrong_version_headers_and_compile_failure_are_not_green(self) -> None:
        for fake in (
            FakeProducers(version="0.17.1"),
            FakeProducers(arch="aarch64"),
            FakeProducers(fail_compile=True),
        ):
            recipe, args, directory = self.fixture()
            with (
                mock.patch.object(
                    corpus, "executable", side_effect=lambda value: value
                ),
                mock.patch.object(
                    corpus.subprocess,
                    "run",
                    side_effect=fake.run,
                ),
            ):
                result = corpus.build_slice(
                    corpus.Selection("zlib", corpus.TARGETS[0], "O1"),
                    recipe,
                    args,
                    directory,
                )
            self.assertEqual(result["status"], "failed", result)
            directory.rename(
                self.base / f"failure-{fake.version}-{fake.arch}-{fake.fail_compile}"
            )

    def test_unavailable_bundled_baseline_is_a_valid_empty_measurement(self) -> None:
        recipe, args, directory = self.fixture()
        fake = FakeProducers(baseline_available=False)
        with (
            mock.patch.object(corpus, "executable", side_effect=lambda value: value),
            mock.patch.object(
                corpus.subprocess,
                "run",
                side_effect=fake.run,
            ),
        ):
            result = corpus.build_slice(
                corpus.Selection("zlib", corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "measured", result)
        self.assertFalse(result["measurements"]["baseline"]["available"])
        self.assertEqual(result["measurements"]["baseline"]["evaluation"]["correct"], 0)
        self.assertEqual(result["measurements"]["new"]["status"], "measured")

    def test_exit_one_preserves_failed_measurements_and_propagates_failure(
        self,
    ) -> None:
        recipe, args, _ = self.fixture()
        manifest = corpus.load_manifest()
        manifest["libraries"]["zlib"] = recipe
        output = self.base / "target/signature-corpus/failed-gate"
        fake = FakeProducers(passed=False)
        with (
            mock.patch.object(corpus, "load_manifest", return_value=manifest),
            mock.patch.object(
                corpus,
                "executable",
                side_effect=lambda value: value,
            ),
            mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = corpus.main(
                [
                    "--source-cache",
                    str(self.base),
                    "--output-dir",
                    str(output),
                    "--zig",
                    args.zig,
                    "--eval",
                    args.evaluator,
                    "--builder",
                    args.builder,
                ]
            )
        self.assertEqual(code, 1)
        inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(inventory["link_policy"], "full_library_gc_disabled")
        result = next(iter(inventory["slices"].values()))
        self.assertEqual(result["status"], "measured_failed", result)
        self.assertFalse(result["builder_report"]["passed"])
        self.assertEqual(result["measurements"]["new"]["evaluation"]["recall"], 0.7)
        self.assertIn("db.json.gz", result["artifacts"])
        self.assertIn("builder-report.json", result["artifacts"])

    def test_invalid_builder_schema_truth_gate_or_artifact_hash_is_not_green(
        self,
    ) -> None:
        changes = [
            {"schema_version": 2},
            {"library_truth": {}},
            {"baseline_available": "false"},
            {"matched_version_recall_gate": 0.0},
            {"database_sha256": "0" * 64},
            {
                "after": {
                    "correct": 7,
                    "wrong": 0,
                    "missed": 3,
                    "spurious": 0,
                    "precision": 1.0,
                    "recall": 0.7,
                }
            },
            {
                "after": {
                    "correct": 9,
                    "wrong": 1,
                    "missed": 0,
                    "spurious": 0,
                    "precision": 0.9,
                    "recall": 0.9,
                }
            },
            {
                "after": {
                    "correct": 10,
                    "wrong": 0,
                    "missed": 0,
                    "spurious": 1,
                    "precision": 0.9,
                    "recall": 1.0,
                }
            },
            {
                "after": {
                    "correct": 0,
                    "wrong": 0,
                    "missed": 10,
                    "spurious": 0,
                    "precision": 0.0,
                    "recall": 1.0,
                }
            },
            {
                "after": {
                    "correct": 10,
                    "wrong": 0,
                    "missed": 0,
                    "spurious": 0,
                    "precision": 0.0,
                    "recall": 1.0,
                }
            },
            {
                "baseline": {
                    "correct": 0,
                    "wrong": 0,
                    "missed": 10,
                    "spurious": 0,
                    "precision": 1.0,
                    "recall": 0.0,
                }
            },
        ]
        for index, change in enumerate(changes):
            with self.subTest(change=change):
                recipe, args, directory = self.fixture()
                fake = FakeProducers()
                fake.report_updates = change
                with (
                    mock.patch.object(
                        corpus, "executable", side_effect=lambda value: value
                    ),
                    mock.patch.object(
                        corpus.subprocess,
                        "run",
                        side_effect=fake.run,
                    ),
                ):
                    result = corpus.build_slice(
                        corpus.Selection("zlib", corpus.TARGETS[0], "O1"),
                        recipe,
                        args,
                        directory,
                    )
                self.assertEqual(result["status"], "failed", result)
                self.assertIn("builder-report.json", result["artifacts"])
                directory.rename(self.base / f"invalid-report-{index}")

    def test_count_derived_recall_gate_accepts_exactly_eighty_percent(self) -> None:
        recipe, args, directory = self.fixture()
        fake = FakeProducers()
        fake.report_updates = {
            "after": {
                "correct": 8,
                "wrong": 0,
                "missed": 2,
                "spurious": 0,
                "precision": 1.0,
                "recall": 0.8,
            },
        }
        with (
            mock.patch.object(corpus, "executable", side_effect=lambda value: value),
            mock.patch.object(
                corpus.subprocess,
                "run",
                side_effect=fake.run,
            ),
        ):
            result = corpus.build_slice(
                corpus.Selection("zlib", corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "measured", result)

    def test_windows_is_explicitly_unsupported_without_producers(self) -> None:
        recipe, args, directory = self.fixture()
        with mock.patch.object(corpus.subprocess, "run") as run:
            result = corpus.build_slice(
                corpus.Selection("zlib", "x86_64-windows-gnu", "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "unsupported")
        run.assert_not_called()

    def test_legacy_refresh_synchronizes_deterministic_gzip_and_counts(self) -> None:
        path = self.base / "musl-x86_64.json"
        database = {
            "arch": "x86_64",
            "scheme": 2,
            "entries": {"hash-a": "one", "hash-b": "two"},
            "exact": {"exact-a": "three"},
            "calls": {"calls-a": "four"},
        }
        corpus.write_json(path, database)
        refresh_starter(path, "x86_64")
        compressed = path.with_suffix(".json.gz").read_bytes()
        self.assertEqual(gzip.decompress(compressed), path.read_bytes())
        self.assertEqual(compressed[4:8], b"\0\0\0\0")
        self.assertEqual(compressed[3] & 8, 0)
        self.assertEqual(path.with_suffix(".counts").read_bytes(), b"3 1\n")
        refresh_starter(path, "x86_64")
        self.assertEqual(path.with_suffix(".json.gz").read_bytes(), compressed)
        self.assertEqual(
            sorted(item.name for item in self.base.iterdir()),
            [
                "musl-x86_64.counts",
                "musl-x86_64.json",
                "musl-x86_64.json.gz",
            ],
        )

    def test_legacy_refresh_invalid_database_preserves_published_artifacts(
        self,
    ) -> None:
        path = self.base / "musl-x86_64.json"
        compressed = path.with_suffix(".json.gz")
        counts = path.with_suffix(".counts")
        compressed.write_bytes(b"previous gzip")
        counts.write_bytes(b"previous counts")
        for raw in (
            b"not json",
            b"[]",
            b'{"arch":"aarch64","scheme":2,"entries":{}}',
            b'{"arch":"x86_64","scheme":3,"entries":{}}',
            b'{"arch":"x86_64","scheme":2,"entries":[],"calls":{}}',
        ):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    refresh_starter(path, "x86_64")
                self.assertEqual(compressed.read_bytes(), b"previous gzip")
                self.assertEqual(counts.read_bytes(), b"previous counts")
                self.assertEqual(len(list(self.base.iterdir())), 3)


if __name__ == "__main__":
    unittest.main()
