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

    def fixture(self, library: str = "zlib") -> tuple[dict[str, Any], Any, Path]:
        recipe = dict(corpus.load_manifest()["libraries"][library])
        if library == "zlib":
            recipe["sources"] = ["adler32.c", "crc32.c"]
        archive = self.base / recipe["archive"]
        entries = [
            (
                f"{recipe['root']}/{source}",
                f"int library_{index}(void) {{ return {index}; }}".encode(),
            )
            for index, source in enumerate(recipe["sources"])
        ]
        if recipe["license_file"] not in recipe["sources"]:
            entries.append(
                (f"{recipe['root']}/{recipe['license_file']}", b"test license")
            )
        make_archive(archive, entries)
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
        stdout = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            mock.patch.object(corpus.subprocess, "run") as run,
        ):
            code = corpus.main(["--list", "--output-dir", str(output)])
        self.assertEqual(code, 0)
        self.assertFalse(output.exists())
        run.assert_not_called()
        sqlite = corpus.load_manifest()["libraries"]["sqlite"]
        pin = sqlite["sha256"] or "PENDING_SHA256"
        self.assertIn(f"sqlite {sqlite['version']} sha256={pin}", stdout.getvalue())
        self.assertIn("6 families, 10 profile aliases", stdout.getvalue())
        self.assertIn("not a broad Phase 2 coverage claim", stdout.getvalue())
        self.assertIn("not typical production-config coverage", stdout.getvalue())

    def test_selection_is_explicit_deduplicated_and_bounded(self) -> None:
        args = corpus.parser().parse_args(
            [
                "--only",
                "lz4",
                "--only",
                "lua",
                "--only",
                "sqlite",
                "--only",
                "lz4",
                "--target",
                "aarch64-linux-musl",
                "--optimization",
                "O2",
            ]
        )
        rows = corpus.select(args)
        self.assertEqual([row.library for row in rows], ["lz4", "lua", "sqlite"])
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

    def test_versioned_selection_preserves_defaults_and_distinct_slice_names(
        self,
    ) -> None:
        default = corpus.select(corpus.parser().parse_args([]))
        self.assertEqual(default, [corpus.Selection("zlib", corpus.TARGETS[0], "O1")])
        profiles = [
            "zlib",
            "zlib-1.2.13",
            "lz4-1.9.4",
            "lua-5.4.8",
            "sqlite-3.45.3",
            "zstd-1.5.6",
            "mbedtls-2.28.9",
        ]
        args = corpus.parser().parse_args(
            [
                item
                for profile in [*profiles, "zlib-1.2.13"]
                for item in ("--only", profile)
            ]
        )
        rows = corpus.select(args)
        self.assertEqual([row.library for row in rows], profiles)
        self.assertEqual(len({row.name for row in rows}), len(profiles))
        for profile in ("zlib-1.2.12", "lua-5.4.9", "../zlib"):
            with (
                self.subTest(profile=profile),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                corpus.parser().parse_args(["--only", profile])

    def test_versioned_manifest_rejects_wrong_version_family_and_paths(self) -> None:
        invalid = (
            ("version", "1.3.1"),
            ("harness", "lua"),
            ("harness", "untrusted"),
            ("harness", "../zlib"),
            ("harness", "/zlib"),
            ("harness", None),
            ("root", "../zlib-1.2.13"),
            ("root", "/zlib-1.2.13"),
            ("root", "nested/zlib-1.2.13"),
            ("root", "."),
            ("archive", "nested/zlib-1.2.13.tar.gz"),
            ("sources", ["../adler32.c"]),
            ("include", "../include"),
            ("license_file", "../LICENSE"),
        )
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                manifest = corpus.load_manifest()
                manifest["libraries"]["zlib-1.2.13"][field] = value
                path = self.base / "recipes.json"
                corpus.write_json(path, manifest)
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_manifest(path)
        manifest = corpus.load_manifest()
        del manifest["libraries"]["zlib-1.2.13"]["harness"]
        path = self.base / "recipes.json"
        corpus.write_json(path, manifest)
        with self.assertRaises(corpus.CorpusError):
            corpus.load_manifest(path)

    def test_harness_rejects_unknown_profiles_and_cross_family_overrides(self) -> None:
        for profile, recipe in (
            ("untrusted", {"harness": "zlib"}),
            ("zlib", {"harness": "sqlite"}),
            ("zlib-1.2.13", {"harness": "../zlib"}),
            ("zstd-1.5.6", {"harness": "../zstd"}),
            ("zstd-1.5.6", {"harness": "mbedtls"}),
            ("mbedtls-2.28.9", {"harness": "/mbedtls"}),
            ("mbedtls-2.28.9", {"harness": "zstd"}),
            ("zstd", {"harness": "zstd"}),
        ):
            with (
                self.subTest(profile=profile, recipe=recipe),
                self.assertRaises(corpus.CorpusError),
            ):
                corpus.harness_family(profile, recipe)

    def test_new_profiles_reject_identity_family_and_version_changes(self) -> None:
        for profile in ("zstd-1.5.6", "mbedtls-2.28.9"):
            for field, value in (
                ("id", "untrusted"),
                ("family", "untrusted"),
                ("version", "future"),
                ("sources", ["../outside.c"]),
            ):
                with self.subTest(profile=profile, field=field):
                    manifest = corpus.load_manifest()
                    manifest["libraries"][profile][field] = value
                    path = self.base / "recipes.json"
                    corpus.write_json(path, manifest)
                    with self.assertRaises(corpus.CorpusError):
                        corpus.load_manifest(path)

    def test_invalid_root_is_rejected_before_archive_access(self) -> None:
        for root in ("..", ".", "nested/root", "/root", "root\\outside"):
            with self.subTest(root=root), self.assertRaises(corpus.CorpusError):
                corpus.extract_archive(
                    self.base / "missing.tar.gz", self.base / "extraction", root
                )
        self.assertFalse((self.base / "extraction").exists())

    def test_sqlite_manifest_rejects_unpinned_versions_and_malformed_hashes(
        self,
    ) -> None:
        for field, value in (
            ("version", "3.46.2"),
            ("sha256", "pending"),
            ("sha256", "a" * 63),
            ("sha256", "A" * 64),
        ):
            with self.subTest(field=field, value=value):
                manifest = corpus.load_manifest()
                manifest["libraries"]["sqlite"][field] = value
                path = self.base / "recipes.json"
                corpus.write_json(path, manifest)
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_manifest(path)

    def test_sqlite_pending_pin_is_valid_but_blocks_production(self) -> None:
        manifest = corpus.load_manifest()
        manifest["libraries"]["sqlite"]["sha256"] = None
        path = self.base / "recipes.json"
        corpus.write_json(path, manifest)
        recipe = corpus.load_manifest(path)["libraries"]["sqlite"]
        with self.assertRaisesRegex(
            corpus.CorpusError, "pin is pending; no download attempted"
        ):
            corpus.checked_archive(self.base, recipe)

    def test_manifest_still_rejects_arbitrary_recipe_rosters(self) -> None:
        manifest = corpus.load_manifest()
        manifest["libraries"]["untrusted"] = manifest["libraries"].pop("sqlite")
        path = self.base / "recipes.json"
        corpus.write_json(path, manifest)
        with self.assertRaises(corpus.CorpusError):
            corpus.load_manifest(path)

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

    def test_scoped_archive_skips_unselected_links_without_materializing_tests(
        self,
    ) -> None:
        archive = self.base / "scoped.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for name in ("root/lib/common/unit.c", "root/LICENSE", "root/COPYING"):
                member = tarfile.TarInfo(name)
                member.size = len(b"selected bytes")
                stream.addfile(member, io.BytesIO(b"selected bytes"))
            link = tarfile.TarInfo("root/tests/cli-tests/bin/unzstd")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../../../outside"
            stream.addfile(link)
        destination = self.base / "extraction"
        root = corpus.extract_archive(
            archive, destination, "root", ["lib", "LICENSE", "COPYING"]
        )
        self.assertEqual(root, destination / "root")
        self.assertEqual((root / "lib/common/unit.c").read_bytes(), b"selected bytes")
        self.assertTrue((root / "LICENSE").is_file())
        self.assertTrue((root / "COPYING").is_file())
        self.assertFalse((root / "tests").exists())
        self.assertFalse(any(path.is_symlink() for path in destination.rglob("*")))

    def test_scoped_archive_rejects_selected_links_and_special_files(self) -> None:
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                archive = self.base / "selected-link.tar.gz"
                with tarfile.open(archive, "w:gz") as stream:
                    member = tarfile.TarInfo("root/lib/link")
                    member.type = kind
                    member.linkname = "root/lib/other"
                    stream.addfile(member)
                with self.assertRaises(corpus.CorpusError):
                    corpus.extract_archive(
                        archive, self.base / "extraction", "root", ["lib"]
                    )
                self.assertFalse((self.base / "extraction").exists())

    def test_scoped_archive_checks_all_names_duplicates_and_budgets(self) -> None:
        oversized = tarfile.TarInfo("root/tests/oversized")
        oversized.size = 128 * 1024 * 1024 + 1
        cases = [
            [tarfile.TarInfo("root/tests/../../outside")],
            [tarfile.TarInfo("other/tests/file")],
            [tarfile.TarInfo("root/tests/duplicate") for _ in range(2)],
            [oversized],
            [tarfile.TarInfo(f"root/tests/{index}") for index in range(10001)],
        ]
        for index, members in enumerate(cases):
            with (
                self.subTest(case=index),
                mock.patch.object(corpus.tarfile, "open") as opened,
            ):
                opened.return_value.__enter__.return_value = members
                with self.assertRaises(corpus.CorpusError):
                    corpus.extract_archive(
                        self.base / "scoped.tar.gz",
                        self.base / "extraction",
                        "root",
                        ["lib"],
                    )
                self.assertFalse((self.base / "extraction").exists())

    def test_archive_rejects_negative_sizes_before_budgeting_or_materialization(
        self,
    ) -> None:
        for roots in (None, ["lib"]):
            for name in ("root/lib/negative", "root/tests/link"):
                with self.subTest(roots=roots, name=name):
                    negative = tarfile.TarInfo(name)
                    negative.size = -128 * 1024 * 1024
                    if "/tests/" in name:
                        negative.type = tarfile.SYMTYPE
                        negative.linkname = "unused"
                    payload = tarfile.TarInfo("root/lib/payload.c")
                    payload.size = 200 * 1024 * 1024
                    source = mock.MagicMock()
                    source.__iter__.return_value = iter([negative, payload])
                    destination = self.base / "extraction"
                    with mock.patch.object(corpus.tarfile, "open") as opened:
                        opened.return_value.__enter__.return_value = source
                        with self.assertRaisesRegex(
                            corpus.CorpusError, "negative size"
                        ):
                            corpus.extract_archive(
                                self.base / "negative.tar.gz",
                                destination,
                                "root",
                                roots,
                            )
                    source.extractfile.assert_not_called()
                    self.assertFalse(destination.exists())

    def test_manifest_rejects_unsafe_or_incomplete_materialization_scopes(self) -> None:
        invalid_roots = (
            None,
            [],
            [""],
            [" "],
            ["."],
            ["../lib"],
            ["/lib"],
            ["lib/common"],
            ["lib", "lib"],
            ["lib", 1],
            ["lib"],
        )
        for roots in invalid_roots:
            with self.subTest(roots=roots):
                manifest = corpus.load_manifest()
                manifest["libraries"]["zstd-1.5.6"]["extract_roots"] = roots
                path = self.base / "recipes.json"
                corpus.write_json(path, manifest)
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_manifest(path)
        for field, value in (
            ("sources", ["tests/outside.c"]),
            ("license_file", "docs/LICENSE"),
            ("include", "include"),
        ):
            with self.subTest(field=field):
                recipe, args, directory = self.fixture("zstd-1.5.6")
                recipe[field] = value
                manifest = corpus.load_manifest()
                manifest["libraries"]["zstd-1.5.6"] = recipe
                path = self.base / "recipes.json"
                corpus.write_json(path, manifest)
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_manifest(path)
                with (
                    mock.patch.object(corpus, "extract_archive") as extract,
                    mock.patch.object(corpus.subprocess, "run") as run,
                ):
                    result = corpus.build_slice(
                        corpus.Selection("zstd-1.5.6", corpus.TARGETS[0], "O1"),
                        recipe,
                        args,
                        directory.with_name(field),
                    )
                self.assertEqual(result["status"], "failed", result)
                self.assertIn("outside extract_roots", result["reason"])
                extract.assert_not_called()
                run.assert_not_called()
        manifest = corpus.load_manifest()
        manifest["libraries"]["zlib"]["extract_roots"] = ["lib", "LICENSE"]
        path = self.base / "recipes.json"
        corpus.write_json(path, manifest)
        with self.assertRaises(corpus.CorpusError):
            corpus.load_manifest(path)

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

    def test_sqlite_pipeline_compiles_only_amalgamation_and_retains_full_profile(
        self,
    ) -> None:
        recipe, args, directory = self.fixture("sqlite")
        fake = FakeProducers()
        with (
            mock.patch.object(corpus, "executable", side_effect=lambda value: value),
            mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
        ):
            result = corpus.build_slice(
                corpus.Selection("sqlite", corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "measured", result)
        self.assertEqual(result["link_policy"], "full_library_gc_disabled")
        compilations = [call for call in fake.calls if call[1] == "cc" and "-c" in call]
        sources = [Path(call[call.index("-c") + 1]) for call in compilations]
        self.assertEqual(
            [source.name for source in sources],
            ["sqlite3.c", "signature-sqlite-reference.c", "signature-sqlite-target.c"],
        )
        for compilation in compilations:
            self.assertIn("-DSQLITE_THREADSAFE=0", compilation)
            self.assertIn("-DSQLITE_OMIT_LOAD_EXTENSION", compilation)
            self.assertEqual(
                Path(compilation[compilation.index("-I") + 1]),
                directory / "source" / recipe["root"],
            )
        links = [call for call in fake.calls if call[1] == "cc" and "-c" not in call]
        self.assertEqual(len(links), 2)
        for link in links:
            self.assertIn("-Wl,--no-gc-sections", link)
            self.assertNotIn("-Wl,--gc-sections", link)
            archive_start = link.index("-Wl,--whole-archive")
            self.assertEqual(Path(link[archive_start + 1]).name, "libsqlite.a")
            self.assertEqual(link[archive_start + 2], "-Wl,--no-whole-archive")
        builder = next(call for call in fake.calls if Path(call[0]).name == "builder")
        owned = [
            Path(builder[index + 1]).name
            for index, flag in enumerate(builder)
            if flag == "--object"
        ]
        self.assertEqual(owned, ["library-00.o"])
        self.assertEqual(
            result["source_sha256"], {"sqlite3.c": corpus.sha256(sources[0])}
        )
        self.assertEqual(result["license_sha256"], result["source_sha256"]["sqlite3.c"])
        self.assertNotEqual(
            result["harness_sha256"]["reference"], result["harness_sha256"]["target"]
        )
        self.assertIn("db.json.gz", result["artifacts"])

    def test_versioned_pipeline_reuses_family_harness_and_profile_sources(self) -> None:
        for profile in corpus.VERSIONED_FAMILIES:
            with self.subTest(profile=profile):
                recipe, args, directory = self.fixture(profile)
                family = recipe["harness"]
                selection = corpus.Selection(profile, corpus.TARGETS[0], "O1")
                directory = directory.with_name(selection.name)
                fake = FakeProducers()
                if family == "mbedtls":
                    fake.report_updates["library_truth"] = {
                        f"0x{0x401000 + index * 16:x}": (
                            "mbedtls_aes_self_test"
                            if index == 0
                            else f"public_library_{index}"
                        )
                        for index in range(10)
                    }
                with (
                    mock.patch.object(
                        corpus, "executable", side_effect=lambda value: value
                    ),
                    mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
                ):
                    result = corpus.build_slice(selection, recipe, args, directory)
                self.assertEqual(result["status"], "measured", result)
                self.assertEqual(result["selection"]["library"], profile)
                if family == "zstd":
                    self.assertEqual(result["archive_sha256"], recipe["sha256"])
                    self.assertEqual(
                        result["materialization"]["archive_root"], recipe["root"]
                    )
                    self.assertEqual(
                        result["materialization"]["extract_roots"],
                        recipe["extract_roots"],
                    )
                    source = directory / "source" / recipe["root"]
                    self.assertEqual(
                        {path.name for path in source.iterdir()}, {"lib", "LICENSE"}
                    )
                self.assertEqual(result["recipe"]["version"], recipe["version"])
                self.assertEqual(set(result["source_sha256"]), set(recipe["sources"]))
                compilations = [
                    call for call in fake.calls if call[1] == "cc" and "-c" in call
                ]
                units = [Path(call[call.index("-c") + 1]) for call in compilations]
                self.assertEqual(
                    units[:-2],
                    [
                        directory / "source" / recipe["root"] / unit
                        for unit in recipe["sources"]
                    ],
                )
                self.assertEqual(
                    units[-2:],
                    [
                        corpus.ROOT / f"tests/fixtures/src/signature-{family}-{role}.c"
                        for role in ("reference", "target")
                    ],
                )
                for role, unit in zip(("reference", "target"), units[-2:]):
                    self.assertEqual(
                        result["harness_sha256"][role], corpus.sha256(unit)
                    )
                for compilation in compilations:
                    for define in recipe["defines"]:
                        self.assertIn(f"-D{define}", compilation)
                archive = next(call for call in fake.calls if call[1] == "ar")
                self.assertEqual(Path(archive[3]).name, f"lib{profile}.a")
                if family == "mbedtls":
                    truth = json.loads(
                        (directory / "truth.json").read_text(encoding="utf-8")
                    )
                    self.assertIn("mbedtls_aes_self_test", truth.values())
                    self.assertEqual(
                        result["builder_report"]["truth_functions"], len(truth)
                    )
                    self.assertEqual(
                        result["measurements"]["new"]["evaluation"]["correct"],
                        len(truth),
                    )
                    for compilation in compilations:
                        self.assertFalse(
                            any(flag.startswith("-DMBEDTLS_") for flag in compilation)
                        )

    def test_new_profile_scope_is_printed_before_any_producer_measurement(self) -> None:
        manifest = corpus.load_manifest()
        for profile in ("zstd-1.5.6", "mbedtls-2.28.9"):
            with self.subTest(profile=profile):
                stdout = io.StringIO()
                output = self.base / "target/signature-corpus" / profile

                def measured(
                    selection: Any,
                    recipe: dict[str, Any],
                    args: Any,
                    directory: Path,
                    *,
                    expected_profile: str = profile,
                    seen_stdout: io.StringIO = stdout,
                ) -> dict[str, str]:
                    self.assertEqual(selection.library, expected_profile)
                    self.assertIn(
                        f"{expected_profile} scope: {recipe['scope']}",
                        seen_stdout.getvalue(),
                    )
                    self.assertNotIn(": measured", seen_stdout.getvalue())
                    return {"status": "measured"}

                with (
                    mock.patch.object(
                        corpus, "build_slice", side_effect=measured
                    ) as build,
                    mock.patch.object(corpus.subprocess, "run") as run,
                    contextlib.redirect_stdout(stdout),
                ):
                    code = corpus.main(
                        [
                            "--only",
                            profile,
                            "--archive-cache",
                            str(self.base),
                            "--output-dir",
                            str(output),
                        ]
                    )
                self.assertEqual(code, 0)
                run.assert_not_called()
                build.assert_called_once()
                inventory = json.loads(
                    (output / "inventory.json").read_text(encoding="utf-8")
                )
                selection = corpus.Selection(profile, corpus.TARGETS[0], "O1")
                self.assertEqual(list(inventory["slices"]), [selection.name])
                copied = json.loads(
                    (output / "recipes.json").read_text(encoding="utf-8")
                )
                self.assertEqual(copied, manifest)

    def test_new_profile_fragments_retain_pins_sources_licenses_and_scope(self) -> None:
        manifest = corpus.load_manifest()
        for profile in ("zstd-1.5.6", "mbedtls-2.28.9"):
            with self.subTest(profile=profile):
                path = corpus.MANIFEST.with_name(f"{profile}.recipe.json")
                fragment = json.loads(path.read_text(encoding="utf-8"))
                recipe = manifest["libraries"][profile]
                for field, value in fragment.items():
                    if field == "build_condition":
                        self.assertTrue(recipe[field].startswith(value))
                    else:
                        self.assertEqual(recipe[field], value, field)

    def test_only_selected_profile_is_reported_without_altering_original_recipes(
        self,
    ) -> None:
        manifest = corpus.load_manifest()
        originals = {
            profile: dict(recipe)
            for profile, recipe in manifest["libraries"].items()
            if corpus.harness_family(profile, recipe) not in ("zstd", "mbedtls")
        }
        output = self.base / "target/signature-corpus/selected-version"
        profile = "sqlite-3.45.3"
        with (
            mock.patch.object(
                corpus, "build_slice", return_value={"status": "measured"}
            ) as build,
            mock.patch.object(corpus.subprocess, "run") as run,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = corpus.main(
                [
                    "--only",
                    profile,
                    "--archive-cache",
                    str(self.base),
                    "--output-dir",
                    str(output),
                ]
            )
        self.assertEqual(code, 0)
        run.assert_not_called()
        build.assert_called_once()
        selection, recipe, _, directory = build.call_args.args
        self.assertEqual(selection.library, profile)
        self.assertEqual(recipe, manifest["libraries"][profile])
        self.assertEqual(directory.name, selection.name)
        inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(list(inventory["slices"]), [selection.name])
        copied = json.loads((output / "recipes.json").read_text(encoding="utf-8"))
        self.assertEqual(
            {family: copied["libraries"][family] for family in originals}, originals
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
