"""Offline runner regressions; real compiler/evaluator measurements belong to the parent gate."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
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
        binary_format: str = "elf",
        emit_pdb: bool = True,
    ) -> None:
        self.version = version
        self.arch = arch
        self.fail_compile = fail_compile
        self.passed = passed
        self.baseline_available = baseline_available
        self.binary_format = binary_format
        self.emit_pdb = emit_pdb
        self.pe_policy = "-DEBUG"
        self.pdb_conflict = False
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
        elif tool == "sh" and Path(argv[1]).name == "config.guess":
            text = "aarch64-apple-darwin24\n"
        elif tool == "make" and argv[1:] == ["--version"]:
            text = "fake make version\n"
        elif tool == "zig" and argv[1] == "cc":
            if self.fail_compile:
                code = 3
                stderr.write(b"fake compilation rejected\n")
            else:
                produced = Path(argv[argv.index("-o") + 1])
                produced.write_bytes(" ".join(argv).encode())
                if self.binary_format == "pe" and "-c" not in argv:
                    pdb = produced.with_suffix(".pdb")
                    if self.emit_pdb:
                        pdb.write_bytes(f"fake explicit {produced.name} PDB".encode())
                    stderr.write(
                        f'lld-link {self.pe_policy} "-PDB:{pdb}" "-OUT:{produced}" "input object.o"\n'.encode()
                    )
        elif tool == "zig" and argv[1] == "ar":
            Path(argv[3]).write_bytes(b"fake library archive")
        elif tool == "zig" and argv[1] == "lld-link":
            program = Path(
                next(argument[5:] for argument in argv if argument.startswith("-OUT:"))
            )
            pdb = Path(
                next(argument[5:] for argument in argv if argument.startswith("-PDB:"))
            )
            program.write_bytes(
                program.read_bytes() + b" replayed explicit NOREF NOICF"
            )
            pdb.write_bytes(pdb.read_bytes() + b" replayed explicit policy")
        elif tool == "eval" and argv[1] == "artifact-info":
            stripped = "stripped" in argv[2]
            text = json.dumps(
                {
                    "format": self.binary_format,
                    "arch": self.arch,
                    "static_function_symbols": 0
                    if stripped or self.binary_format == "pe"
                    else 10,
                    "dynamic_function_symbols": 4 if self.binary_format == "pe" else 0,
                    "debug_sections": [],
                    "thumb_ranges": 1 if self.arch == "arm" else 0,
                }
            )
        elif tool == "eval" and argv[1] in ("strip", "strip-pe"):
            Path(argv[3]).write_bytes(Path(argv[2]).read_bytes())
        elif tool == "builder":
            if self.pdb_conflict:
                stderr.write(
                    b"malformed binary: PDB: conflicting function names at one RVA\n"
                )
                return subprocess.CompletedProcess(argv, 1)
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
                "evaluator_binary_sha256": corpus.sha256(Path(argv[0])),
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
            if self.binary_format == "pe":
                report.update(
                    producer_range_source="explicit_identity_matched_pdb_procedures",
                    reference_pdb_sha256=corpus.sha256(
                        Path(argv[argv.index("--pdb") + 1])
                    ),
                    target_pdb_sha256=corpus.sha256(
                        Path(argv[argv.index("--target-pdb") + 1])
                    ),
                )
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
        if library == "zlib-1.2.13":
            entries.extend(
                (f"{recipe['root']}/{filename}", b"test dependency header")
                for filename in ("zlib.h", "zconf.h")
            )
        if library == "libpng-1.6.44":
            header = b"#define PNG_TEST_PREBUILT 1\n"
            entries.append((f"{recipe['root']}/{corpus.PNG_HEADER_SOURCE}", header))
            recipe["header_copy"]["sha256"] = hashlib.sha256(header).hexdigest()
            recipe["license_sha256"] = hashlib.sha256(b"test license").hexdigest()
            dependency, _, _ = self.fixture("zlib-1.2.13")
            patched = mock.patch.object(
                corpus, "png_zlib_recipe", return_value=dependency
            )
            patched.start()
            self.addCleanup(patched.stop)
        if library in corpus.configured.PINS:
            scripts = (
                ("Configure",)
                if library.startswith("openssl")
                else ("config.guess", "configure")
            )
            entries.extend(
                (f"{recipe['root']}/{filename}", b"fake trusted host script")
                for filename in scripts
            )
        make_archive(archive, entries)
        recipe["sha256"] = corpus.sha256(archive)
        paths: dict[str, str] = {}
        tool_names = ("zig", "eval", "builder")
        if library in corpus.configured.PINS:
            tool_names += ("make", "perl", "sh")
        for name in tool_names:
            tool = self.base / name
            tool.write_text(f"fake {name}", encoding="utf-8")
            tool.chmod(0o755)
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
        self.assertIn("9 families, 13 profile aliases", stdout.getvalue())
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
        for profile in ("zstd-1.5.6", "mbedtls-2.28.9", "libpng-1.6.44"):
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

    def test_measurement_tool_capture_binds_exact_bytes_and_refuses_existing_outputs(
        self,
    ) -> None:
        source = self.base / "source-tool"
        source.write_bytes(b"original trusted host tool")
        source.chmod(0o755)
        output = self.base / "captured-tool"
        receipt = corpus.freeze_measurement_tool(str(source), output)
        source.write_bytes(b"rebuilt original host tool")
        self.assertEqual(output.read_bytes(), b"original trusted host tool")
        self.assertEqual(receipt["original_path"], str(source.resolve()))
        self.assertEqual(receipt["path"], str(output.resolve()))
        self.assertEqual(receipt["original_sha256"], corpus.sha256(output))
        self.assertEqual(receipt["sha256"], corpus.sha256(output))
        self.assertNotEqual(receipt["original_sha256"], corpus.sha256(source))
        self.assertTrue(output.stat().st_mode & 0o111)
        self.assertFalse(output.stat().st_mode & 0o222)
        with self.assertRaises(corpus.CorpusError):
            corpus.freeze_measurement_tool(str(source), output)
        self.assertEqual(output.read_bytes(), b"original trusted host tool")

    def test_measurement_tool_capture_refuses_special_empty_and_oversized_inputs(
        self,
    ) -> None:
        fifo = self.base / "tool-fifo"
        corpus.os.mkfifo(fifo)
        empty = self.base / "empty-tool"
        empty.write_bytes(b"")
        oversized = self.base / "oversized-tool"
        with oversized.open("wb") as stream:
            stream.truncate(256 * 1024 * 1024 + 1)
        for source in (fifo, empty, oversized):
            with (
                self.subTest(source=source),
                mock.patch.object(corpus, "executable", return_value=str(source)),
                self.assertRaises(corpus.CorpusError),
            ):
                corpus.freeze_measurement_tool(str(source), self.base / "not-created")
            self.assertFalse((self.base / "not-created").exists())

    def test_main_captures_measurement_tools_once_and_survives_original_binary_rebuilds(
        self,
    ) -> None:
        recipe, args, _ = self.fixture()
        manifest = corpus.load_manifest()
        manifest["libraries"]["zlib"] = recipe
        original_builder_sha = corpus.sha256(Path(args.builder))
        original_eval_sha = corpus.sha256(Path(args.evaluator))
        fake = FakeProducers()
        rebuilt = False

        def produce(
            argv: list[str],
            *,
            cwd: Path,
            env: dict[str, str],
            stdout: BinaryIO,
            stderr: BinaryIO,
            check: bool,
        ) -> subprocess.CompletedProcess[bytes]:
            nonlocal rebuilt
            completed = fake.run(
                argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr, check=check
            )
            if Path(argv[0]).name == "builder" and not rebuilt:
                Path(args.builder).write_bytes(b"rebuilt original collector")
                Path(args.evaluator).write_bytes(b"rebuilt original evaluator")
                rebuilt = True
            return completed

        output = self.base / "target/signature-corpus/captured"
        with (
            mock.patch.object(corpus, "load_manifest", return_value=manifest),
            mock.patch.object(corpus.subprocess, "run", side_effect=produce),
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
                    "--optimization",
                    "O1",
                    "--optimization",
                    "O2",
                ]
            )
        self.assertEqual(code, 0)
        inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
        captured = inventory["measurement_tool_snapshot"]
        self.assertEqual(captured["builder"]["sha256"], original_builder_sha)
        self.assertEqual(captured["evaluator"]["sha256"], original_eval_sha)
        self.assertEqual(len(inventory["slices"]), 2)
        for result in inventory["slices"].values():
            self.assertEqual(result["status"], "measured", result)
            self.assertEqual(result["tools"]["builder"]["sha256"], original_builder_sha)
            self.assertEqual(
                result["builder_report"]["evaluator_binary_sha256"],
                original_builder_sha,
            )
            self.assertEqual(result["tools"]["evaluator"]["sha256"], original_eval_sha)
            self.assertEqual(
                result["tools"]["builder"]["path"], captured["builder"]["path"]
            )
        self.assertEqual(Path(captured["builder"]["path"]).parent.name, "tools")

    def test_installed_zig_drift_during_case_invalidates_the_measurement(self) -> None:
        recipe, args, directory = self.fixture()
        fake = FakeProducers()

        def produce(
            argv: list[str],
            *,
            cwd: Path,
            env: dict[str, str],
            stdout: BinaryIO,
            stderr: BinaryIO,
            check: bool,
        ) -> subprocess.CompletedProcess[bytes]:
            completed = fake.run(
                argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr, check=check
            )
            if Path(argv[0]).name == "builder":
                Path(args.zig).write_bytes(b"changed installed compiler")
            return completed

        with mock.patch.object(corpus.subprocess, "run", side_effect=produce):
            result = corpus.build_slice(
                corpus.Selection("zlib", corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "failed", result)
        self.assertFalse(result["tool_identity_valid"])
        self.assertIn("zig binary changed", result["reason"])
        self.assertEqual(
            result["measurements"]["new"]["status"], "invalid_producer_identity"
        )
        self.assertTrue(result["builder_report"]["passed"])

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

    def test_archive_preflight_rejects_case_collisions_before_any_materialization(
        self,
    ) -> None:
        archive = self.base / "case-collision.tar.gz"
        make_archive(
            archive, [("root/Configure", b"first"), ("root/configure", b"second")]
        )
        destination = self.base / "extraction"
        with self.assertRaisesRegex(corpus.CorpusError, "case-colliding"):
            corpus.extract_archive(archive, destination, "root")
        self.assertFalse(destination.exists())

    def test_archive_snapshot_rejects_pin_mismatch_and_special_files_before_tar_open(
        self,
    ) -> None:
        archive = self.base / "pinned.tar.gz"
        make_archive(archive, [("root/Configure", b"trusted script")])
        destination = self.base / "extraction"
        with (
            mock.patch.object(corpus.tarfile, "open") as opened,
            self.assertRaisesRegex(corpus.CorpusError, "SHA-256 mismatch"),
        ):
            corpus.extract_archive(
                archive, destination, "root", expected_sha256="0" * 64
            )
        opened.assert_not_called()
        self.assertFalse(destination.exists())
        fifo = self.base / "archive-fifo"
        corpus.os.mkfifo(fifo)
        for path in (fifo, self.base):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(corpus.CorpusError, "regular file"),
            ):
                corpus.archive_snapshot(path, None)
        oversized = self.base / "oversized.tar.gz"
        with oversized.open("wb") as stream:
            stream.truncate(128 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(corpus.CorpusError, "snapshot size bound"):
            corpus.archive_snapshot(oversized, None)
        linked = self.base / "linked.tar.gz"
        linked.symlink_to(archive)
        with self.assertRaises(corpus.CorpusError):
            corpus.archive_snapshot(linked, corpus.sha256(archive))

    def test_extraction_consumes_verified_snapshot_even_if_cache_path_is_replaced(
        self,
    ) -> None:
        archive = self.base / "pinned.tar.gz"
        replacement = self.base / "replacement.tar.gz"
        trusted = b"trusted pinned host script"
        make_archive(archive, [("root/Configure", trusted)])
        make_archive(
            replacement, [("root/Configure", b"unverified replacement script")]
        )
        pin = corpus.sha256(archive)
        real_open = corpus.tarfile.open

        def replace_cache(*, fileobj: io.BytesIO, mode: str) -> tarfile.TarFile:
            self.assertEqual(hashlib.sha256(fileobj.getvalue()).hexdigest(), pin)
            replacement.replace(archive)
            return real_open(fileobj=fileobj, mode=mode)

        with mock.patch.object(corpus.tarfile, "open", side_effect=replace_cache):
            source = corpus.extract_archive(
                archive, self.base / "extraction", "root", expected_sha256=pin
            )
        self.assertEqual((source / "Configure").read_bytes(), trusted)
        self.assertNotEqual(corpus.sha256(archive), pin)

    def test_configured_cache_swap_after_precheck_refuses_source_scripts(self) -> None:
        profile = "curl-8.10.1"
        recipe, args, directory = self.fixture(profile)
        real_check = corpus.checked_archive

        def swap(cache: Path, selected: dict[str, Any]) -> Path:
            archive = real_check(cache, selected)
            make_archive(
                archive, [(f"{selected['root']}/configure", b"unverified host script")]
            )
            return archive

        fake = FakeProducers()
        with (
            mock.patch.dict(corpus.configured.PINS, {profile: recipe["sha256"]}),
            mock.patch.object(corpus, "checked_archive", side_effect=swap),
            mock.patch.object(corpus, "executable", side_effect=lambda value: value),
            mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
            mock.patch.object(corpus.configured, "build_configured_profile") as build,
        ):
            result = corpus.build_slice(
                corpus.Selection(profile, corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("SHA-256 mismatch", result["reason"])
        self.assertEqual(fake.calls, [[args.zig, "version"]])
        self.assertFalse((directory / "source").exists())
        self.assertNotIn("archive_sha256", result)
        build.assert_not_called()

    def test_png_dependency_revalidates_snapshot_before_compilation(self) -> None:
        recipe, _, directory = self.fixture("zlib-1.2.13")
        archive = corpus.checked_archive(self.base, recipe)
        make_archive(
            archive, [(f"{recipe['root']}/adler32.c", b"unverified replacement")]
        )
        directory.mkdir()
        commands = corpus.Commands(directory)
        with (
            mock.patch.object(corpus.subprocess, "run") as run,
            self.assertRaisesRegex(corpus.CorpusError, "SHA-256 mismatch"),
        ):
            corpus.build_png_zlib(
                archive,
                recipe,
                corpus.Selection("libpng-1.6.44", corpus.TARGETS[0], "O1"),
                directory,
                commands,
                "zig",
            )
        run.assert_not_called()
        self.assertFalse((directory / "dependency-source").exists())

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
        (self.base / "scoped.tar.gz").write_bytes(b"mocked archive backing")
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
        (self.base / "negative.tar.gz").write_bytes(b"mocked archive backing")
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
            if profile in corpus.configured.PINS:
                continue
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
                    call
                    for call in fake.calls
                    if call[1] == "cc"
                    and "-c" in call
                    and not Path(call[call.index("-o") + 1]).name.startswith(
                        "dependency-"
                    )
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
                archive = next(
                    call
                    for call in fake.calls
                    if call[1] == "ar" and Path(call[3]).name == f"lib{profile}.a"
                )
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

    def test_configured_profiles_link_all_owned_archives_and_preserve_provenance(
        self,
    ) -> None:
        for profile in corpus.configured.PINS:
            with self.subTest(profile=profile):
                recipe, args, directory = self.fixture(profile)
                directory = directory.with_name(profile)
                fake = FakeProducers()
                returned: list[Any] = []

                def build(
                    context: Any,
                    *,
                    recipe: dict[str, Any] = recipe,
                    profile: str = profile,
                    directory: Path = directory,
                    returned: list[Any] = returned,
                ) -> Any:
                    self.assertEqual(
                        context.verified_archive_sha256,
                        corpus.sha256(self.base / recipe["archive"]),
                    )
                    self.assertEqual(context.source_class, "public-source-archive")
                    self.assertEqual(context.jobs, 1)
                    self.assertNotIn("CREDENTIAL_SENTINEL", context.environment)
                    script = (
                        "Configure" if profile.startswith("openssl") else "configure"
                    )
                    self.assertEqual(
                        (context.source / script).read_bytes(),
                        b"fake trusted host script",
                    )
                    context.run(
                        [str(context.make), "--version"],
                        cwd=context.source,
                        env={"CC": "recorded-wrapper", "SOURCE_DATE_EPOCH": "0"},
                    )
                    names = (
                        ("libssl.a", "libcrypto.a")
                        if profile.startswith("openssl")
                        else ("libcurl.a",)
                    )
                    archives = tuple(directory / name for name in names)
                    objects = tuple(
                        directory / f"owned-{index}.o" for index in range(len(names))
                    )
                    for path in (*archives, *objects):
                        path.write_bytes(b"fake owned library output")
                    includes = (
                        context.source / "include",
                        context.source / "generated/include",
                    )
                    provenance = {
                        "archive_sha256": context.verified_archive_sha256,
                        "compiler_wrapper": {"sha256": "f" * 64},
                        "host_script_sha256": {
                            name: corpus.sha256(context.source / name)
                            for name in (
                                ("Configure",)
                                if profile.startswith("openssl")
                                else ("configure",)
                            )
                        },
                        "tools": {
                            "make": {
                                "path": str(context.make),
                                "sha256": corpus.sha256(context.make),
                            }
                        },
                    }
                    produced = corpus.configured.ConfiguredBuild(
                        archives, objects, includes, ("-lm",), provenance
                    )
                    returned.append(produced)
                    return produced

                def resolve(value: str) -> str:
                    return (
                        str(self.base / value)
                        if value in ("make", "perl", "sh")
                        else value
                    )

                poisoned = {
                    "CREDENTIAL_SENTINEL": "not-for-receipts",
                    "OPENSSL_LOCAL_CONFIG_DIR": "/not-executed",
                    "OPENSSL_CONF": "/not-executed",
                    "PERL5OPT": "not-executed",
                    "PERL5LIB": "/not-executed",
                    "BASH_ENV": "/not-executed",
                    "ENV": "/not-executed",
                    "CONFIG_SITE": "/not-executed",
                    "HOME": "/not-the-isolated-home",
                }
                with (
                    mock.patch.dict(
                        corpus.configured.PINS, {profile: recipe["sha256"]}
                    ),
                    mock.patch.dict(corpus.os.environ, poisoned),
                    mock.patch.object(corpus, "executable", side_effect=resolve),
                    mock.patch.object(
                        corpus.configured, "build_configured_profile", side_effect=build
                    ),
                    mock.patch.object(
                        corpus.subprocess, "run", side_effect=fake.run
                    ) as run,
                ):
                    result = corpus.build_slice(
                        corpus.Selection(profile, corpus.TARGETS[0], "O1"),
                        recipe,
                        args,
                        directory,
                    )
                self.assertEqual(result["status"], "measured", result)
                produced = returned[0]
                self.assertEqual(result["configured_build"], produced.provenance)
                self.assertEqual(result["archive_sha256"], recipe["sha256"])
                self.assertEqual(
                    result["source_snapshot_policy"],
                    "bounded-regular-fd-sha256-verified-bytes-v1",
                )
                self.assertEqual(result["env_policy"], "configured-clean-allowlist-v1")
                self.assertEqual(
                    result["tools"]["zig"]["sha256"], corpus.sha256(Path(args.zig))
                )
                license_path = (
                    directory / "source" / recipe["root"] / recipe["license_file"]
                )
                self.assertEqual(result["license_sha256"], corpus.sha256(license_path))
                compilations = [
                    call for call in fake.calls if call[1] == "cc" and "-c" in call
                ]
                self.assertEqual(len(compilations), 2)
                for call in compilations:
                    for include in produced.include_directories:
                        self.assertIn(str(include), call)
                links = [
                    call for call in fake.calls if call[1] == "cc" and "-c" not in call
                ]
                for call in links:
                    start, end = (
                        call.index("-Wl,--whole-archive"),
                        call.index("-Wl,--no-whole-archive"),
                    )
                    self.assertEqual(
                        call[start + 1 : end], list(map(str, produced.archives))
                    )
                    self.assertIn("-Wl,--no-gc-sections", call)
                builder = next(
                    call for call in fake.calls if Path(call[0]).name == "builder"
                )
                owned = [
                    builder[index + 1]
                    for index, flag in enumerate(builder)
                    if flag == "--object"
                ]
                self.assertEqual(owned, list(map(str, produced.objects)))
                records = json.loads(
                    (directory / "commands.json").read_text(encoding="utf-8")
                )
                self.assertEqual(len(records), len(run.call_args_list))
                for record, call in zip(records, run.call_args_list):
                    actual_env = call.kwargs["env"]
                    self.assertEqual(
                        record["env_policy"], "configured-clean-allowlist-v1"
                    )
                    self.assertEqual(record["environment"], actual_env)
                    self.assertEqual(
                        actual_env["HOME"], str(directory / "configured-home")
                    )
                    self.assertEqual(actual_env["CONFIG_SITE"], "/dev/null")
                    self.assertTrue(
                        set(actual_env) <= corpus.configured.CLEAN_ENVIRONMENT_KEYS
                    )
                    for key in poisoned.keys() - {"HOME", "CONFIG_SITE"}:
                        self.assertNotIn(key, actual_env)
                host = next(
                    record
                    for record in records
                    if Path(record["argv"][0]).name == "make"
                )
                self.assertEqual(
                    host["cwd"], str(directory / "source" / recipe["root"])
                )
                self.assertEqual(host["environment"]["CC"], "recorded-wrapper")
                self.assertNotIn("CREDENTIAL_SENTINEL", json.dumps(records))
                if profile.startswith("curl"):
                    guess = directory / "source" / recipe["root"] / "config.guess"
                    self.assertEqual(
                        result["host_build_triplet"]["sha256"], corpus.sha256(guess)
                    )
                    self.assertEqual(
                        result["host_build_triplet"]["value"], "aarch64-apple-darwin24"
                    )

    def test_command_recorder_preserves_positional_api_and_scopes_overlay_receipts(
        self,
    ) -> None:
        directory = self.base / "commands"
        directory.mkdir()
        child = directory / "host-build"
        child.mkdir()
        fake = FakeProducers()
        with mock.patch.dict(
            corpus.os.environ, {"CREDENTIAL_SENTINEL": "not-for-receipts"}
        ):
            commands = corpus.Commands(directory)
        output = directory / "version.txt"
        with mock.patch.object(corpus.subprocess, "run", side_effect=fake.run) as run:
            self.assertEqual(
                commands.run(["zig", "version"], output, (0,)), fake.version
            )
            commands.run(["zig", "version"], cwd=child, env={"CFLAGS": "-O1 -g0"})
        self.assertEqual(output.read_text(encoding="utf-8"), fake.version)
        first, second = run.call_args_list
        self.assertEqual(first.kwargs["cwd"], directory)
        self.assertEqual(second.kwargs["cwd"], child)
        self.assertEqual(second.kwargs["env"]["CFLAGS"], "-O1 -g0")
        self.assertEqual(
            second.kwargs["env"]["CREDENTIAL_SENTINEL"], "not-for-receipts"
        )
        records = json.loads((directory / "commands.json").read_text(encoding="utf-8"))
        self.assertEqual(records[1]["environment"]["CFLAGS"], "-O1 -g0")
        self.assertEqual(records[1]["cwd"], str(child))
        self.assertNotIn("CREDENTIAL_SENTINEL", json.dumps(records))

    def test_clean_command_mode_rejects_inherited_and_overlay_script_environment(
        self,
    ) -> None:
        directory = self.base / "clean-commands"
        directory.mkdir()
        poisoned = {
            "PERL5OPT": "not-executed",
            "PERL5LIB": "/not-executed",
            "BASH_ENV": "/not-executed",
            "ENV": "/not-executed",
            "OPENSSL_LOCAL_CONFIG_DIR": "/not-executed",
            "HOME": "/not-the-isolated-home",
            "CONFIG_SITE": "/not-executed",
        }
        with mock.patch.dict(corpus.os.environ, poisoned):
            commands = corpus.Commands(directory, clean_environment=True)
        fake = FakeProducers()
        with mock.patch.object(corpus.subprocess, "run", side_effect=fake.run) as run:
            commands.run(
                ["zig", "version"],
                env={**poisoned, "CFLAGS": "-O1"},
                clean_environment=True,
            )
        actual = run.call_args.kwargs["env"]
        for key in poisoned.keys() - {"HOME", "CONFIG_SITE"}:
            self.assertNotIn(key, actual)
        self.assertEqual(actual["HOME"], str(directory / "configured-home"))
        self.assertEqual(actual["CONFIG_SITE"], "/dev/null")
        self.assertEqual(actual["CFLAGS"], "-O1")
        self.assertEqual(commands.records[0]["environment"], actual)
        self.assertEqual(
            commands.records[0]["env_policy"], "configured-clean-allowlist-v1"
        )

    def test_configured_manifest_refuses_custom_commands_sources_or_driver_overrides(
        self,
    ) -> None:
        invalid = (
            ("curl-8.10.1", "sources", ["lib/url.c"]),
            ("curl-8.10.1", "build_driver", "custom"),
            ("curl-8.10.1", "configure_argv", ["echo", "arbitrary"]),
            ("curl-8.10.1", "source_class", "unknown"),
            ("openssl-3.0.15", "sha256", "0" * 64),
            ("openssl-3.0.15", "defines", ["CUSTOM_CONFIG"]),
            ("zlib", "build_driver", "configured"),
            ("zlib", "sources", []),
        )
        for profile, field, value in invalid:
            with self.subTest(profile=profile, field=field):
                manifest = corpus.load_manifest()
                manifest["libraries"][profile][field] = value
                path = self.base / "configured-recipes.json"
                corpus.write_json(path, manifest)
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_manifest(path)

    def test_configured_unsupported_targets_do_not_touch_cache_or_execute_tools(
        self,
    ) -> None:
        for profile in corpus.configured.PINS:
            recipe = corpus.load_manifest()["libraries"][profile]
            for target in corpus.TARGETS[2:]:
                with (
                    self.subTest(profile=profile, target=target),
                    mock.patch.object(corpus, "checked_archive") as check,
                    mock.patch.object(corpus.subprocess, "run") as run,
                ):
                    directory = self.base / f"{profile}-{target}"
                    result = corpus.build_slice(
                        corpus.Selection(profile, target, "O1"), recipe, None, directory
                    )
                self.assertEqual(result["status"], "unsupported", result)
                check.assert_not_called()
                run.assert_not_called()

    def test_configured_archive_corruption_stops_before_host_scripts(self) -> None:
        profile = "curl-8.10.1"
        recipe, args, directory = self.fixture(profile)
        (self.base / recipe["archive"]).write_bytes(b"corrupted archive")
        with (
            mock.patch.dict(corpus.configured.PINS, {profile: recipe["sha256"]}),
            mock.patch.object(corpus.configured, "build_configured_profile") as build,
            mock.patch.object(corpus.subprocess, "run") as run,
        ):
            result = corpus.build_slice(
                corpus.Selection(profile, corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("SHA-256 mismatch", result["reason"])
        run.assert_not_called()
        build.assert_not_called()

    def test_configured_driver_error_remains_failed_without_direct_source_fallback(
        self,
    ) -> None:
        profile = "openssl-3.0.15"
        recipe, args, directory = self.fixture(profile)
        fake = FakeProducers()
        with (
            mock.patch.dict(corpus.configured.PINS, {profile: recipe["sha256"]}),
            mock.patch.object(
                corpus,
                "executable",
                side_effect=lambda value: (
                    str(self.base / value) if value in ("make", "perl", "sh") else value
                ),
            ),
            mock.patch.object(
                corpus.configured,
                "build_configured_profile",
                side_effect=corpus.configured.ConfiguredBuildError(
                    "explicit configured producer failure"
                ),
            ),
            mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
        ):
            result = corpus.build_slice(
                corpus.Selection(profile, corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("configured producer failure", result["reason"])
        self.assertEqual(fake.calls, [[args.zig, "version"]])

    def test_png_dependency_is_linked_but_never_owned_on_elf_targets(self) -> None:
        recipe, args, directory = self.fixture("libpng-1.6.44")
        for target in corpus.TARGETS[:-1]:
            for optimization in ("O1", "O2"):
                with self.subTest(target=target, optimization=optimization):
                    selection = corpus.Selection("libpng-1.6.44", target, optimization)
                    output = directory.with_name(selection.name)
                    fake = FakeProducers(arch=corpus.ARCHES[target])
                    with (
                        mock.patch.object(
                            corpus, "executable", side_effect=lambda value: value
                        ),
                        mock.patch.object(
                            corpus.subprocess, "run", side_effect=fake.run
                        ),
                    ):
                        result = corpus.build_slice(selection, recipe, args, output)
                    self.assertEqual(result["status"], "measured", result)
                    builder = next(
                        call for call in fake.calls if Path(call[0]).name == "builder"
                    )
                    owned = [
                        Path(builder[index + 1]).name
                        for index, flag in enumerate(builder)
                        if flag == "--object"
                    ]
                    self.assertEqual(
                        owned, [f"library-{index:02}.o" for index in range(15)]
                    )
                    dependency = result["dependency"]
                    self.assertTrue(dependency["objects"])
                    self.assertTrue(set(owned).isdisjoint(dependency["objects"]))
                    self.assertEqual(
                        set(result["source_sha256"]), set(recipe["sources"])
                    )
                    self.assertEqual(
                        set(dependency["header_sha256"]), {"zlib.h", "zconf.h"}
                    )
                    for call in fake.calls:
                        if call[1] != "cc":
                            continue
                        self.assertIn(f"-{optimization}", call)
                        self.assertEqual(call[call.index("-target") + 1], target)
                        if "-c" not in call:
                            end = call.index("-Wl,--no-whole-archive")
                            self.assertEqual(
                                Path(call[end + 1]).name, dependency["archive"]
                            )
                            self.assertEqual(call[end + 2], "-lm")
                            self.assertIn("-Wl,--no-gc-sections", call)
                        else:
                            obj = Path(call[call.index("-o") + 1]).name
                            if obj.startswith("dependency-"):
                                self.assertIn("-DZ_SOLO", call)
                                self.assertFalse(
                                    any(flag.startswith("-DPNG_") for flag in call)
                                )
                            else:
                                self.assertNotIn("-DZ_SOLO", call)
                                for define in recipe["defines"]:
                                    self.assertIn(f"-D{define}", call)
                                includes = [
                                    Path(call[index + 1])
                                    for index, flag in enumerate(call)
                                    if flag == "-I"
                                ]
                                self.assertEqual(
                                    includes,
                                    [
                                        output / "source" / recipe["root"],
                                        output / "dependency-source/zlib-1.2.13",
                                    ],
                                )
                    header = result["header_copy"]
                    root = output / "source" / recipe["root"]
                    self.assertEqual(
                        (root / header["source"]).read_bytes(),
                        (root / header["destination"]).read_bytes(),
                    )
                    self.assertEqual(
                        header["source_sha256"], recipe["header_copy"]["sha256"]
                    )
                    self.assertEqual(
                        header["destination_sha256"], header["source_sha256"]
                    )
                    self.assertNotEqual(
                        result["harness_sha256"]["reference"],
                        result["harness_sha256"]["target"],
                    )
                    self.assertTrue(
                        all(
                            Path(call[0]).name in ("zig", "eval", "builder")
                            for call in fake.calls
                        )
                    )

    def test_png_manifest_rejects_unsafe_header_dependency_and_simd_changes(
        self,
    ) -> None:
        original = corpus.load_manifest()["libraries"]["libpng-1.6.44"]
        invalid = [
            ("dependency", "zlib"),
            ("dependency", ["zlib-1.2.13"]),
            ("dependency", "../zlib-1.2.13"),
            ("dependency", "libpng-1.6.44"),
            ("header_copy", {**original["header_copy"], "source": "../header.h"}),
            ("header_copy", {**original["header_copy"], "destination": "/header.h"}),
            (
                "header_copy",
                {**original["header_copy"], "destination": "nested/header.h"},
            ),
            ("header_copy", {**original["header_copy"], "sha256": "bad"}),
            ("header_copy", {**original["header_copy"], "command": "configure"}),
            ("defines", ["PNG_ARM_NEON_OPT=1"]),
            ("defines", list(corpus.PNG_SIMD_DEFINES[:-1])),
            ("sources", ["../png.c"]),
            ("sources", ["pngtest.c"]),
            ("sources", original["sources"][:-1]),
            ("extract_roots", ["scripts"]),
            ("license_sha256", None),
            ("license_sha256", "A" * 64),
        ]
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                manifest = corpus.load_manifest()
                manifest["libraries"]["libpng-1.6.44"][field] = value
                path = self.base / "recipes.json"
                corpus.write_json(path, manifest)
                with self.assertRaises(corpus.CorpusError):
                    corpus.load_manifest(path)
        for profile in ("zlib", "zstd-1.5.6", "mbedtls-2.28.9"):
            for field in ("dependency", "header_copy"):
                with self.subTest(profile=profile, field=field):
                    manifest = corpus.load_manifest()
                    manifest["libraries"][profile][field] = original[field]
                    path = self.base / "recipes.json"
                    corpus.write_json(path, manifest)
                    with self.assertRaises(corpus.CorpusError):
                        corpus.load_manifest(path)

    def test_png_bad_dependency_archive_fails_before_any_producer(self) -> None:
        recipe, args, directory = self.fixture("libpng-1.6.44")
        (self.base / "zlib-1.2.13.tar.gz").write_bytes(b"corrupt dependency")
        with mock.patch.object(corpus.subprocess, "run") as run:
            result = corpus.build_slice(
                corpus.Selection("libpng-1.6.44", corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("archive SHA-256 mismatch", result["reason"])
        run.assert_not_called()

    def test_png_bad_header_or_notice_hash_prevents_compilation(self) -> None:
        recipe, args, directory = self.fixture("libpng-1.6.44")
        for field in ("header_copy", "license_sha256"):
            changed = dict(recipe)
            if field == "header_copy":
                changed[field] = {**recipe[field], "sha256": "0" * 64}
            else:
                changed[field] = "0" * 64
            fake = FakeProducers()
            with (
                self.subTest(field=field),
                mock.patch.object(
                    corpus, "executable", side_effect=lambda value: value
                ),
                mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
            ):
                result = corpus.build_slice(
                    corpus.Selection("libpng-1.6.44", corpus.TARGETS[0], "O1"),
                    changed,
                    args,
                    directory.with_name(field),
                )
            self.assertEqual(result["status"], "failed", result)
            self.assertIn("SHA-256 mismatch", result["reason"])
            self.assertEqual([call[1:] for call in fake.calls], [["version"]])

    def test_png_prebuilt_copy_refuses_existing_destination_and_source_links(
        self,
    ) -> None:
        recipe, _, _ = self.fixture("libpng-1.6.44")
        source = self.base / "copy-source"
        original = source / recipe["header_copy"]["source"]
        destination = source / recipe["header_copy"]["destination"]
        original.parent.mkdir(parents=True)
        original.write_bytes(b"#define PNG_TEST_PREBUILT 1\n")
        destination.write_bytes(b"existing user header")
        with self.assertRaises(corpus.CorpusError):
            corpus.copy_png_header(source, recipe)
        self.assertEqual(destination.read_bytes(), b"existing user header")
        destination.unlink()
        original.unlink()
        original.symlink_to(self.base / "outside-header")
        (self.base / "outside-header").write_bytes(b"#define PNG_TEST_PREBUILT 1\n")
        with self.assertRaises(corpus.CorpusError):
            corpus.copy_png_header(source, recipe)
        self.assertFalse(destination.exists())

    def test_png_dependency_is_one_level_only(self) -> None:
        recipe, args, directory = self.fixture("libpng-1.6.44")
        dependency = dict(corpus.png_zlib_recipe())
        dependency["dependency"] = "libpng-1.6.44"
        fake = FakeProducers()
        with (
            mock.patch.object(corpus, "png_zlib_recipe", return_value=dependency),
            mock.patch.object(corpus, "executable", side_effect=lambda value: value),
            mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
        ):
            result = corpus.build_slice(
                corpus.Selection("libpng-1.6.44", corpus.TARGETS[0], "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("nonrecursive", result["reason"])
        self.assertEqual([call[1:] for call in fake.calls], [["version"]])

    def test_new_profile_scope_is_printed_before_any_producer_measurement(self) -> None:
        manifest = corpus.load_manifest()
        _, tool_args, _ = self.fixture()
        for profile in ("zstd-1.5.6", "mbedtls-2.28.9", "libpng-1.6.44"):
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
                            "--zig",
                            tool_args.zig,
                            "--eval",
                            tool_args.evaluator,
                            "--builder",
                            tool_args.builder,
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
        _, tool_args, _ = self.fixture()
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
                    "--zig",
                    tool_args.zig,
                    "--eval",
                    tool_args.evaluator,
                    "--builder",
                    tool_args.builder,
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
            {"evaluator_binary_sha256": "0" * 64},
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

    def test_windows_direct_profiles_use_matched_pdbs_and_native_pe_policy(
        self,
    ) -> None:
        for profile in ("zlib", "lz4"):
            with self.subTest(profile=profile):
                recipe, args, directory = self.fixture(profile)
                directory = directory.with_name(profile + "-windows")
                args.diagnostic_limit = 0
                fake = FakeProducers(binary_format="pe")
                with (
                    mock.patch.object(
                        corpus, "executable", side_effect=lambda value: value
                    ),
                    mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
                ):
                    result = corpus.build_slice(
                        corpus.Selection(profile, "x86_64-windows-gnu", "O1"),
                        recipe,
                        args,
                        directory,
                    )
                self.assertEqual(result["status"], "measured", result)
                compilations = [
                    call for call in fake.calls if call[1] == "cc" and "-c" in call
                ]
                self.assertTrue(compilations)
                for call in compilations:
                    self.assertIn("-gcodeview", call)
                    self.assertIn("-g", call)
                    self.assertNotIn("-g0", call)
                links = [
                    call for call in fake.calls if call[1] == "cc" and "-c" not in call
                ]
                for call in links:
                    self.assertIn("-Wl,--no-gc-sections", call)
                    self.assertIn("-v", call)
                    self.assertNotIn("-no-pie", call)
                    self.assertNotIn("-Wl,--icf=none", call)
                    self.assertFalse(
                        any(flag.startswith("-Wl,--pdb=") for flag in call)
                    )
                strip = next(call for call in fake.calls if call[1] == "strip-pe")
                self.assertEqual(Path(strip[2]).name, "target.exe")
                self.assertEqual(Path(strip[3]).name, "target.stripped.exe")
                builder = next(
                    call for call in fake.calls if Path(call[0]).name == "builder"
                )
                self.assertEqual(
                    builder[builder.index("--pdb") + 1],
                    str(directory / "reference.pdb"),
                )
                self.assertEqual(
                    builder[builder.index("--target-pdb") + 1],
                    str(directory / "target.pdb"),
                )
                self.assertEqual(builder[builder.index("--diagnostic-limit") + 1], "0")
                for role in ("reference", "target"):
                    receipt = result["pdb_producer"][role]
                    self.assertEqual(
                        receipt["sha256"], corpus.sha256(directory / f"{role}.pdb")
                    )
                    self.assertEqual(
                        result["builder_report"][f"{role}_pdb_sha256"],
                        receipt["sha256"],
                    )
                    replay = receipt["replay"]
                    self.assertEqual(replay["argv"][1], "lld-link")
                    self.assertEqual(replay["argv"][-2:], ["-OPT:NOREF", "-OPT:NOICF"])
                    self.assertEqual(
                        replay["argv"][2:-2], replay["captured_linker_argv"][1:]
                    )
                    self.assertIn("input object.o", replay["argv"])
                    self.assertNotEqual(
                        replay["before"]["program_sha256"],
                        replay["after"]["program_sha256"],
                    )
                owned = [
                    builder[index + 1]
                    for index, flag in enumerate(builder)
                    if flag == "--object"
                ]
                self.assertTrue(
                    all(Path(path).name.startswith("library-") for path in owned)
                )

    def test_windows_missing_pdb_or_unproven_linker_policy_never_reaches_collector(
        self,
    ) -> None:
        for missing_pdb in (True, False):
            with self.subTest(missing_pdb=missing_pdb):
                recipe, args, directory = self.fixture()
                directory = directory.with_name(f"windows-blocked-{missing_pdb}")
                fake = FakeProducers(binary_format="pe", emit_pdb=not missing_pdb)
                if not missing_pdb:
                    fake.pe_policy = "-DEBUG -OPT:REF -OPT:ICF"
                with (
                    mock.patch.object(
                        corpus, "executable", side_effect=lambda value: value
                    ),
                    mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
                ):
                    result = corpus.build_slice(
                        corpus.Selection("zlib", "x86_64-windows-gnu", "O1"),
                        recipe,
                        args,
                        directory,
                    )
                self.assertEqual(
                    result["status"], "unsupported" if missing_pdb else "failed", result
                )
                self.assertIn("PDB" if missing_pdb else "ICF", result["reason"])
                self.assertFalse(
                    any(Path(call[0]).name == "builder" for call in fake.calls)
                )

    def test_pe_receipt_does_not_accept_echoed_policy_without_native_execution(
        self,
    ) -> None:
        directory = self.base / "echoed-pe-policy"
        directory.mkdir()
        program, pdb = directory / "reference.exe", directory / "reference.pdb"
        program.write_bytes(b"owned generated executable")
        pdb.write_bytes(b"owned generated PDB")
        stderr = directory / "command-000.stderr"
        stderr.write_text(
            f"lld-link -DEBUG -OPT:NOREF -OPT:NOICF -OUT:{program} -PDB:{pdb}\n",
            encoding="utf-8",
        )
        commands = corpus.Commands(directory)
        commands.records.append(
            {"argv": ["zig", "cc", "-v"], "returncode": 0, "stderr": stderr.name}
        )
        with self.assertRaisesRegex(corpus.CorpusError, "native Zig lld-link"):
            corpus.pe_linker_receipt(commands, "zig", program, pdb)

    def test_pe_replay_refuses_captured_linker_command_for_another_output(self) -> None:
        directory = self.base / "wrong-pe-output"
        directory.mkdir()
        program, pdb = directory / "reference.exe", directory / "reference.pdb"
        program.write_bytes(b"owned generated executable")
        pdb.write_bytes(b"owned generated PDB")
        stderr = directory / "command-000.stderr"
        stderr.write_text(
            f"lld-link -DEBUG -OUT:{directory / 'other.exe'} -PDB:{pdb}\n",
            encoding="utf-8",
        )
        commands = corpus.Commands(directory)
        commands.records.append(
            {
                "argv": ["zig", "cc", "-v", "-o", str(program)],
                "returncode": 0,
                "stderr": stderr.name,
                "cwd": str(directory),
            }
        )
        with (
            mock.patch.object(commands, "run") as run,
            self.assertRaisesRegex(corpus.CorpusError, "owned output"),
        ):
            corpus._replay_pe_link(commands, "zig", program, pdb)
        run.assert_not_called()

    def test_windows_conflicting_pdb_names_are_explicitly_unsupported_without_measurements(
        self,
    ) -> None:
        recipe, args, directory = self.fixture()
        fake = FakeProducers(binary_format="pe")
        fake.pdb_conflict = True
        with mock.patch.object(corpus.subprocess, "run", side_effect=fake.run):
            result = corpus.build_slice(
                corpus.Selection("zlib", "x86_64-windows-gnu", "O1"),
                recipe,
                args,
                directory,
            )
        self.assertEqual(result["status"], "unsupported", result)
        self.assertIn("conflicting function names", result["reason"])
        self.assertNotIn("measurements", result)
        self.assertNotIn("builder_report", result)
        self.assertFalse((directory / "db.json").exists())
        self.assertTrue(
            result["pdb_producer"]["target"]["replay"]["after"]["pdb_sha256"]
        )

    def test_windows_rejects_collector_pdb_hash_or_range_source_mismatch(self) -> None:
        for index, update in enumerate(
            (
                {"reference_pdb_sha256": "0" * 64},
                {"target_pdb_sha256": "0" * 64},
                {"producer_range_source": "unmatched_symbols"},
            )
        ):
            with self.subTest(update=update):
                recipe, args, directory = self.fixture()
                directory = directory.with_name(f"windows-wrong-pdb-{index}")
                fake = FakeProducers(binary_format="pe")
                fake.report_updates.update(update)
                with (
                    mock.patch.object(
                        corpus, "executable", side_effect=lambda value: value
                    ),
                    mock.patch.object(corpus.subprocess, "run", side_effect=fake.run),
                ):
                    result = corpus.build_slice(
                        corpus.Selection("zlib", "x86_64-windows-gnu", "O1"),
                        recipe,
                        args,
                        directory,
                    )
                self.assertEqual(result["status"], "failed", result)

    def test_pe_inspection_relaxes_only_symbol_presence_not_format_or_strip_checks(
        self,
    ) -> None:
        directory = self.base / "inspect"
        directory.mkdir()
        commands = corpus.Commands(directory)
        metadata = {
            "format": "pe",
            "arch": "x86_64",
            "static_function_symbols": 0,
            "dynamic_function_symbols": 4,
            "debug_sections": [],
        }
        with mock.patch.object(commands, "run", return_value=json.dumps(metadata)):
            corpus.inspect(
                commands,
                "eval",
                directory / "input.exe",
                "x86_64-windows-gnu",
                stripped=True,
            )
            with self.assertRaises(corpus.CorpusError):
                corpus.inspect(
                    commands, "eval", directory / "wrong.elf", "x86_64-linux-musl"
                )
        for update in (
            {"debug_sections": [".debug_info"]},
            {"static_function_symbols": 1},
            {"arch": "x86"},
        ):
            with self.subTest(update=update):
                changed = {**metadata, **update}
                with (
                    mock.patch.object(
                        commands, "run", return_value=json.dumps(changed)
                    ),
                    self.assertRaises(corpus.CorpusError),
                ):
                    corpus.inspect(
                        commands,
                        "eval",
                        directory / "bad.exe",
                        "x86_64-windows-gnu",
                        stripped=True,
                    )

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
