"""Hermetic runtime producer tests. Fake recorders never launch a compiler or target."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import lzma
import os
import shlex
import sys
import tarfile
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[2] / "tools/signature_runtime.py"
SPEC = importlib.util.spec_from_file_location("signature_runtime", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)


def elf_object(marker: bytes = b"native-object") -> bytes:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[16:20] = b"\x01\x00\x3e\x00"
    return bytes(header) + marker


def ar_member(name: str, payload: bytes) -> bytes:
    encoded = name.encode("ascii")
    if len(encoded) > 16:
        raise ValueError(
            "test ar header requires a short name or explicit BSD encoding"
        )
    header = (
        encoded.ljust(16)
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"100644".ljust(8)
        + str(len(payload)).encode().ljust(10)
        + b"`\n"
    )
    return header + payload + (b"\n" if len(payload) % 2 else b"")


def archive_bytes(*members: tuple[str, bytes]) -> bytes:
    return b"!<arch>\n" + b"".join(
        ar_member(name, payload) for name, payload in members
    )


class FakeRecorder:
    def __init__(self, lib: Path, archives: list[Path], sysroot: Path) -> None:
        self.lib = lib
        self.archives = archives
        self.sysroot = sysroot
        self.calls: list[list[str]] = []
        self.environments: list[dict[str, str]] = []
        self.zig_version = "0.17.0"
        self.lld_version = "Homebrew LLD 22.1.8 (compatible with GNU linkers)\n"
        self.mutate_after_reference: Path | None = None
        self.mutate_during_replay: Path | None = None
        self.direct_inputs: list[Path] = []
        self.lookup_arguments: list[str] = []

    def __call__(self, argv: list[str], *, cwd: Path, env: Mapping[str, str]) -> str:
        self.calls.append(list(argv))
        self.environments.append(dict(env))
        executable = Path(argv[0]).name
        if executable == "zig" and argv[1:] == ["version"]:
            return self.zig_version
        if executable == "zig" and argv[1:] == ["env"]:
            return f'.{{ .lib_dir = "{self.lib}", }}'
        if executable == "rustc" and argv[1:] == ["--version", "--verbose"]:
            return "rustc fake exact installed toolchain\nhost: aarch64-apple-darwin\nrelease: 1.87.0\n"
        if executable == "rustc" and argv[1:] == ["--print", "sysroot"]:
            return str(self.sysroot)
        if executable == "zig" and argv[1:] == ["ld.lld", "--version"]:
            return self.lld_version
        embedded_lld = executable == "zig" and argv[1] == "ld.lld"
        if executable not in ("zig", "rustc") or "-o" not in argv:
            raise AssertionError(f"unexpected command or target execution: {argv}")
        if executable == "zig" and argv[1] not in ("cc", "c++", "ld.lld"):
            raise AssertionError(f"unexpected driver: {argv}")
        if not embedded_lld and any(
            "--trace" in arg or "--icf" in arg or "-Map" in arg for arg in argv
        ):
            raise AssertionError(f"Zig 0.17 rejects the supplied linker option: {argv}")
        output = Path(argv[argv.index("-o") + 1])
        output.write_bytes(
            b"fake replay image" if embedded_lld else b"fake original Zig link image"
        )
        for argument in argv:
            if embedded_lld and argument.startswith("-Map="):
                Path(argument.removeprefix("-Map=")).write_text(
                    "actual fake embedded linker map\n", encoding="utf-8"
                )
        if output.stem == "reference" and self.mutate_after_reference:
            self.mutate_after_reference.write_bytes(
                archive_bytes(("changed.o/", elf_object(b"changed")))
            )
        if embedded_lld and self.mutate_during_replay:
            self.mutate_during_replay.write_bytes(b"changed during replay")
        owned = [
            argument.removeprefix("-Clink-arg=")
            for argument in argv
            if argument.endswith(".o") and not argument.startswith("-Wl")
        ]
        for argument in argv:
            if argument.startswith("-Clinker="):
                wrapper = Path(argument.removeprefix("-Clinker="))
                script = wrapper.read_text(encoding="utf-8")
                line = next(
                    line
                    for line in script.splitlines()
                    if line.startswith("arguments = ")
                )
                owned.extend(
                    ast.literal_eval(
                        line.removeprefix("arguments = ").split(" + ", 1)[0]
                    )
                )
        raw = (
            shlex.join(
                [
                    "ld.lld",
                    "--no-gc-sections",
                    "-o",
                    str(output),
                    *owned,
                    *map(str, self.direct_inputs),
                    *map(str, self.archives),
                    *self.lookup_arguments,
                ]
            )
            + "\n"
        )
        for argument in argv:
            if argument.startswith("-Clinker="):
                log = Path(argument.removeprefix("-Clinker=")).with_suffix(".argv.log")
                with log.open("a", encoding="utf-8") as stream:
                    stream.write(raw)
        return raw


class RuntimeArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="signature-runtime-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.run_root = self.root / "target/signature-corpus/run"
        self.run_root.mkdir(parents=True)
        self.archive = self.root / "runtime.a"

    def extract(self, content: bytes, name: str = "members") -> Any:
        self.archive.write_bytes(content)
        return runtime.extract_runtime_archive(
            self.archive, self.run_root / name, self.run_root
        )

    def test_duplicate_names_preserve_ordinals_bytes_and_exact_hashes(self) -> None:
        content = archive_bytes(
            ("same.o/", elf_object(b"first")), ("same.o/", elf_object(b"second"))
        )
        receipts = self.extract(content)
        self.assertEqual([receipt.member_ordinal for receipt in receipts], [0, 1])
        self.assertEqual(
            [receipt.original_name for receipt in receipts], ["same.o", "same.o"]
        )
        self.assertNotEqual(receipts[0].object_path, receipts[1].object_path)
        self.assertNotEqual(receipts[0].object_sha256, receipts[1].object_sha256)
        for receipt in receipts:
            self.assertEqual(
                receipt.archive_sha256, hashlib.sha256(content).hexdigest()
            )
            self.assertEqual(
                hashlib.sha256(Path(receipt.object_path).read_bytes()).hexdigest(),
                receipt.object_sha256,
            )
            self.assertTrue(Path(receipt.object_path).is_relative_to(self.run_root))

    def test_gnu_long_names_and_index_match_object_crate_iterator_ordinal(self) -> None:
        content = archive_bytes(
            ("/", b"index"),
            ("//", b"libcxxabi/cxa_exception.cpp.o/\n"),
            ("/0", elf_object()),
        )
        receipts = self.extract(content)
        self.assertEqual(receipts[0].member_ordinal, 0)
        self.assertEqual(receipts[0].original_name, "libcxxabi/cxa_exception.cpp.o")
        self.assertEqual(Path(receipts[0].object_path).name, "member.o")

    def test_bsd_padded_extended_names_and_symbol_table(self) -> None:
        name = b"libcxx/string.cpp.o\0\0"
        content = archive_bytes(
            ("__.SYMDEF/", b"symbol table"), (f"#1/{len(name)}", name + elf_object())
        )
        receipts = self.extract(content)
        self.assertEqual(receipts[0].original_name, "libcxx/string.cpp.o")
        self.assertEqual(receipts[0].member_ordinal, 0)

    def test_coff_leading_tables_and_null_names_match_object_crate_iterator(
        self,
    ) -> None:
        content = archive_bytes(
            ("/", b"first index"),
            ("/", b"second index"),
            ("//", b"long-name-native.o\0"),
            ("/0", elf_object()),
        )
        receipts = self.extract(content)
        self.assertEqual(receipts[0].member_ordinal, 0)
        self.assertEqual(receipts[0].original_name, "long-name-native.o")

    def test_late_index_table_is_rejected_instead_of_changing_object_crate_ordinal(
        self,
    ) -> None:
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "ordinal mismatch"):
            self.extract(
                archive_bytes(("first.o/", elf_object()), ("/", b"misplaced index"))
            )

    def test_rejects_traversal_absolute_and_windows_names_before_writing(self) -> None:
        for number, name in enumerate(
            ("../evil.o", "/evil.o", "a/../../x.o", "C:/evil.o", "a\\evil.o")
        ):
            encoded = name.encode()
            with self.subTest(name=name), self.assertRaises(runtime.RuntimeBuildError):
                self.extract(
                    archive_bytes((f"#1/{len(encoded)}", encoded + elf_object())),
                    f"bad-{number}",
                )
            self.assertFalse((self.run_root / f"bad-{number}").exists())

    def test_rejects_bitcode_nested_archives_and_non_object_elf(self) -> None:
        executable = bytearray(elf_object())
        executable[16:18] = b"\x02\0"
        for number, payload in enumerate(
            (b"BC\xc0\xde" + b"x" * 64, b"!<arch>\n", bytes(executable))
        ):
            with (
                self.subTest(payload=payload[:8]),
                self.assertRaises(runtime.RuntimeBuildError),
            ):
                self.extract(archive_bytes(("bad.o/", payload)), f"bad-{number}")

    def test_rust_metadata_is_skipped_only_in_rlib_and_does_not_hide_nested_archive(
        self,
    ) -> None:
        metadata = b"rust.metadata.bin"
        content = archive_bytes(
            (f"#1/{len(metadata)}", metadata + b"rust metadata"),
            ("native.o/", elf_object()),
        )
        self.archive = self.root / "libcore-deadbeef.rlib"
        receipts = self.extract(content)
        self.assertEqual([receipt.member_ordinal for receipt in receipts], [1])
        self.archive = self.root / "not-rust.a"
        with self.assertRaises(runtime.RuntimeBuildError):
            self.extract(content, "not-rust")
        self.archive = self.root / "libcore-bad.rlib"
        with self.assertRaises(runtime.RuntimeBuildError):
            self.extract(
                archive_bytes((f"#1/{len(metadata)}", metadata + b"!<arch>\n")),
                "nested-metadata",
            )

    def test_actual_lib_rmeta_object_is_not_a_code_input_but_consumes_an_iterator_ordinal(
        self,
    ) -> None:
        self.archive = self.root / "libcore-deadbeef.rlib"
        receipts = self.extract(
            archive_bytes(
                ("lib.rmeta/", elf_object(b"metadata-only object")),
                ("native.o/", elf_object(b"runtime code")),
            )
        )
        self.assertEqual([receipt.original_name for receipt in receipts], ["native.o"])
        self.assertEqual(receipts[0].member_ordinal, 1)

    def test_regular_coff_is_allowed_but_import_header_is_not(self) -> None:
        coff = bytearray(24)
        coff[:4] = b"\x64\x86\x01\0"
        receipts = self.extract(archive_bytes(("native.o/", bytes(coff))))
        self.assertEqual(len(receipts), 1)
        with self.assertRaises(runtime.RuntimeBuildError):
            self.extract(
                archive_bytes(("import.o/", b"\0\0\xff\xff" + b"x" * 32)), "imports"
            )

    def test_malformed_variants_fail_closed(self) -> None:
        valid = archive_bytes(("a.o/", elf_object(b"odd")))
        variants = [
            b"!<thin>\n",
            valid[:-1],
            valid[:-1] + b"x",
            archive_bytes(("/99", elf_object())),
            archive_bytes(("#1/999", b"short")),
            b"!<arch>\n" + b"x" * 60,
            archive_bytes(("//", b"name-without-terminator"), ("/0", elf_object())),
        ]
        for number, content in enumerate(variants):
            with (
                self.subTest(number=number),
                self.assertRaises(runtime.RuntimeBuildError),
            ):
                self.extract(content, f"bad-{number}")

    def test_extraction_never_reuses_directory_or_leaves_selected_run(self) -> None:
        self.archive.write_bytes(archive_bytes(("a.o/", elf_object())))
        existing = self.run_root / "existing"
        existing.mkdir()
        for destination in (existing, self.root / "outside", self.run_root):
            with (
                self.subTest(destination=destination),
                self.assertRaises(runtime.RuntimeBuildError),
            ):
                runtime.extract_runtime_archive(
                    self.archive, destination, self.run_root
                )
        linked = self.run_root / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(runtime.RuntimeBuildError):
            runtime.extract_runtime_archive(
                self.archive, linked / "output", self.run_root
            )

    def test_archive_symlink_and_size_bounds_are_rejected(self) -> None:
        real = self.root / "real.a"
        real.write_bytes(archive_bytes(("a.o/", elf_object())))
        self.archive.symlink_to(real)
        with self.assertRaises(runtime.RuntimeBuildError):
            runtime.extract_runtime_archive(
                self.archive, self.run_root / "linked", self.run_root
            )
        self.archive.unlink()
        with (
            patch.object(runtime, "MAX_MEMBER_BYTES", 16),
            self.assertRaises(runtime.RuntimeBuildError),
        ):
            self.extract(real.read_bytes(), "oversized")

    def test_full_selected_archive_over_downstream_limit_is_unsupported_before_extraction(
        self,
    ) -> None:
        self.archive.write_bytes(archive_bytes(*[("native.o/", elf_object())] * 2049))
        with self.assertRaisesRegex(
            runtime.RuntimeUnsupported, "downstream count/byte"
        ):
            runtime.extract_runtime_archive(
                self.archive, self.run_root / "too-many", self.run_root
            )
        self.assertFalse((self.run_root / "too-many").exists())

    def test_explicit_subset_bounds_extraction_not_just_returned_receipts(self) -> None:
        self.archive.write_bytes(archive_bytes(*[("native.o/", elf_object())] * 2049))
        inventory: dict[str, int] = {}
        receipts = runtime.extract_runtime_archive(
            self.archive,
            self.run_root / "subset",
            self.run_root,
            member_limit=2,
            inventory=inventory,
        )
        self.assertEqual(inventory["available"], 2049)
        self.assertEqual(len(receipts), 2)
        self.assertEqual(len(list((self.run_root / "subset").rglob("member.o"))), 2)

    def test_owned_byte_budget_fails_before_writing_objects(self) -> None:
        self.archive.write_bytes(
            archive_bytes(("one.o/", elf_object()), ("two.o/", elf_object()))
        )
        with self.assertRaisesRegex(
            runtime.RuntimeUnsupported, "downstream count/byte"
        ):
            runtime.extract_runtime_archive(
                self.archive,
                self.run_root / "too-large",
                self.run_root,
                byte_budget=len(elf_object()),
            )
        self.assertFalse((self.run_root / "too-large").exists())

    def test_absolute_native_count_remains_bounded_even_with_explicit_subset(
        self,
    ) -> None:
        self.archive.write_bytes(
            archive_bytes(("one.o/", elf_object()), ("two.o/", elf_object()))
        )
        with (
            patch.object(runtime, "MAX_NATIVE_INPUTS", 1),
            self.assertRaisesRegex(runtime.RuntimeBuildError, "native member count"),
        ):
            runtime.extract_runtime_archive(
                self.archive,
                self.run_root / "subset",
                self.run_root,
                member_limit=1,
            )
        self.assertFalse((self.run_root / "subset").exists())

    def test_native_input_snapshots_require_regular_source_and_new_destination(
        self,
    ) -> None:
        source = self.root / "crt1.o"
        source.write_bytes(elf_object())
        destination = self.run_root / "captured.o"
        record = runtime._snapshot_file(source, destination, runtime.MAX_MEMBER_BYTES)
        self.assertEqual(record["sha256"], runtime._sha256(destination))
        with self.assertRaises(FileExistsError):
            runtime._snapshot_file(source, destination, runtime.MAX_MEMBER_BYTES)
        linked = self.root / "symlink.o"
        linked.symlink_to(source)
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "regular file"):
            runtime._snapshot_file(
                linked, self.run_root / "bad.o", runtime.MAX_MEMBER_BYTES
            )


class StaticLibraryLookupTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(
            prefix="signature-runtime-static-lookup-"
        )
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.first = self.root / "first"
        self.second = self.root / "second"
        self.first.mkdir()
        self.second.mkdir()
        self.library = self.first / "libm.a"
        self.library.write_bytes(archive_bytes(("math.o/", elf_object(b"first"))))
        (self.second / "libm.a").write_bytes(
            archive_bytes(("math.o/", elf_object(b"second")))
        )

    def resolve(self, *arguments: str) -> Any:
        return runtime._resolve_static_libraries(
            ["ld.lld", *arguments], self.root, "test-driver-unmeasured"
        )

    def test_later_joined_and_separate_search_paths_keep_recorded_order(self) -> None:
        resolved, evidence = self.resolve("-Bstatic", "-lm", "-Lfirst", "-L", "second")
        self.assertEqual(resolved[2], str(self.library))
        self.assertEqual(
            evidence[0]["search_directories"], [str(self.first), str(self.second)]
        )
        self.assertEqual(evidence[0]["sha256"], runtime._sha256(self.library))
        self.assertEqual(evidence[0]["tokens"], ["-lm"])
        self.assertEqual(evidence[0]["discovery_role"], "test-driver-unmeasured")
        resolved, _ = self.resolve("-static", "-l", "m", "-Lsecond", "-Lfirst")
        self.assertEqual(resolved[2], str(self.second / "libm.a"))

    def test_exact_simple_basename_archive_and_elf_object_are_retained_as_inputs(
        self,
    ) -> None:
        archive = self.first / "opaque-runtime"
        archive.write_bytes(archive_bytes(("ir.o/", b"BC\xc0\xde" + b"x" * 64)))
        obj = self.first / "crt-object"
        obj.write_bytes(elf_object())
        argv = [
            "ld.lld",
            "-static",
            "-l:opaque-runtime",
            "-l",
            ":crt-object",
            "-Lfirst",
        ]
        resolved, evidence, inputs, archives = runtime._link_plan(
            argv, self.root, "exact"
        )
        self.assertEqual(resolved[2:4], [str(archive), str(obj)])
        self.assertEqual(inputs, (archive, obj))
        self.assertEqual(archives, (archive,))
        self.assertEqual([item["kind"] for item in evidence], ["archive", "object"])
        self.assertEqual(evidence[1]["argv_count"], 2)

    def test_retained_zig_final_link_o3_and_joined_znow_preserve_native_input_mapping(
        self,
    ) -> None:
        relative_inputs = [
            "zig-global-cache/o/crt/crt1.o",
            "zig-local-cache/o/harness/signature-runtime-c-reference.o",
            "zig-global-cache/o/libc/libc.a",
            "zig-global-cache/o/zigc/libzigc.a",
            "zig-global-cache/o/compiler/libcompiler_rt.a",
        ]
        paths = [self.root / relative for relative in relative_inputs]
        for path in paths:
            path.parent.mkdir(parents=True)
            path.write_bytes(
                archive_bytes(("native.o/", elf_object()))
                if path.suffix == ".a"
                else elf_object()
            )
        argv = [
            "ld.lld",
            "--error-limit=0",
            "-mllvm",
            "-float-abi=hard",
            "-O3",
            "--entry",
            "_start",
            "-z",
            "stack-size=16777216",
            "--build-id=none",
            "--image-base=16777216",
            "--eh-frame-hdr",
            "-znow",
            "-m",
            "elf_x86_64",
            "-static",
            "-o",
            str(self.root / "discovery"),
            *relative_inputs[:2],
            "--as-needed",
            "-L/",
            *relative_inputs[2:],
        ]
        resolved, evidence, inputs, archives = runtime._link_plan(
            argv, self.root, "retained-driver-unmeasured"
        )
        self.assertEqual(resolved, argv)
        self.assertEqual(evidence, [])
        self.assertEqual(inputs, tuple(paths))
        self.assertEqual(archives, tuple(paths[2:]))
        baseline = [word for word in argv if word != "-O3"]
        index = baseline.index("-znow")
        baseline[index : index + 1] = ["-z", "now"]
        self.assertEqual(
            runtime._link_plan(baseline, self.root, "baseline")[2:], (inputs, archives)
        )
        for unsupported in ("-O4", "-O3=unrecorded", "-znow=unrecorded"):
            with (
                self.subTest(option=unsupported),
                self.assertRaises(runtime.RuntimeUnsupported),
            ):
                runtime._link_plan([*argv, unsupported], self.root, "unsupported")

    def test_static_dynamic_state_applies_at_each_library_not_afterwards(self) -> None:
        resolved, _ = self.resolve(
            "-Bdynamic", str(self.library), "-Bstatic", "-lm", "-Bdynamic", "-Lfirst"
        )
        self.assertIn(str(self.library), resolved)
        for args in (
            ("-lm", "-static"),
            ("-Bstatic", "-lm", "-Bdynamic", "-lm"),
            ("-Bdynamic", "-lm"),
        ):
            with (
                self.subTest(args=args),
                self.assertRaisesRegex(runtime.RuntimeUnsupported, "dynamic/default"),
            ):
                self.resolve(*args, "-Lfirst")

    def test_bad_missing_dynamic_and_implicit_lookup_forms_refuse(self) -> None:
        variants = [
            ["-static", "-lmissing", "-Lfirst"],
            ["-static", "-l../m", "-Lfirst"],
            ["-static", "-l:../libm.a", "-Lfirst"],
            ["-static", "-l:m/libm.a", "-Lfirst"],
            ["-static", "-l:", "-Lfirst"],
            ["-static", "-l"],
            ["-static", "-L"],
            ["-static", "-lm", "-L=first"],
            ["-static", "-lm", "-L$SYSROOT/first"],
            ["-static", "-lm", "-Lmissing"],
            ["--sysroot=/ignored", "-static", "-lm"],
            ["--start-lib", str(self.library), "--end-lib"],
            ["-T", "script.ld"],
            ["--script=script.ld"],
            ["--push-state", "-Bstatic", "-lm", "--pop-state"],
            ["-Bstatic=unknown", "-lm", "-Lfirst"],
            ["-shared"],
            ["script.lds"],
            ["--library=m"],
            ["--library-path=first"],
            ["@response"],
            ["-dTscript.a"],
            ["--unknown-file-input=unrelated.a"],
            ["-mllvm", "-sample-profile-file=unrelated.a"],
        ]
        for args in variants:
            with self.subTest(args=args), self.assertRaises(runtime.RuntimeUnsupported):
                self.resolve(*args)

    def test_first_found_script_shared_image_thin_archive_and_symlink_do_not_fall_through(
        self,
    ) -> None:
        shared = bytearray(elf_object())
        shared[16:18] = b"\x03\0"
        for payload in (
            b"INPUT(unrecorded.a)\n",
            b"GROUP(unrecorded.a)\n",
            bytes(shared),
            b"!<thin>\n",
        ):
            with self.subTest(payload=payload[:12]):
                self.library.write_bytes(payload)
                with self.assertRaisesRegex(
                    runtime.RuntimeUnsupported, "not a script/shared"
                ):
                    self.resolve("-static", "-lm", "-Lfirst", "-Lsecond")
        self.library.unlink()
        self.library.symlink_to(self.second / "libm.a")
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "regular file"):
            self.resolve("-static", "-lm", "-Lfirst", "-Lsecond")

    def test_search_directory_bound_is_enforced(self) -> None:
        with self.assertRaisesRegex(runtime.RuntimeUnsupported, "directory count"):
            self.resolve("-static", "-lm", *["-Lfirst"] * 257)

    def test_archive_parser_resolves_static_lookup_only_with_recorded_cwd(self) -> None:
        output = shlex.join(["ld.lld", "-static", "-lm", "-Lfirst", "-o", "image"])
        self.assertEqual(
            runtime.archives_from_link_output(
                output, cwd=self.root, expected_output=self.root / "image"
            ),
            (self.library,),
        )
        with self.assertRaisesRegex(
            runtime.RuntimeUnsupported, "recorded compiler cwd"
        ):
            runtime.archives_from_link_output(output)
        with self.assertRaisesRegex(runtime.RuntimeUnsupported, "resolve captured"):
            runtime._native_link_inputs(["ld.lld", "-static", "-lm"], self.root)

    def test_option_values_and_search_directories_are_not_native_file_inputs(
        self,
    ) -> None:
        directory = self.root / "search.o"
        directory.mkdir()
        argv = [
            "ld.lld",
            "-static",
            "--undefined",
            "not-a-file.o",
            "-L",
            "search.o",
            str(self.library),
        ]
        _, _, inputs, archives = runtime._link_plan(argv, self.root, "option-values")
        self.assertEqual(inputs, (self.library,))
        self.assertEqual(archives, (self.library,))


class RuntimeProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="signature-runtime-producer-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.directory = self.root / "target/signature-corpus/run"
        self.directory.mkdir(parents=True)
        self.zig = self.root / "zig"
        self.zig.write_bytes(b"fake installed executable")
        self.lib = self.root / "zig-lib"
        self.lib.mkdir()
        self.archive = self.root / "libc.a"
        self.archive.write_bytes(
            archive_bytes(
                ("strlen.o/", elf_object()), ("strlen.o/", elf_object(b"duplicate"))
            )
        )
        self.dependency = self.root / "libdependency.a"
        self.dependency.write_bytes(archive_bytes(("dependency.o/", elf_object())))
        self.sysroot = self.root / "rust-sysroot"
        self.sysroot.mkdir()
        self.recorder = FakeRecorder(
            self.lib, [self.archive, self.dependency], self.sysroot
        )
        source_patch = patch.object(
            runtime,
            "_source_provenance",
            return_value={"source_class": "installed-runtime"},
        )
        source_patch.start()
        self.addCleanup(source_patch.stop)

    def context(self, **updates: Any) -> Any:
        context = runtime.RuntimeContext(
            profile="musl",
            target="x86_64-linux-musl",
            optimization="O2",
            directory=self.directory,
            zig=self.zig,
            environment={"LC_ALL": "wrong", "SOURCE_DATE_EPOCH": "123"},
            run=self.recorder,
        )
        return replace(context, **updates)

    def test_actual_verbose_archive_frozen_once_same_objects_both_links_without_unsupported_flags(
        self,
    ) -> None:
        decoy = self.root / "newest-libc.a"
        decoy.write_bytes(b"not a real archive and must never be selected")
        result = runtime.build_runtime_profile(self.context())
        self.assertEqual(len(result.objects), 2)
        self.assertEqual(len(result.archives), 1)
        self.assertEqual(result.archives[0].read_bytes(), self.archive.read_bytes())
        self.assertEqual(
            result.provenance["frozen_archives"][0]["original_path"], str(self.archive)
        )
        links = [
            argv for argv in self.recorder.calls if "-o" in argv and argv[1] != "ld.lld"
        ]
        self.assertEqual(len(links), 3)
        replays = [
            argv for argv in self.recorder.calls if "-o" in argv and argv[1] == "ld.lld"
        ]
        self.assertEqual(len(replays), 2)
        for argv in replays:
            self.assertIn("--icf=none", argv)
            self.assertIn("--no-relax", argv)
            self.assertFalse(any(word.startswith("-Map") for word in argv))
        for argv in links:
            self.assertIn("-v", argv)
            self.assertFalse(
                any(
                    "--trace" in argument or "--icf" in argument or "-Map" in argument
                    for argument in argv
                )
            )
        for argv in links[1:]:
            self.assertTrue(all(str(path) in argv for path in result.objects))
            self.assertIn("-Wl,--no-gc-sections", argv)
            self.assertNotIn(str(decoy), argv)
        self.assertIsNone(result.reference_map)
        self.assertIsNone(result.target_map)
        self.assertNotEqual(
            links[1][links[1].index("cc") + 1 :], links[2][links[2].index("cc") + 1 :]
        )
        self.assertEqual(len(result.provenance["link_dependencies"]), 2)
        self.assertIn(
            "weak/hidden attribution excluded", result.provenance["ownership"]
        )
        self.assertFalse(result.provenance["host_target_execution"])
        self.assertTrue(
            all(env["SOURCE_DATE_EPOCH"] == "0" for env in self.recorder.environments)
        )

    def test_unsupported_embedded_lld_version_fails_before_compilation_instead_of_synthesizing_maps(
        self,
    ) -> None:
        self.recorder.lld_version = "LLD 23.0.0"
        with self.assertRaisesRegex(runtime.RuntimeUnsupported, "embedded LLD 22.1.8"):
            runtime.build_runtime_profile(self.context())
        self.assertFalse(any("-o" in argv for argv in self.recorder.calls))

    def test_static_lookup_archives_are_shared_snapshot_inputs_in_both_default_replays(
        self,
    ) -> None:
        unwind = self.root / "libunwind.a"
        math = self.root / "libm.a"
        unwind.write_bytes(archive_bytes(("unwind.o/", elf_object(b"unwind"))))
        math.write_bytes(archive_bytes(("math.bc/", b"BC\xc0\xde" + b"x" * 64)))
        self.recorder.lookup_arguments = [
            "-Bstatic",
            "-lunwind",
            "-l",
            "c",
            "-l:libm.a",
            "-L",
            str(self.root),
        ]
        before = {path: runtime._sha256(path) for path in (unwind, math, self.archive)}
        result = runtime.build_runtime_profile(self.context())
        shared: dict[str, str] = {}
        for role in ("reference", "target"):
            replay = result.provenance[f"{role}_embedded_lld_replay"]
            self.assertFalse(replay["zig_link_measured"])
            self.assertTrue(replay["final_measured"])
            self.assertEqual(
                replay["native_input_sha256_before"],
                replay["native_input_sha256_after"],
            )
            self.assertFalse(
                any(
                    word == "-l"
                    or word.startswith("-l:")
                    or word in ("-lunwind", "-lc")
                    for word in replay["replay_argv"]
                )
            )
            for record in result.provenance[f"{role}_library_search"]:
                source, consumed = record["resolved_path"], record["consumed_path"]
                self.assertEqual(shared.setdefault(source, consumed), consumed)
                self.assertIn(consumed, replay["replay_argv"])
                self.assertNotIn(source, replay["replay_argv"])
                self.assertEqual(runtime._sha256(Path(consumed)), before[Path(source)])
                self.assertEqual(record["consumed_sha256"], before[Path(source)])
        self.assertEqual({path: runtime._sha256(path) for path in before}, before)
        self.assertEqual(len(result.provenance["link_dependencies"]), 4)
        self.assertEqual(len(result.archives), 1)
        self.assertIsNone(result.reference_map)
        unwind.write_bytes(archive_bytes(("unwind.o/", elf_object(b"source changed"))))
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "source changed"):
            runtime._revalidate_runtime(result)

    def test_dynamic_lookup_is_refused_before_any_measured_replay(self) -> None:
        self.recorder.lookup_arguments = ["-Bdynamic", "-lc", "-L", str(self.root)]
        with self.assertRaisesRegex(runtime.RuntimeUnsupported, "dynamic/default"):
            runtime.build_runtime_profile(self.context())
        self.assertFalse(
            any(argv[1] == "ld.lld" and "-o" in argv for argv in self.recorder.calls)
        )

    def test_musl_and_math_static_lookup_without_explicit_libc_path_is_supported(
        self,
    ) -> None:
        math = self.root / "libm.a"
        math.write_bytes(archive_bytes(("math.o/", elf_object())))
        self.recorder.archives = [self.dependency]
        self.recorder.lookup_arguments = ["-static", "-lc", "-lm", f"-L{self.root}"]
        result = runtime.build_runtime_profile(self.context())
        self.assertEqual(len(result.objects), 2)
        self.assertEqual([archive.name for archive in result.archives], ["libc.a"])
        self.assertEqual(
            {
                item["resolved_path"]
                for item in result.provenance["discovery_library_search"]
            },
            {str(self.archive), str(math)},
        )

    def test_resolved_library_source_mutation_during_default_replay_is_rejected(
        self,
    ) -> None:
        math = self.root / "libm.a"
        math.write_bytes(archive_bytes(("math.o/", elf_object())))
        self.recorder.lookup_arguments = ["-static", "-lm", "-L", str(self.root)]
        self.recorder.mutate_during_replay = math
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "source changed"):
            runtime.build_runtime_profile(self.context())
        self.assertFalse((self.directory / "runtime-provenance.json").exists())

    def test_crt_change_after_first_driver_link_binds_frozen_b_for_both_measured_outputs(
        self,
    ) -> None:
        crt = self.root / "crt1.o"
        original, captured = elf_object(b"CRT-A"), elf_object(b"CRT-B")
        crt.write_bytes(original)
        self.recorder.direct_inputs = [crt]
        consumed: list[bytes] = []

        def recorder(argv: list[str], *, cwd: Path, env: Mapping[str, str]) -> str:
            previous = crt.read_bytes()
            text = self.recorder(argv, cwd=cwd, env=env)
            if "-o" not in argv:
                return text
            output = Path(argv[argv.index("-o") + 1])
            if argv[1] != "ld.lld":
                output.write_bytes(previous)
                if output.name == "reference.zig-link":
                    crt.write_bytes(captured)
            else:
                snapshots = [
                    Path(word)
                    for word in argv
                    if word.endswith(".o") and "/link-inputs/" in word
                ]
                self.assertEqual(len(snapshots), 1)
                consumed.append(snapshots[0].read_bytes())
                output.write_bytes(consumed[-1])
            return text

        result = runtime.build_runtime_profile(self.context(run=recorder))
        self.assertEqual(consumed, [captured, captured])
        self.assertEqual(result.reference.read_bytes(), captured)
        self.assertEqual(result.target.read_bytes(), captured)
        self.assertEqual((self.directory / "reference.zig-link").read_bytes(), original)
        discovery = next(
            record
            for record in result.provenance["discovery_native_inputs"]
            if record["path"] == str(crt)
        )
        self.assertEqual(discovery["sha256"], hashlib.sha256(original).hexdigest())
        self.assertFalse(discovery["measured"])
        shared_paths = []
        for role in ("reference", "target"):
            record = next(
                record
                for record in result.provenance[f"{role}_native_link_inputs"]
                if record["original_path"] == str(crt)
            )
            self.assertEqual(
                record["consumed_sha256"], hashlib.sha256(captured).hexdigest()
            )
            self.assertEqual(record["discovery_role"], "reference-driver-unmeasured")
            shared_paths.append(record["consumed_path"])
        self.assertEqual(shared_paths[0], shared_paths[1])

    def test_explicit_member_budget_is_reported_as_a_subset_not_full_runtime_coverage(
        self,
    ) -> None:
        result = runtime.build_runtime_profile(self.context(owned_member_limit=1))
        self.assertEqual(len(result.objects), 1)
        self.assertEqual(len(list((self.directory / "frozen").rglob("member.o"))), 1)
        self.assertEqual(result.provenance["available_component_native_members"], 2)
        self.assertEqual(result.provenance["selected_component_native_members"], 1)
        self.assertIn("subset", result.provenance["coverage"])
        self.assertTrue(
            all(
                str(result.objects[0]) in argv
                for argv in self.recorder.calls
                if "-o" in argv and "discovery" not in argv[argv.index("-o") + 1]
            )
        )

    def test_changed_dependency_fails_final_link_hash_gate(self) -> None:
        self.recorder.mutate_after_reference = self.dependency
        with self.assertRaisesRegex(
            runtime.RuntimeBuildError, "dependency differs|source changed"
        ):
            runtime.build_runtime_profile(self.context())

    def test_dependency_bitcode_archives_are_hashed_but_never_extracted_as_owned(
        self,
    ) -> None:
        dependency = self.root / "libcompiler_rt.a"
        dependency.write_bytes(archive_bytes(("bitcode.o/", b"BC\xc0\xde" + b"x" * 64)))
        self.recorder.archives.append(dependency)
        result = runtime.build_runtime_profile(self.context())
        self.assertEqual(len(result.archives), 1)
        self.assertEqual(len(result.provenance["link_dependencies"]), 3)
        self.assertTrue(
            all(
                Path(receipt.archive_path).name == "libc.a"
                for receipt in result.member_receipts
            )
        )

    def test_native_dependency_and_crt_mutations_during_replay_fail_post_gate(
        self,
    ) -> None:
        crt = self.root / "crt1.o"
        for number, selected in enumerate((self.dependency, crt)):
            with self.subTest(selected=selected):
                directory = self.directory.parent / f"mutation-{number}"
                directory.mkdir()
                self.dependency.write_bytes(
                    archive_bytes(("dependency.o/", elf_object()))
                )
                crt.write_bytes(elf_object(b"crt input"))
                self.recorder.direct_inputs = [crt]
                self.recorder.mutate_during_replay = selected
                with self.assertRaisesRegex(
                    runtime.RuntimeBuildError, "source changed"
                ):
                    runtime.build_runtime_profile(
                        self.context(directory=directory, require_link_maps=True)
                    )
                self.assertFalse((directory / "runtime-provenance.json").exists())

    def test_all_replay_native_inputs_are_hash_bound_and_revalidated_at_publication(
        self,
    ) -> None:
        crt = self.root / "crt1.o"
        crt.write_bytes(elf_object(b"crt input"))
        self.recorder.direct_inputs = [crt]
        result = runtime.build_runtime_profile(self.context(require_link_maps=True))
        for role in ("reference", "target"):
            replay = result.provenance[f"{role}_embedded_lld_replay"]["replay_argv"]
            records = result.provenance[f"{role}_native_link_inputs"]
            for source in (crt, self.archive, self.dependency):
                record = next(
                    item for item in records if item["original_path"] == str(source)
                )
                self.assertNotEqual(record["path"], str(source))
                self.assertIn(record["path"], replay)
                self.assertNotIn(str(source), replay)
                self.assertEqual(
                    runtime._sha256(Path(record["path"])), record["sha256"]
                )
        runtime._revalidate_runtime(result)
        for role in ("reference", "target"):
            replay = result.provenance[f"{role}_embedded_lld_replay"]
            self.assertEqual(
                replay["native_input_sha256_before"],
                replay["native_input_sha256_after"],
            )
            self.assertTrue(
                all(
                    record["consumed_path"] == record["path"]
                    for record in result.provenance[f"{role}_native_link_inputs"]
                )
            )
        crt.write_bytes(elf_object(b"changed after links"))
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "source changed"):
            runtime._revalidate_runtime(result)

    def test_consumed_dependency_snapshot_mutation_is_rejected_at_publication(
        self,
    ) -> None:
        result = runtime.build_runtime_profile(self.context(require_link_maps=True))
        record = next(
            item
            for item in result.provenance["reference_native_link_inputs"]
            if item["original_path"] == str(self.dependency)
        )
        captured = Path(record["consumed_path"])
        captured.chmod(0o644)
        captured.write_bytes(b"changed captured dependency")
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "source changed"):
            runtime._revalidate_runtime(result)

    def test_publication_hashes_each_owned_archive_once_not_once_per_member(
        self,
    ) -> None:
        result = runtime.build_runtime_profile(self.context())
        with patch.object(runtime, "_sha256", wraps=runtime._sha256) as digest:
            runtime._revalidate_runtime(result)
        self.assertEqual(
            sum(call.args == (result.archives[0],) for call in digest.call_args_list), 1
        )

    def test_changed_member_receipt_json_is_rejected_at_publication(self) -> None:
        result = runtime.build_runtime_profile(self.context())
        (self.directory / "archive-member-receipts.json").write_text(
            "[]\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "receipt JSON changed"):
            runtime._revalidate_runtime(result)

    def test_native_input_lookup_uses_captured_cwd_not_output_or_newest_cache(
        self,
    ) -> None:
        crt = self.root / "crt1.o"
        crt.write_bytes(elf_object())
        (self.root / "newest-crt1.o").write_bytes(b"must never be consumed")
        captured = [
            "ld.lld",
            "-o",
            "uncreated-output.o",
            "../../../crt1.o",
            "../../../libc.a",
        ]
        self.assertEqual(
            runtime._native_link_inputs(captured, self.directory), (crt, self.archive)
        )
        with (
            patch.object(runtime, "MAX_NATIVE_INPUTS", 1),
            self.assertRaises(runtime.RuntimeUnsupported),
        ):
            runtime._native_link_inputs(captured, self.directory)

    def test_receipt_and_cumulative_object_bounds_fail_before_final_links(self) -> None:
        for name, limit in (
            ("MAX_RECEIPT_BYTES", 10),
            ("MAX_OWNED_BYTES", 1),
            ("MAX_OWNED_MEMBERS", 1),
        ):
            with self.subTest(name=name):
                directory = self.directory.parent / name
                directory.mkdir()
                self.recorder.calls.clear()
                with (
                    patch.object(runtime, name, limit),
                    self.assertRaises(runtime.RuntimeUnsupported),
                ):
                    runtime.build_runtime_profile(self.context(directory=directory))
                self.assertEqual(sum("-o" in argv for argv in self.recorder.calls), 1)

    def test_explicit_limit_above_downstream_preflight_is_rejected_before_commands(
        self,
    ) -> None:
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "member limit"):
            runtime.build_runtime_profile(self.context(owned_member_limit=2049))
        self.assertEqual(self.recorder.calls, [])

    def test_wrong_or_unavailable_runtime_is_explicitly_unsupported(self) -> None:
        self.recorder.archives = [self.dependency]
        with self.assertRaisesRegex(runtime.RuntimeUnsupported, "no unambiguous"):
            runtime.build_runtime_profile(self.context(profile="compiler-runtime"))

    def test_unsafe_contexts_are_rejected_before_any_host_command(self) -> None:
        for updates in (
            {"profile": "sdk"},
            {"target": "aarch64-macos"},
            {"optimization": "O3"},
            {"profile": "musl", "target": "x86_64-windows-gnu"},
            {"profile": "mingw-support"},
        ):
            with (
                self.subTest(updates=updates),
                self.assertRaises(runtime.RuntimeBuildError),
            ):
                runtime.build_runtime_profile(self.context(**updates))
        self.assertEqual(self.recorder.calls, [])
        (self.directory / "user-file").write_bytes(b"must survive")
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "empty"):
            runtime.build_runtime_profile(self.context())
        self.assertEqual((self.directory / "user-file").read_bytes(), b"must survive")

    def test_missing_rust_cross_component_does_not_substitute_host_core(self) -> None:
        rustc = self.root / "rustc"
        rustc.write_bytes(b"matching installed compiler")
        host = self.sysroot / "lib/rustlib/aarch64-apple-darwin/lib"
        host.mkdir(parents=True)
        (host / "libcore-deadbeef.rlib").write_bytes(
            archive_bytes(("core.o/", elf_object()))
        )
        with self.assertRaisesRegex(
            runtime.RuntimeUnsupported, "operator must install exact"
        ):
            runtime.build_runtime_profile(
                self.context(profile="rust-core", rustc=rustc)
            )
        self.assertFalse(any("-o" in argv for argv in self.recorder.calls))

    def test_installed_rust_core_owns_only_exact_traced_core_not_std_alloc_or_builtins(
        self,
    ) -> None:
        rustc = self.root / "rustc"
        rustc.write_bytes(b"matching installed compiler")
        libraries = self.sysroot / "lib/rustlib/x86_64-unknown-linux-musl/lib"
        libraries.mkdir(parents=True)
        core = libraries / "libcore-deadbeef.rlib"
        std = libraries / "libstd-012345.rlib"
        alloc = libraries / "liballoc-abcdef.rlib"
        builtins = libraries / "libcompiler_builtins-abcdef.rlib"
        for path in (core, std, alloc, builtins):
            path.write_bytes(
                archive_bytes(("native.o/", elf_object(path.name.encode())))
            )
        notices = self.sysroot / "share/doc/rust"
        notices.mkdir(parents=True)
        (notices / "COPYRIGHT-library.html").write_text(
            "fake original notice", encoding="utf-8"
        )
        self.recorder.archives = [core, std, alloc, builtins, self.archive]
        result = runtime.build_runtime_profile(
            self.context(profile="rust-core", rustc=rustc)
        )
        self.assertEqual(len(result.objects), 1)
        self.assertEqual(result.archives[0].name, core.name)
        self.assertEqual(len(result.provenance["link_dependencies"]), 5)
        rust_links = [
            argv
            for argv in self.recorder.calls
            if "-o" in argv and Path(argv[0]).name == "rustc"
        ]
        self.assertTrue(
            all("-Cpanic=abort" in argv and "-Clto=off" in argv for argv in rust_links)
        )
        self.assertTrue(
            all(
                "-Clinker-flavor=ld.lld" in argv and "-Csave-temps=yes" in argv
                for argv in rust_links
            )
        )
        self.assertFalse(
            any(
                "--trace" in argument or "--icf" in argument or "-Map" in argument
                for argv in rust_links
                for argument in argv
            )
        )
        owned_linker = Path(result.provenance["rust_owned_linker"]["path"])
        script = owned_linker.read_text(encoding="utf-8")
        self.assertIn(str(result.objects[0]), script)
        self.assertLess(
            script.index(str(result.objects[0])), script.index("sys.argv[1:]")
        )
        self.assertIn(f"-Clinker={owned_linker}", rust_links[1])
        self.assertIsNone(result.reference_map)
        self.assertIsNone(result.target_map)

    def test_rust_std_does_not_extract_bitcode_only_core_dependency(self) -> None:
        rustc = self.root / "rustc"
        rustc.write_bytes(b"matching installed compiler")
        libraries = self.sysroot / "lib/rustlib/x86_64-unknown-linux-musl/lib"
        libraries.mkdir(parents=True)
        std = libraries / "libstd-deadbeef.rlib"
        core = libraries / "libcore-abcdef.rlib"
        std.write_bytes(archive_bytes(("native.o/", elf_object())))
        core.write_bytes(archive_bytes(("bitcode.o/", b"BC\xc0\xde" + b"x" * 64)))
        notice = self.sysroot / "share/doc/rust/COPYRIGHT-library.html"
        notice.parent.mkdir(parents=True)
        notice.write_bytes(b"original notice")
        self.recorder.archives = [std, core]
        self_contained = libraries / "self-contained"
        self_contained.mkdir()
        for name in ("libunwind.a", "libc.a"):
            (self_contained / name).write_bytes(
                archive_bytes(("native.o/", elf_object(name.encode())))
            )
        crt = self_contained / "crt1.o"
        crt.write_bytes(elf_object(b"target CRT"))
        self.recorder.direct_inputs = [crt]
        self.recorder.lookup_arguments = [
            "-Bstatic",
            "-lunwind",
            "-lc",
            "-Bdynamic",
            "-L",
            str(self_contained),
        ]
        result = runtime.build_runtime_profile(
            self.context(profile="rust-std", rustc=rustc)
        )
        self.assertEqual([path.name for path in result.archives], [std.name])
        self.assertEqual(len(result.provenance["link_dependencies"]), 4)
        self.assertEqual(len(list((self.directory / "frozen").rglob("member.o"))), 1)
        for role in ("reference", "target"):
            self.assertEqual(
                [
                    item["library"]
                    for item in result.provenance[f"{role}_library_search"]
                ],
                ["unwind", "c"],
            )

    def test_merged_cxx_archive_selects_source_members_not_symbol_name_guesses(
        self,
    ) -> None:
        for family, name in (
            ("libcxx", "string.cpp"),
            ("libcxxabi", "cxa_exception.cpp"),
        ):
            path = self.lib / family / "src" / name
            path.parent.mkdir(parents=True)
            path.write_bytes(b"fake source")
        archive = self.root / "libc++.a"
        archive.write_bytes(
            archive_bytes(
                ("string.o/", elf_object(b"cxx")),
                ("cxa_exception.o/", elf_object(b"abi")),
            )
        )
        self.recorder.archives = [archive, self.dependency]
        result = runtime.build_runtime_profile(self.context(profile="libc++abi"))
        self.assertEqual(
            [receipt.original_name for receipt in result.member_receipts],
            ["cxa_exception.o"],
        )
        self.assertIn("subset", result.provenance["coverage"])
        self.assertTrue(
            all(
                argv[1] == "c++"
                for argv in self.recorder.calls
                if "-o" in argv and argv[1] != "ld.lld"
            )
        )

    def test_combined_archive_unselected_bitcode_member_is_not_owned_or_extracted(
        self,
    ) -> None:
        source = self.lib / "libcxx/src/string.cpp"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"selected source unit")
        archive = self.root / "libc++.a"
        archive.write_bytes(
            archive_bytes(
                ("string.o/", elf_object()), ("cxa.o/", b"BC\xc0\xde" + b"x" * 64)
            )
        )
        self.recorder.archives = [archive, self.dependency]
        result = runtime.build_runtime_profile(self.context(profile="libc++"))
        self.assertEqual(
            [receipt.original_name for receipt in result.member_receipts], ["string.o"]
        )
        self.assertEqual(len(list((self.directory / "frozen").rglob("member.o"))), 1)

    def test_link_output_parser_ignores_cache_hints_and_takes_real_linker_argv(
        self,
    ) -> None:
        output = (
            f"newest cache file: {self.archive}\n"
            + shlex.join(["/installed/ld.lld", str(self.archive)])
            + f"\n{self.dependency}\n"
        )
        self.assertEqual(runtime.archives_from_link_output(output), (self.archive,))
        self.assertEqual(
            runtime.archives_from_link_output(f"cache hint: {self.archive}\n"), ()
        )

    def test_verbose_link_parser_accepts_direct_and_zig_subcommand_invocations_only(
        self,
    ) -> None:
        for prefix in (["ld.lld"], ["/installed/ld.lld"], ["/installed/zig", "ld.lld"]):
            with self.subTest(prefix=prefix):
                output = shlex.join(
                    [*prefix, "--error-limit=0", "-static", str(self.archive)]
                )
                self.assertEqual(
                    runtime.archives_from_link_output(output), (self.archive,)
                )
        unrelated = shlex.join(["/installed/zig", "cc", str(self.archive)])
        self.assertEqual(runtime.archives_from_link_output(unrelated), ())

    def test_actual_relative_link_inputs_use_recorded_cwd_and_ignore_ar_cc_and_relocatable_links(
        self,
    ) -> None:
        output_path = self.directory / "discovery"
        output = "\n".join(
            (
                "ld.lld -r -o crt1.o missing-crt-input.a",
                "ar rcs newest-guessed.a missing-ar-input.a",
                "zig cc missing-cc-input.a",
                f"ld.lld --error-limit=0 -mllvm -float-abi=hard -static -o {output_path} ../../../libc.a",
            )
        )
        observed = runtime.archives_from_link_output(
            output, cwd=self.directory, expected_output=output_path
        )
        self.assertEqual(observed, (self.archive,))
        self.assertEqual(runtime.archives_from_link_output(output), ())
        with self.assertRaisesRegex(
            runtime.RuntimeUnsupported, "exact compiler output"
        ):
            runtime.final_link_argv(
                output, cwd=self.directory, expected_output=self.directory / "other"
            )

    def test_embedded_lld_replays_only_captured_inputs_and_emits_real_maps(
        self,
    ) -> None:
        result = runtime.build_runtime_profile(self.context(require_link_maps=True))
        assert result.reference_map is not None and result.target_map is not None
        self.assertTrue(result.reference_map.is_file())
        self.assertTrue(result.target_map.is_file())
        embedded_links = [
            argv
            for argv in self.recorder.calls
            if argv[:2] == [str(self.zig), "ld.lld"] and "-o" in argv
        ]
        self.assertEqual(len(embedded_links), 2)
        for role, argv in zip(("reference", "target"), embedded_links):
            self.assertIn("--icf=none", argv)
            self.assertIn(f"-Map={self.directory / f'{role}.map'}", argv)
            self.assertTrue(all(str(obj) in argv for obj in result.objects))
            replay = result.provenance[f"{role}_embedded_lld_replay"]
            self.assertNotEqual(replay["zig_link_sha256"], replay["final_sha256"])
            self.assertTrue(Path(replay["zig_link_path"]).is_file())
            captured = replay["captured_argv"]
            expected = [str(self.zig), "ld.lld", *captured[1:]]
            expected[expected.index("-o") + 1] = str(self.directory / role)
            replacements = {
                record["original_path"]: record["path"]
                for record in result.provenance[f"{role}_native_link_inputs"]
            }
            expected = [replacements.get(word, word) for word in expected]
            expected.extend(
                ("--icf=none", "--no-relax", f"-Map={self.directory / f'{role}.map'}")
            )
            self.assertEqual(argv, expected)

    def test_isolated_rust_sysroot_requires_matching_pinned_receipt_and_does_not_modify_host(
        self,
    ) -> None:
        rustc = self.root / "rustc"
        rustc.write_bytes(b"matching installed compiler")
        isolated = self.root / "target/operator-rust-sysroot"
        libraries = isolated / "lib/rustlib/x86_64-unknown-linux-musl/lib"
        libraries.mkdir(parents=True)
        core = libraries / "libcore-deadbeef.rlib"
        core.write_bytes(archive_bytes(("native.o/", elf_object())))
        std = libraries / "libstd-deadbeef.rlib"
        std.write_bytes(archive_bytes(("native.o/", elf_object(b"standard runtime"))))
        crt = libraries / "self-contained/crt1.o"
        crt.parent.mkdir()
        crt.write_bytes(elf_object(b"self-contained runtime dependency"))
        source_archive = self.root / "operator-component.tar.xz"
        snapshot = io.BytesIO()
        prefix = "rust-std-1.87.0-x86_64-unknown-linux-musl/rust-std-x86_64-unknown-linux-musl"
        with tarfile.open(fileobj=snapshot, mode="w") as source:
            for path in (core, std, crt):
                data = path.read_bytes()
                member = tarfile.TarInfo(f"{prefix}/{path.relative_to(isolated)}")
                member.size = len(data)
                source.addfile(member, io.BytesIO(data))
        source_archive.write_bytes(lzma.compress(snapshot.getvalue()))
        notice = self.sysroot / "share/doc/rust/COPYRIGHT-library.html"
        notice.parent.mkdir(parents=True)
        notice.write_bytes(b"original compiler-matched library notice")
        receipt = {
            "schema_version": 1,
            "version": "1.87.0",
            "target": "x86_64-unknown-linux-musl",
            "sysroot": str(isolated),
            "archive_sha256": hashlib.sha256(source_archive.read_bytes()).hexdigest(),
            "file_sha256": {
                str(path.relative_to(isolated)): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in (core, std, crt)
            },
            "installer_executed": False,
            "target_executed": False,
        }
        receipt_path = isolated / "component-receipt.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        context = self.context(
            profile="rust-core",
            rustc=rustc,
            rust_sysroot=isolated,
            rust_component_archive=source_archive,
        )
        with self.assertRaisesRegex(
            runtime.RuntimeBuildError, "exact release/target pin"
        ):
            runtime._rust_setup(context, {})
        pin = {("1.87.0", "x86_64-unknown-linux-musl"): receipt["archive_sha256"]}
        with patch.object(runtime, "RUST_COMPONENT_PINS", pin):
            compiler, provenance = runtime._rust_setup(context, {})
            runtime._recheck_rust_component(context, provenance)
            crt.write_bytes(elf_object(b"changed after initial verification"))
            with self.assertRaisesRegex(
                runtime.RuntimeBuildError, "differ from component receipt"
            ):
                runtime._recheck_rust_component(context, provenance)
            receipt["file_sha256"][str(crt.relative_to(isolated))] = hashlib.sha256(
                crt.read_bytes()
            ).hexdigest()
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(
                runtime.RuntimeBuildError, "do not match pinned archive payload"
            ):
                runtime._isolated_rust_component(
                    context, "1.87.0", "x86_64-unknown-linux-musl"
                )
        self.assertIn("--sysroot", compiler)
        self.assertEqual(compiler[compiler.index("--sysroot") + 1], str(isolated))
        self.assertEqual(provenance["compiler_installed_sysroot"], str(self.sysroot))
        self.assertEqual(provenance["sysroot"], str(isolated))
        self.assertFalse(
            (self.sysroot / "lib/rustlib/x86_64-unknown-linux-musl").exists()
        )

    def test_cli_real_commands_clean_environment_and_tool_capture_precede_first_host_call(
        self,
    ) -> None:
        corpus = runtime._corpus_module()
        evaluator = self.root / "eval"
        builder = self.root / "builder"
        for tool in (self.zig, evaluator, builder):
            tool.write_bytes(b"original executable")
            tool.chmod(0o755)
        observed: list[str] = []

        def host(argv: list[str], **kwargs: Any) -> Any:
            environment = kwargs["env"]
            self.assertFalse(
                {"CPATH", "ENV", "PERL5OPT", "INHERITED_SECRET"} & environment.keys()
            )
            self.assertEqual(
                environment["HOME"], str(self.directory / "configured-home")
            )
            self.assertTrue(Path(environment["HOME"]).is_dir())
            kwargs["stdout"].write(b"stdout only")
            kwargs["stderr"].write(shlex.join(["ld.lld", str(self.archive)]).encode())
            return SimpleNamespace(returncode=0)

        def unavailable(context: Any) -> Any:
            runtime._validate_context(context)
            self.assertEqual(
                (self.directory / "tools/eval").read_bytes(), evaluator.read_bytes()
            )
            self.assertEqual(
                (self.directory / "tools/builder").read_bytes(), builder.read_bytes()
            )
            observed.append(
                context.run(
                    [str(self.zig), "env"], cwd=self.directory, env=context.environment
                )
            )
            raise runtime.RuntimeUnsupported("fixture missing target component")

        poison = {
            key: "harmless-poison"
            for key in ("CPATH", "ENV", "PERL5OPT", "INHERITED_SECRET")
        }
        with (
            patch.dict(os.environ, poison),
            patch.object(runtime, "_corpus_module", return_value=corpus),
            patch.object(corpus.subprocess, "run", side_effect=host),
            patch.object(runtime, "build_runtime_profile", side_effect=unavailable),
        ):
            status = runtime.main(
                [
                    "--profile",
                    "musl",
                    "--target",
                    "x86_64-linux-musl",
                    "--output-dir",
                    str(self.directory),
                    "--zig",
                    str(self.zig),
                    "--eval",
                    str(evaluator),
                    "--builder",
                    str(builder),
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(
            runtime.archives_from_link_output(observed[0]), (self.archive,)
        )
        result = json.loads(
            (self.directory / "result.json").read_text(encoding="utf-8")
        )
        self.assertEqual(result["status"], "unsupported")
        self.assertNotIn("harmless-poison", json.dumps(result))
        records = json.loads(
            (self.directory / "commands.json").read_text(encoding="utf-8")
        )
        self.assertEqual(records[0]["env_policy"], "configured-clean-allowlist-v1")
        self.assertNotIn("CPATH", records[0]["environment"])
        snapshots = result["measurement_tool_snapshot"]
        for key, original in (("evaluator", evaluator), ("builder", builder)):
            self.assertEqual(snapshots[key]["original_path"], str(original))
            self.assertEqual(
                snapshots[key]["original_sha256"], snapshots[key]["sha256"]
            )
            self.assertNotEqual(snapshots[key]["path"], str(original))


class RuntimeNoticeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="signature-runtime-notices-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def layout(self, homebrew: bool = False) -> tuple[Path, Path]:
        distribution = self.root / ("homebrew" if homebrew else "unpacked")
        zig = distribution / ("bin/zig" if homebrew else "zig")
        zig.parent.mkdir(parents=True)
        zig.write_bytes(b"installed Zig")
        lib = distribution / ("lib/zig" if homebrew else "lib")
        for relative in ("compiler_rt", "libc/include", "include"):
            directory = lib / relative
            directory.mkdir(parents=True)
            (directory / "source.h").write_bytes(relative.encode())
        (lib / "compiler_rt.zig").write_bytes(b"compiler source")
        return zig, lib

    def test_zig_license_uses_correlated_unpacked_or_homebrew_distribution_only(
        self,
    ) -> None:
        for homebrew in (False, True):
            with self.subTest(homebrew=homebrew):
                zig, lib = self.layout(homebrew)
                distribution = zig.parent.parent if homebrew else zig.parent
                notice = distribution / "LICENSE"
                notice.write_bytes(b"actual Zig MIT license")
                provenance = runtime._source_provenance(lib, zig, "compiler-runtime")
                self.assertEqual(
                    provenance["original_notices"],
                    {
                        "compiler-runtime": {
                            "path": str(notice),
                            "sha256": runtime._sha256(notice),
                        },
                    },
                )
                self.assertEqual(provenance["source_root"], str(lib))
                self.assertEqual(
                    provenance["source_configuration_header_sha256"]["compiler_rt.zig"],
                    runtime._sha256(lib / "compiler_rt.zig"),
                )

    def test_unpacked_missing_license_cannot_use_unrelated_parent_license(self) -> None:
        zig, lib = self.layout()
        (zig.parent.parent / "LICENSE").write_bytes(b"unrelated repository license")
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "required regular file"):
            runtime._source_provenance(lib, zig, "compiler-runtime")
        with self.assertRaisesRegex(runtime.RuntimeBuildError, "distribution layout"):
            runtime._source_provenance(
                self.root / "unrelated-lib", zig, "compiler-runtime"
            )

    def test_selected_component_notice_does_not_require_or_hash_other_component_notices(
        self,
    ) -> None:
        zig, lib = self.layout()
        selected = lib / "libc/musl/COPYRIGHT"
        selected.parent.mkdir(parents=True)
        selected.write_bytes(b"actual musl notice")
        unrelated = lib / "libcxx/LICENSE.TXT"
        unrelated.parent.mkdir()
        unrelated.write_bytes(b"unselected license")
        provenance = runtime._source_provenance(lib, zig, "musl")
        self.assertEqual(set(provenance["original_notices"]), {"musl"})
        self.assertNotIn(
            "libcxx/LICENSE.TXT", provenance["source_configuration_header_sha256"]
        )
        self.assertEqual(
            provenance["original_notices"]["musl"]["sha256"], runtime._sha256(selected)
        )


class RuntimeCLITests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="signature-runtime-cli-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.directory = self.root / "target/signature-corpus/run"
        self.directory.mkdir(parents=True)
        self.corpus = runtime._corpus_module()
        self.evaluator = self.root / "already-frozen-eval"
        self.builder = self.root / "already-frozen-builder"
        self.zig = self.root / "zig"
        for tool in (self.evaluator, self.builder, self.zig):
            tool.write_bytes(tool.name.encode())
            tool.chmod(0o555)
        self.dependency = self.root / "dependency.a"
        self.dependency.write_bytes(b"original native dependency")

    def run_cli(
        self,
        *,
        wrong_tool_hash: bool = False,
        mutate_source: bool = False,
        mutate_capture: bool = False,
    ) -> tuple[int, dict[str, Any], dict[str, Any]]:
        original_builder_hash = runtime._sha256(self.builder)

        def build(context: Any) -> Any:
            runtime._validate_context(context)
            reference, target = self.directory / "reference", self.directory / "target"
            reference.write_bytes(b"reference image")
            target.write_bytes(b"target image")
            self.builder.chmod(0o755)
            self.builder.write_bytes(b"new mutable source executable")
            return runtime.RuntimeBuild(
                (),
                (),
                reference,
                target,
                None,
                None,
                (),
                {
                    "link_dependencies": [
                        {
                            "path": str(self.dependency),
                            "sha256": runtime._sha256(self.dependency),
                        }
                    ],
                },
            )

        def host(argv: list[str], **kwargs: Any) -> Any:
            executable = Path(argv[0])
            self.assertEqual(executable.parent, self.directory / "tools")
            if executable.name == "eval":
                self.assertEqual(argv[1], "strip")
                Path(argv[3]).write_bytes(b"stripped image")
                return SimpleNamespace(returncode=0)
            self.assertEqual(executable.name, "builder")
            self.assertEqual(runtime._sha256(executable), original_builder_hash)
            database, compressed = (
                self.directory / "db.json",
                self.directory / "db.json.gz",
            )
            database.write_bytes(b"database")
            compressed.write_bytes(b"compressed database")
            metrics = {
                "correct": 0,
                "wrong": 1,
                "missed": 0,
                "spurious": 0,
                "precision": 0,
                "recall": 0,
            }
            report: dict[str, Any] = {
                "schema_version": 1,
                "measurement": "phase2-1-library-signatures",
                "arch": "x86_64",
                "passed": False,
                "baseline_available": True,
                "target_executed": False,
                "load_image_equivalent_stripped_twin": True,
                "ownership_scope": "public-strong",
                "library_truth": {"0x401000": "runtime_function"},
                "truth_functions": 1,
                "baseline": metrics,
                "after": metrics,
                "matched_version_recall_gate": 0.8,
                "evaluator_binary_sha256": "0" * 64
                if wrong_tool_hash
                else runtime._sha256(executable),
            }
            for field, path in (
                ("reference_sha256", self.directory / "reference"),
                ("symbolized_target_sha256", self.directory / "target"),
                ("stripped_target_sha256", self.directory / "target.stripped.elf"),
                ("database_sha256", database),
                ("compressed_database_sha256", compressed),
            ):
                report[field] = runtime._sha256(path)
            (self.directory / "builder-report.json").write_text(
                json.dumps(report), encoding="utf-8"
            )
            if mutate_source:
                self.dependency.write_bytes(b"changed during measurement")
            if mutate_capture:
                executable.chmod(0o755)
                executable.write_bytes(b"changed captured builder")
            return SimpleNamespace(returncode=1)

        with (
            patch.object(runtime, "_corpus_module", return_value=self.corpus),
            patch.object(runtime, "build_runtime_profile", side_effect=build),
            patch.object(self.corpus.subprocess, "run", side_effect=host),
            patch.object(self.corpus, "inspect"),
        ):
            status = runtime.main(
                [
                    "--profile",
                    "musl",
                    "--target",
                    "x86_64-linux-musl",
                    "--output-dir",
                    str(self.directory),
                    "--zig",
                    str(self.zig),
                    "--eval",
                    str(self.evaluator),
                    "--builder",
                    str(self.builder),
                ]
            )
        result = json.loads(
            (self.directory / "result.json").read_text(encoding="utf-8")
        )
        report = json.loads(
            (self.directory / "builder-report.json").read_text(encoding="utf-8")
        )
        return status, result, report

    def test_cli_invokes_only_captured_tools_and_binds_actual_frozen_builder_not_eval(
        self,
    ) -> None:
        status, result, report = self.run_cli()
        self.assertEqual(status, 1)
        self.assertEqual(result["status"], "measured_failed")
        self.assertEqual(report["after"]["wrong"], 1)
        self.assertEqual(
            report["evaluator_binary_sha256"],
            result["measurement_tool_snapshot"]["builder"]["sha256"],
        )
        self.assertNotEqual(
            report["evaluator_binary_sha256"], runtime._sha256(self.builder)
        )
        self.assertNotEqual(
            report["evaluator_binary_sha256"],
            result["measurement_tool_snapshot"]["evaluator"]["sha256"],
        )

    def test_report_with_wrong_builder_identity_is_rejected(self) -> None:
        status, result, _ = self.run_cli(wrong_tool_hash=True)
        self.assertEqual(status, 1)
        self.assertEqual(result["status"], "failed")
        self.assertIn("evaluator_binary_sha256", result["reason"])

    def test_publication_source_change_rejects_without_regrading_or_overwriting_raw_metric(
        self,
    ) -> None:
        status, result, report = self.run_cli(mutate_source=True)
        self.assertEqual(status, 1)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["publication_rejected"])
        self.assertIn("source changed", result["reason"])
        self.assertEqual(report["after"]["wrong"], 1)
        self.assertFalse(report["passed"])
        self.assertEqual(result["builder_report"], report)

    def test_captured_tool_mutation_is_rejected_by_end_hash_check(self) -> None:
        status, result, report = self.run_cli(mutate_capture=True)
        self.assertEqual(status, 1)
        self.assertEqual(result["status"], "failed")
        self.assertIn("captured measurement tool changed", result["reason"])
        self.assertFalse(report["passed"])


if __name__ == "__main__":
    unittest.main()
