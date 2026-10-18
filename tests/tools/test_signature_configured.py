"""Configured-driver unit tests with a fake recorder; never invoke build tools."""

from __future__ import annotations

import importlib.util
import shlex
import sys
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

MODULE_PATH = Path(__file__).resolve().parents[2] / "tools/signature_configured.py"
SPEC = importlib.util.spec_from_file_location("signature_configured", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
configured = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = configured
SPEC.loader.exec_module(configured)


class FakeRecorder:
    def __init__(self, source: Path) -> None:
        self.source = source
        self.calls: list[tuple[list[str], Path, dict[str, str]]] = []
        self.members = "library-function.o\n"
        self.zig_version = "0.17.0"

    def __call__(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        clean_environment: bool = False,
    ) -> str:
        if not clean_environment:
            raise AssertionError(
                "configured driver must explicitly request a clean environment"
            )
        self.calls.append((argv, cwd, dict(env)))
        tool = Path(argv[0]).name
        if tool == "zig" and argv[1:] == ["version"]:
            return self.zig_version
        if tool == "make" and argv[1:] == ["--version"]:
            return "GNU Make fake version\n"
        if tool == "perl" and argv[1:] == ["-v"]:
            return "Perl fake version\n"
        if tool == "sh" and argv[1] == "-c":
            return "fake host shell\n"
        if (tool == "perl" and Path(argv[1]).name == "Configure") or (
            tool == "sh" and Path(argv[1]).name == "configure"
        ):
            for name in (
                "Makefile",
                "configdata.pm",
                "include/openssl/configuration.h",
                "lib/Makefile",
                "lib/curl_config.h",
                "config.log",
                "config.status",
                "libtool",
            ):
                path = self.source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fake generated configuration", encoding="utf-8")
            (self.source / "Makefile").write_text(
                "CFLAGS=-O3\nCPPFLAGS=-DAPI_CONFIG=1\nCNF_CFLAGS=-m64\n"
                "CNF_CPPFLAGS=-DOPENSSL_BUILDING_OPENSSL\n"
                "LIB_CFLAGS=-fPIC $(CNF_CFLAGS) $(CFLAGS)\n"
                "LIB_CPPFLAGS=$(CNF_CPPFLAGS) $(CPPFLAGS)\n",
                encoding="utf-8",
            )
            (self.source / "lib/Makefile").write_text(
                "CFLAGS = -O0\nCPPFLAGS = -DAPI_CONFIG=1\nAM_CFLAGS = \n"
                "top_srcdir = ..\ntop_builddir = ..\n"
                "AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/lib -DBUILDING_LIBCURL\n"
                "libcurl_la_CFLAGS = $(AM_CFLAGS) $(am__disabled_extra)\n"
                "libcurl_la_CPPFLAGS = $(AM_CPPFLAGS)\nDEFS=-DHAVE_CONFIG_H\nDEFAULT_INCLUDES=-I.\nINCLUDES=\n",
                encoding="utf-8",
            )
            return ""
        if tool == "make" and "build_generated" in argv:
            return ""
        if tool == "make" and "libcrypto.a" in argv:
            (self.source / "libcrypto.a").write_bytes(b"!<arch>\nfake crypto")
            (self.source / "libssl.a").write_bytes(b"!<arch>\nfake ssl")
            return ""
        if tool == "make" and "libcurl.la" in argv:
            archive = self.source / "lib/.libs/libcurl.a"
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(b"!<arch>\nfake curl")
            return ""
        if tool == "zig" and argv[1:3] == ["ar", "t"]:
            return self.members
        if tool == "zig" and argv[1:3] == ["ar", "x"]:
            for name in self.members.splitlines():
                (cwd / name).write_bytes(b"fake object")
            return ""
        raise AssertionError(f"unexpected command, possibly target execution: {argv}")


class ConfiguredProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="signature-configured-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.source = self.directory / "source"
        self.source.mkdir()
        (self.source / "build.info").write_text(
            "fake pinned host source", encoding="utf-8"
        )
        self.tools: dict[str, Path] = {}
        for name in ("zig", "make", "perl", "sh"):
            path = self.directory / name
            path.write_text("fake host tool", encoding="utf-8")
            self.tools[name] = path
        self.recorder = FakeRecorder(self.source)

    def context(self, library: str = "openssl-3.0.15", **updates: Any) -> Any:
        script = "Configure" if library.startswith("openssl") else "configure"
        (self.source / script).write_text("fake pinned host source", encoding="utf-8")
        context = configured.ConfiguredContext(
            library=library,
            target="x86_64-linux-musl",
            optimization="O2",
            source=self.source,
            directory=self.directory,
            zig=self.tools["zig"],
            make=self.tools["make"],
            perl=self.tools["perl"],
            shell=self.tools["sh"],
            build_triplet="aarch64-apple-darwin24",
            verified_archive_sha256=configured.PINS[library],
            source_class="public-source-archive",
            environment={"SOURCE_DATE_EPOCH": "123", "CC": "wrong-compiler"},
            run=self.recorder,
        )
        return replace(context, **updates)

    def test_openssl_builds_only_libraries_and_keeps_per_archive_ownership(
        self,
    ) -> None:
        result = configured.build_configured_profile(self.context())
        builds = [
            argv for argv, _, _ in self.recorder.calls if Path(argv[0]).name == "make"
        ]
        override = (
            "CFLAGS="
            + result.provenance["effective_library_flags"]["make_overrides"]["CFLAGS"]
        )
        self.assertEqual(builds[1][1:], ["-j1", override, "build_generated"])
        self.assertEqual(builds[2][1:], ["-j1", override, "libcrypto.a", "libssl.a"])
        self.assertEqual(len(result.objects), 2)
        self.assertNotEqual(result.objects[0].parent, result.objects[1].parent)
        self.assertEqual(result.objects[0].name, result.objects[1].name)
        self.assertTrue(all(path.is_file() for path in result.objects))
        self.assertEqual(
            len(result.provenance["object_ownership"]), len(result.objects)
        )
        self.assertIn("Configure", result.provenance["host_script_sha256"])
        self.assertIn(
            "include/openssl/configuration.h",
            result.provenance["generated_configuration_sha256"],
        )
        self.assertEqual(
            result.provenance["archive_sha256"], configured.PINS["openssl-3.0.15"]
        )
        for _, _, env in self.recorder.calls:
            self.assertEqual(env["SOURCE_DATE_EPOCH"], "0")
            self.assertIn("-g0", env["CFLAGS"])
            self.assertIn("-fno-lto", env["CFLAGS"])
            self.assertNotEqual(env["CC"], "wrong-compiler")

    def test_curl_forces_cross_mode_and_does_not_build_cli(self) -> None:
        result = configured.build_configured_profile(
            self.context("curl-8.10.1", target="aarch64-linux-musl", jobs=2)
        )
        argv = result.provenance["configure_argv"]
        self.assertIn("--build=aarch64-apple-darwin24", argv)
        self.assertIn("--host=aarch64-unknown-linux-musl", argv)
        for option in (
            "--without-ssl",
            "--without-zlib",
            "--disable-ldap",
            "--disable-threaded-resolver",
        ):
            self.assertIn(option, argv)
        builds = [
            argv for argv, _, _ in self.recorder.calls if Path(argv[0]).name == "make"
        ]
        override = (
            "CFLAGS="
            + result.provenance["effective_library_flags"]["make_overrides"]["CFLAGS"]
        )
        self.assertEqual(
            builds[1][1:], ["-C", "lib", "-j2", "V=1", override, "libcurl.la"]
        )
        self.assertEqual(len(result.objects), 1)
        self.assertEqual(result.archives[0].name, "libcurl.a")

    def test_driver_filters_script_injection_variables_and_isolates_home(self) -> None:
        poisoned = {
            "OPENSSL_LOCAL_CONFIG_DIR": "/not-executed",
            "OPENSSL_CONF": "/not-executed",
            "PERL5OPT": "not-executed",
            "PERL5LIB": "/not-executed",
            "BASH_ENV": "/not-executed",
            "ENV": "/not-executed",
            "CONFIG_SITE": "/not-executed",
            "HOME": "/not-the-isolated-home",
        }
        result = configured.build_configured_profile(self.context(environment=poisoned))
        for _, _, env in self.recorder.calls:
            self.assertTrue(set(env) <= configured.CLEAN_ENVIRONMENT_KEYS)
            for key in poisoned.keys() - {"HOME", "CONFIG_SITE"}:
                self.assertNotIn(key, env)
            self.assertEqual(env["HOME"], str(self.directory / "configured-home"))
            self.assertEqual(env["CONFIG_SITE"], "/dev/null")
        self.assertEqual(
            result.provenance["env_policy"], "configured-clean-allowlist-v1"
        )

    def test_equal_curl_build_and_host_are_refused_before_any_command(self) -> None:
        context = self.context("curl-8.10.1", build_triplet="x86_64-unknown-linux-musl")
        with self.assertRaisesRegex(
            configured.ConfiguredBuildError, "equal build/host"
        ):
            configured.build_configured_profile(context)
        self.assertFalse(self.recorder.calls)

    def test_unverified_or_wrong_source_class_is_refused_before_host_execution(
        self,
    ) -> None:
        invalid_cases: tuple[dict[str, Any], ...] = (
            {"verified_archive_sha256": "0" * 64},
            {"source_class": "unclassified"},
            {"target": "x86-linux-musl"},
            {"optimization": "O3"},
            {"jobs": 3},
        )
        for updates in invalid_cases:
            with (
                self.subTest(updates=updates),
                self.assertRaises(configured.ConfiguredBuildError),
            ):
                configured.build_configured_profile(self.context(**updates))
        self.assertFalse(self.recorder.calls)

    def test_library_optimization_overrides_configure_defaults_for_both_profiles_and_levels(
        self,
    ) -> None:
        for library in configured.PINS:
            for optimization in ("O1", "O2"):
                with self.subTest(library=library, optimization=optimization):
                    directory = self.directory / f"{library}-{optimization}"
                    source = directory / "source"
                    source.mkdir(parents=True)
                    script = (
                        "Configure" if library.startswith("openssl") else "configure"
                    )
                    (source / script).write_text("fake pinned script", encoding="utf-8")
                    recorder = FakeRecorder(source)
                    context = replace(
                        self.context(library),
                        directory=directory,
                        source=source,
                        optimization=optimization,
                        run=recorder,
                    )
                    result = configured.build_configured_profile(context)
                    evidence = result.provenance["effective_library_flags"]
                    self.assertEqual(evidence["last_optimization"], f"-{optimization}")
                    self.assertIn("-DAPI_CONFIG=1", evidence["effective_cppflags"])
                    self.assertIn("-g0", evidence["effective_cflags"])
                    self.assertIn("-fno-lto", evidence["effective_cflags"])
                    self.assertNotIn(
                        "--disable-optimize", result.provenance["configure_argv"]
                    )
                    make_calls = [
                        argv
                        for argv, _, _ in recorder.calls
                        if Path(argv[0]).name == "make"
                    ]
                    for argv in make_calls[1:]:
                        self.assertIn(
                            "CFLAGS=" + evidence["make_overrides"]["CFLAGS"], argv
                        )

    def test_effective_flags_refuse_late_optimization_override_after_requested_cflags(
        self,
    ) -> None:
        makefile = self.source / "Makefile"
        makefile.write_text(
            "CFLAGS=-O3\nCPPFLAGS=-O0\nLIB_CFLAGS=$(CFLAGS)\nLIB_CPPFLAGS=$(CPPFLAGS)\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(configured.ConfiguredBuildError, "requested -O1"):
            configured.effective_make_flags(
                makefile, "openssl-3.0.15", "O1", "-O1 -g0 -fno-lto"
            )

    def test_wrong_zig_version_stops_before_configure(self) -> None:
        self.recorder.zig_version = "0.16.0"
        with self.assertRaisesRegex(configured.ConfiguredBuildError, "exact Zig"):
            configured.build_configured_profile(self.context())
        self.assertEqual(len(self.recorder.calls), 1)

    def test_wrapper_quotes_compiler_path_and_uses_literal_target(self) -> None:
        path = self.directory / "compiler ' quoted"
        path.write_text("fake", encoding="utf-8")
        context = self.context(zig=path)
        wrapper = self.directory / "cc-wrapper"
        configured._write_wrapper(wrapper, path, ("cc", "-target", context.target))
        text = wrapper.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh\nexec "))
        self.assertEqual(
            shlex.split(text.splitlines()[1])[1:5],
            [str(path), "cc", "-target", context.target],
        )
        self.assertTrue(text.endswith(' "$@"\n'))
        self.assertEqual(wrapper.stat().st_mode & 0o777, 0o755)

    def test_archive_listing_rejects_traversal_duplicates_and_nonobjects_before_extract(
        self,
    ) -> None:
        archive = self.source / "known.a"
        archive.write_bytes(b"!<arch>\n")
        for listing in (
            "../escape.o\n",
            "/absolute.o\n",
            "same.o\nsame.o\n",
            "script.sh\n",
            "",
            "a\\b.o\n",
        ):
            self.recorder.members = listing
            with (
                self.subTest(listing=listing),
                self.assertRaises(configured.ConfiguredBuildError),
            ):
                configured.extract_owned_objects(
                    self.context(), archive, self.directory / "owned", {}
                )
        self.assertFalse(
            any(argv[1:3] == ["ar", "x"] for argv, _, _ in self.recorder.calls)
        )

    def test_thin_archive_is_rejected_without_ar(self) -> None:
        archive = self.source / "thin.a"
        archive.write_bytes(b"!<thin>\n")
        with self.assertRaisesRegex(configured.ConfiguredBuildError, "non-thin"):
            configured.extract_owned_objects(
                self.context(), archive, self.directory / "owned", {}
            )
        self.assertFalse(self.recorder.calls)


if __name__ == "__main__":
    unittest.main()
