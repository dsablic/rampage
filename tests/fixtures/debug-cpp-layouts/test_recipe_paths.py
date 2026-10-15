# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class RecipePathTests(unittest.TestCase):
    def make_executable(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def resolve(self, directory: Path, overrides: dict[str, str]) -> list[str]:
        helper = Path(__file__).resolve().with_name("tool_paths.sh")
        after = directory / "after chdir"
        after.mkdir()
        environment = dict(os.environ)
        environment.update(
            {
                "CLANG": "",
                "LD": "",
                "OBJCOPY": "",
                "PYTHON": "",
                "RUST_SYSROOT": "",
                "RUST_HOST": "",
            }
        )
        environment.update(overrides)
        script = (
            "set -euo pipefail\n"
            'source "$1"\n'
            "resolve_fixture_tools\n"
            'cd "$2"\n'
            'for executable in "$compiler" "$linker" "$objcopy" "$python"; do\n'
            '  test -f "$executable" && test -x "$executable"\n'
            "done\n"
            'printf "%s\\n" "$compiler" "$linker" "$objcopy" "$python" "$rust_sysroot"\n'
            'printf "%s\\n" "$CLANG" "$LD" "$OBJCOPY" "$PYTHON" "$RUST_SYSROOT"'
        )
        result = subprocess.run(
            ["/bin/bash", "-c", script, "recipe-path-test", str(helper), str(after)],
            cwd=directory,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = result.stdout.splitlines()
        self.assertEqual(
            lines[5:],
            [
                environment[key]
                for key in ["CLANG", "LD", "OBJCOPY", "PYTHON", "RUST_SYSROOT"]
            ],
        )
        return lines[:5]

    def test_relative_explicit_executables_survive_chdir_and_keep_linker_basename(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="rampage-cpp-paths-") as temporary:
            directory = Path(temporary).resolve()
            names = ["clang", "rust-lld", "rust-objcopy", "python3"]
            paths = [
                self.make_executable(directory / "tool bin" / name) for name in names
            ]
            implementation = self.make_executable(
                directory / "tool bin" / "linker implementation"
            )
            paths[1].unlink()
            paths[1].symlink_to(implementation.name)
            overrides = dict(
                zip(
                    ["CLANG", "LD", "OBJCOPY", "PYTHON"],
                    [f"tool bin/{name}" for name in names],
                )
            )
            self.assertEqual(
                self.resolve(directory, overrides), [str(path) for path in paths] + [""]
            )

    def test_path_names_resolve_relative_path_entries_before_chdir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rampage-cpp-paths-") as temporary:
            directory = Path(temporary).resolve()
            names = ["clang", "rust-lld", "rust-objcopy", "python3"]
            paths = [
                self.make_executable(directory / "tool bin" / name) for name in names
            ]
            overrides = dict(zip(["CLANG", "LD", "OBJCOPY", "PYTHON"], names))
            overrides["PATH"] = (
                f"tool bin{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
            )
            self.assertEqual(
                self.resolve(directory, overrides), [str(path) for path in paths] + [""]
            )

    def test_relative_sysroot_is_canonical_before_deriving_tools_without_rewriting_environment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="rampage-cpp-paths-") as temporary:
            directory = Path(temporary).resolve()
            sysroot = directory / "real sysroot"
            tool_bin = sysroot / "lib" / "rustlib" / "fixture-host" / "bin"
            compiler = self.make_executable(directory / "tool bin" / "clang")
            python = self.make_executable(directory / "tool bin" / "python3")
            linker = self.make_executable(tool_bin / "rust-lld")
            objcopy = self.make_executable(tool_bin / "rust-objcopy")
            (directory / "sysroot alias").symlink_to(sysroot, target_is_directory=True)
            overrides = {
                "CLANG": "tool bin/clang",
                "PYTHON": "tool bin/python3",
                "RUST_SYSROOT": "sysroot alias",
                "RUST_HOST": "fixture-host",
            }
            expected = [
                str(path) for path in [compiler, linker, objcopy, python, sysroot]
            ]
            self.assertEqual(self.resolve(directory, overrides), expected)


if __name__ == "__main__":
    unittest.main()
