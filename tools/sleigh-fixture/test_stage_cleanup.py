# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack, suppress
from pathlib import Path
from typing import Any
from unittest.mock import patch


def load_helper(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(filename)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("fixed cleanup helper unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INITIAL = load_helper("cleanup_initial", "run_extended_oracle.py")
RETRY = load_helper("cleanup_retry", "run_extended_retry.py")


class StageCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cleanup-regression-", dir=INITIAL.RAW
        )
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def exercise(self, module: Any, fault: str) -> None:
        helper = module.v1 if module is RETRY else module
        directory = self.root / ("retry-" if module is RETRY else "initial-") / fault
        directory.mkdir(parents=True)
        raw_root, output, sdk = (
            directory / "raw",
            directory / "output",
            directory / "sdk",
        )
        raw_root.mkdir()
        output.mkdir()
        families = ("SuperH", "Hexagon") if module is RETRY else ("8051", "PIC")
        selected = []
        admitted = []
        owner_hash = helper.sha(b"owned")
        truths = []
        for family in families:
            relative = f"Ghidra/Processors/{family}/data/languages"
            language_dir = sdk / relative
            language_dir.mkdir(parents=True)
            record = {
                "family": family,
                "language_id": family + ":test",
                "compiler_id": "default",
            }
            for field, suffix in (
                ("sla_path", "sla"),
                ("pspec_path", "pspec"),
                ("cspec_path", "cspec"),
                ("ldefs_path", "ldefs"),
            ):
                path = relative + "/owned." + suffix
                record[field] = path
                admitted.append({"path": path, "sha256": owner_hash})
                (sdk / path).write_bytes(b"owned")
            selected.append(record)
            truths.append(
                {
                    "name": family + "-test",
                    "family": family,
                    "language_id": family + ":test",
                    "instruction_ledger": [],
                    "functions": [],
                    "version": 1,
                }
            )
        manifest = {
            "profiles": selected + [dict(selected[0]) for _ in range(14)],
            "files": admitted,
        }
        plan = {
            "profiles": [{"selected_sdk_metadata": {}} for _ in helper.NAMES],
            "selected_profiles_source": {"sha256": "historical-planning-test"},
        }
        classes_seen = snapshots_seen = validations_seen = oracle_calls = 0
        child_running = False
        fault_triggered = False
        events: list[str] = []
        original_read = helper.io.read_bounded
        original_remove = helper.remove_owned_directory

        def snapshot(files: dict[str, Path], budget: Any) -> dict[str, Any]:
            nonlocal snapshots_seen, fault_triggered
            snapshots_seen += 1
            failure_call = {
                "initial_snapshot": 1,
                "compile_snapshot": 2,
                "after_snapshot": 4,
            }.get(fault)
            if snapshots_seen == failure_call:
                fault_triggered = True
                raise ValueError("simulated after snapshot failure")
            result = {name: {"sha256": owner_hash, "bytes": 5} for name in files}
            if module is RETRY:
                result["sdk/" + module.HEXAGON_JAR]["sha256"] = module.HEXAGON_JAR_SHA
                result["sdk/" + module.HEXAGON_SOURCE]["sha256"] = (
                    module.HEXAGON_SOURCE_SHA
                )
            return result

        def inventory(path: Path) -> dict[str, Any]:
            nonlocal classes_seen, fault_triggered
            classes_seen += 1
            failure_call = {
                "compile_inventory": 1,
                "before_inventory": 2,
                "after_inventory": 3,
            }.get(fault)
            if classes_seen == failure_call:
                fault_triggered = True
                raise ValueError("simulated class inventory failure")
            return {"Owned.class": {"sha256": "mock-host-class", "bytes": 5}}

        def read(path: Path, cap: int, budget: Any = None) -> bytes:
            nonlocal fault_triggered
            if path.suffix in (".java", ".py") or path.name.endswith(
                ("-v1.bin", "-v1.asm")
            ):
                return b"owned"
            if path.name == "oracle.json" and fault == "decode":
                fault_triggered = True
                raise ValueError("simulated JSON decode failure")
            return original_read(path, cap, budget)

        def command(
            argv: list[str], stage: Path, raw: Path, name: str
        ) -> dict[str, Any]:
            nonlocal child_running, oracle_calls, fault_triggered
            child_running = True
            events.append("start:" + name)
            try:
                (stage / "child-transient").mkdir()
                (stage / "child-transient/data").write_bytes(b"owned temporary")
                (raw / (name + ".stderr")).write_text("retained simulated child log\n")
                (raw / (name + ".stdout")).write_text("")
                if name == "compile":
                    classes = Path(argv[argv.index("-d") + 1])
                    (classes / "Owned.class").write_bytes(b"owned")
                    if fault == "compile":
                        fault_triggered = True
                    return {"exit_code": 1 if fault == "compile" else 0}
                oracle_calls += 1
                helper.io.write_new_json(
                    raw / "oracle.json", {"program_oracle": {"status": "observed"}}
                )
                return {"exit_code": 0}
            finally:
                child_running = False
                events.append("reaped:" + name)

        def validation(
            actual: dict[str, Any], wanted: dict[str, Any]
        ) -> dict[str, Any]:
            nonlocal validations_seen, fault_triggered
            validations_seen += 1
            if fault in ("validation", "partial") and validations_seen == 1:
                fault_triggered = True
                raise ValueError("simulated validation failure")
            return {"status": "pass", "failures": []}

        def load(path: Path) -> dict[str, Any]:
            if path.name.endswith("-v1.truth.json"):
                family = path.name.removesuffix("-v1.truth.json")
                return next(item for item in truths if item["family"] == family)
            if path.name == "provenance.json":
                return {"cohort": "mock-prior-cohort"}
            if path.name.endswith("-v1.provenance.json"):
                return {"attempt": "mock-prior-attempt", "limits": {}}
            return json.loads(read(path, helper.io.JSON_CAP))

        def remove(parent_fd: int, name: str, expected: tuple[int, int]) -> None:
            self.assertFalse(
                child_running, "stage removed before simulated child was reaped"
            )
            events.append("cleanup:" + name)
            original_remove(parent_fd, name, expected)

        with ExitStack() as patches:
            patches.enter_context(patch.object(helper, "ROOT", directory))
            patches.enter_context(patch.object(helper, "RAW", raw_root))
            patches.enter_context(patch.object(helper, "OUTPUT", output))
            patches.enter_context(patch.object(helper.io, "SDK", sdk))
            patches.enter_context(
                patch.object(helper.io, "read_bounded", side_effect=read)
            )
            patches.enter_context(
                patch.object(helper.io, "class_inventory", side_effect=inventory)
            )
            patches.enter_context(
                patch.object(helper, "snapshot", side_effect=snapshot)
            )
            patches.enter_context(
                patch.object(helper, "command_run", side_effect=command)
            )
            patches.enter_context(
                patch.object(helper, "remove_owned_directory", side_effect=remove)
            )
            patches.enter_context(
                patch.object(module, "validate", side_effect=validation)
            )
            patches.enter_context(
                patch.object(
                    helper,
                    "pinned_json",
                    side_effect=lambda path, expected: (
                        plan if path == helper.PLAN else manifest
                    ),
                )
            )
            if module is RETRY:
                patches.enter_context(patch.object(module, "KEYS", families))
                patches.enter_context(patch.object(helper, "NAMES", families))
                patches.enter_context(patch.object(module, "load", side_effect=load))
            else:
                patches.enter_context(
                    patch.object(module, "materialize", return_value=truths)
                )
            with suppress(ValueError, RuntimeError):
                module.run()
        self.assertTrue(fault_triggered, "requested control-flow fault was not reached")
        self.assertFalse(list(raw_root.rglob("stage")), events)
        self.assertFalse(list(raw_root.rglob("compile-stage")), events)
        if "start:compile" in events:
            self.assertTrue(
                list(raw_root.rglob("compile.stderr")), "raw child logs were removed"
            )
        if fault != "initial_snapshot":
            self.assertTrue(
                list(raw_root.rglob("compile-before.json")), "raw snapshot was removed"
            )
        self.assertIn("cleanup:compile-stage", events)
        if oracle_calls:
            self.assertIn("cleanup:stage", events)
            self.assertTrue(list(raw_root.rglob("oracle.stderr")))
            self.assertTrue(list(raw_root.rglob("command-before-launch.json")))
        if fault == "partial":
            self.assertEqual(oracle_calls, 1 if module is RETRY else 2)

    def exercise_both(self, fault: str) -> None:
        for module in (INITIAL, RETRY):
            with self.subTest(runner=module.__name__, fault=fault):
                self.exercise(module, fault)

    def test_compilation_failure_cleans_entire_created_lifetime(self) -> None:
        self.exercise_both("compile")

    def test_initial_snapshot_failure_cleans_new_compile_stage(self) -> None:
        self.exercise_both("initial_snapshot")

    def test_post_compile_snapshot_failure_cleans_compile_stage(self) -> None:
        self.exercise_both("compile_snapshot")

    def test_compile_class_inventory_failure_cleans_stage(self) -> None:
        self.exercise_both("compile_inventory")

    def test_before_launch_class_inventory_failure_cleans_current_stage(self) -> None:
        self.exercise_both("before_inventory")

    def test_after_execution_class_inventory_failure_cleans_current_stage(self) -> None:
        self.exercise_both("after_inventory")

    def test_after_snapshot_failure_cannot_skip_cleanup(self) -> None:
        self.exercise_both("after_snapshot")

    def test_decode_failure_cleans_stage_after_reaping(self) -> None:
        self.exercise_both("decode")

    def test_validation_failure_cleans_current_and_compile_stages(self) -> None:
        self.exercise_both("validation")

    def test_partial_cohort_failure_preserves_logs_and_cleans_stages(self) -> None:
        self.exercise_both("partial")

    def test_nested_symlink_is_unlinked_without_following_external_tree(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        marker = outside / "keep"
        marker.write_bytes(b"outside must survive")
        with INITIAL.owned_stage(self.root, "stage") as stage:
            (stage / "nested").mkdir()
            (stage / "nested/external").symlink_to(outside, target_is_directory=True)
        self.assertEqual(marker.read_bytes(), b"outside must survive")
        self.assertFalse((self.root / "stage").exists())

    def test_held_parent_descriptor_does_not_follow_replaced_path(self) -> None:
        parent = self.root / "parent"
        parent.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        outside_stage = outside / "stage"
        outside_stage.mkdir()
        marker = outside_stage / "keep"
        marker.write_bytes(b"outside must survive")
        moved = self.root / "moved-parent"
        with INITIAL.owned_stage(parent, "stage"):
            parent.rename(moved)
            parent.symlink_to(outside, target_is_directory=True)
        self.assertEqual(marker.read_bytes(), b"outside must survive")
        self.assertFalse((moved / "stage").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
