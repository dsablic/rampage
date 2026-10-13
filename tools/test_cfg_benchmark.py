"""Stdlib-only tests for tools/cfg-benchmark.py: run with `python3 -m unittest tools.test_cfg_benchmark -v`."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from typing import Any

_SPEC = importlib.util.spec_from_file_location("cfg_benchmark", Path(__file__).with_name("cfg-benchmark.py"))
assert _SPEC and _SPEC.loader
benchmark = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(benchmark)


class CacheKeyTest(unittest.TestCase):
    def test_a_changed_export_script_misses_the_cache(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            script = Path(work) / "export.java"
            script.write_text("first")
            first = benchmark.cache_key("abc", "12.0", script)
            self.assertEqual(first, benchmark.cache_key("abc", "12.0", script))
            script.write_text("second")
            self.assertNotEqual(first, benchmark.cache_key("abc", "12.0", script))
        self.assertTrue(benchmark.cache_key("abc", "12.0").startswith("abc-12.0-"))


class ReadExportTest(unittest.TestCase):
    def test_a_missing_or_truncated_export_exits_with_ghidras_logs(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            out = Path(work) / "cfg.json"
            logs = ["", "ERROR ghidra_cfg_export.java> NullPointerException"]
            for written, problem in ((None, "wrote no CFG export"), ('{"functions":[{"address"', "truncated")):
                if written is not None:
                    out.write_text(written)
                with self.assertRaises(SystemExit) as raised:
                    benchmark.read_export(out, Path("fixture.elf"), logs)
                self.assertIn(problem, str(raised.exception))
                self.assertIn("NullPointerException", str(raised.exception))
            out.write_text('{"functions":[]}')
            self.assertEqual(benchmark.read_export(out, Path("fixture.elf"), logs), {"functions": []})


def ghidra_function(start: int, blocks: dict[int, list[int]], calls: list[tuple[int, int, str]]) -> dict[str, Any]:
    return {
        "address": hex(start), "noreturn": False,
        "blocks": [
            {"start": hex(block), "successors": [[hex(target), "FALL_THROUGH"] for target in targets]}
            for block, targets in blocks.items()
        ],
        "calls": [[hex(source), hex(target), kind] for source, target, kind in calls],
    }


def rampage_function(blocks: dict[int, list[int]], calls: dict[tuple[int, int], str]) -> dict[str, Any]:
    edges = {(block, target) for block, targets in blocks.items() for target in targets}
    return {"blocks": set(blocks), "edges": edges, "calls": calls}


class CompareTest(unittest.TestCase):
    def test_a_block_shared_by_two_functions_counts_in_each(self) -> None:
        # Both functions end in the shared tail at 0x50 for Ghidra; rampage keeps it only in the first.
        ghidra = {"functions": [
            ghidra_function(0x10, {0x10: [0x50], 0x50: []}, []),
            ghidra_function(0x30, {0x30: [0x50], 0x50: []}, []),
        ]}
        rampage = {
            0x10: rampage_function({0x10: [0x50], 0x50: []}, {}),
            0x30: rampage_function({0x30: []}, {}),
        }
        report = benchmark.compare(ghidra, rampage)
        self.assertEqual(report["blocks"]["matched"], 3)
        self.assertEqual(report["blocks"]["recall"], 3 / 4)
        self.assertEqual(report["edges"]["recall"], 1 / 2)

    def test_computed_calls_of_every_kind_count_only_where_rampage_resolved_them(self) -> None:
        calls = [
            (0x14, 0x900, "COMPUTED_CALL"), (0x18, 0x904, "COMPUTED_CALL_TERMINATOR"), (0x1c, 0x908, "COMPUTED_CALL"),
        ]
        ghidra = {"functions": [ghidra_function(0x10, {0x10: []}, calls)]}
        rampage = {0x10: rampage_function({0x10: []}, {(0x1c, 0x908): "call"})}
        report = benchmark.compare(ghidra, rampage)
        self.assertEqual(report["ghidra_computed_calls"], 2)
        self.assertEqual(report["calls"]["recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
