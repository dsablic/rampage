"""Stdlib-only tests for tools/cfg-benchmark.py: run with `python3 -m unittest tools.test_cfg_benchmark -v`."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
