"""Offline checks of the transfer acceptance script's truth: which C function bodies count as unchanged."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[2] / "tools/transfer-acceptance.py"
SPEC = importlib.util.spec_from_file_location("transfer_acceptance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
acceptance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = acceptance
SPEC.loader.exec_module(acceptance)

KNR = """
#include "zutil.h"
#define DO1(buf,i)  {adler += (buf)[i]; \\
                     sum2 += adler;}
local const char hello[] = "{ not a body }";
int ZEXPORT f OF((int a));

/* The old style. */
int ZEXPORT f(a, b)
    int a;
    const char *b;
{
    return a + (b != Z_NULL);   /* comment */
}

local void g(s)
    deflate_state *s;
{
    s->x = 1;
}
"""

ANSI = """
#include "zutil.h"
local const char hello[] = "{ not a body }";
int ZEXPORT f(int a, const char *b) {
    return a + (b != Z_NULL);
}

local void g(deflate_state *s) {
    s->x = 2;
}
"""


class FunctionBodies(unittest.TestCase):
    def test_knr_and_prototype_headers_compare_by_body(self) -> None:
        old, new = acceptance.function_bodies(KNR), acceptance.function_bodies(ANSI)
        self.assertEqual(set(old), {"f", "g"})
        self.assertEqual(old["f"], new["f"])
        self.assertNotEqual(old["g"], new["g"])

    def test_unique_names_drop_shared_names_and_aliases(self) -> None:
        functions = {0x10: {"a"}, 0x20: {"b", "b_alias"}, 0x30: {"c"}, 0x40: {"c"}}
        self.assertEqual(acceptance.unique_names(functions), {"a": 0x10})


if __name__ == "__main__":
    unittest.main()
