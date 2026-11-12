"""Extract named structure layouts from a twin's DWARF (via llvm-dwarfdump) into a small committed JSON file, so
the twin itself can drop its debug info (whose statically linked C library parts hold build-machine paths).

Usage: python3 -I tools/agent-bench/v3/dwarf-extract.py OUT.json TWIN STRUCT [STRUCT ...]
OUT holds {struct: {"size": bytes, "members": {name: [offset, size]}}}.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location("v2_truth", Path(__file__).resolve().parents[1] / "v2/derive-truth.py")
assert _spec and _spec.loader
v2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v2)


def size_of(dies: dict, offset: int) -> int:
    die = dies[offset]
    if die.tag == "DW_TAG_array_type":
        count = 1
        for child in die.children:
            if child.tag == "DW_TAG_subrange_type":
                count *= int(child.attrs.get("DW_AT_count", "0"), 0) or int(child.attrs["DW_AT_upper_bound"], 0) + 1
        return count * size_of(dies, v2.ref(die.attrs["DW_AT_type"]))
    if "DW_AT_byte_size" in die.attrs:
        return int(die.attrs["DW_AT_byte_size"], 0)
    if die.tag == "DW_TAG_pointer_type":
        return 8
    return size_of(dies, v2.ref(die.attrs["DW_AT_type"]))


def main() -> None:
    out, twin, names = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3:]
    dies = v2.dwarf(twin)
    layouts = {}
    for name in names:
        die = v2.named(dies, "DW_TAG_structure_type", name)
        members = {}
        for child in die.children:
            if child.tag == "DW_TAG_member":
                members[child.attrs["DW_AT_name"].strip('"')] = [int(child.attrs["DW_AT_data_member_location"], 0),
                                                                 size_of(dies, v2.ref(child.attrs["DW_AT_type"]))]
        layouts[name] = {"size": int(die.attrs["DW_AT_byte_size"], 0), "members": members}
    out.write_text(json.dumps(layouts, indent=1) + "\n")


if __name__ == "__main__":
    main()
