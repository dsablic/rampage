"""Direct-call graph and RIP-relative data references of a Go binary, from `go tool objdump` (the Go toolchain's
own disassembler, reading the unstripped twin's symbol table). Used by derive-truth.py for the scale tasks.

Usage: python3 -I tools/agent-bench/v2/go_graph.py BINARY OUT.json
OUT holds {"functions": {name: [start, end]}, "calls": {caller: [callee, ...]},
"refs": {caller: [data address, ...]}}.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

LINE = re.compile(r"^\s+\S+\s+0x([0-9a-f]+)\s+([0-9a-f]+)\s+(.*?)\s*$")


def graph(binary: Path) -> dict:
    functions: dict[str, list[int]] = {}
    calls: dict[str, set[str]] = {}
    refs: dict[str, set[int]] = {}
    current = None
    process = subprocess.Popen(["go", "tool", "objdump", str(binary)], stdout=subprocess.PIPE, text=True,
                               bufsize=1 << 20)
    assert process.stdout
    for line in process.stdout:
        if line.startswith("TEXT "):
            current = line.split()[1].removesuffix("(SB)")
            calls.setdefault(current, set())
            refs.setdefault(current, set())
            continue
        if current is None:
            continue
        match = LINE.match(line.replace("\t", " "))
        if not match:
            continue
        address, encoding, instruction = int(match.group(1), 16), match.group(2), match.group(3)
        span = functions.setdefault(current, [address, address])
        span[1] = address + len(encoding) // 2
        if instruction.startswith("CALL ") and instruction.endswith("(SB)"):
            calls[current].add(re.sub(r"\+0x[0-9a-f]+$", "", instruction[5:-4]))
        relative = re.search(r"(-?0x[0-9a-f]+)\(IP\)", instruction)
        if relative:
            refs[current].add(address + len(encoding) // 2 + int(relative.group(1), 16))
    if process.wait() != 0:
        raise SystemExit("go tool objdump failed")
    return {"functions": functions, "calls": {k: sorted(v) for k, v in calls.items()},
            "refs": {k: sorted(v) for k, v in refs.items()}}


if __name__ == "__main__":
    Path(sys.argv[2]).write_text(json.dumps(graph(Path(sys.argv[1]))))
