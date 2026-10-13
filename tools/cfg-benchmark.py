#!/usr/bin/env python3
"""Compare rampage's basic blocks, CFG edges and call edges against Ghidra's on the functions both tools find.

Ghidra is a reference, not ground truth: agreement means the two tools made the same decisions, and every
disagreement still has to be inspected to say which side (if either) is right.

Ghidra side: headless auto-analysis plus tools/ghidra_cfg_export.java (BasicBlockModel blocks, intra-function
successors, call references). rampage side: `rampage export-cfg`, the same function graphs and xrefs the
`function_graph` and `xrefs` tools return, without their output-size bound.

Usage: tools/cfg-benchmark.py RAMPAGE GHIDRA_INSTALL FIXTURE... [--out DIR] [--ghidra-cache DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parent
SCRIPT = TOOLS / "ghidra_cfg_export.java"
TOP = 10


def cache_key(image_sha256: str, version: str, script: Path = SCRIPT) -> str:
    """Names a cached Ghidra export by the image, the Ghidra version and the export script that produced it."""
    return f"{image_sha256}-{version}-{hashlib.sha256(script.read_bytes()).hexdigest()[:16]}"


def ghidra_version(install: Path) -> str:
    for line in (install / "Ghidra" / "application.properties").read_text().splitlines():
        if line.startswith("application.version="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"no application.version in {install}")


def java_home() -> str:
    if os.environ.get("JAVA_HOME"):
        return os.environ["JAVA_HOME"]
    prefix = subprocess.run(["brew", "--prefix", "openjdk@21"], capture_output=True, text=True, check=True)
    return f"{prefix.stdout.strip()}/libexec/openjdk.jdk/Contents/Home"


def ghidra_export(install: Path, fixture: Path, key: str, cache: Path | None) -> tuple[dict[str, Any], float | None]:
    cached = cache / f"{key}.json" if cache else None
    if cached and cached.exists():
        return json.loads(cached.read_text()), None
    with tempfile.TemporaryDirectory() as work:
        out = Path(work) / "cfg.json"
        command = [
            str(install / "support" / "analyzeHeadless"), work, "bench", "-import", str(fixture),
            "-scriptPath", str(TOOLS), "-postScript", "ghidra_cfg_export.java", str(out), "-deleteProject",
        ]
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, env={**os.environ, "JAVA_HOME": java_home()})
        elapsed = time.monotonic() - started
        if not out.exists():
            raise SystemExit(f"ghidra failed on {fixture}:\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}")
        data = json.loads(out.read_text())
    if cached:
        cache.mkdir(parents=True, exist_ok=True)
        cached.write_text(json.dumps(data))
    return data, elapsed


def address(text: str) -> int:
    return int(text, 16)


def rampage_functions(rampage: Path, fixture: Path) -> dict[int, dict[str, Any]]:
    with tempfile.TemporaryDirectory() as work:
        # A private copy, so annotation sidecars beside the fixture cannot change names or results.
        copy = Path(work) / fixture.name
        copy.write_bytes(fixture.read_bytes())
        result = subprocess.run([str(rampage), "export-cfg", str(copy)], capture_output=True, text=True, check=True)
    functions = {}
    exported = json.loads(result.stdout)
    starts = {address(function["address"]) for function in exported}
    for function in exported:
        start = address(function["address"])
        # Ghidra records a jump to another function's entry (a tail call) as a call reference; count rampage's
        # the same way.
        calls = {
            (address(source), address(target)): kind for source, target, kind in function["references"]
            if kind == "call" or address(target) in starts - {start}
        }
        functions[start] = {
            "blocks": {address(block) for block in function["blocks"]},
            "edges": {(address(source), address(target)) for source, target, _ in function["edges"]},
            "calls": calls,
        }
    return functions


def ghidra_functions(data: dict[str, Any]) -> dict[int, dict[str, Any]]:
    functions = {}
    for function in data["functions"]:
        functions[address(function["address"])] = {
            "blocks": {address(block["start"]) for block in function["blocks"]},
            "edges": {
                (address(block["start"]), address(target))
                for block in function["blocks"] for target, _ in block["successors"]
            },
            "calls": {(address(source), address(target)): kind for source, target, kind in function["calls"]},
            "noreturn": function["noreturn"],
        }
    return functions


def collapse(entry: int, blocks: set[int], edges: set[tuple[int, int]]) -> tuple[set[int], set[tuple[int, int]]]:
    """Merges straight-line chains (a block whose only predecessor has it as its only successor) into one block.

    Ghidra's BasicBlockModel also starts a block at every labelled instruction, such as a local `.L` symbol or a
    data reference target; this canonical form compares control flow without those splits on either side.
    """
    edges = {(a, b) for a, b in edges if a in blocks and b in blocks}
    successors: dict[int, set[int]] = {block: set() for block in blocks}
    predecessors: dict[int, set[int]] = {block: set() for block in blocks}
    for a, b in edges:
        successors[a].add(b)
        predecessors[b].add(a)

    def merged(block: int) -> bool:
        if block == entry or len(predecessors[block]) != 1:
            return False
        (previous,) = predecessors[block]
        return previous != block and successors[previous] == {block}

    def leader(block: int) -> int:
        seen = {block}
        while merged(block):
            (block,) = predecessors[block]
            if block in seen:
                break
            seen.add(block)
        return block

    leaders = {block for block in blocks if not merged(block)}
    return leaders, {(leader(a), b) for a, b in edges if b in leaders}


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def agreement(rampage: set[Any], ghidra: set[Any]) -> dict[str, Any]:
    matched = len(rampage & ghidra)
    return {
        "rampage": len(rampage), "ghidra": len(ghidra), "matched": matched,
        "precision": ratio(matched, len(rampage)), "recall": ratio(matched, len(ghidra)),
    }


def compare(ghidra: dict[str, Any], ram: dict[int, Any]) -> dict[str, Any]:
    ghi = ghidra_functions(ghidra)
    common = sorted(set(ghi) & set(ram))
    totals: dict[str, dict[str, set[Any]]] = {
        name: {"rampage": set(), "ghidra": set()}
        for name in ("blocks", "edges", "chains", "chain_edges", "calls", "call_graph", "computed_calls")
    }
    identical = 0
    per_function = []
    for start in common:
        g, r = ghi[start], ram[start]

        # Pooled per function, so a block or edge that two functions share counts in each of them.
        def owned(items: set[Any]) -> set[tuple[int, Any]]:
            return {(start, item) for item in items}

        for side, function in (("ghidra", g), ("rampage", r)):
            totals["blocks"][side] |= owned(function["blocks"])
            totals["edges"][side] |= owned(function["edges"])
            blocks, edges = collapse(start, function["blocks"], function["edges"])
            totals["chains"][side] |= owned(blocks)
            totals["chain_edges"][side] |= owned(edges)
            # Ghidra's computed calls carry a target read from memory, which can be an unrelocated GOT slot or
            # header bytes; they count only where rampage resolved the same call.
            counted = {
                call for call, kind in function["calls"].items() if kind != "COMPUTED_CALL" or call in r["calls"]
            }
            totals["calls"][side] |= owned(counted)
            totals["call_graph"][side] |= {(start, target) for _, target in counted}
            totals["computed_calls"][side] |= owned(set(function["calls"]) - counted)
        identical += g["blocks"] == r["blocks"]
        union = g["blocks"] | r["blocks"]
        jaccard = len(g["blocks"] & r["blocks"]) / len(union) if union else 1.0
        g_chains, r_chains = collapse(start, g["blocks"], g["edges"])[0], collapse(start, r["blocks"], r["edges"])[0]
        chain_union = g_chains | r_chains
        chain_jaccard = len(g_chains & r_chains) / len(chain_union) if chain_union else 1.0
        entry = {
            "function": hex(start), "jaccard": round(jaccard, 3), "chain_jaccard": round(chain_jaccard, 3),
            "ghidra_noreturn": g["noreturn"],
            "blocks_only_ghidra": [hex(a) for a in sorted(g["blocks"] - r["blocks"])],
            "blocks_only_rampage": [hex(a) for a in sorted(r["blocks"] - g["blocks"])],
            "edges_only_ghidra": [[hex(a), hex(b)] for a, b in sorted(g["edges"] - r["edges"])],
            "edges_only_rampage": [[hex(a), hex(b)] for a, b in sorted(r["edges"] - g["edges"])],
            "calls_only_ghidra": [
                [hex(a), hex(b), g["calls"][a, b]] for a, b in sorted(set(g["calls"]) - set(r["calls"]))
            ],
            "calls_only_rampage": [
                [hex(a), hex(b), r["calls"][a, b]] for a, b in sorted(set(r["calls"]) - set(g["calls"]))
            ],
        }
        if jaccard < 1 or any(entry[key] for key in entry if key.startswith(("edges_", "calls_"))):
            per_function.append(entry)
    blocks, chains = totals["blocks"], totals["chains"]
    union = blocks["ghidra"] | blocks["rampage"]
    per_function.sort(key=lambda f: (
        f["chain_jaccard"], f["jaccard"], -sum(len(v) for k, v in f.items() if k.startswith("edges_"))
    ))
    return {
        "functions": {"ghidra": len(ghi), "rampage": len(ram), "common": len(common)},
        "blocks": {
            "jaccard": ratio(len(blocks["ghidra"] & blocks["rampage"]), len(union)),
            "identical_functions": identical,
            **agreement(blocks["rampage"], blocks["ghidra"]),
        },
        "edges": agreement(totals["edges"]["rampage"], totals["edges"]["ghidra"]),
        "chains": {
            "jaccard": ratio(len(chains["ghidra"] & chains["rampage"]), len(chains["ghidra"] | chains["rampage"])),
            **agreement(chains["rampage"], chains["ghidra"]),
        },
        "chain_edges": agreement(totals["chain_edges"]["rampage"], totals["chain_edges"]["ghidra"]),
        "calls": agreement(totals["calls"]["rampage"], totals["calls"]["ghidra"]),
        "call_graph": agreement(totals["call_graph"]["rampage"], totals["call_graph"]["ghidra"]),
        "ghidra_computed_calls": len(totals["computed_calls"]["ghidra"]),
        "disagreements": per_function,
    }


def percent(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.1%}"


def pair(metric: dict[str, Any]) -> str:
    return f"{percent(metric['precision'])} / {percent(metric['recall'])}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rampage", type=Path)
    parser.add_argument("ghidra", type=Path, help="Ghidra install directory (contains support/analyzeHeadless)")
    parser.add_argument("fixtures", type=Path, nargs="+")
    parser.add_argument("--out", type=Path, help="write each fixture's full JSON report, disagreements included")
    parser.add_argument(
        "--ghidra-cache", type=Path, help="reuse Ghidra exports keyed by image, Ghidra version and export script"
    )
    arguments = parser.parse_args()

    version = ghidra_version(arguments.ghidra)
    rampage_version = subprocess.run(
        [str(arguments.rampage), "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    commit = subprocess.run(["git", "-C", str(TOOLS), "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
    print(f"Ghidra {version}; {rampage_version} ({commit.stdout.strip() or 'unknown commit'}). "
          "Ghidra is the reference, not ground truth.\n")
    print("| binary | funcs G/R/both | same blocks | block J | chain J | edge P/R | chain edge P/R "
          "| call P/R | callgraph P/R | G-only computed calls | ghidra s |")
    print("|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
    if arguments.out:
        arguments.out.mkdir(parents=True, exist_ok=True)
    for fixture in arguments.fixtures:
        sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
        ghidra, seconds = ghidra_export(arguments.ghidra, fixture, cache_key(sha, version), arguments.ghidra_cache)
        report = compare(ghidra, rampage_functions(arguments.rampage, fixture))
        report.update({
            "fixture": fixture.name, "image_sha256": sha, "ghidra_version": version,
            "rampage_version": rampage_version,
        })
        if arguments.out:
            (arguments.out / f"{fixture.name}.json").write_text(json.dumps(report, indent=1))
        f, b, k = report["functions"], report["blocks"], report["chains"]
        print(f"| {fixture.name} | {f['ghidra']}/{f['rampage']}/{f['common']} | "
              f"{b['identical_functions']}/{f['common']} | {percent(b['jaccard'])} | {percent(k['jaccard'])} | "
              f"{pair(report['edges'])} | {pair(report['chain_edges'])} | {pair(report['calls'])} | "
              f"{pair(report['call_graph'])} | "
              f"{report['ghidra_computed_calls']} | {'cached' if seconds is None else f'{seconds:.0f}'} |", flush=True)
        for item in report["disagreements"][:TOP]:
            print(f"{fixture.name} {json.dumps(item)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
