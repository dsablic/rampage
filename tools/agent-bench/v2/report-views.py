"""Derived views of a suite-v2 head-to-head report, from its published JSON only (no transcripts, no model calls).

The harness report scores the latest run of every (task, server, repetition). The fairness review asked for
views that differ from it in which run counts:

- headline: the first run of each slot, except where the task itself changed after the full pass (the scale
  fixture was rebuilt, the diff question reworded): there the first run under the new definition counts. A run
  stopped from outside before any answer (an outside kill, the client's usage limit, a safeguard model fallback)
  is an infrastructure failure: it counts for neither server, and its once-only rerun counts instead when there
  is one.
- core: the headline restricted to the C++, typing and investigation categories.
- original_pass: the first full pass as first published (old scale fixture, old diff wording, every run as
  measured, infrastructure failures counted as failures).
- lenient: each view again, counting a correct answer with an extra "status":"ok" field as correct.
- scale_timing: agent wall time with and without the longest single tool call (REA's Ghidra import).

Usage: python3 -I tools/agent-bench/v2/report-views.py REPORT.json OUT.json [RUNS_DIR]
RUNS_DIR (target/bench/h2h/LABEL/runs) adds tool-call timings to scale_timing; the scored scale runs must be the
current ones there.
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

CHANGED_TASKS = {"scale-callees-x64-elf", "scale-caller-count-x64-elf", "scale-string-function-x64-elf",
                 "library-diff-x64-so"}
CORE = {"cpp", "typing", "investigation"}
INFRA_MARKERS = ("model differs from", "claude exited 143")


def infra(row: dict) -> bool:
    error = row.get("runner_error") or ""
    return row["runner_exit"] == "error" and any(marker in error for marker in INFRA_MARKERS)


def history(report: dict) -> dict[tuple, list[dict]]:
    """Every run of each slot in measurement order: superseded rows in the order they were superseded, then the
    current row."""
    slots: dict[tuple, list[dict]] = defaultdict(list)
    for row in report["superseded_runs"] + report["runs"]:
        slots[(row["task_id"], row["server"], row["repetition"])].append(row)
    return slots


def redefinition_pass(report: dict) -> set[tuple]:
    """Slots superseded by the passes that changed a task's definition (scale fixture, diff wording)."""
    redefined = set()
    for row in report["superseded_runs"]:
        reason = row.get("superseded_reason") or ""
        if "Rebuilt with go1.23.4" in reason or "reworded" in reason:
            redefined.add((row["task_id"], row["server"], row["repetition"], json.dumps(row, sort_keys=True)))
    return redefined


def headline_rows(report: dict) -> list[dict]:
    redefined = redefinition_pass(report)
    rows = []
    for slot, runs in history(report).items():
        task = slot[0]
        if task in CHANGED_TASKS:
            # Drop every run superseded by the redefinition pass, and every run before it.
            last_old = max((index for index, run in enumerate(runs)
                            if (*slot, json.dumps(run, sort_keys=True)) in redefined), default=-1)
            runs = runs[last_old + 1:]
        # First run under the current definition; past an infrastructure failure, its once-only rerun.
        chosen = runs[0]
        if infra(chosen) and len(runs) > 1:
            chosen = runs[1]
        rows.append(chosen)
    return rows


def original_rows(report: dict) -> list[dict]:
    return [runs[0] for runs in history(report).values()]


def score(rows: list[dict], exclude_infra: bool) -> dict:
    out: dict = {}
    for server in sorted({row["server"] for row in rows}):
        mine = [row for row in rows if row["server"] == server and not (exclude_infra and infra(row))]
        out[server] = {
            "correct": sum(row["outcome"] == "answer_matches" for row in mine),
            "correct_lenient": sum(bool(row.get("lenient")) or row["outcome"] == "answer_matches" for row in mine),
            "runs": len(mine),
            "infrastructure_failures_excluded": sum(infra(row) for row in rows if row["server"] == server)
            if exclude_infra else 0,
        }
    return out


def by_category(rows: list[dict]) -> dict:
    categories: dict = {}
    for category in sorted({row["category"] for row in rows}):
        categories[category] = score([row for row in rows if row["category"] == category], True)
    return categories


def scale_timing(rows: list[dict], runs_dir: Path | None) -> dict:
    """Median and range of scale-run wall time, and (with the run directories) the same without the longest
    single tool call, which for REA is the fresh Ghidra import a long-lived session would pay once."""
    def spread(values: list[float]) -> dict | None:
        if not values:
            return None
        return {"median": round(statistics.median_low(values), 1), "min": round(min(values), 1),
                "max": round(max(values), 1)}

    out = {}
    for server in ("rampage", "rea"):
        scale = [row for row in rows if row["server"] == server and row["category"] == "scale" and not infra(row)]
        walls = [row["wall_ms"] / 1000 for row in scale]
        entry = {"runs": len(scale), "wall_s": spread(walls)}
        if runs_dir is not None:
            longest, rest = [], []
            for row in scale:
                result = runs_dir / server / f"{row['task_id']}-r{row['repetition']}" / "result.json"
                calls = json.loads(result.read_text())["tool_calls"]
                top = max((call.get("duration_ms") or 0 for call in calls), default=0) / 1000
                longest.append(top)
                rest.append(row["wall_ms"] / 1000 - top)
            entry["longest_tool_call_s"] = spread(longest)
            entry["wall_s_without_longest_call"] = spread(rest)
        out[server] = entry
    return out


def main() -> None:
    report = json.loads(Path(sys.argv[1]).read_text())
    headline = headline_rows(report)
    original = original_rows(report)
    views = {
        "rules": __doc__.split("Usage:")[0].strip(),
        "headline": score(headline, True),
        "headline_by_category": by_category(headline),
        "core": score([row for row in headline if row["category"] in CORE], True),
        "outside_core": score([row for row in headline if row["category"] not in CORE], True),
        "original_pass_as_published": score(original, False),
        "original_pass_infrastructure_excluded": score(original, True),
        "headline_runs": sorted(f"{row['task_id']}:{row['server']}:{row['repetition']}:{row['outcome']}"
                                for row in headline),
        "scale_timing": scale_timing(headline, Path(sys.argv[3]) if len(sys.argv) > 3 else None),
    }
    Path(sys.argv[2]).write_text(json.dumps(views, indent=1) + "\n")
    print(json.dumps({key: value for key, value in views.items() if key not in ("rules", "headline_runs")},
                     indent=1))


if __name__ == "__main__":
    main()
