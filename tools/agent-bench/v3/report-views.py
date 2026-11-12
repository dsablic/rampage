"""Derived views of a suite-v3 head-to-head report, from its published JSON only (no transcripts, no model calls).
Declared before any suite-v3 run (fairness review); a view added after a run must say so.

Which run counts, per (task, server, repetition) slot:

- headline: the first run of each slot. A run stopped from outside before any answer (an outside kill, the client's
  usage limit, a safeguard model fallback) is an infrastructure failure: it counts for neither server, and its
  once-only rerun counts instead when there is one (suite v2's rule). Should a task's definition change after a
  run, its first run under the new definition counts, the change is listed in REDEFINED below with the date, and
  the report says so; there is none.
- every score is given strict (the manifest contract) and lenient (an extra "status":"ok" field and the task's
  declared lenient_spellings in neutral-v3.toml forgiven), side by side; strict is the headline.

Views:

- headline: strict and lenient correct over all tasks.
- headline_by_category: the same per category.
- category_averaged: the mean over categories of each category's strict (and lenient) accuracy, so that a
  category's task count does not weight it.
- ghidra_advantage_core: every task except the call-graph lookups (sqlite-callers, go-callers).
- combined_v2_v3: with a suite-v2 report given, v2's headline rows (its own published rule,
  tools/agent-bench/v2/report-views.py) and v3's headline rows together, overall and per suite.
- timing: per server and category, agent wall time (median and range), reported apart from accuracy.
- rea_import: with RUNS_DIR, per fixture the longest single tool call of each REA run (its fresh Ghidra import and
  analysis), and wall time without it; measurements made outside the agent (the report's `attachments`) are copied
  as they are.

Usage: python3 -I tools/agent-bench/v3/report-views.py REPORT.json OUT.json [V2_REPORT.json|-] [RUNS_DIR]
"""

from __future__ import annotations

import importlib.util
import json
import statistics
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

_spec = importlib.util.spec_from_file_location("v2_views", Path(__file__).resolve().parents[1] / "v2/report-views.py")
assert _spec and _spec.loader
v2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v2)
infra, history, score, by_category = v2.infra, v2.history, v2.score, v2.by_category

TASKS = Path(__file__).resolve().parents[3] / "crates/rampage-eval/tasks/v3"
# task id -> (date, marker in the superseded runs' reason); a run before the change does not count in the headline.
REDEFINED: dict[str, tuple[str, str]] = {}
OUTSIDE_CORE = {"sqlite-callers-x64-elf", "go-callers-x64-elf"}


def headline_rows(report: dict) -> list[dict]:
    rows = []
    for slot, runs in history(report).items():
        if slot[0] in REDEFINED:
            marker = REDEFINED[slot[0]][1]
            runs = [run for run in runs if marker not in (run.get("superseded_reason") or "")] or runs
        chosen = runs[0]
        if infra(chosen) and len(runs) > 1:
            chosen = runs[1]
        rows.append(chosen)
    return rows


def core(row: dict) -> bool:
    return row["task_id"] not in OUTSIDE_CORE


def category_averaged(rows: list[dict]) -> dict:
    out = {}
    categories = by_category(rows)
    for server in sorted({row["server"] for row in rows}):
        strict, lenient = [], []
        for scores in categories.values():
            entry = scores.get(server)
            if entry and entry["runs"]:
                strict.append(entry["correct"] / entry["runs"])
                lenient.append(entry["correct_lenient"] / entry["runs"])
        out[server] = {"strict": round(statistics.fmean(strict), 4) if strict else None,
                       "lenient": round(statistics.fmean(lenient), 4) if lenient else None,
                       "categories": len(strict)}
    return out


def spread(values: list[float]) -> dict | None:
    if not values:
        return None
    return {"median": round(statistics.median_low(values), 1), "min": round(min(values), 1),
            "max": round(max(values), 1)}


def timing(rows: list[dict]) -> dict:
    out: dict = defaultdict(dict)
    for server in sorted({row["server"] for row in rows}):
        for category in sorted({row["category"] for row in rows}):
            walls = [row["wall_ms"] / 1000 for row in rows
                     if row["server"] == server and row["category"] == category and not infra(row)]
            out[server][category] = {"runs": len(walls), "wall_s": spread(walls)}
    return dict(out)


def rea_import(rows: list[dict], report: dict, runs_dir: Path | None) -> dict:
    out: dict = {"outside_agent": report.get("attachments", {})}
    if runs_dir is None:
        return out
    per_fixture: dict = defaultdict(lambda: {"longest_tool_call_s": [], "wall_s_without_longest_call": []})
    for row in rows:
        if row["server"] != "rea" or infra(row):
            continue
        result = runs_dir / "rea" / f"{row['task_id']}-r{row['repetition']}" / "result.json"
        calls = json.loads(result.read_text())["tool_calls"]
        top = max((call.get("duration_ms") or 0 for call in calls), default=0) / 1000
        manifest = TASKS / f"{row['task_id']}.toml"
        fixture = tomllib.loads(manifest.read_text())["fixture"]["id"] if manifest.is_file() else row["task_id"]
        per_fixture[fixture]["longest_tool_call_s"].append(top)
        per_fixture[fixture]["wall_s_without_longest_call"].append(row["wall_ms"] / 1000 - top)
    out["in_agent_runs"] = {fixture: {key: spread(values) for key, values in entry.items()}
                            for fixture, entry in sorted(per_fixture.items())}
    return out


def main() -> None:
    report = json.loads(Path(sys.argv[1]).read_text())
    v2_path = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else None
    runs_dir = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    headline = headline_rows(report)
    views = {
        "rules": __doc__.split("Usage:")[0].strip(),
        "redefined_tasks": REDEFINED,
        "headline": score(headline, True),
        "headline_by_category": by_category(headline),
        "category_averaged": category_averaged(headline),
        "ghidra_advantage_core": score([row for row in headline if core(row)], True),
        "outside_core": score([row for row in headline if not core(row)], True),
        "headline_runs": sorted(f"{row['task_id']}:{row['server']}:{row['repetition']}:{row['outcome']}"
                                for row in headline),
        "timing": timing(headline),
        "rea_import": rea_import(headline, report, runs_dir),
    }
    if v2_path:
        earlier = v2.headline_rows(json.loads(Path(v2_path).read_text()))
        views["combined_v2_v3"] = {"v2": score(earlier, True), "v3": score(headline, True),
                                   "both": score(earlier + headline, True)}
    Path(sys.argv[2]).write_text(json.dumps(views, indent=1) + "\n")
    print(json.dumps({key: value for key, value in views.items() if key not in ("rules", "headline_runs")},
                     indent=1))


if __name__ == "__main__":
    main()
