"""Derived views of a suite-v4 head-to-head report, from its published JSON only (no transcripts, no model calls).
Declared before any suite-v4 run (docs/plans/agent-bench-v4.md); a view added after a run must say so.

Which run counts: suite v3's rule (tools/agent-bench/v3/report-views.py): the first run of each slot, an
infrastructure failure's once-only rerun instead of it, strict scores as the headline and lenient beside them. An
export task's run is correct only when its answer and its written file both pass (failure `wrong_artifact`
otherwise); the lenient variant never forgives a failed file.

Views:

- headline: strict and lenient correct over all 20 tasks, and headline_by_category.
- category_averaged: the mean over categories of each category's accuracy (categories hold 2 to 4 tasks).
- new_features: the 16 tasks on what shipped after 1.0.0 (every category but regression).
- regression: v3's four tasks; with a suite-v3 report given, regression_drift sets each task's v4 result beside
  its v3 headline result, per server.
- without_general_runner: every task except patch-export-srec-cm4-srec, the one task whose REA route found before
  the run needs a general command runner (Rizin's shell escape) to write the file; see the plan's fairness notes.
- known_rampage_gaps: the six tasks where validation found rampage's scripted tool route short of the truth (four
  were fixed before any run, which the report must disclose; validate-rampage.py GAPS keeps the two still open),
  and the other ten, scored apart, so the fixes are visible in both.
- artifacts: per server, export runs whose file failed while the answer passed.
- contaminated_runs: runs scored wrong because their transcript reached the suite's own files or the repository.
- timing: per server and category, agent wall time (median and range), apart from accuracy.

Usage: python3 -I tools/agent-bench/v4/report-views.py REPORT.json OUT.json [V3_REPORT.json]
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v3 = load("v3_views", HERE.parent / "v3/report-views.py")
score, by_category, headline_rows, category_averaged, timing = (v3.score, v3.by_category, v3.headline_rows,
                                                                v3.category_averaged, v3.timing)

GENERAL_RUNNER = {"patch-export-srec-cm4-srec"}
KNOWN_GAPS = {"emulate-control-thumb-elf", "patch-values-cm4-hex", "patch-export-srec-cm4-srec",
              "patch-export-bin-cm4-raw", "libid-names-m0-elf", "libid-names-m0-raw"}


def artifacts(rows: list[dict]) -> dict:
    out: dict = {}
    for server in sorted({row["server"] for row in rows}):
        exports = [row for row in rows if row["server"] == server and row.get("artifact") is not None]
        out[server] = {"export_runs": len(exports),
                       "file_failed_answer_passed": sum(1 for row in exports if row.get("failure") == "wrong_artifact"),
                       "file_ok": sum(1 for row in exports if row.get("artifact") == "ok")}
    return out


def drift(rows: list[dict], earlier: list[dict]) -> dict:
    out: dict = {}
    for row in sorted(rows, key=lambda row: (row["task_id"], row["server"], row["repetition"])):
        if row["category"] != "regression":
            continue
        entry = out.setdefault(row["task_id"], {}).setdefault(row["server"], {"v3": [], "v4": []})
        entry["v4"].append(row["outcome"] == "answer_matches")
    for row in earlier:
        if row["task_id"] in out and row["server"] in out[row["task_id"]]:
            out[row["task_id"]][row["server"]]["v3"].append(row["outcome"] == "answer_matches")
    return {task: {server: {suite: f"{sum(values)}/{len(values)}" for suite, values in entry.items()}
                   for server, entry in servers.items()} for task, servers in out.items()}


def main() -> None:
    report = json.loads(Path(sys.argv[1]).read_text())
    headline = headline_rows(report)
    views = {
        "rules": __doc__.split("Usage:")[0].strip(),
        "headline": score(headline, True),
        "headline_by_category": by_category(headline),
        "category_averaged": category_averaged(headline),
        "new_features": score([row for row in headline if row["category"] != "regression"], True),
        "regression": score([row for row in headline if row["category"] == "regression"], True),
        "without_general_runner": score([row for row in headline if row["task_id"] not in GENERAL_RUNNER], True),
        "known_rampage_gaps": score([row for row in headline if row["task_id"] in KNOWN_GAPS], True),
        "outside_known_gaps": score([row for row in headline if row["task_id"] not in KNOWN_GAPS], True),
        "artifacts": artifacts(headline),
        # Runs whose transcript reached the suite's own files (truth, twins, sources) or the repository; scored wrong.
        "contaminated_runs": sorted(f"{row['task_id']}:{row['server']}:{row['repetition']}: {row.get('contamination')}"
                                    for row in headline if row.get("failure") == "contaminated"),
        "headline_runs": sorted(f"{row['task_id']}:{row['server']}:{row['repetition']}:{row['outcome']}"
                                for row in headline),
        "timing": timing(headline),
    }
    if len(sys.argv) > 3:
        views["regression_drift"] = drift(headline, headline_rows(json.loads(Path(sys.argv[3]).read_text())))
    Path(sys.argv[2]).write_text(json.dumps(views, indent=1) + "\n")
    print(json.dumps({key: value for key, value in views.items() if key not in ("rules", "headline_runs")},
                     indent=1))


if __name__ == "__main__":
    main()
