# Flywheel phase 2: a fast loop where AI both uses and improves rampage

**Date:** 2026-11-05. **Status:** approved 2026-11-05 as proposed (all five decisions; a $5 per family per run budget); iterate if it proves problematic. It builds on
[the flywheel strategy](2026-10-12-heuristic-self-improvement-flywheel.md), whose loop, ground-truth sources and
guardrails still apply. Its Phase 1 (the evaluation substrate) is implemented. This document covers Phases 2–3:
the proposer and automation. It is written around two requirements:

1. **Fast iterations.** One improvement cycle takes minutes, not hours, and the inner loop never rebuilds rampage.
2. **One interface.** An agent improves rampage through the same MCP surface it uses to analyse binaries. No
   separate scripting environment, and no second toolchain to learn.

## Design

### Heuristics stay runtime data
Every heuristic family the loop touches loads at runtime from a pack: signatures, PEiD, YARA, capa and constants
today, and later tool-ID and discovery rules once they are moved into data. A candidate is a scratch pack layered
over the bundled databases, so evaluating it needs no `cargo build`. Families still compiled into code, such as
discovery idioms and type rules, either move into pack form first or stay in the slower, code-review loop below.

### An opt-in `improve` tool group
This group exists only when the server is started with a corpus (`--corpus <dir>`), so normal analysis sessions
never see it. It shares the server, packs and annotation log with the analysis tools.

| Tool | Purpose |
|---|---|
| `corpus_failures` | A bounded, paged slice of the disagreement set for one family and slice (arch, compiler, opt level): missed or wrong items, each with the bytes, context and truth source. |
| `propose_heuristic` | Write one candidate row or rule into a scratch pack, schema-checked. It is never applied outside evaluation. |
| `evaluate_candidate` | Run the gate: a fast slice first, then the held-out split. Returns per-slice metric deltas, regressions and the cases that changed. Results are cached by candidate hash. |
| `promote_candidate` | Allowed only after a passing held-out gate on the current corpus version. Writes to the target pack with provenance (driving cases, metric deltas, corpus version, proposer run), and returns a revert id. |
| `report_observation` | Available in ordinary sessions too. An agent records a typed observation it can back with evidence, for example "a function starts at X, confirmed by a debugger stop" or "this import is a library function, confirmed by its build ID". These become weak labels for the corpus, never automatic promotions. |

Because analysis and improvement share one MCP server, the same agent can notice a miss while analysing (for
example, `decompile` fails because a function start was missed), call `report_observation`, and in an improve
session turn the corpus's matching failures into a candidate.

### Exporting and integrating improvements
Promotions are only useful if they can leave the machine where they were found. The format is the same at every
step, so moving them is a copy and a check, not a conversion.

- **Promoted packs are portable files.** `rampage packs export <pack> -o file.rpack` writes one archive. It
  holds:
  - the rows or rules, in the existing pack formats;
  - a manifest: format version, rampage version range, families, a content hash, and per-entry provenance
    (driving cases, metric deltas, corpus version and split, gate result, revert id).

  `rampage packs import file.rpack` validates the schema, hashes and version range before it adds anything, and
  `rampage packs diff` shows exactly what an import would change. Packs load through the existing `--packs`
  layering, so a user can install a pack without rebuilding.
- **Integrating into the bundled databases is one command:**
  `rampage-eval bundle --from <pack> [--entries <ids>]`.
  It merges the selected promoted entries into the repo's bundled-database sources: the same inputs the bundled
  signature and rule assets are built from today. It then regenerates the assets and reruns the held-out gate
  against the bundled baseline, because a candidate gated against an older baseline must pass again. If the gate
  passes, it writes a commit-ready change with a generated summary (entries, metric deltas, provenance links). The
  change lands through normal review like any other commit; nothing is merged into the bundled databases
  automatically.
- **Removal stays easy.** Every bundled entry keeps its provenance id, so
  `rampage-eval bundle --remove <id>` reverts it the same way.
- **Imports from other people pass the same gate.** A pack from someone else is data, never code. Before
  bundling, `bundle` reruns the gate on our corpus, so an imported pack is held to the same standard as a local
  promotion.

### Speed

- **Prebuilt, content-addressed corpus.** Binaries are built once from pinned sources: packages × compilers ×
  flags × architectures, each with a debug twin. Truth is derived once and cached by binary hash.
- **Cached baseline analysis.** Per-binary analysis results for the current bundled packs are cached. A candidate
  re-runs only the binaries and functions it could affect. A signature row, for example, only touches functions
  whose masked hash matches.
- **Two-stage gate.** A fast slice of tens of binaries takes seconds and rejects most bad candidates. The full
  held-out split, with per-slice regression checks, runs only before promotion.
- **Parallel workers** across binaries. The machine is shared, so the worker count is configurable.
- **One command:**
  `rampage-eval flywheel --family <f> --rounds N --budget $X`.
  It starts the server with `--corpus`, drives an agent through the existing swappable runner
  (`tools/agent-bench/claude-runner.py`), and writes a round report. The runner seam stays the same, so the
  model or CLI can change later.

Target: one round (failures → proposal → fast gate) in about 1–3 minutes on a laptop, and a held-out gate in under
15 minutes for the first family.

### The ergonomics loop: agents improving the tool surface
Benchmark and session transcripts already show tool errors, wasted calls, schema mistakes and wrong answers.

1. `rampage-eval mine-transcripts` clusters these into a bounded report: each failure pattern with counts and
   example calls.
2. Proposals here are code (descriptions, defaults, error text, argument validation), so they keep human review.
3. The gate is automatic: rerun only the benchmark tasks the change can affect, comparing calls, errors and
   accuracy before and after.
This formalises what the v2 quick-wins pass did by hand.

### Guardrails (unchanged, restated where speed could erode them)
- **The gate decides, not the agent.** `promote_candidate` refuses without a passing held-out result for the same
  candidate hash and corpus version.
- **The held-out split is never visible to the proposer.** `corpus_failures` serves only the training split. The
  split is rotated per corpus version, so a candidate can't be tuned to the gate.
- **Per-slice regressions are rejected,** or the candidate is scoped to the slices it helps.
- **Promotions are data with provenance and revert ids.** The improve tools never execute proposed content
  outside evaluation.
- **Observations from real use are opt-in, local and evidence-backed.** They are weak labels only, and never
  shared or promoted without the gate.

## First family

Start with library identification signatures. They are already pack-driven, truth comes cheaply from symbolised
references (the FLIRT-from-symbols path), and metrics exist. Follow with compiler and tool identification (exact
labels from controlled builds, but the rules need moving into data first), then function-start discovery.

**Acceptance:** an unattended `flywheel` run on the library-ID family promotes at least one candidate. That
candidate must give a measured held-out improvement with no slice regression. Provenance must make the promotion
reproducible, and the revert id must undo it cleanly. The promoted pack must then go through `packs export`, then
`packs import` on a clean checkout, then `rampage-eval bundle`. The result must be a commit-ready change to the
bundled databases that passes the gate against the bundled baseline.

## Decisions requested
1. Approve the `improve` group as an opt-in MCP group behind `--corpus`, with improvement going through the same
   MCP surface as analysis.
2. Approve library-ID signatures as the first family.
3. Approve the corpus build: pinned open-source packages, downloaded and compiled locally, and never committed.
4. Approve the `.rpack` export/import format and the `bundle` integration command.
5. Per-round model budget for unattended runs (suggested default: $5 per family per run).
