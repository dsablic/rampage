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

## M1 implementation notes (2026-11-06)

M1 implements everything the acceptance test needs except export/import, `bundle` and the transcript miner,
which are M2. The how-to is in [docs/flywheel.md](../flywheel.md).

### As built
- **Corpus.** `tools/flywheel/build-corpus.sh` builds `libid-89cf5995396f`: zlib 1.3.1, LZ4 1.10.0 and cJSON
  1.7.18, each pinned by SHA-256. They are built for x86-64 and AArch64 static-musl ELF, at O1, O2 and Os, with
  `zig cc` (Zig 0.17.0) and Homebrew clang 23.1.4. Four owned driver programs per library give 144 stripped
  binaries with symbolized twins. The split holds out one program per library: 36 held-out binaries and 108
  training binaries. The fast slice is 36 training binaries.
- **Truth.** Truth comes from the twin's function symbols, minus the driver object's own functions, with the
  stripped bytes checked against the twin. Each truth function is tagged with its library, or `runtime`. It is
  cached by binary hashes.
- **Baseline.** The baseline is the API's own path (project analysis, then `identify_functions` with the bundled
  databases only). It is cached by (binary hash, bundled asset SHA-256, executable SHA-256).
- **Candidates.** Candidates are PAT records in the existing signature pack format: a whole-function pattern
  with `..` wildcards, a name, and a library tag kept as provenance. A candidate is evaluated merged with the
  promoted rows, exactly as promoting it would leave the pack.
- **Incremental evaluation.** Only binaries holding a body that some row's pattern matches are identified
  again. On the held-out split this gave the same metrics as full re-identification: 10 of 36 binaries in
  47 ms, against 36 binaries in 226 ms.
- **Gate defaults.** Held-out F1 must gain at least 0.001 and must rise. False positives may not rise on the
  held-out split or the fast slice. No slice or cell may lose F1. A server runs at most 12 held-out evaluations.

### Baseline (bundled databases only)
| Split | Binaries | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| train | 108 | 5481 | 44 | 14301 | 0.9920 | 0.2771 | 0.4332 |
| heldout | 36 | 1702 | 11 | 4062 | 0.9936 | 0.2953 | 0.4553 |
| fast | 36 | 1884 | 11 | 5022 | 0.9942 | 0.2728 | 0.4281 |

The slice with the most headroom is Os (held-out F1 0.267). Of the 3,023 training failure groups, 1,898 bodies
are below the hash confidence gate: no signature can name them.

### Acceptance run
`rampage-eval flywheel --rounds 4 --budget-usd 5` (Sonnet 5.5 through `claude-runner.py`, unattended) ran four
rounds and promoted four candidates of 20, 17, 13 and 32 rows. It spent $0.62. Held-out F1 rose from 0.4553 to
0.5856 (+689 TP, +0 FP). Every per-dimension slice improved and no cell lost F1. Reverting the last promotion reproduced its recorded
pre-promotion metrics exactly. Reverting all four restored all 47 held-out slices, cells included, to the
baseline exactly.

### Timings (shared, heavily loaded laptop; load average about 120)
- **Corpus build:** 117 s with sources cached, three jobs.
- **Cold analysis:** about 55 ms per binary with three workers (108 training binaries in 6 s). Warm loads come
  from the cache.
- **Round:** about 24 s (target 1–3 minutes). Tool time is 1.3–2.8 s per round, mostly `corpus_failures`
  (0.7–1.6 s); the rest is model and client time.
- **Fast gate:** 0.27–0.69 s.
- **Held-out gate:** 0.15–0.47 s warm, about 2.2 s on a fresh server (target under 15 minutes).

### Deviations and decisions
- **One row form.** Rows are PAT patterns only, not masked-hash entries. PAT is the pack format's "pattern with
  masks", and the library tag is provenance because PAT has no field for it. A pattern holds at most 2,080
  bytes; longer bodies are flagged `proposable: false`.
- **Gate scope.** The gate compares against the current promoted state, not the bare bundled baseline, so two
  promotions are never credited with the same gain. `flywheel-eval` still reports deltas against the cached
  bundled baseline.
- **Observations.** `report_observation` writes to a dedicated opt-in store (`target/flywheel/observations/`,
  `--observations` or `RAMPAGE_OBSERVATIONS`), not the annotation sidecar, which is the analyst's replayed
  record. The tool is served in `core` whenever a store is configured, so the `improve` group itself still
  exists only with `--corpus`.
- **Held-out probing.** Held-out probing is bounded by `max_heldout_evaluations`. Held-out results expose
  overall and per-dimension metrics only; cell-level detail is a count of failing slices.
- **Twin symbols.** `zig cc -Os` strips symbols at link time, so the corpus links with `-g` and strips debug
  sections afterwards. The build now refuses a twin without function symbols.

### Gaps for M2
- **Export and bundling.** `.rpack` export/import, `packs diff` and `rampage-eval bundle` are not built yet, so
  the acceptance's last step (bundle against the bundled baseline) is open.
- **What the split holds out.** The split holds out programs, but the library code is shared across a
  configuration's programs. Most gains are therefore same-build recognition (cJSON, musl and compiler-rt
  functions present in every program). Holding out library versions or configurations would test
  generalization harder.
- **Corpus breadth.** The corpus has no gcc, no PE or Mach-O, and three libraries. Larger corpora need the
  per-binary caches to stay cheap.
- **Observations unused.** Observations are recorded but not yet read into the corpus.
- **Other families.** The transcript miner and the tool-ID and discovery families are not started.
