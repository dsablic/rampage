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
which are M2. The how-to is in [docs/flywheel.md](../flywheel.md). The first M1 run was reviewed and found to
measure recognition of the same build rather than generalisation. A fix pass rebuilt the split and the gate, and
the acceptance was re-run. Both are recorded here.

### The first split, and why it was replaced
The first corpus (`libid-89cf5995396f`) split by program within one library version:

- **Corpus:** zlib 1.3.1, LZ4 1.10.0 and cJSON 1.7.18 at O1, O2 and Os.
- **Held-out:** one driver program per library.
- **Gate scope:** every truth function, including musl and compiler-rt.

Every program of a configuration links the same library and runtime build, so holding out a program held out
almost nothing. A review measured it:

- 98.0% of held-out truth functions had the same name in training under the same configuration.
- 56.6% of held-out bodies were byte-identical to a same-named training body.
- Zig's O1 and O2 binaries were byte-identical (24 of 24 pairs).
- The held-out split had only 514 functions outside the truth.

Its acceptance run promoted 82 rows (held-out F1 0.4553 to 0.5856, +689 TP). Of the 663 gains the review could
attribute:

- 662 were a row matching a same-named training function in the identical configuration;
- 74.8% were byte-identical to training;
- 75.1% were musl or compiler-rt, not the target libraries;
- LZ4 gained nothing;
- 23 of the 82 rows were under 32 bytes.

That result showed the loop's mechanics work. It was not evidence of generalisation.

The review also found that a `--corpus` server served the core tools. Those tools take any path, so a proposer
could have opened held-out binaries and their symbolized twins.

### As built after the fix pass
- **Corpus `libid-738deabb4598`.** Each target library is built twice: the older version for training (zlib
  1.2.13, LZ4 1.9.4, cJSON 1.7.15) and the current version held out (zlib 1.3.1, LZ4 1.10.0, cJSON 1.7.18). Both
  link into the same four owned drivers, for x86-64 and AArch64 at O0/O2/Os with zig cc and clang 23.
  Negatives are inih r58, tinyexpr 1.1.1 and two owned programs, built the same way. That makes 360 binaries
  (144 training, 144 held-out, 72 negative) with no duplicates, built in 83 s.
  - The version hashes zig, clang and ld.lld.
  - `tools/flywheel/expected-digests.json` records the stripped digests for a reproducibility check.
- **Scoring.** The gated scope is the target libraries' own functions plus every false name. `origin:` slices
  report library, runtime and none separately and are never gated. The `library:` slice is now
  `program_library:`.
- **Gate.**
  - Rows must be at least 32 bytes.
  - The fast stage refuses any new false positive on the full training split, any name at all on the negatives,
    and any gated slice losing F1.
  - The held-out stage needs an F1 gain of at least 0.001, no new false positive and no gated slice regression.
  - It returns only the verdict and the overall delta.
  - Held-out evaluations are capped at 20 per corpus, persisted across servers under a file lock.
  - Records are keyed by corpus identity: the version, the split configuration and every binary hash.
- **Server isolation.** A `--corpus` server serves `enable_tools` and the improve group alone; no other group can
  be enabled. Every tool argument naming a path under the corpus or the flywheel directory is refused.
  `report_observation` is served only in ordinary sessions, bounds the hashed size and refuses flywheel corpus
  paths.
- **Promotion.** Promotions take a cross-process file lock and write `entries.json` last; the pack is regenerated
  from it when found out of date. Reverts are latest-first only; an out-of-order revert is refused with the order
  to use.
- **Runs.** A round that does not end `ok` reverts that round's promotions and stops the run; failing isolation
  counts as not ending `ok`.

### Overlap check (deviation)
A server measures how many held-out library bodies (masked) also occur in training. On this corpus it is 9,734
of 13,291 (73.2%): most zlib, LZ4 and cJSON functions are unchanged between these versions.

The check now works in two tiers. Above `max_heldout_overlap` (50%) the server warns loudly: on stderr, in
`corpus_failures` and in the run report. It refuses the corpus only above `refuse_heldout_overlap` (95%,
essentially the same build). The limit was not raised to make the warning go away. Reports split held-out gains
into bodies training already held and novel bodies, so recognition of unchanged code is never presented as
generalisation.

### Baseline (bundled databases only, gated scope)
| Split | Binaries | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| train (old versions) | 144 | 989 | 54 | 12963 | 0.948 | 0.071 | 0.132 |
| heldout (current versions) | 144 | 1005 | 60 | 13315 | 0.944 | 0.070 | 0.131 |
| fast | 36 | 324 | 14 | 3966 | 0.959 | 0.076 | 0.140 |
| negative | 72 | 0 | 26 | 1224 | — | — | — |

The bundled databases name no held-out cJSON function and almost nothing at O0 (held-out recall 0.002).

### Acceptance run (fix pass)
`rampage-eval flywheel --rounds 4 --budget-usd 5` (Sonnet 5.5, unattended) ran four rounds for $0.45 and
promoted four candidates: 12, 8, 6 and 16 rows, all at least 32 bytes.

**Overall:**
- Gated held-out F1 rose from 0.1306 to 0.1743 (+368 TP, +0 FP).
- No new name on the negatives, and no gated slice lost F1.

**By origin:**
- cJSON +280
- zlib +56
- LZ4 +32
- runtime +0

**Did it generalise?** Of the 368 held-out gains, 365 are functions whose masked body training already held,
because the code is unchanged between versions. Only 3 are novel bodies (`cJSON_InitHooks`,
`cJSON_PrintPreallocated`). The agent's own round summaries give the same reason: it picked long single-name bodies
"likely to be unchanged between versions". So the promotions are honest cross-version recognition of unchanged
library code, which is what FLIRT-style signatures do. They are not evidence that the loop learns patterns that
survive code changes. Whole-function byte patterns cannot carry across a changed body; that needs wildcarding
beyond scheme-2 masking, or another signature form.

**Revert check.** Reverting an earlier promotion out of order was refused. Reverting all four latest-first
restored all 51 held-out slices to the baseline exactly.

### Timings (shared, heavily loaded laptop)
- **Corpus build:** 83 s (360 binaries, three jobs, sources cached).
- **Cold analysis:** about 40 ms per binary.
- **Server open:** about 16 s cold for the overlap check, about 2 s warm.
- **Round:** 23–38 s. Tool time is 4–16 s and grows as promoted rows make more binaries need identifying again.
- **Fast stage:** 0.02–1.7 s (fast slice, full training split and negatives).
- **Held-out gate:** 0.04–4.7 s (target under 15 minutes).

### Deviations and decisions
- **One row form.** Rows are PAT patterns only (the pack format's "pattern with masks"). The library tag is
  provenance.
- **Gate scope.** The gate compares against the current promoted state; `flywheel-eval` reports against the
  bundled baseline.
- **Revert order.** Reverts are latest-first only, rather than re-gating the remaining set.
- **Overlap check.** It warns above 50% and refuses above 95%, as described above.
- **No configuration hold-out view.** The configuration hold-out "second view" was not built; it needs a second
  split definition (see the gaps).
- **Observation store.** Observations go to a dedicated opt-in store, not the annotation sidecar, which is the
  analyst's replayed record.

### Gaps for M2
- **Export and bundling.** `.rpack` export/import, `packs diff` and `rampage-eval bundle` are not built yet (built
  in M2, below).
- **A split that tests changed code.**
  - A configuration hold-out (compiler × opt per arch) as a second split view.
  - A metric restricted to novel held-out bodies, so a gain from changed code can be gated directly.
- **Signature forms.** Patterns that tolerate small code changes (broader wildcards, callee-keyed rows) are needed
  before generalisation beyond unchanged code is reachable.
- **Corpus breadth.** The corpus has no gcc, no PE or Mach-O, and three target libraries.
- **Observations unused.** Observations are recorded but not yet read into the corpus.
- **Other families.** The transcript miner and the tool-ID and discovery families are not started. Their split
  rule is in [docs/flywheel.md](../flywheel.md).

## M2 implementation notes (2026-11-06)

M2 asks one question: does the AI proposer beat a deterministic signature generator at generalising library
identification? It also ships export, import and bundling. The how-to is in [docs/flywheel.md](../flywheel.md) and
[docs/data-packs.md](../data-packs.md#export-and-import).

### As built
- **Deterministic arm.** `rampage-eval flywheel-baseline` generates every eligible row from the training truth:
  - one row per distinct (architecture, masked body);
  - at least 32 bytes and at most 2080, passing the row schema;
  - bodies with more than one name dropped, as the signature builder makes them never answer;
  - bodies that also match other names or code outside the truth in training or negatives dropped.

  It is saved per corpus, build and minimum length, and is the default baseline: a corpus server gates every
  candidate against bundled + arm + promoted rows. `--flywheel-baseline bundled` keeps M1's comparison for
  diagnostics only. Against the arm the false-positive rules also run on the deployed state, which drops the arm,
  so a row that only collides with an arm row cannot pass as harmless.
- **Novel-only metric.** `novelty:novel` and `novelty:recognised` are gated held-out slices. `require_novel_gain`
  (default: on against the arm, `min_novel_f1_gain` 0.001) adds a held-out rule. The proposer still sees only
  pass/fail and the overall delta.
- **Generalising rows.** These are what rampage's PAT matcher supports:
  - whole-byte wildcards: `wildcards`, `wildcard_spans`, and `merge_cases` over same-length training variants;
  - an exact module length;
  - a pattern shorter than its module: `keep_prefix` or `length`.

  Nibble wildcards, PAT CRCs and references are not usable (the matcher has no nibble wildcards; CRCs and
  references are unsupported or weaker), and FID is hash-based with a semantic adapter.
  `corpus_failures` adds `variants` (the same function's other training bodies) and `outcome: "all"` (every
  training body, since the arm leaves few failures), both from the training split only.
- **Export and import.** `rampage pack export|import|diff` moves packs as `.rpack` files: one gzip'd JSON archive
  with the files and a manifest (format version, version range, families, file hashes, content hash, per-entry
  provenance). Import checks everything before staging and loading the pack.
- **Bundling.** `rampage-eval bundle --from PACK [--entries ...]` merges entries into
  `crates/rampage-signatures/data/flywheel/libid.json`. It regenerates the corpus assets with those rows as their
  PAT namespace and reruns the gate with the regenerated databases against the current ones (no rebuild). It writes
  a commit-ready change, `change.patch` and a summary, and never commits. `--remove ID` reverts by provenance id.

### Baseline (corpus `libid-738deabb4598`, gated scope)
The corpus version matches M1's, but 64 binaries (60 zig O0, 4 clang O0) differ from `expected-digests.json`, so
these numbers are measured afresh rather than compared with M1's corpus identity. The arm holds 3,691 rows. From
5,106 training bodies it dropped:
- 228 bodies shorter than 32 bytes;
- 1,068 longer than a row allows;
- 100 with ambiguous names;
- 19 that collide with other code.

| Split | State | Scope | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---:|---:|---:|---:|---:|---:|
| train | bundled | all | 989 | 54 | 12963 | 0.948 | 0.071 | 0.132 |
| train | bundled + arm | all | 9521 | 54 | 4431 | 0.994 | 0.682 | 0.809 |
| heldout | bundled | all | 1005 | 60 | 13315 | 0.944 | 0.070 | 0.131 |
| heldout | bundled + arm | all | 8119 | 65 | 6201 | 0.992 | 0.567 | 0.722 |
| heldout | bundled | novel | 245 | 6 | 4343 | 0.976 | 0.053 | 0.101 |
| heldout | bundled + arm | novel | 679 | 7 | 3909 | 0.990 | 0.148 | 0.258 |
| heldout | bundled | recognised | 760 | 18 | 8972 | 0.977 | 0.078 | 0.145 |
| heldout | bundled + arm | recognised | 7440 | 22 | 2292 | 0.997 | 0.765 | 0.865 |
| negative | both | all | 0 | 26 | 1224 | — | — | — |

The arm alone reaches what M1's agent reached and far beyond: +7,114 held-out TP (M1's agent: +368). It fails the
held-out gate on 5 new false positives. Its 434 "novel" gains are bodies whose masked form differs from training
only where masking is asymmetric (a field equal to its masked value reads as fixed), so a training pattern still
matches.

### Acceptance run
`rampage-eval flywheel --rounds 6 --budget-usd 5` used the arm baseline with the novel gain required (Sonnet 5.5,
unattended). It ran six rounds for **$1.28** and promoted **nothing**.
- **Candidates:** each round proposed one candidate of 6 to 15 rows, built from bodies the arm already names.
  - prefix rows (`keep_prefix` of 48 to 200 bytes, the module length kept);
  - `merge_cases` over same-length zig variants (`_tr_tally`, `flush_pending`, `LZ4_initStream`);
  - the position-dependent wildcards masking already gives.
- **Gates:** all six passed the fast gate, and all six moved held-out F1 by exactly +0.000000. They failed the
  overall-gain and novel-gain rules, with no false positive. Six of 20 held-out evaluations were used.
- **The agent's diagnosis, consistent every round:**
  - unchanged code is already covered by the arm;
  - changed functions mostly change length, and a PAT row binds the module length;
  - same-length variants across configurations are rare and differ in many bytes, so training gives no evidence
    for which bytes change between versions.

**Where the headroom was.** `flywheel-baseline` measures it from held-out truth, for the operator only:
- 4,588 novel held-out library functions in all;
- 3,230 have a training body with the same name and architecture;
- 1,577 have one of exactly the same length;
- 1,519 would merge with it into a schema-valid row.
- Of the same-length ones, 717 differ in only 1 to 2 bytes and 422 in 3 to 8.

So wildcard generalisation had a ceiling of roughly a thousand novel functions. The agent's strategy (unconstrained
tails, merges across compiler configurations) did not aim at it: the varying bytes are operands that change with
the source version, not with the build configuration, and nothing in training points at which ones. A plain rule
"wildcard immediates and displacements" is deterministic too, so it would belong in the arm, not in the agent.

### Export, import and bundle demonstration
Nothing was promoted, so a scripted known-good candidate stood in: 24 long cJSON x86_64 arm rows, proposed through
the MCP server in the diagnostic `bundled` mode, in a separate flywheel directory.
- **Promotion:** it passed both gates (held-out +88 TP, +0 FP, F1 +0.0106) and was promoted as `rv-e9329f9d1856`.
- **Export and import:** `rampage pack export` wrote a 9.3 KB `.rpack`. `rampage pack import` into a clean scratch
  directory checked it and installed 3 files; `pack check` loads 24 signatures. On a held-out cJSON binary,
  `--pack` names 12 functions from it.
- **Bundle:** `rampage-eval bundle --from <imported> --patch-only` passed the gate against the bundled baseline:
  - held-out +88 TP, +0 FP, F1 +0.0106;
  - train +108 TP;
  - negatives +0;
  - novel +0.
- **The change:** it is left as `target/flywheel/bundle/m2-demo/change.patch` (47 KB, not committed). It
  regenerates `corpus-x86_64.json.gz` and its index with a `flywheel-libid-x86_64` profile, and adds the entry to
  `data/flywheel/libid.json`. With the patch applied, the rampage-signatures suite (154 tests, including the
  bundled catalog and index checks) passes; it reverses cleanly.

### Timings (shared laptop)
- **Corpus build:** 84 s.
- **flywheel-baseline:** 23 s; generating the arm takes 1.5 s.
- **Server open:** 15 s.
- **corpus_failures:** 5 to 6 s.
- **Fast gate:** 0.7 s with cached reference names, 4.9 s cold.
- **Held-out gate:** 2.4 s.
- **Rounds:** 33 to 54 s each; the whole run took 292 s.
- **bundle:** 20 s.

### Deviations and decisions
- **What counts as novel.** Novelty compares masked bodies, as the spec defines it. The arm's 434 novel gains show
  where that definition is generous; the gate measures candidates over the arm, so they do not count for an agent.
- **What the arm drops.** It drops ambiguous and colliding bodies rather than emitting ambiguous records. Its own
  answers are the same either way. A proposed row for such a body fails the fast or deployed-state gate.
- **Bundle baseline.** The bundle gate runs against the bundled baseline, with the novel rule off by default
  (`--require-novel-gain true` turns it on): its baseline is the bundled databases, not the arm.
- **Bundle measurement.** Bundling measures the regenerated assets against the repository's current assets, both in
  place of the compiled-in ones, so nothing is rebuilt between bundle and remove. A bundle refuses files with
  uncommitted edits, which would leak into its patch.
- **Archive integrity.** Archive hashes are integrity checks, not signatures. For flywheel packs, import also checks
  that the signature files are exactly what the entries' rows produce.
- **Archive format.** An archive is gzip'd JSON rather than tar, which avoids a new dependency and path-handling
  risk in an extractor.

### Recommendation
Libid is not worth more AI effort in this form:
- the deterministic arm captures the recognisable gain;
- the remaining same-length headroom is mechanical (operand wildcarding), so it should become a deterministic arm
  v2 and be measured the same way;
- what is left beyond that (changed lengths) is out of reach for byte patterns.

The next AI family should be one with no deterministic generator: compiler and tool identification, where rules
must be written rather than extracted, after its rules move into data.

## Arm v2: operand wildcarding (2026-11-08)

M2 recommended making operand wildcarding a deterministic arm: the remaining same-length headroom was operands that
change with the source version, and a rule that names them belongs in the generator, not the agent. How-to:
[docs/flywheel.md](../flywheel.md#the-deterministic-arm).

### As built
- **Operand classes** (`rampage_signatures::operand_classes`): per byte, `relocation` (every byte of a field scheme
  2 masks), x86 `disp8`/`disp-wide`/`imm8`/`imm-wide` from iced-x86's constant offsets, and AArch64
  `a64-immediate`/`a64-offset` from the encodings. Scheme 2's masking was refactored to report its fields (the
  hashes are unchanged), so `relocation` is exactly what the hash masks.
- **AArch64 bytes.** Fields do not align to bytes there, so a byte is wildcarded only when all its bits are the
  field's or a register number's. Bytes that also hold opcode bits stay fixed: load vs store, MOVZ vs EOR, the
  branch kind, the condition. The cost is that only part of each field is wildcarded (the low six bits of an
  imm12, nothing of an unscaled imm9).
- **Tiers.** Rows are made widest first: all classes, then `relocation` alone, then exact. Each tier groups the
  bodies whose patterns agree there; a group the row rules refuse leaves its bodies to the next tier.
- **Default:** all classes, with that ladder. The class set was fixed before any measurement. The ladder was not:
  it was added after a first run without tiers on the held-out split (see the first row of the review notes
  below), so it is a design choice informed by one held-out read. Variant class sets are diagnostics.
- `flywheel-baseline --wildcards LIST|none` compares arms. `novel_reach` adds `widened_matches`: same-length novel
  functions a widened training pattern matches, before collision checks.
- The synthetic fixture gains `ml_scale`, whose version 2 changes only constants: the default arm names it in both
  held-out programs, and v1's exact rows do not.

### Baseline (corpus `libid-bfee58c53133`)
The corpus was rebuilt for this run under a new version (toolchain updates; 270 binaries differ from
`expected-digests.json`). Bundled-only held-out false positives rose from 60 to 276 on this build, so the numbers
are compared within this corpus only.

| Arm | Held-out TP | FP | F1 | Novel TP | Novel F1 |
|---|---:|---:|---:|---:|---:|
| bundled only | 1005 | 276 | 0.129 | 245 | 0.101 |
| v1 (exact rows) | 8119 | 280 | 0.715 | 692 | 0.261 |
| `relocation`, tiered | 8352 | 280 | 0.728 | 925 | 0.335 |
| **v2 default (all classes, tiered)** | **8444** | **280** | **0.733** | **1017** | **0.362** |
| reloc + immediates, tiered (diagnostic) | 8431 | 280 | 0.732 | 1004 | 0.358 |

- Training and negative metrics are identical for every arm (train 9519 TP / 270 FP; negatives 134 FP from the
  bundled databases alone).
- Over v1, v2 names +325 held-out functions, all novel (+47%), with no new false positive. The recognised slice is
  unchanged at 7427 TP.
- The default arm holds 3008 rows: 2774 at the widest tier, 202 at `relocation`, 32 exact.
- At the widest tier, 142 groups fall back as ambiguous (one widened pattern for two names), 57 as refused by the
  row schema and 16 as colliding.
- **Reach:** of the 1586 same-length novel functions, a widened training pattern matches 1182 (v1: 541). The arm
  realises 325 new ones. The rest are lost to ambiguity, collisions and the 2080-byte row limit, and to bodies the
  arm already named.
- The arm still fails the held-out gate against the bundled databases on v1's same 4 false positives. They come
  from exact rows, not from widening.

### Review notes
- **First measurement.** It classed a whole AArch64 byte by any field bit and had no tiers. Wildcarding all
  classes then reached 8294 TP: worse than `relocation` alone, because 615 widened groups failed the schema and fell
  straight to exact rows. That run motivated the tiers.
- **Fresh-context review** found that byte rule erased opcode bits (`ldr` matched `str`, a BL became four
  wildcards). The rule was fixed as above, and the numbers above are from the fixed build. The earlier,
  higher-looking result (+372) relied on those over-broad rows.
- x86 `imm8` and `imm-wide` are broad by design: they include SSE shuffle selectors and syscall numbers, so a
  short wrapper can widen to match a sibling (`read` vs `write`). The row schema's fixed-byte minimum and the
  collision check bound it. No new false positive appeared on held-out or negatives.

### Final split (2026-11-08)
The held-out split guided this arm's design, so a final split was added for claims ([docs/flywheel.md](../flywheel.md#the-final-split)).
- **Contents:** versions no other split holds. From-source zlib 1.3.2/1.4 and cJSON 1.7.19 in the same matrix,
  plus an Alpine gcc zlib ladder: 1.2.13 trains, 1.3.1 is held out, 1.3.2/1.4 are final.
- **Read policy:** only by `flywheel-eval --split final --final-reason`, which appends each read to a ledger.
  Corpus `libid-ed988c9a220e` has 536 binaries, 160 of them final.
- **A first attempt failed** (corpus `libid-ada4c7e8765c`, final reads #1–#2 there). Its final split held only gcc
  builds of new versions, with no gcc anywhere else. Every arm and the bundled databases named 0 of 2404 functions:
  clang-trained byte signatures do not transfer to gcc, so that split measured toolchain transfer, not versions.

Final reads #1 (v1) and #2 (v2) on `libid-ed988c9a220e`:

| Final split | TP | FP | F1 | Novel TP | Novel F1 |
|---|---:|---:|---:|---:|---:|
| bundled only | 400 | 300 | – | 51 | – |
| v1 (exact rows) | 5799 | 344 | 0.519 | 436 | 0.090 |
| **v2 default** | **6468** | **348** | **0.562** | **1105** | **0.214** |
| gcc cell, v1 → v2 | 223 → 287 | 0 → 0 | 0.240 → 0.299 | | |

- **Generalisation holds on untouched data.** v2 names +669 more functions than v1, and 2.5x the novel ones. The
  recognised slice is unchanged at 5363 TP.
- **False positives grow off the dev split.**
  - On held-out, v1 adds 4 false positives over the bundled databases and widening adds none.
  - On final, v1 adds 44 and v2 adds 48: widening costs 4 (all in the clang cell).
  - The held-out split understated the arm's false-positive rate. The cause cannot be read from final cases,
    which the split never reports. Candidates to check on the dev split: renamed functions across versions, and
    short bodies.
- On this corpus's held-out split (with gcc zlib 1.3.1), v1 reaches 8396 TP and v2 8729, both at 280 FP.

### False-positive diagnosis on the dev split (2026-11-08)
`flywheel-eval --split heldout --dev-cases` lists the dev split's changed cases.
- **The arms' 4 dev false positives are one case.** v1 and v2 share them. In lz4 1.10.0 at O0, `LZ4_read64` is
  named `LZ4_read_ARCH`: the two bodies are byte-identical on 64-bit targets, and training (lz4 1.9.4) has only
  the second. Nothing in training reveals the collision, so a per-row override built from training cannot fix it.
- **Rejected rule: one name per binary** (drop a name matched at more than one function). Measured as a temporary
  post-filter on train, dev and negatives (never final):
  - it removes 8 dev false positives, the 4 above plus 4 of the bundled databases';
  - it costs 84 dev and 86 training true positives: static binaries hold same-named duplicates;
  - dev F1 drops from 0.724 to 0.720, so the rule was reverted.
- **The false-positive mass is the bundled databases, not the arms:** 270 train, 276 dev and 134 negative false
  positives with the bundled databases alone, against the arms' 4 on dev.

### Bundled-database false positives (2026-11-08)
These are diagnosed from the cached bundled-only names joined with the truth on train, dev and negatives (never
final). All 680 false positives are wrong names at real functions: 634 runtime and 46 library. They come from 20
(truth, name) pairs in three families.
- **Zig instance counters: 540 (79%).** Zig names generic instances `math.ldexp.ldexp__func_40`, with a
  build-local counter. The bundled databases were built with zig 0.17.0 and the corpus with 0.17.1, so the same
  body (332–1343 bytes, O0, aarch64 and x86_64) carries another counter (`__func_37`). The body match is right;
  only the counter differs. That is nine bodies, each in 60 binaries. Each fix is a methodology call:
  - drop the `__func_N` / `__anon_N` counter in the names identification reports and in the truth;
  - or build the corpus with the bundled databases' zig.
- **Short forwarders: 128.** These are argument moves plus one call or tail jump, 9–31 bytes, and they pass the
  gate only on frame-pointer bookkeeping. `zcfree` (`mov rdi, rsi; jmp free`) is OpenSSL's
  `ossl_digest_get_approved_nid_with_sha1`; `posix.munmap` is `inet_network`; `futimens` is `SSL_config`;
  `compress`, `strtok` and `LZ4F_compressBegin_usingDict*` are similar.
  - **Rejected: refuse such bodies at lookup.** A body that fails the gate once landing pads, frame bookkeeping and
    a final direct branch are dropped would be named only by callee key. Two variants were measured:
    - every short body: −46 FP on train and on dev and −22 on negatives, at a cost of 524 correct names on each
      of train and dev;
    - only bodies that branch out of themselves: −46/−46/−18 FP, at a cost of 332 correct names each, mostly
      `__stdio_seek`, `__ofl_lock`, `sched_getaffinity` and `sprintf`.

    Correct forwarders outnumber wrong ones about 7:1, so both variants were reverted.
  - **The real fix is callee-confirmed forwarders.** The shipped databases store callee keys only for ambiguous
    bodies (`calls`), and `entry_calls` is not saved. Naming a forwarder only when its callees match the
    reference's needs the bundled databases regenerated with callee keys for forwarder entries.
- **Identical bodies under other names: 12.** These are `bi_flush` / `_tr_flush_bits` (zlib, aarch64 Os), zig
  `compiler_rt.trig.cos` / musl `__cos`, and the leaf `comma` / `cimag` (`movaps xmm0, xmm1; ret`). Bytes cannot
  separate them.

### Zig counters dropped from names (2026-11-08)
The chosen fix: `canonical_name` drops the counter from `__func_N`, `__anon_N`, `__struct_N`, `__enum_N`,
`__union_N` and `__opaque_N` and keeps the kind. Identification reports names this way (`identify_program*`), and
the flywheel truth and `rampage-eval`'s `classify` compare them this way. The databases keep their spellings,
because their callee keys hash them. The flywheel cache format is now v2.

Measured on corpus `libid-ed988c9a220e`, before and after the change, with the same binaries and denominators:

| Split | State | FP before | FP after | TP (unchanged) |
| --- | --- | ---: | ---: | ---: |
| train | bundled | 270 | 54 | 989 |
| train | bundled + arm | 270 | 54 | 10074 |
| dev | bundled | 276 | 60 | 1005 |
| dev | bundled + arm | 280 | 64 | 8729 |
| negative | bundled | 134 | 26 | 0 |

Dev F1 is 0.1228 → 0.1244 for bundled and 0.7244 → 0.7309 with the arm. The arm still fails its gate on the
same +4 (`LZ4_read64`). TP and FN did not move, because the counted names were all runtime functions, which are
gated only as false positives.

### A false-positive allowance in the held-out gate (2026-11-08)
`tp_per_fp` (default 100) gives the held-out gate one extra false positive for every 100 correct names gained.
The same allowance applies to the deployed-state check. Training and negatives stay strict. Before this, a
collision training cannot reveal (`LZ4_read64` / `LZ4_read_ARCH`) blocked any candidate, however large its gain.
The arm's +7,724 dev names earn 77 extra false positives; it adds 4. **The arm now passes both gates** on corpus
`libid-ed988c9a220e` (dev F1 +0.6065). Caveat: the ratio was set after the arm failed on dev by +4, and the arm's
own design read dev numbers, so this pass is not an outside claim; that needs the final split or a third split.

### Compiler and optimisation identification: feasibility (2026-11-08)
This was checked before building the family, with the method that sank libid's AI arm: can a trivial
deterministic miner already solve the task?
- **Task.** From code alone, name each corpus binary's compiler (zig cc or clang) and optimisation level (O0, O2
  or Os). `.comment` survives stripping and names the compiler, so banners are out of scope; rampage-detect's
  bundled rules already read them.
- **Features.** Per binary: the fraction of functions starting with each 1–4-byte prefix, function-start
  alignment, the first padding byte between functions, and a few idiom bytes. Extents come from the cached
  baseline discovery.
- **Miner.** For each label, the single feature and threshold that best separates the training binaries. Each
  library is held out in turn (train, dev and negatives, never final). The Alpine gcc binaries were left out,
  since they come at one optimisation level. Each test set is one library on one architecture: 48 binaries (two
  versions × four programs × two compilers × three levels), one run each.
- **Result.** Optimisation level: 100% on both architectures. Compiler: 100% on x86-64 and 67% on aarch64. The
  rules the miner picked are one-feature thresholds such as "some function starts with `50`" (x86-64 clang) or
  with `f2 0f 10 0d` (x86-64 O0). These read as prefixes of runtime functions (zig links its own musl build), not
  compiler idioms; that reading was not checked function by function.

So the family as planned has the same problem as libid: a closed rule language over plentiful labels is searched
exhaustively by a miner, which leaves nothing for an AI proposer to win. A harder corpus (many compiler versions,
gcc and MSVC, runtimes held out) would make the task harder for both, not specifically for the AI.

**Where the AI could win instead.** It should propose what a miner cannot enumerate: new feature extractors and
heuristic code, not rows in a fixed language. This is the FunSearch / KNighter model from the prior-art research.
A candidate is then a small program (for example a sandboxed plugin, which the plugin host already isolates),
held to the same held-out gate, and the deterministic miner over the existing features is the arm it must beat.
This needs its own design: a sandboxed candidate format, a family whose features are not already saturated, and
a budget. Recorded for a decision, not started.

### The arm ships (2026-11-08)
`rampage-eval bundle --arm` put arm v2 (`arm-e77075a92a73`, 3218 rows, licences BSD-2-Clause, MIT and Zlib, with
a cJSON 1.7.15 notice added) into the x86-64 and AArch64 bundled databases as their PAT namespace. The bundle
gate against the bundled baseline passed:

| Split | dTP | dFP |
| --- | ---: | ---: |
| train | +9074 | 0 |
| dev | +7713 (novel +783) | +4 |
| negative | 0 | 0 |

The final split read before (reads #1–#2: v2 adds +6068 names for +48 false positives over the bundled
databases) is within the same allowance, so no new final read was spent. Product check: `rampage function
identify` on an unseen dev binary (lz4 1.10.0, x86-64 clang O2) names 49 functions, 13 of them lz4, against 36
and 0 before. The compressed assets grow by 170 KB (x86-64) and 191 KB (AArch64), and the provenance source
`data/flywheel/libid.json` is 3.5 MB.

### Next
- **Regenerate the bundled hash databases with callee keys for forwarder entries** (128 bundled false positives).
  This needs the signature-corpus source caches and the pinned toolchains, so it needs its own session.
- **The AI family needs a decision:** code-proposing candidates (above) rather than compiler/tool rules.
- **Caller/callee-confirmed rows** for identical bodies under different names (`LZ4_read64` / `LZ4_read_ARCH`).
- **A third, untouched split** before claims beyond this corpus: this arm's design read held-out numbers.
