# The flywheel fast loop

The flywheel lets an AI agent improve rampage's heuristics through rampage's own MCP server, with a gate on
held-out ground truth. Milestone 1 covers library identification (libid) signatures. The design is in
[the fast-loop plan](plans/2026-11-05-flywheel-fast-loop.md); the guardrails are in
[the flywheel strategy](plans/2026-10-12-heuristic-self-improvement-flywheel.md).

Everything the loop writes lives under `target/flywheel/`:

| Path | What it holds |
|---|---|
| `sources/` | Downloaded source archives, checked against their pinned SHA-256 |
| `corpus/<version>/` | The built corpus: `bin/` (stripped binaries and symbolized twins), `obj/`, `lib/`, `manifest.json` |
| `cache/` | Truth by binary hash; baseline analysis by (binary hash, bundled-database hash, rampage build id) |
| `scratch/libid/<id>/` | Candidates, each a data pack with a `candidate.json` |
| `evaluations/libid/` | Gate results by (candidate hash, corpus version, baseline hash) |
| `promoted/libid/` | The promoted pack (`rampage-pack.toml`, `sigs/`) and `entries.json` with provenance |
| `observations/` | `report_observation`'s store |
| `runs/<label>/` | Run reports (`report.json`, `report.md`) and each round's transcript, prompt and server events |

Nothing under `target/` is committed. The repository holds only the recipe (`tools/flywheel/corpus.json`), the
driver programs (`tools/flywheel/drivers/`) and the build script.

## Build the corpus

```sh
cargo build --release -p rampage-eval -p rampage-cli
tools/flywheel/build-corpus.sh --jobs 3
```

The script downloads zlib 1.3.1, LZ4 1.10.0 and cJSON 1.7.18 and checks each archive against its pinned SHA-256.
It compiles each library for x86-64 and AArch64 Linux (ELF, static musl) at O1, O2 and Os, with two compilers:
`zig cc`, and Homebrew clang 23 against Zig's musl headers. Four owned driver programs per library are linked
against each build. That makes 144 stripped binaries, each with a symbolized twin of the same linked image.

The corpus version is `libid-` plus a hash of the script, the recipe, the drivers and the toolchain versions. The
same inputs always give the same version. The script prints the version and refuses to overwrite a finished
build. Pass `--clang` to use a different clang and `--source-cache` to reuse downloaded archives.

**Truth.** Every function symbol of the twin except the driver's own functions (from its object) is a truth
function. Each truth function is tagged with its library, or `runtime` (musl, compiler runtime) when the library's
objects do not define it. Every truth function's bytes are checked to be identical in the stripped binary.

**Split.** The corpus is split by program. Within each library, programs are ordered by SHA-256 of the corpus
version and program name, and the first quarter (at least one) is held out. All binaries of a held-out program are
held out, so none of its own functions are ever seen in training. A new corpus version rotates the split. The
fast slice is the first training program of each library: 36 binaries.

**Slices.** Every metric is reported overall (`all`), per `arch`, `compiler`, `opt` and `library`, and per
`cell` (all four together).

## Measure

```sh
rampage-eval flywheel-eval --corpus target/flywheel/corpus/<version> --split heldout
rampage-eval flywheel-eval --corpus target/flywheel/corpus/<version> --split train \
    --pack target/flywheel/promoted/libid
```

Without `--pack`, the command measures the bundled baseline. With one or more packs it measures them layered over
the bundled databases (the first pack wins) and reports deltas against the baseline. Each slice shows TP, FP and
FN, precision, recall and F1.

- A correct name is a true positive.
- A wrong name at a truth function counts as both a false positive and a false negative.
- A name where the truth has no library function (the program's own code) is a false positive.
- An unnamed truth function is a false negative.

Changed cases are listed for the training and fast splits only. Pass `--show-heldout-cases` to see them for the
held-out split; that flag is for the operator and never for a proposer.

The first evaluation of a corpus analyses every binary. Later ones reuse the caches and identify again only the
binaries a candidate's patterns could match.

## The gate

Gate settings come from a TOML file (`--gate`); keys it leaves out keep their defaults. The defaults are
conservative:

| Key | Default | Rule |
|---|---|---|
| `max_fast_fp_increase` | 0 | Fast gate: false positives on the fast slice may not rise. |
| `max_slice_f1_drop` | 0.0 | Both gates: no slice (dimension or cell) may lose F1. |
| `min_f1_gain` | 0.001 | Held-out gate: overall F1 must rise by at least this much, and by more than zero. |
| `max_fp_increase` | 0 | Held-out gate: false positives may not rise. |
| `max_heldout_evaluations` | 12 | Held-out evaluations one server runs (cached results excepted). |

A candidate is always evaluated merged with the rows already promoted, against the current promoted state, which
is exactly what promoting it would produce. A promotion changes the baseline hash, so earlier gate results stop
counting. The cap on held-out evaluations limits how much a proposer can learn about the held-out split from its
metrics.

## Run a loop

```sh
rampage-eval flywheel --family libid --corpus target/flywheel/corpus/<version> --rounds 4 --budget-usd 5
```

Each round is one agent session through `tools/agent-bench/claude-runner.py` (default model `claude-sonnet-5-5`;
`--runner` swaps it). The session sees only rampage's MCP server, started with `--corpus` and the `improve` group
enabled. Before the first round, the command warms the server's caches through one `corpus_failures` call.
Every round passes the remaining budget to the runner (`--max-budget-usd`), and no round starts with less than
`--min-round-usd` left. The next round's prompt summarizes the earlier rounds: candidates, gate verdicts and
promotions, never held-out cases.

## Read the report

`target/flywheel/runs/<label>/report.md` has a table of rounds with:

- wall time and time spent in tools;
- cost and number of calls;
- each candidate's fast and held-out verdicts, and its revert id if it was promoted.

It ends with the held-out metrics under the promoted pack against the bundled baseline. `report.json` holds the
same data plus tokens, per-tool call counts and times, and each candidate's gate checks and deltas. Each round's
`round-N/` directory keeps the prompt, the runner's normalized result, the private transcript and the server's
event log (`events.jsonl`: every proposal, evaluation and promotion).

## Use and revert a promotion

The promoted pack is an ordinary data pack:

```sh
rampage --pack target/flywheel/promoted/libid function identify stripped.elf
rampage-eval flywheel-revert rv-0123456789ab
```

Reverting removes the entry from `entries.json` and regenerates the pack. The promoted rows are then exactly
those of the remaining entries, so the metrics return to what they were before the promotion.

## Observations

`report_observation` records a typed observation (`function_start`, `function_name`, `library_function` or
`not_a_function`) with 1 to 8 evidence items. Records are appended to `observations/observations.jsonl` with the
binary's SHA-256. An ordinary session opts in with `rampage mcp --observations DIR` or `RAMPAGE_OBSERVATIONS`;
with `--corpus` the store is `target/flywheel/observations/`. The store is a directory of its own rather than the
binary's annotation sidecar, for two reasons. The sidecar is the analyst's record: every client replays it, under
its reader's limits. Observations are unreviewed labels, and the corpus must collect them across binaries.
Recording one changes nothing else. In M1 the corpus does not yet read them.
