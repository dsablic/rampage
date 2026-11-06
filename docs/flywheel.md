# The flywheel fast loop

The flywheel lets an AI agent improve rampage's heuristics through rampage's own MCP server, gated on held-out
ground truth. Milestone 1 covers library-identification (libid) signatures. The design is in
[the fast-loop plan](plans/2026-11-05-flywheel-fast-loop.md); the guardrails are in
[the flywheel strategy](plans/2026-10-12-heuristic-self-improvement-flywheel.md).

Everything the loop writes lives under `target/flywheel/`:

| Path | What it holds |
|---|---|
| `sources/` | Downloaded source archives, checked against their pinned SHA-256 |
| `corpus/<version>/` | The built corpus: `bin/` (stripped binaries and symbolized twins), `obj/`, `lib/`, `manifest.json` |
| `cache/` | Truth by file hashes; baseline analysis by (binary hash, bundled-database hash, rampage build id) |
| `scratch/libid/<id>/` | Candidates, each a data pack with a `candidate.json` |
| `evaluations/libid/<corpus key>/` | Gate results by (candidate hash, corpus identity, baseline hash), and the held-out budget |
| `promoted/libid/` | The promoted pack (`rampage-pack.toml`, `sigs/`) and `entries.json` with provenance |
| `runs/<label>/` | Run reports (`report.json`, `report.md`), and each round's transcript, prompt and server events |

Nothing under `target/` is committed. The repository holds the recipe (`tools/flywheel/corpus.json`), the driver
programs (`tools/flywheel/drivers/`), the build script and a reference build's digests
(`tools/flywheel/expected-digests.json`).

## Build the corpus

```sh
cargo build --release -p rampage-eval -p rampage-cli
tools/flywheel/build-corpus.sh --jobs 3
```

The script downloads every pinned archive and checks its SHA-256. It builds three groups of binaries:

- **Targets, two versions each.** zlib 1.2.13/1.3.1, LZ4 1.9.4/1.10.0 and cJSON 1.7.15/1.7.18. The older
  versions are for training; the current versions are held out.
- **Negatives.** inih r58, tinyexpr 1.1.1 and two owned programs that link no library.
- **Configurations.** Each is built for x86-64 and AArch64 Linux (ELF, static musl) at O0, O2 and Os, with two
  compilers: `zig cc`, and Homebrew clang 23 against Zig's musl headers. O1 is left out because zig's O1 and O2
  produce byte-identical binaries.

Owned driver programs link each build: four per target library, two per negative. The result is 360 stripped
binaries (144 training, 144 held-out, 72 negative), each with a symbolized twin of the same linked image.

The corpus version is `libid-` plus a hash of the script, the recipe, the drivers and the toolchain versions
(zig, clang, ld.lld). Every build compares the binaries with `expected-digests.json` and reports any that differ;
`--record-digests` rewrites that file.

**Truth.** Every function symbol of the twin is a truth function, except the driver's own functions (from its
object). Each is tagged with its library, or `runtime` (musl, compiler runtime) when the library's objects do
not define it. Every truth function's bytes are checked to be identical in the stripped binary.

**Split: hold out what is measured.** The split holds out library versions:

- Every training binary links a target library's older version; every held-out binary links its current one.
- A held-out gain needs a signature that carries across versions, and recognising the training build again earns
  nothing.
- Negatives link no target library, so any target name there is false.
- The fast slice is one training program per library.

When a server opens a corpus it measures how many held-out library bodies (masked, as a signature sees them) also
occur in training. Above the recipe's `max_heldout_overlap` (50%) it warns loudly: on stderr, in
`corpus_failures` and in the run report. Above `refuse_heldout_overlap` (95%) it refuses the corpus, because the
held-out split would be the training build again. On `libid-738deabb4598` the share is 73.2%: most functions are
unchanged between these library versions. Reports therefore split held-out gains into bodies training already held
and novel bodies.

The split rule for other families follows the same principle: hold out the thing the heuristic must generalise
over, never a unit that shares the measured code with training.

| Family | Hold out |
|---|---|
| libid | Library versions (or whole configurations) |
| Tool ID | Whole tools and packers |
| Function-start discovery | Compilers or architectures |

Never split per program when programs share the measured code; the first M1 corpus did, and 98% of its held-out
functions were in training under the same name and configuration.

**What is scored.** The gated slices score the target libraries' own functions, plus every false name: a wrong
name on a runtime function, or a name where the truth has none. Runtime functions are the same build in every
program, so naming them is not counted as a gain.

| Slice | Gated | Contents |
|---|---|---|
| `all` | yes | The gated scope over the whole split |
| `arch:` | yes | Per architecture |
| `compiler:` | yes | Per compiler |
| `opt:` | yes | Per optimisation level |
| `program_library:` | yes | Per library the program links |
| `cell:` | yes | All four together |
| `origin:<library>`, `origin:runtime`, `origin:none` | no | Every outcome, by where the function comes from (`none`: the truth has no function) |

## Measure

```sh
rampage-eval flywheel-eval --corpus target/flywheel/corpus/<version> --split heldout
rampage-eval flywheel-eval --corpus target/flywheel/corpus/<version> --split negative \
    --pack target/flywheel/promoted/libid
```

`--split` is `train`, `heldout`, `fast` or `negative`. Without `--pack`, the command measures the bundled baseline.
With one or more packs it layers them over the bundled databases (the first pack wins) and reports deltas
against the baseline. Each slice shows TP, FP and FN, precision, recall and F1.

- A correct name is a true positive.
- A wrong name at a truth function counts as both a false positive and a false negative.
- A name where the truth has no function is a false positive.
- An unnamed truth function is a false negative.

The training and held-out runs also print the overlap check. Changed cases are listed except for the held-out
split, which never keeps any.

## The gate

Gate settings come from a TOML file (`--gate`); keys it leaves out keep their defaults. The defaults are
conservative:

| Key | Default | Rule |
|---|---|---|
| `min_pattern_bytes` | 32 | No row shorter than this: short bodies (accessors, thunks) collide with unrelated code. |
| `max_train_fp_increase` | 0 | Fast gate: false positives on the full training split may not rise. |
| `max_negative_matches` | 0 | Fast gate: the candidate may give no name at all on the negative binaries. |
| `max_slice_f1_drop` | 0.0 | No gated slice (dimension or cell) may lose F1, on the fast slice, the training split or the held-out split. |
| `min_f1_gain` | 0.001 | Held-out gate: gated F1 must rise by at least this much, and by more than zero. |
| `max_fp_increase` | 0 | Held-out gate: false positives may not rise. |
| `max_heldout_evaluations` | 20 | Held-out evaluations per corpus, counted across every server and run (cached results excepted). |

A candidate is always evaluated merged with the rows already promoted, against the current promoted state, which
is exactly what promoting it would produce. A promotion changes the baseline hash, so earlier gate results stop
counting.

The held-out stage returns only the verdict and the gated overall delta. Per-slice deltas, or counts of fixed and
broken functions, would tell a proposer which held-out code its rows touch.

## Run a loop

```sh
rampage-eval flywheel --family libid --corpus target/flywheel/corpus/<version> --rounds 4 --budget-usd 5
```

Each round is one agent session through `tools/agent-bench/claude-runner.py` (default model `claude-sonnet-5-5`;
`--runner` swaps it). The session sees only rampage's MCP server, started with `--corpus`. A corpus server serves
`enable_tools` and the improve group, and nothing else:

- no analysis tool;
- no other group can be enabled;
- every tool argument naming a file under the corpus or the flywheel directory is refused.

Before the first round, the command warms the server's caches through one `corpus_failures` call. Every round gets
the remaining budget (`--max-budget-usd`), and no round starts with less than `--min-round-usd` left. The next
round's prompt carries only the earlier rounds' candidates and gate verdicts.

A round that does not end `ok` stops the run and reverts that round's promotions. Failing the runner's isolation
check counts as not ending `ok`.

## Read the report

`target/flywheel/runs/<label>/report.md` opens with the overlap check, then has a table of rounds:

- wall time and time spent in tools;
- cost and number of calls;
- each candidate's fast and held-out verdicts, and its revert id if it was promoted.

It ends with the held-out metrics under the promoted pack against the bundled baseline, gated and by origin.
`report.json` holds the same data plus tokens, per-tool calls and times, and each candidate's gate checks.
Each round's `round-N/` directory keeps:

- the prompt;
- the runner's normalized result;
- the private transcript;
- the server's event log (`events.jsonl`).

## Use and revert a promotion

The promoted pack is an ordinary data pack:

```sh
rampage --pack target/flywheel/promoted/libid function identify stripped.elf
rampage-eval flywheel-revert rv-0123456789ab
```

Reverts go latest first. A later promotion was gated against the state that included the earlier ones, so a
revert out of order is refused and names what to revert first. A revert removes the entry from `entries.json` and
regenerates the pack, which restores exactly the state before that promotion.

Writers hold a file lock, and `entries.json` is written last. A pack that does not match `entries.json` is
regenerated from it when a server opens the corpus.

## Observations

`report_observation` records a typed observation (`function_start`, `function_name`, `library_function` or
`not_a_function`) with 1 to 8 evidence items. Records are appended to `observations.jsonl` with the binary's
SHA-256; binaries over 256 MiB are refused.

It is served only in ordinary sessions, which opt in with `rampage mcp --observations DIR` or
`RAMPAGE_OBSERVATIONS`; a corpus server does not serve it. A store inside a flywheel directory refuses files from
that directory.

The store is a directory of its own rather than the binary's annotation sidecar, for two reasons. The sidecar is
the analyst's record: every client replays it, under its reader's limits. Observations are unreviewed labels, and
the corpus must collect them across binaries. Recording one changes nothing else. In M1 the corpus does not yet
read them.
