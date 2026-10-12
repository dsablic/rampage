# Flywheel Phase 1 — eval harness + disagreement set (execution plan)

> **For Claude:** execute task-by-task; each task is TDD (write the failing test, make it pass, commit). This is
> the executable breakdown of Phase 1 of `2026-10-12-heuristic-self-improvement-flywheel.md`.

**Goal:** A reproducible, offline, self-supervised evaluation of the *library-identification* heuristic family
that emits per-slice precision/recall and a machine-readable **disagreement set** -- the "measure" step the whole
flywheel is gated on. Library ID first because its ground truth is the cheapest (symbols).

**Architecture:** strip-and-compare self-supervision. Build a symbolized reference and a stripped twin from the
same source + toolchain; the reference's symbol table is ground truth. Build a signature DB from *other*
symbolized binaries, run `identify` on the stripped twin, and compare each proposed name to the twin's known
name. Output metrics + a disagreement set (address, proposed, truth, outcome).

**Tech:** Rust (new crate `rampage-eval`, binary + lib), existing `rampage-signatures` / `rampage-loaders`, `zig`
for the matched-pair corpus (already used by `tools/gen-signatures.sh`), `serde_json` for artifacts.

**Scope boundaries:** only the library-ID family; only x86_64 + aarch64 (the arches `gen-signatures.sh` already
builds); no proposer/promotion yet (Phases 2-4). Reference tools (Ghidra) are out of scope for Phase 1 -- symbols
are the oracle.

---

### Task 1: matched-pair corpus generator

**Files:** `tools/eval-corpus.sh` (new); reuse `tools/signatures-corpus.c`, `tools/signatures-target.c`.

- Build, per arch (`x86_64-linux-musl`, `aarch64-linux-musl`): a **symbolized** reference set (several small
  programs linking the same static libc, keeping symbols) and a **symbolized-then-recorded, stripped** target
  (`signatures-target.c`). Emit, into a scratch/output dir: `ref-<arch>/*.elf` (symbolized),
  `target-<arch>.elf` (stripped), and `truth-<arch>.json` = `{ "<hex addr>": "<name>" }` extracted from the
  **unstripped** twin of the target (the symbol table), filtered to function symbols with nonzero size.
- Deterministic and re-runnable; records the `zig version`. Do not commit the large binaries; commit only the
  script. (A tiny committed fixture pair for the test is Task 3.)

**Verify:** running the script produces the three artifacts per arch and `truth-*.json` is nonempty.

### Task 2: the eval library (metrics + disagreement set)

**Files:** `crates/rampage-eval/Cargo.toml` (new, `license = "Apache-2.0"`), `crates/rampage-eval/src/lib.rs`.

- `struct Truth(BTreeMap<u64, String>)` loaded from `truth-*.json`.
- `fn evaluate(db: &SignatureDb, target: &Binary, truth: &Truth) -> Report` where
  `Report { precision, recall, correct, wrong, missed, disagreements: Vec<Disagreement> }` and
  `Disagreement { address, proposed: Option<String>, truth: Option<String>, outcome }` with
  `outcome ∈ {Correct, Wrong, Missed, Spurious}`.
  - For each discovered function in `target`: get the proposed name from `db.identify(...)` (via the target's
    `Target`), and the true name from `truth` (if the address is a known library function).
  - `Correct` = proposed == truth; `Wrong` = proposed present but != truth; `Missed` = truth present, no
    proposal; `Spurious` = proposed present, address not in truth (a library name applied where there is none).
  - `precision = correct / (correct + wrong + spurious)`; `recall = correct / (correct + missed)`; guard /0.
- Serialize `Report` (serde) to JSON.

**Test (`crates/rampage-eval/tests/` or unit):** construct a synthetic `Truth`, a `SignatureDb` and a tiny
in-memory/binary target where the expected outcome of each category is known; assert the counts and that
precision/recall are computed correctly, including the /0 guards.

### Task 3: end-to-end eval against a committed matched-pair fixture

**Files:** commit one small matched pair under `tests/fixtures/bin/` -- `eval-ref-x86_64.elf` (symbolized
reference used to build the DB) and `eval-target-x86_64.elf` (stripped) -- plus `tests/fixtures/data/`
`eval-truth-x86_64.json`. Add their build lines to `tools/eval-corpus.sh` output selection. A new integration
test in `crates/rampage-eval/tests/`.

- Build a `SignatureDb` from the reference, `evaluate` against the stripped target + truth, and assert a
  **baseline**: `correct >= N` and `wrong == 0` and `spurious == 0` for some conservative committed `N` (the
  gate's floor; raise it only when a real improvement lands). Keep the fixture small.

**Verify:** `cargo test -p rampage-eval` green; the committed baseline holds.

### Task 4: CLI entry + JSON artifact

**Files:** `crates/rampage-eval/src/main.rs` (a `rampage-eval` binary) or a subcommand; wiring is the executor's
call. Reads a DB path, a target path and a truth path; prints the `Report` JSON and a one-line summary; exits
nonzero if `wrong > 0` or `spurious > 0` (the hard-failure conditions).

**Test:** a CLI test that runs it against the Task 3 fixture and checks the summary + exit code.

### Task 5: per-slice reporting + aarch64

- Extend the corpus/eval to tag each run with its arch slice and aggregate a `{slice -> Report}` map; add the
  aarch64 matched-pair fixture and assert its baseline too. This is the anti-corpus-bias hook: the gate reads
  per-slice, so a candidate that helps one slice and regresses another is visible.

**Verify:** both slices report; aggregate JSON emitted.

---

## Done = the disagreement set is real

At the end of Phase 1 there is: a reproducible matched-pair corpus, a `Report` with precision/recall per arch
slice, a machine-readable disagreement set, committed baselines that fail CI on `wrong`/`spurious`, and a
`rampage-eval` entry point. That is the **measure** and **gate** substrate. Phase 2 (the AI proposer) then
consumes the disagreement set to propose signature/heuristic edits, and a promoted edit is accepted only when it
raises `correct`/recall on a held-out slice without introducing `wrong`/`spurious` -- which this harness checks.

## Notes for the executor

- This is parallelizable as one agent owning `crates/rampage-eval` (+ `tools/eval-corpus.sh`), since it only
  depends on `rampage-signatures`/`rampage-loaders` and adds a new crate (auto-included by the `crates/*`
  workspace glob). It does not touch the in-flight `rampage-detect` / `rampage-yara` / capa work.
- Later phases generalize the same `Truth`/`Report` shape to other families: discovery recall (truth = symbol
  function starts), packer/compiler ID (truth = the known build toolchain), type recovery (truth = DWARF/PDB).
  Keep `Report`/`Disagreement` family-agnostic so the gate is one mechanism.
