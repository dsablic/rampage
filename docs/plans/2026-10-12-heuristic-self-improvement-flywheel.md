# Heuristic self-improvement flywheel

**Date:** 2026-10-12. **Status:** historical strategy / design; the evaluation substrate is implemented,
while the proposer and automated promotion loop remain proposed.

**Original status (2026-10-12):** proposal / design. Not started. This is the strategic plan, not a
task-by-task execution plan.

The motivation, phase order and competitive thesis below record the original proposal, not a verified
comparison with every heuristic used by IDA or Ghidra. "Mostly exists", "current" and roadmap references
describe the planning snapshot. The [Phase 1 execution plan](2026-10-12-flywheel-phase1-execution.md) records
the initial library-ID scope; the evaluator now also covers discovery, tool identification and type recovery.
A passing fixed-baseline gate is not evidence that an autonomous held-out promotion loop has shipped.
For current behavior and references, see the [README](../../README.md),
[measurement reference](../features.md#measurements-and-development) and [accuracy benchmarks](../benchmarks.md).

**Goal (one sentence):** A `propose -> measure -> gate -> promote` loop in which an AI proposes heuristic edits
from rampage's own failures against ground truth, an eval gate accepts only measured held-out improvements, and
accepted heuristics land in the versioned, user-extensible databases -- turning rampage's heuristic corpus into a
continuously and automatically improving asset.

## Why this is the highest-leverage bet

- The moat in reverse engineering is **heuristics**, not algorithms. The algorithms (discovery, SSA, value-set,
  jump-table recovery, FLIRT masking, type propagation, structuring) are public science. What makes IDA/Ghidra
  good is the tacit, corpus-tested heuristic tail accumulated over decades, which lives in test corpora and bug
  history, not in papers.
- **AI is uniquely strong at proposing heuristics from concrete failures** -- which is exactly the manual work
  the recent parallel waves did by hand (masking rules, RTTI scanners, capa rules, packer signatures). The loop
  automates the prompt.
- **Heuristics-as-data** (our bundled + user-supplied DB model) makes promotion and rollback trivial: a new
  heuristic is a row, versioned, diffable, revertible -- not baked into C++/Java like the incumbents'.
- It **compounds**: every binary analyzed can become evidence that sharpens the corpus. IDA/Ghidra cannot answer
  this easily because their heuristics are compiled in; ours are a living, AI-tended, confidence-tagged dataset.

This reframes the competitive position: scope is not the moat (most of it is mechanical, known breadth plus
human-analyst UX we deliberately skip); the moat is a self-sharpening heuristic corpus with calibrated
confidence.

## The loop

1. **Corpus with an oracle in.** A set of binaries for which we have ground truth or a usable reference signal.
2. **Run and diff.** Rampage runs discovery / signatures / detection / (optionally) decompilation and compares
   its output to the oracle, producing a **disagreement set**: functions missed (recall), rules that fired wrong
   (false positives), signatures that disagreed with reality, mis-identified packers/compilers.
3. **Propose.** The AI consumes the specific failing cases with their bytes and context and emits candidate
   heuristic edits in the existing DB formats (signature masking rules, capa rules, `rampage-detect`
   signatures, discovery seeds, prototype/type hints).
4. **Gate.** A candidate is accepted only if it improves the target metric on a **held-out** split without
   regressing other slices. Provenance (which cases drove it, which metric moved) is recorded.
5. **Promote.** Accepted heuristics are written into the versioned DBs. No rebuild; auditable; revertible.

The AI is the **proposer**; the corpus + metrics are the **judge**; the versioned DB is the **memory**. There is
no gradient training -- this is generate/measure/gate/promote, which is why it is buildable and honest rather
than a black box.

## Ground truth is the bottleneck, not the model

Where the flywheel spins is entirely determined by how cheaply we can get a correct answer to compare against.

- **Self-supervision via symbols (cheapest, scalable).** Take any binary that *has* symbols/debug info, strip
  it, run rampage, compare recovered-vs-known. Generatable at industrial scale from any build system with no
  labeling. Already underpins the bundled FLIRT databases (built from symbolized references) and the cross-build
  `add` identification test. This covers the whole **accuracy** family -- discovery recall, library ID,
  compiler/ABI idioms, type recovery -- which is most of the value.
- **Controlled-toolchain builds (perfect labels).** We own the compiler, so packer/compiler/linker
  identification has exact ground truth: build with a known toolchain/packer, verify rampage names it.
- **Cross-tool reference (noisy oracle).** A separately installed Ghidra headless analyzer can provide a
  CFG/type/switch reference for discovery and structuring. Rampage embeds Ghidra's decompiler, but that does
  not provide a headless reference installation or an independent oracle. Reference output is not ground
  truth; treat disagreements as candidates to investigate, not as automatic labels.
- **Labeled corpora (expensive, slow).** Malicious-intent and family-attribution heuristics need curated
  benign/malware labels, which are scarce and legally fraught. This family improves slowly and conservatively.

Fastest-spinning families first: library identification, discovery precision/recall, packer/compiler ID, then
type/signature recovery, then capa behaviors, with malicious-intent last and most cautious.

## Guardrails (non-negotiable)

- **The gate is the boss, not the AI.** Auto-accepting generated rules poisons the DB. Accept only on measured,
  held-out improvement.
- **Monotonic ratchet with provenance.** Every promoted heuristic records what drove it and what moved, so any
  regression traces to the rule that caused it and reverts cleanly.
- **Slice against corpus bias.** A corpus that is all x86/GCC/Linux breeds heuristics that overfit it and
  silently regress ARM/MSVC. Metrics are sliced per arch/compiler/optimization/ABI; a candidate that helps one
  slice and hurts another is rejected or scoped.
- **Keep the honesty contract.** Promoted heuristics carry calibrated confidence; the loop never converts a
  probabilistic heuristic into an unqualified claim. Never ship an ungated heuristic.

## Phases

These are the original phases and planning-time substrate assessment. Phase 1's measurement and regression-gate
substrate has since been implemented; Phases 2-4 still describe the intended proposer/promotion workflow rather
than current automation.

- **Phase 0 - substrate (mostly exists).** Heuristics-as-data DBs (signatures/capabilities/detect/yara; done or
  in progress). Partial strip-and-compare generation (`tools/gen-signatures.sh`, the FLIRT-from-symbols path).
  Partial benchmark harness (discovery precision/recall vs a separately installed Ghidra; the versioned
  corpus-runner items already on the todo).
- **Phase 1 - eval harness + disagreement set.** A reproducible corpus from controlled compilers; per-family
  metrics; a held-out split; per-slice reporting; a stable, machine-readable **disagreement set** artifact.
  Deterministic, offline, CI-gateable. (Extends the "versioned differential benchmark / accuracy corpus / CI
  gates" todo items rather than inventing new infrastructure.)
- **Phase 2 - proposer, human-in-the-loop.** Given the disagreement set, an agent proposes heuristic edits; the
  Phase 1 gate decides accept/reject. This is the current parallel-wave workflow, formalized and measured.
- **Phase 3 - automation.** A workflow runs the loop headless -- generate corpus, measure, propose, gate -- with
  human approval only at promotion.
- **Phase 4 - continuous.** Scheduled runs over an expanding corpus; the DBs grow; regressions are caught by the
  gate; provenance is inspectable.

## Build vs reuse

Reuse what is already planned or built: the accuracy-corpus/CI-gate todo items are the judge; strip-and-compare
already exists in part (FLIRT generation, the `add` cross-build test); the Ghidra comparison harness is the
CFG/type oracle. The new work is (a) a per-family metric + held-out eval harness that emits a disagreement set,
(b) a promotion gate with provenance, and (c) the generation step that turns disagreements into candidate DB
edits. The flywheel is an assembly of pieces already on the roadmap plus a generation-and-gate layer, not a new
moonshot.

## Risks and honest limits

- **Oracle availability bounds the whole thing.** Families without cheap ground truth (malicious intent) improve
  slowly; do not promise a self-learning malware detector.
- **Corpus bias / overfitting to controlled compilers.** Mitigated by per-slice metrics and held-out splits, but
  real -- the corpus must deliberately span arch/compiler/optimization/ABI.
- **Reference tools are not ground truth.** Ghidra disagreements are leads, not labels.
- **Compute cost** of large corpora and repeated full runs; keep runs bounded and incremental.
- **This is corpus curation, not model finetuning.** The improving asset is the DB, not the model; framing it as
  autonomous learning would overclaim.

## One-line pitch

An engine whose heuristic corpus is continuously sharpened by AI against cheap self-supervised ground truth,
gated by held-out metrics, and stored as versioned, confidence-tagged data -- a moat the incumbents' compiled-in
heuristics cannot match.
