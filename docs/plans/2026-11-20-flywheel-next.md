# Flywheel: how to proceed (2026-11-20)

Status: decided 2026-11-20 (the maintainer delegated the three choices; they are recorded at the end), not
started. It replaces the open decision in
[the code-candidates proposal](2026-11-08-flywheel-code-candidates.md) and builds on the record in
[the fast-loop plan](2026-11-05-flywheel-fast-loop.md).

## What the record shows

1. **An AI proposing rows has not beaten a generator, twice.** For library identification the deterministic arm
   took the recognisable gain, and gated against it the agent promoted nothing in six rounds. For compiler and
   optimisation identification a one-feature miner reached 100% on optimisation level and on the x86-64 compiler
   before the family was built. Both are closed rule languages over plentiful labels, which a miner searches
   exhaustively.
2. **Every gain that shipped was code, and an agent wrote it.** Operand wildcarding and call-graph propagation
   (+5285 correct names on the final split, inside the allowance) were designed, diagnosed and implemented in
   agent sessions, against the same splits and gate, with a person approving the order of work. So "an AI proposes
   heuristic code that passes the held-out gate" has already happened. What has not happened is that loop running
   unattended, and nothing in the product makes it repeatable.
3. **The corpus was the binding constraint each time.** The first acceptance measured same-build memorisation; the
   first dev split did not reproduce the final split's errors; a larger corpus with more versions and libraries
   fixed both and let the call graph pass. The strategy document said it at the start: ground truth is the
   bottleneck, not the model.
4. **Nothing yet learns from real use.** `report_observation` writes a store the corpus never reads. The five
   firmware agent runs each produced a gap list that was turned into fixes by hand, and that has been the most
   productive loop in the project.

## Conclusion

The flywheel is three loops, and they are in different states:

| Loop | What turns | State |
| --- | --- | --- |
| Data | corpus → deterministic arms → gate → bundled databases | Works and ships. Limited by corpus breadth. |
| Code | an agent writes a matcher or heuristic → gate → merge | Works when supervised. Not automated. |
| Usage | agent runs → failure patterns → fixes → rerun | Works by hand. Not tooled. |

Row proposals by an AI are closed for families a generator can enumerate. The `improve` group, the gate, the
ledgered final split, `.rpack` and `bundle` stay: they are the judge and the delivery path for all three loops.

The bet itself still stands, in a narrower form: the moat is a gate with honest held-out truth plus an agent that
writes heuristics against it faster than a compiled-in tool can be revised. The work below automates the loop that
has actually produced gains, and grows the truth it is judged on.

## Steps

### 1. Close out row proposals (small)

Say in [flywheel.md](../flywheel.md) and the README that row proposals are infrastructure with a measured null
result, not the mechanism. No further unattended row runs on libid or tool identification.

### 2. Measure where code can win before building anything (small)

The method that sank two families applies to the third: check the headroom first. Against the databases as bundled
today (arm, zstd and Lua rows, call graph), classify what is still missed, for these candidate families:

| Family | Known figure | Why it might suit code |
| --- | --- | --- |
| Library identification, novel functions | Residue after fuzzy on the older corpus: about 2000 without a descriptor, 1149 of them 1–3 instructions; about 370 wrong top name | Length-changed bodies need structure, not bytes. Much of the residue may be unidentifiable. |
| Embedded library identification | Held-out GCC 14.3 firmware: 51% (M4F) and 31% (M0) recall at 100% precision | Large gap; the arms and call graph have never been gated on firmware. Likely deterministic first. |
| Parameter type classes | 224 correct, 108 wrong (precision and recall 0.65) against DWARF | Large gap, truth is cheap, and the heuristics are code with an open design space. |

For each: how many misses are reachable in principle, and what a trivial deterministic baseline already gets.
The family with the most reachable headroom that a miner does not take becomes the first target of step 3. If
none has any, step 3 stops there and that is recorded.

### 3. The code loop, unattended, as a source change (medium)

The cheapest form of "candidates that are code" is the one that already worked: an agent editing rampage's own
source, judged by the gate. Build the harness for that before any new candidate format.

- **Workspace.** A git worktree with a private target directory. The agent may change only a listed set of paths
  for the family (for libid: the matcher modules of `rampage-signatures` and their tests). A change outside them
  fails the run.
- **What the agent sees.** Training binaries and truth, and the gate's verdicts. The dev split answers as the
  corpus server does today: verdict and overall delta only. The final split is not readable from the session at
  all; its files live outside every directory the session may read.
- **Gate.** Build, the crate's tests, then the existing rules: training leaving one build out, dev with the
  allowance, negatives at zero, no slice regression, a time bound per binary. A pass earns one ledgered final
  read. A final pass produces a branch and a report for review; nothing merges unattended.
- **Baseline.** The bundled databases as shipped. Fuzzy at 0.95/0.05 is reported beside it, since it is the best
  matcher that failed final.
- **Runner and budget.** `tools/agent-bench/claude-runner.py`, `claude-sonnet-5-5`, $5 per family per run, as now.
- **Acceptance.** One unattended run yields a branch that passes the final read on the family chosen in step 2.
  Three runs without one is a recorded null result, and step 4 below is dropped with it.

This departs from one requirement of the fast-loop design: a promoted source change needs a rebuild and ships in
a release, not in a pack. Rows and call-graph data stay rebuild-free. The trade is deliberate: it tests the bet
for the cost of a harness, where the pack route needs a new candidate format, a sandboxed compiler and a new pack
kind before the first measurement.

### 4. Code in packs (deferred, conditional)

Steps 2–4 of the code-candidates proposal: the `flywheel-matcher` component world, `propose_matcher`, sandboxed
builds, components as a pack content kind. Build it only when both hold:

- step 3 has produced at least two promoted heuristics whose logic fits the matcher interface (per-function
  inputs, a read-only training index, names out);
- someone needs heuristics delivered without a rebuild, such as a user improving an installed release.

### 5. Grow the data loop (medium, repeatable)

This is the loop that ships, and it closes the signature-recall gap against IDA's FLIRT coverage directly.

- **Firmware through the arms.** Gate operand wildcarding and the call graph on the embedded set (newlib,
  FreeRTOS, HAL) with older GCC releases added, against the 51% and 31% recall.
- **Windows corpus** (the proposed track in todo.md): clang-cl builds against the MSVC CRT through `xwin`, truth
  from PDBs.
- **A demand signal from use.** List the libraries real sessions meet and cannot name: a binary whose strings or
  version banners name a library while `identify_functions` names few of its functions. Record that as a local,
  opt-in observation. An agent then drafts the recipe entry (pinned source, checksum, build matrix), a person
  approves the licence and the pin, and the existing build, arm, gate and bundle steps do the rest. Writing
  recipes is open-ended work a generator cannot do, and it attacks the measured bottleneck.
- **Debts from the fast-loop plan:** regenerate the bundled hash databases with callee keys for forwarders (128
  false positives), a generator rule for rows matching another library's body, and a third untouched split before
  any claim beyond this corpus.

### 6. Tool the usage loop (small)

`rampage-eval mine-transcripts`, as designed in the fast-loop plan and never built: cluster tool errors, retries
and wasted calls from benchmark and agent-run transcripts into a bounded report. Proposals are code and keep human
review; the check is a rerun of the affected tasks on Haiku. This formalises what the firmware runs did by hand.

## Order

1, then 2, then 3 if step 2 finds headroom. Step 5's firmware slice comes next whatever step 3 shows, then step 6.
Step 4 waits for its conditions. One track at a time, each reviewed before merge.

## Decisions (2026-11-20)

Chosen for the goal of matching or improving on IDA through an agent, with the UI aside:

1. **Code heuristics are delivered as source changes; code in packs is deferred.** The goal is better analysis,
   and every shipped gain came this way. Rebuild-free delivery is a convenience for users who do not exist yet,
   and it would cost a new candidate format before the first measurement. Rows and call-graph data stay
   rebuild-free.
2. **Step 2's measurement picks the first family.** Naming one in advance is how two families were built before
   their headroom was checked.
3. **Firmware first for corpus growth, then Windows.** The arms and the gate exist, the recall gap is measured
   (51% and 31%), and no licence step is needed. Windows matters more against IDA, whose FLIRT coverage is
   strongest on MSVC runtimes, so it follows directly; it waits only because `xwin` needs the maintainer to accept
   Microsoft's licence terms.
