# Flywheel: candidates that are code (proposal, 2026-11-08)

Status: proposal, not started. Needs a go-ahead.

## Why

So far the AI proposer has made no promotion that a deterministic generator could not also make:

- **Library identification.** The deterministic arm (exact rows, then operand wildcarding) captures the
  recognisable gain. The arm now ships in the bundled databases.
- **Compiler and optimisation identification.** A one-feature threshold miner reaches 100% on optimisation level
  and on x86-64 compiler (see the fast-loop plan).

Both are closed rule languages over plentiful labels, and a miner searches such a language exhaustively.
The AI's advantage is proposing what a miner cannot enumerate: new features, new matching procedures, new
heuristics. FunSearch and KNighter (from the prior-art research) work this way. The candidate is a small
program, and a fixed evaluator gates it.

## Where the headroom is

The measured headroom that byte patterns cannot reach is the largest one left in library identification. On the
dev split, the arm names 1028 of 5051 novel library functions. An earlier reach analysis on this corpus, before
the Alpine cells were added, counted 4596 novel functions:
- only 1586 of them had a training body of the same length, which is all a PAT row can reach;
- the rest changed length between versions: inserted code, inlining changes, changed constants.

A matcher that tolerates length changes (structural or CFG similarity, instruction n-grams, call-graph context)
can reach them. The repository already has fuzzy signatures (`fuzzy_signatures.rs`, `rampage_signatures::fuzzy`),
and they are the deterministic baseline to measure first.

## Proposal

1. **Arm 3: measure the existing fuzzy matcher on the dev split.** Use the same corpus and gate, against bundled
   + arm v2. If fuzzy matching closes most of the novel gap, it becomes the next deterministic arm and the AI
   question moves again. Small: a day or less.
2. **A code-candidate interface.** A WIT world `flywheel-matcher` for the component host the triage plugin uses
   (import-free ABI, supervised worker, bounded admission). The host gives the candidate:
   - each unnamed function's bytes and masked bytes;
   - its discovered extent and its callees' names so far;
   - a read-only training index: bodies, names and features, built by the host.

   The candidate returns zero or one name per function. It cannot do I/O and cannot see held-out truth. Its
   only output is names, scored by the existing gate.
3. **Proposer tools.** `propose_matcher` takes Rust source for the component. The server compiles it with a
   pinned toolchain into a sandboxed build directory, without network, and stores it as a candidate. Evaluation,
   held-out budget, promotion and revert work as for rows. A promoted matcher ships as a component in a pack
   (a new pack content kind), off by default until the user selects it, as with `triage-report`.
4. **Gate additions for code.** These apply on top of the existing gate:
   - a deterministic-output check (two runs, same names);
   - a wall-time and memory budget per binary;
   - a size limit;
   - the fuzzy arm from step 1 as the baseline the candidate must beat.

## Risks and costs

- **Compiling AI-written Rust** on the operator's machine is the main new risk. The worker sandbox bounds what the
  component can do at run time, but not what the build does. The build must run in a disposable environment
  (container or VM) with no network and no access outside its directory; build scripts and proc macros are
  disallowed.
- **Overfitting.** A program can memorise training names as easily as a row can. The held-out gate already
  prevents that from counting, and the final split stays the claim check.
- **Cost.** Each candidate needs a compile (seconds) and a corpus pass in the worker (minutes). The $5 per family
  per run budget still applies.

## Decision needed

- Whether to run step 1 now. It is cheap and informative either way.
- Whether to build steps 2–4. This is the first family where the AI's output is code, which is the actual test
  of the flywheel idea.
