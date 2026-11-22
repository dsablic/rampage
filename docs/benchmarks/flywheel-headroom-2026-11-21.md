# Flywheel headroom: where code can still win (2026-11-21)

Part of the [accuracy benchmarks](../benchmarks.md). This is step 2 of
[how to proceed with the flywheel](../plans/2026-11-20-flywheel-next.md): before building the unattended code
loop, measure, for three candidate families, how much of what rampage still gets wrong is reachable in principle,
and how much of that a trivial deterministic baseline or a one-feature miner already takes. The plan's rule: the
family with the most reachable headroom that a miner does not take becomes step 3's first target; if none has
any, step 3 stops.

Everything here is deterministic and local. No agent ran. The libid final split was not read: its ledger still
holds two reads, the last on 2026-11-09. Measured on 1.10.0 (`c911c27`) with the bundled databases it ships.

## Result

| Family | Scored items | Missed or wrong | Unreachable | Reachable | Taken by a baseline or miner | Reachable, not taken |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| (a) Library identification, libid dev split | 106,368 functions | 37,840 | 6,687 missed + 408 wrong | 30,353 missed | 9,856 (3,692 by the arm and fuzzy alone) | **20,497** (19% of functions) |
| (b) Embedded library identification, held-out GCC 14.3 firmware | 385 functions | 233 | 52 | 181 | 57, plus about 28 a Thumb operand-wildcard arm would likely take | **about 96** (25%) |
| (c) Parameter type classes, real-code dev set | 3,221 positions | 1,771 | 27 | 1,744 | up to 967 (the best miner nets +433) | **about 777** (24% of positions) |

**Recommendation: (a), library identification, becomes step 3's first target.** By share of scored items the three are
close (19%, about 25% and about 24%), so the rule cannot be applied by share alone. By size and by how firmly the
number stands, (a) leads:

- **It is the largest headroom by far:** 20,497 reachable functions on 504 dev binaries that no baseline takes
  (two thirds of everything reachable), 26,661 if only the arm and fuzzy count. Firmware has about 96 functions on two
  binaries; types about 777 positions on eight.
- **The classification is the firmest.** Unreachable is defined by the data (names absent from training, bodies
  shared without context), and only 18% of the libid misses are unreachable, so the plan's worry that "much of
  the residue may be unidentifiable" does not hold. For types, `ambiguous` is an upper bound; for firmware the
  set is the held-out gate itself.
- **What is left needs code.** Novel bodies where fuzzy's top candidate is often right but not separable by a
  threshold, two-instruction wrappers whose callee is named, and shared bodies with named neighbours: open design
  space, not a closed rule language a miner enumerates.
- **Step 3 can start now.** The corpus, the dev split with its allowance, the negatives and the ledgered final
  split exist, and step 3's harness is already specified around libid's matcher modules.

The other two are not dropped. Firmware's first gains are deterministic (the call graph alone adds 49 names at 100%
precision, a Thumb operand-wildcard arm is the next likely 28), so they belong to step 5's firmware slice, as the plan
already orders. Types is the strongest second candidate: the highest error rate (55% of positions wrong), cheap truth,
and its first +433 is a deterministic remap that should be done as ordinary work; it needs a corpus and gate (this set
is a seed) before an unattended loop can be judged on it.

## Method

**Baselines are the shipped state.** For libid, each dev binary's cached baseline is `identify_functions` with the
compiled-in databases of 1.10.0: the signature corpus with arm v2 and the zstd and Lua rows, then the bundled call
graph. For firmware it is `identify_functions` on the committed fixtures, which reproduces the published 81/158
(M4F) and 71/227 (M0) at 100% precision. For types it is the decompiler's recovered signature, as the `types`
eval family scores it.

**Reachable in principle.** A miss is unreachable when no heuristic working from this binary and this training
data could name or type it:

- *libid and firmware:* the function is not discovered; its name occurs in no training binary of that
  architecture (`absent`: API renames such as `compress2` → `compress2_z`, functions added in a later version);
  its masked body equals a training body carrying another name (`shared_body`) and nothing around it is named;
  or it has 1–3 instructions (`tiny`) and nothing around it is named. "Something around it is named" means a
  caller or a callee has a name from the baseline or the loader; with that context, a shared or tiny body is
  counted as reachable, because call-graph context can still tell it apart.
- *types:* the function was not decompiled; the parameter has no DWARF location, so the callee never reads it
  and holds no evidence of its type (`dead`). Everything else is reachable, split into `register_class` (the
  recovered class is in the wrong register file, float for integer or the reverse, or the position is missing),
  which the code always decides, and `ambiguous` (a narrow integer widened, pointer versus integer, struct
  pointer versus pointer, a small struct by value versus an integer), which the code decides only when the body
  uses the value in a telling way.

**Baselines and miners, scored on the reachable misses.**

- *libid:* the deterministic arm generated from this corpus's training split (exact rows and operand
  wildcarding), layered over the bundled databases; fuzzy matching at 0.95/0.05 (training-calibrated, the best
  matcher that failed final); fuzzy followed by call-graph propagation; and four one-feature miners. A miner
  learns, on the training split, every feature value whose occurrences all carry one name in at least two
  builds, and names an unnamed function with that value. Features: body length; the masked body (the arm without
  its length and collision guards); the sequence of named callees; the set of named callers.
- *firmware:* the training references of the embedded set (267 symbolized ELFs from the training toolchains;
  the held-out 14.3 references are not used) supply call-graph propagation with the shipped rule, fuzzy at
  0.95/0.05, and the same miners. Thumb has no operand-wildcard arm, so a shape proxy stands in for it: the best
  share of identical 16-bit units against a same-length reference body of the same name.
- *types:* one-feature miners learn, on training libraries, the majority DWARF class for each value of one feature
  of the decompiler's answer (its class; its raw spelling; its class at that position) and replace the answer on
  dev libraries.

**Reachable, not taken** is the reachable misses that no baseline or miner names correctly. It counts a miner as
taking a function even when the miner's precision would fail the gate, so it is a lower bound on what is left for
code. The libid row also gives the stricter figure, counting only the matchers built for the gate (arm, fuzzy).

## (a) Library identification on the libid corpus

Corpus `libid-00da6363626a` (1112 binaries: zlib, LZ4, cJSON, zstd, Lua; clang, zig and Alpine gcc; x86-64 and
AArch64; O0/O2/Os). Dev is its held-out split, 504 binaries; training is 248 binaries; the 72 negatives are
scored for false positives.

**Baseline on dev** (target-library functions only; runtime functions are not scored, as in the gate): 68,528
correct, 800 wrong, 37,040 missed (64.4% recall).

| Class of miss | Missed | Wrong name |
| --- | ---: | ---: |
| `absent`: name in no training binary of that architecture | 1,576 | 328 |
| `shared_body`, no named neighbour | 2,097 | 80 |
| `tiny` (1–3 instructions), no named neighbour | 3,014 | — |
| **Unreachable** | **6,687** | **408** |
| `shared_body` with a named neighbour | 3,373 | 247 |
| `tiny` with a named neighbour | 1,665 | — |
| other (discovered, trained name, own body) | 25,315 | 145 |
| **Reachable** | **30,353** | **392** |

No dev truth function was undiscovered. Per library, the reachable misses are zstd 12,823, zlib 6,635, LZ4 3,381,
cJSON 3,918 and Lua 3,596.

**What baselines take of the 30,353 reachable misses** (precision is over everything each one names on dev,
target-library functions only):

| Baseline | Reachable taken | Dev correct / wrong / spurious | Precision | Negatives (wrong + spurious) |
| --- | ---: | --- | ---: | ---: |
| Arm from this corpus's training | 614 | 614 / 27 / 0 | 95.8% | 0 |
| Fuzzy 0.95/0.05 | 2,775 | 2,775 / 8 / 3 | 99.6% | 0 |
| Fuzzy, then call-graph propagation | 3,116 | 3,174 / 23 / 3 | 99.2% | 0 |
| Miner: masked body | 3,179 | 3,179 / 37 / 9 | 98.6% | 10 |
| Miner: named-callee sequence | 2,393 | 2,393 / 228 / 0 | 91.3% | 0 |
| Miner: named callers | 1,782 | 1,782 / 257 / 52 | 85.2% | 0 |
| Miner: body length | 7 | 7 / 95 / 0 | 6.9% | 4 |
| **Any of them** | **9,856** | | | |
| The arm and fuzzy only (with propagation) | 3,692 | | | |

The gate's allowance is about one false positive per 100 added names, with none on negatives, so only fuzzy and
fuzzy + propagation are near gate quality, and fuzzy already failed the final split on two corpora. The body miner
is close (98.6%) but misnames negatives.

**What is left: 20,497 reachable misses no baseline takes** (26,661 if only the arm and fuzzy count):

| Kind | Count |
| --- | ---: |
| Novel body (training holds no equal masked body), fuzzy descriptor exists | 11,616 |
| Novel body, refused by fuzzy (12+ instructions, over bounds or too few constants) | 3,935 |
| Novel body, refused by fuzzy, under 12 instructions | 526 |
| `tiny` with a named neighbour (wrappers such as `cJSON_Print`, two instructions) | 1,190 |
| `shared_body` with a named neighbour | 2,336 |
| Body as trained (equal to one training body of the same name), refused by every rule | 894 |

In a sample of 400 untaken misses (from every seventh dev binary in corpus order, so mostly cJSON), more than half of
the `other` ones (147 of 267) have the right name as fuzzy's top candidate, below the 0.95 threshold; the information
is there, but no fixed threshold separates it from the false positives (lower thresholds failed the allowance in the
[fast-loop record](../plans/2026-11-05-flywheel-fast-loop.md)). That, plus wrappers and shared bodies that need their
neighbours, is heuristic code with an open design space, and the corpus, the gate and the ledgered final split for it
already exist.

## (b) Embedded library identification on the held-out firmware

The two committed fixtures built with Arm GNU Toolchain 14.3 (held out of training): Cortex-M4F at -Os and
Cortex-M0 at -O1, scored against their library truth (`tests/fixtures/data/eval-truth-embedded-*.json`).

| | M4F | M0 |
| --- | ---: | ---: |
| Library functions | 158 | 227 |
| Baseline correct (wrong or spurious: 0) | 81 | 71 |
| Missed | 77 | 156 |
| Undiscovered | 12 | 7 |
| `absent` | 0 | 0 |
| `shared_body`, no named neighbour | 1 | 18 |
| `tiny`, no named neighbour | 8 | 6 |
| **Unreachable** | **21** | **31** |
| **Reachable** | **56** | **125** |
| Call-graph propagation from the training references (all names, 0 wrong) | +16 | +33 |
| Miners (named callees, named callers; any) | 6 | 11 |
| Taken by any | 17 | 40 |
| **Reachable, not taken** | **39** | **85** |
| of which same length as a reference and ≥ 90% identical 16-bit units | 14 | 14 |
| of which same length and 75–90% identical | 5 | 8 |
| of which shorter or longer than every reference of that name | 9 | 41 |

- Every missed name exists in the training references: the misses are code a different GCC (or a different
  FreeRTOS configuration) generated differently, not missing libraries.
- **The call graph, never run on firmware, is the first deterministic step:** it lifts recall from 51.3% to
  61.4% (M4F) and from 31.3% to 45.8% (M0) with no wrong name. That is the firmware slice of the plan's step 5.
  *Shipped after this measurement:* the embedded call graph (`data/embedded-callgraph.json.gz`, built from the same
  training references) now runs in `identify_functions` on firmware. It leaves out the references' link stubs
  and weak override points (application hooks, the HAL's weak defaults, `__aeabi_idiv0`), which this measurement
  counted, so the product reaches 95 of 158 (60.1%) and 103 of 227 (45.4%), 0 wrong or spurious; see the
  [embedded firmware set](../signature-corpus.md#embedded-firmware-set). Run on that build, this example's
  baseline already includes those names.
- **Fuzzy matching cannot run on this firmware:** of about 120,000 reference functions none gets a descriptor
  (block bound 51,912; too few fixed constants or known calls 60,450; descriptor bounds 7,203; entry block 882).
- A quarter to a third of what is left (28 to 41 of 124) has the same length as a reference and differs only in
  scattered 16-bit units (mostly FreeRTOS functions whose structure offsets follow the configuration): an
  operand-wildcard arm for Thumb, a generator, is the natural tool for those. Subtracting the ≥ 90% cases leaves
  about 96 functions (83 if the 75–90% cases go too), on two binaries.
  *Shipped after this measurement (2026-11-22):* the embedded set's operand tier (hash scheme 4: Thumb load/store
  offsets and stack adjustments masked bit by bit, `data/embedded-thumb-operands.json.gz`, 1.25 MB) and a call graph
  that also trains on kernels with every application hook on. Gated on a new dev split (11 images from GCC 11.3,
  12.2, 13.2 and a training toolchain with other options, an owned program and kernel configuration; 3,562 library
  functions): 1,835 → 2,007 correct, false names 1 → 0, none added in training (each GCC release left out) or on
  negatives. On these fixtures, read once afterwards: 95 → 101 (63.9%) and 103 → 105 (46.3%), 0 wrong. The shape
  proxy above overestimated the reach: masking data immediates too failed the training gate, and most same-length
  misses here differ in more than offsets. See the
  [embedded firmware set](../signature-corpus.md#embedded-firmware-set).
- The miners are not gate quality here either: on M0 they also named 6 functions wrongly and 3 spuriously.

Two binaries are too few to choose a family by: they are the held-out gate itself, not a dev split (one was built
afterwards: `build.py dev`, see the signature corpus), and there is
no training-versus-dev structure on firmware to run an unattended loop against.

## (c) Parameter type classes against DWARF

Truth is DWARF (`rampage-eval type-truth`), scored per declared parameter position by class, as the `types` eval
family does. Two sets:

- **The committed probe fixtures** (`eval-types-{x86_64,aarch64}.elf`, 39 functions each, one synthetic source):
  85 of 138 positions correct today, 39 `ambiguous`, 11 `register_class`, 3 `dead`. The two slices reproduce the
  matching phase-0 slices exactly (x86-64 zig O2: 43 correct and 26 not; AArch64 zig O2: 42 and 27). They are a
  probe, not a dev set: 39 hand-written functions, and nothing to train a miner on.
- **A real-code set built for this measurement:** zlib 1.3.1, LZ4 1.10.0, cJSON 1.7.18 and Lua 5.4.6, each linked
  statically with `zig cc` for x86-64 and AArch64 at O0 and O2 with `-g`, stripped with `rampage-eval strip`, and
  truth restricted to the functions the library's own objects define (musl left out). zlib and Lua (2,534 of
  8,231 positions correct) train the miners; **LZ4 and cJSON are dev**.

**Dev: 3,221 declared positions in 1,207 functions (8 binaries).** The decompiler gets 1,450 right (45.0%); one
spurious extra position.

| Class of miss | Positions | Main pairs (truth → recovered) |
| --- | ---: | --- |
| `not_decompiled` | 0 | |
| `dead` (no DWARF location: never read) | 27 | `int32` → none 12, `struct_pointer` → none 9 |
| **Unreachable** | **27** | |
| `register_class` | 121 | `pointer` → none 38, `int32` → none 31, `struct_pointer` → none 20, `float64` → `int64` 10 |
| `ambiguous` | 1,623 | `pointer` → `int64` 701, `struct_pointer` → `int64` 649, `struct_pointer` → `pointer` 244 |
| **Reachable** | **1,744** | |

The gap is mostly one thing: pointers recovered as 8-byte integers (1,350 of 1,771 misses), and struct pointers
recovered as plain pointers (244).

**One-feature miners** (learnt on zlib and Lua, applied to LZ4 and cJSON):

| Feature | Dev correct after (before: 1,450) | Fixed | Broken |
| --- | ---: | ---: | ---: |
| Recovered class (for example `int64` → `struct_pointer`, `int8` → `int32`) | 1,664 | 899 | 685 |
| Recovered raw spelling (`char *` → `pointer`, `uint8` → `struct_pointer`) | 1,883 | 898 | 465 |
| Recovered class at that position | 1,794 | 967 | 623 |

A remap of the decompiler's own answer, with no new analysis, takes up to 967 reachable positions, and the best one
nets +433 (45.0% → 58.5%) because it also breaks 465 correct answers: a majority vote cannot tell which `int64`
was a pointer. **Reachable, not taken: about 777 positions (24% of dev)** after the miner that fixes most,
ignoring what it breaks (the union of the three miners was not computed); 1,311 (41%) if the best miner's net
gain is what counts.

Caveats: two dev libraries, one compiler family (clang through zig), and `ambiguous` is an upper bound on what is
reachable: a pointer that the program only stores and never dereferences anywhere cannot be told from an integer.
There is no corpus, split or gate for this family yet; the set above is a seed for one.

## What could not be measured

- **The published 224 / 108 figure itself.** It sums five private phase-0 builds (x86-64 gcc O0/O2, clang O2, zig
  O2; AArch64 zig O2) of the same 39-function probe source; those binaries are not kept locally and the
  cross-compiling gcc used then is not installed. The committed probe fixtures (x86-64 and AArch64) and a new
  real-code set built with zig cc stand in for them.
- **Types on gcc builds.** The real-code type set is clang-based (zig cc) only.
- **A Thumb operand-wildcard arm.** Operand classes exist for x86 and AArch64 only, so the shape proxy above is an
  upper-bound estimate of what such an arm would take, not a measurement.
- **Fuzzy on firmware**, which refuses every Thumb reference function (see (b)).
- **Firmware beyond two binaries.** Recall across older GCC releases (step 5) needs the older toolchains fetched
  and the references rebuilt; that was not attempted.

## Reproduce

Release build of this commit (`cargo build --release -p rampage-eval --bins --examples`); about 8 minutes.

```sh
# (a) about 3 minutes with 6 workers; needs the built corpus (docs/flywheel.md, "Build the corpus")
target/release/examples/flywheel_headroom target/flywheel/corpus/libid-00da6363626a libid.json 6

# (b) about 50 s per fixture; needs the embedded set's training references (docs/signature-corpus.md)
for core in m4f m0; do
  target/release/examples/embedded_headroom --out emb-$core.json \
    --target tests/fixtures/firmware/embedded-libs-$core.elf \
    --truth tests/fixtures/data/eval-truth-embedded-$core.json WORK/refs/*.elf
done

# (c) about 1 hour, most of it decompiling the x86-64 O0 builds. Build the real-code set (zig 0.17), then:
#   for each library, arch and opt: zig cc -target ARCH-linux-musl -static -g -OPT -Wl,--no-gc-sections ... -o X.debug.elf
#   rampage-eval strip X.debug.elf X.elf; rampage-eval type-truth X.debug.elf --stripped X.elf > X.truth.json
#   keep only the names the library's objects define (llvm-nm --defined-only) in X.lib.json
target/release/examples/types_headroom types.json \
  train:zlib-x86_64-O0.debug.elf:zlib-x86_64-O0.elf:zlib-x86_64-O0.lib.json ... \
  dev:lz4-x86_64-O0.debug.elf:lz4-x86_64-O0.elf:lz4-x86_64-O0.lib.json ... \
  fixture:tests/fixtures/bin/eval-types-sym-x86_64.elf:tests/fixtures/bin/eval-types-x86_64.elf:tests/fixtures/data/eval-truth-types-x86_64.json
```

The examples write JSON with every count above, per-library and per-kind breakdowns, and samples of untaken
misses. None of the corpora, fixtures built for (c) or outputs is committed.
