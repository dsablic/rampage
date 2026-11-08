# The flywheel fast loop

The flywheel lets an AI agent improve rampage's heuristics through rampage's own MCP server, gated on held-out
ground truth. It covers library-identification (libid) signatures. A deterministic signature generator (the
*arm*) is the bar the agent must clear; a novel-only metric checks that a gain survives code changes; and
promotions leave as `.rpack` archives or go into the bundled databases after the gate runs again.

The flywheel is *experimental*. Results on a 360-binary corpus of zlib, LZ4 and cJSON
([fast-loop plan](plans/2026-11-05-flywheel-fast-loop.md), M1 and M2 records):

- Without the arm, an unattended agent promoted four candidates in four rounds for $0.45: held-out F1 rose from
  0.1306 to 0.1743 (+368 true positives, no new false positive). 365 of the 368 gains were functions unchanged
  between library versions.
- The deterministic arm alone adds 7,114 held-out true positives. Gated against it, the agent ran six rounds for
  $1.28 and promoted nothing: every candidate passed the fast gate and moved held-out F1 by zero.
- For libid, then, the arm captures the recognisable gain, and the loop is infrastructure for families that have
  no deterministic generator. The plan names compiler and tool identification as the next families.

The design is in [the fast-loop plan](plans/2026-11-05-flywheel-fast-loop.md); the guardrails are in
[the flywheel strategy](plans/2026-10-12-heuristic-self-improvement-flywheel.md).

Everything the loop writes lives under `target/flywheel/`:

| Path | What it holds |
|---|---|
| `sources/` | Downloaded source archives, checked against their pinned SHA-256 |
| `corpus/<version>/` | The built corpus: `bin/` (stripped binaries and symbolized twins), `obj/`, `lib/`, `manifest.json` |
| `cache/` | Truth by file hashes; baseline analysis by (binary hash, bundled-database hash, rampage build id) |
| `baseline/libid/<key>/` | The deterministic arm (`arm.json`, a data pack of its rows) and its `report.md` |
| `scratch/libid/<id>/` | Candidates, each a data pack with a `candidate.json` |
| `evaluations/libid/<corpus key>/` | Gate results by (candidate hash, corpus identity, baseline hash), and the held-out budget |
| `promoted/libid/` | The promoted pack (`rampage-pack.toml`, `sigs/`) and `entries.json` with provenance |
| `runs/<label>/` | Run reports (`report.json`, `report.md`), and each round's transcript, prompt and server events |
| `bundle/<label>/` | A bundle's `summary.md`, `summary.json` and `change.patch` |

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
not define it. Every truth function's bytes are checked to be identical in the stripped binary. Names are
compared as identification reports them, without the build-local counters of Zig's generated declarations
(`math.ldexp.ldexp__func_40` is `math.ldexp.ldexp__func`; see `canonical_name` in `rampage-signatures`).

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

### The final split

The held-out split guides decisions: the gate reads it, and the operator reads its reports while designing arms and
rules. That makes it a development split, and gains measured on it are no longer clean evidence. The final split is
held back for claims:

- **What it holds.** Target-library versions neither training nor held-out holds (the corpus refuses one that
  does), in two cells:
  - zlib 1.3.2 and 1.4 and cJSON 1.7.19 built from source with the same matrix, so the split measures version
    generalisation in the same toolchains;
  - Alpine Linux's gcc-built static zlib (`prebuilt` in `corpus.json`), for x86-64 and AArch64. gcc gets its own
    ladder: Alpine's zlib 1.2.13 trains, 1.3.1 is held out, and 1.3.2 and 1.4 are final. It reports as the
    `compiler:alpine-gcc` slice.

  A final cell must never change the compiler and the version at once. Byte signatures learned from clang builds
  name nothing in gcc builds: a first final split made only of gcc builds of new versions scored 0 for every arm.
  cJSON and lz4 have no gcc cell. Alpine packages cJSON statically only from 3.22, so no older version could
  train, and its `liblz4.a` holds gcc slim-LTO bitcode, which only gcc can link.
- **Origins only.** Packages are pinned by URL and SHA-256, downloaded into `target/flywheel/sources/`, unpacked and
  never committed or run. Distributions replace package revisions, so a pin can stop resolving; updating it changes
  the corpus version.
- **Who reads it.** A corpus server, the arm and `flywheel-baseline` never load it. Only an explicit evaluation
  does, and every read is appended, numbered and with its reason, to `final-ledger.jsonl` inside the corpus
  directory, so any flywheel directory reading that corpus counts into the same ledger:

  ```sh
  rampage-eval flywheel-eval --corpus target/flywheel/corpus/<version> --split final \
      --pack target/flywheel/baseline/libid/<arm> --final-reason "arm v2 claim"
  ```

  Like the held-out split, a final evaluation reports metrics and no per-function cases. A claim cites its read
  number; a design changed after a final read is measured on a later corpus's final split, not on the same one
  again.

| Family | Hold out |
|---|---|
| libid | Library versions (or whole configurations) |
| Tool ID | Whole tools and packers |
| Function-start discovery | Compilers or architectures |

Never split per program when programs share the measured code: a per-program split of this kind put 98% of its
held-out functions in training under the same name and configuration.

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
| `novelty:novel`, `novelty:recognised` | yes | Held-out only: the target libraries' functions whose masked body training does not hold (novel), and the rest |
| `origin:<library>`, `origin:runtime`, `origin:none` | no | Every outcome, by where the function comes from (`none`: the truth has no function) |

**Novel and recognised.** A held-out function is *recognised* when its masked body (scheme 2, as a signature
sees it) equals the masked body of some training library function, and *novel* otherwise; a body failing the
confidence gate counts as novel. A gain on recognised functions is recognition of code unchanged between versions,
which the deterministic arm already gets; a gain on novel ones needs a row that survives a code change. The arm
itself names many novel bodies: it wildcards operand fields, so a constant, offset or address that changed between
versions no longer stops a match (below).

## The deterministic arm

```sh
rampage-eval flywheel-baseline --family libid --corpus target/flywheel/corpus/<version>
```

The arm is every signature row a plain generator makes from the training split's truth, with no AI. For each
target-library truth function of the training binaries it takes the body as scheme 2 masks it (the `masked_bytes`
a `corpus_failures` group shows) and keeps one row per distinct (architecture, masked body), under the rules a
proposed row meets:

- the pattern is at least `min_pattern_bytes` and at most a row's 2080 bytes, and passes the row schema;
- a body seen with more than one name is ambiguous and dropped, as the signature builder makes it never answer;
- a body whose pattern also matches another name, or code outside the truth, in any training or negative binary
  is dropped: a proposed row like it would fail the fast gate.

**Operand wildcarding.** Each body also has widened patterns: the masked body with every byte of chosen operand
classes made a wildcard. Patterns wildcard whole bytes, so a byte holding any bit of a field takes its class:

| Class | Bytes |
|---|---|
| `relocation` | Every byte of a field scheme 2 masks: branch and call targets, RIP-relative and absolute image addresses, ADRP pages and their low halves. Masking zeroes a field, so a byte already equal to zero would otherwise read as fixed |
| `disp8`, `disp-wide` | x86 one-byte and wider displacements: stack slots and structure offsets |
| `imm8`, `imm-wide` | x86 one-byte and wider immediates (SSE selectors and syscall numbers included) |
| `a64-immediate` | AArch64 ADD/SUB, logical and move-wide immediates |
| `a64-offset` | AArch64 load/store offsets: unsigned, unscaled, pre/post-indexed and pair |

AArch64 fields do not align to bytes, so there a byte takes a field's class only when every bit of it belongs to
the field or to a register number. A byte that also holds opcode bits (load or store, MOVZ or EOR, the branch kind,
the condition) stays fixed, and so do the field's bits in it.

Rows are made tier by tier, widest first: every class, then `relocation` alone, then the exact masked body.
Bodies whose patterns agree at a tier form one group, and the group becomes one row under the rules above. A
group the rules refuse leaves its bodies to the next tier, so a widened row with too few fixed bytes, or one that
merges two names, costs nothing. The default is every class with that ladder; variant class sets are for
comparison, not for choosing by held-out score. `--wildcards LIST` (or `none`, v1's exact rows) generates another arm for comparison; a corpus server
always gates against the default.

It reads training and negative binaries only. The arm is saved under `baseline/libid/<corpus key>-<key>/`
(`arm.json` and a data pack of its rows), keyed by the corpus identity, the rampage build, the minimum length and
the wildcard classes, and regenerated when any changes (`--regenerate` forces it). The report adds rows by tier,
fallbacks by tier and reason, and (from held-out truth, for the operator only) how many same-length novel
functions a widened training pattern matches. The command evaluates the arm through the same gate
against the bundled databases, and reports bundled-only and bundled-plus-arm metrics on every split, overall and
for novel and recognised held-out functions.

**The arm is the default baseline.** A corpus server gates every candidate against the bundled databases plus the
arm plus the promoted rows (`rampage server serve --corpus DIR --flywheel-baseline arm`, the default). A candidate's rows are
merged with the arm's into one database, so a row repeating an arm body under another name makes both ambiguous
instead of overriding it. Against the arm the held-out gate also requires a novel-body gain (below), because the
arm already names the recognised functions. `--flywheel-baseline bundled` selects the bundled-only comparison
for diagnostics; it is never the comparison for a promotion that is meant to show the agent adds value.
`corpus_failures` lists only what the baseline still misses, and names the baseline in its header.

The arm is never promoted or deployed. A candidate row whose pattern also matches a body an arm row names under
another name only makes that body ambiguous in the merged evaluation (a lost name, not a false one), yet once
promoted without the arm it would name the body wrongly. So against the arm the false-positive rules are also
checked on the deployed state, the promoted rows plus the candidate's without the arm:
`deployed_train_fp_increase` and `deployed_negative_matches` in the fast stage, `heldout_deployed_fp_increase`
(pass or fail only) in the held-out stage.

## Measure

```sh
rampage-eval flywheel-eval --corpus target/flywheel/corpus/<version> --split heldout
rampage-eval flywheel-eval --corpus target/flywheel/corpus/<version> --split negative \
    --pack target/flywheel/promoted/libid
```

`--split` is `train`, `heldout`, `fast`, `negative` or `final` ([the final split](#the-final-split)). Without `--pack`, the command measures the bundled baseline.
With one or more packs it layers them over the bundled databases (the first pack wins) and reports deltas
against the baseline. Each slice shows TP, FP and FN, precision, recall and F1.

- A correct name is a true positive.
- A wrong name at a truth function counts as both a false positive and a false negative.
- A name where the truth has no function is a false positive.
- An unnamed truth function is a false negative.

The training and held-out runs also print the overlap check. Changed cases are listed except for the held-out and
final splits. `--dev-cases` lists the held-out split's cases too, for the operator designing arms and rules on the
development split. A proposer never sees them, and the final split has no such view.

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
| `max_fp_increase` | 0 | Held-out gate: false positives may rise by at most this many, plus the `tp_per_fp` allowance. Checked again on the deployed state (without the arm). |
| `tp_per_fp` | 100 | Held-out gate: one more false positive is allowed for every this many correct names gained (net of names lost); 0 allows none. Training and negatives get no allowance. The deployed check earns its allowance from its own gain. A gate file written for the old strict default needs `tp_per_fp = 0` to stay strict. |
| `max_heldout_evaluations` | 20 | Held-out evaluations per corpus, counted across every server and run (cached results excepted). |
| `require_novel_gain` | unset | Held-out gate: the `novelty:novel` slice's F1 must rise too. Unset, it is required exactly when the arm is the baseline; `--require-novel-gain true/false` on the server or the run overrides it. |
| `min_novel_f1_gain` | 0.001 | The least novel-slice F1 gain, when one is required (and more than zero). |

A candidate is always evaluated merged with the reference rows (the arm's, when it is the baseline, and the rows
already promoted), against that reference, which is exactly what promoting it would produce. A promotion changes
the baseline hash, so earlier gate results stop counting. Only binaries a candidate row can match are identified
again; the rest keep the reference's answers, which are computed once per baseline.

The held-out stage returns only the verdict and the gated overall delta. The novel rule reports pass or fail
without its delta. Per-slice deltas, or counts of fixed and broken functions, would tell a proposer which
held-out code its rows touch.

## Rows that generalise

A row is a FLIRT PAT record, and can use everything rampage's PAT matcher supports:

- whole-byte wildcards (`..`) anywhere: changed constants, displacements, register bytes (ModRM, REX, an AArch64
  instruction word's register bytes), call targets. There are no nibble or bit wildcards.
- an exact module length: a body matches only at exactly that many bytes, so code whose length changed between
  versions cannot be reached by a byte pattern.
- a pattern shorter than the module: `length` above the pattern's own length leaves the remaining bytes
  unconstrained, as a PAT tail that ends early does.

PAT's CRC16 field is not used (explicit bytes are stronger), and the matcher does not support references or
dumpsig tuples. Ghidra FID records are hashes that need a semantic adapter, not byte patterns, so they are not a
row form.

`propose_heuristic` builds rows from training bodies:

| Field | Effect |
|---|---|
| `case` | Start from a training body: a failure group, or any variant id `corpus_failures` listed |
| `pattern` + `arch` | Start from explicit hex with `..` wildcards |
| `wildcards` | Byte offsets that become wildcards |
| `wildcard_spans` | `[start, end)` ranges that become wildcards |
| `merge_cases` | Other training bodies of the same arch and length; every byte where any differs becomes a wildcard |
| `keep_prefix` | Keep only the first N bytes; the body's length is kept as the module length |
| `length` | The module length, for a `pattern` row shorter than the body |

The schema still applies: the explicit pattern is at least `min_pattern_bytes`, has at least 6 fixed bytes and
fixed bytes in at least half its positions, and a pattern shorter than its module ends in a fixed byte. More
wildcards match more code, and the fast gate's training and negative checks, and the held-out false-positive rule,
catch the collisions. Each row's preview says how many training functions it matches, whether their truth is its
name, and whether the baseline already holds it.

**Every training body.** Against the arm few training failures are left, so `corpus_failures` with
`outcome: "all"` lists every training library body, failing or not (`failing` says which): the bodies the
baseline already names are the ones a generalising row starts from. `proposable: true` leaves out bodies too short
or long for a row.

**Training-only variants.** `corpus_failures` with `variants: true` lists, per group, the same function's other
training bodies (other compilers and optimisation levels) with their case ids, configurations and, for
same-length ones, how many bytes differ. They come from the training split alone; a held-out body is never listed
or merged. Bytes that vary across configurations are the evidence for which bytes may vary across versions.

## Run a loop

```sh
rampage-eval flywheel --family libid --corpus target/flywheel/corpus/<version> --rounds 4 --budget-usd 5
```

`--baseline arm` (the default) or `bundled` and `--require-novel-gain true/false` are passed to every round's
server.

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

It ends with the held-out metrics under the promoted pack against the bundled baseline, gated and by origin,
and a reference table: bundled only, bundled plus the arm, and bundled plus the arm plus the promoted rows,
overall and for novel and recognised functions, with the promoted rows' delta over the arm.
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

## Export, import and bundle

A promoted pack leaves the machine as a `.rpack` archive ([data packs](data-packs.md#export-and-import)):

```sh
rampage pack export target/flywheel/promoted/libid -o libid.rpack
rampage pack import libid.rpack --into /path/to/libid      # checks hashes and version range first
rampage --pack /path/to/libid function identify stripped.elf
```

### Bundle a promotion

```sh
rampage-eval bundle --from /path/to/libid --corpus target/flywheel/corpus/<version> [--entries rv-...]
rampage-eval bundle --remove rv-... --corpus target/flywheel/corpus/<version>
```

The bundled-database source for flywheel promotions is `crates/rampage-signatures/data/flywheel/libid.json`: every
bundled entry with its provenance id (the revert id it was promoted under), the pack it came from, its corpus,
what it was gated against, the deltas at promotion and at bundling, and its rows. The bundled assets
(`data/corpus-<arch>.json.gz` and `.index.json`) hold those rows as their PAT namespace, with a
`flywheel-libid-<arch>` provenance profile; their hash entries are never changed. In a bundled database a PAT row
names a function only when the hash entries have no answer for it, never against one.

`bundle --arm` bundles the deterministic arm for the corpus as one entry (`arm-<rows hash>`, replacing an earlier
arm entry), with the licence of the code its rows come from, through the same gate. The shipped databases carry
arm `arm-e77075a92a73` (3218 rows from corpus `libid-ed988c9a220e`): against the bundled baseline it gains 7713
held-out names (783 novel) for 4 false positives, and none on training or the negatives.

`bundle --from <pack>` merges the selected entries (default: all) into the source, regenerates the affected
assets and indexes, and reruns the gate on the corpus: every split identified with the regenerated databases
against the repository's current ones, so nothing is rebuilt. The rules are the fast gate and the held-out gate
against the bundled baseline (overall gain, false positives within the `tp_per_fp` allowance, no slice
regression; a novel gain only with
`--require-novel-gain true`), because an entry gated against an older baseline, or the arm, must pass again. An
asset whose PAT namespace is not exactly the source's rows is refused.

When the gate passes, the change stays in the working tree, commit-ready, and is written to
`target/flywheel/bundle/<label>/change.patch` (`git diff --binary`) with `summary.md` and `summary.json`;
`--patch-only` writes them and restores the tree. It never commits. When the gate fails, nothing is changed.
`--remove <id>` takes an entry out the same way; it must add no false positive on any split. After a bundle is
committed, rebuild rampage so the compiled-in databases carry it.

## Observations

`report_observation` records a typed observation (`function_start`, `function_name`, `library_function` or
`not_a_function`) with 1 to 8 evidence items. Records are appended to `observations.jsonl` with the binary's
SHA-256; binaries over 256 MiB are refused.

It is served only in ordinary sessions, which opt in with `rampage server serve --observations DIR` or
`RAMPAGE_OBSERVATIONS`; a corpus server does not serve it. A store inside a flywheel directory refuses files from
that directory.

The store is a directory of its own rather than the binary's annotation sidecar, for two reasons. The sidecar is
the analyst's record: every client replays it, under its reader's limits. Observations are unreviewed labels, and
the corpus must collect them across binaries. Recording one changes nothing else. The corpus does not read them.
