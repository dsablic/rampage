# To do

## Parity roadmap: Phase 0 and 1.1–1.6 implementation completed; live Phase 1 sign-off open

Execution ordering follows `docs/plans/2026-10-16-ida-ghidra-parity-roadmap.md`. One milestone at a time;
parallel slices share central builds and undergo fresh-context review before publication.

- [x] Required source-built corpus: genuine GCC `-O0/-O2`, Clang, x64/AArch64 ELF, AArch64 Mach-O, x64 PE,
  Thumb and MIPS32 BE, plus C++/exceptions, Go, Rust and pinned MIT Lua. Twelve verified profiles plus Lua.
- [x] Check native headers, stripping, source/twin hashes and nonempty symbol or explicit checked DWARF truth;
  external C++/Rust debug files require matching UUIDs, exact CPU identities and retained code bytes.
- [x] Record 29 static slices, Lua/Ghidra graph agreement and 247 decompiler observations across 13 targets.
- [x] Run the canonical 20 tasks through actual MCP using `github-copilot/gpt-6.1-sol`, variant `default`:
  17/17 analysis contracts matched; three capability probes remain one match, one unknown and one format failure.
  Actual usage: 38 MCP calls, 286183 input / 4347 output / 1555 reasoning tokens; no tool/model errors.
- [x] Emit one combined JSON report, pass all 22 evidence-completeness checks, publish the scorecard and its
  path/transcript-free data view. Collector `65a7e99`; baseline evidence is in `docs/benchmarks.md`.
- [x] Fix the measured SIGCHLD interaction between CLI deadlines and MCP workers, pass the interoperability
  regression, and rerun the full unchanged task set; preserve the initial run as diagnostic evidence.
- [x] Revalidate the raw-firmware acceptance window through MCP without execution or payload publication.

Phase 0 is a measured baseline, not parity or full-workspace/release acceptance. Broader corpus, graph,
all-functions health and cross-model comparisons remain future scorecard maintenance. No Ghidra MCP bridge
was available in the benchmark's configured project context. Optional unscored profiles remain visible.

## Phase 1.1: local variables and parameters completed

- [x] Measure an owned addressable pointer local before/after: offset/index accesses become named struct fields.
- [x] Persist function-plus-storage local names/types; apply actual native scope locks, not C-text substitution.
- [x] Expose bounded Types-group `edit_variable` with current-name/storage selection and refreshed C in one call.
- [x] Accept undo/redo, clear/replacement, shared logs, replay, native and supervised paths and exact-entry replay.
- [x] Verify same-size pointer retypes, x64/AArch64 parameters, stack locals and register-use disambiguation;
  reject ambiguous/stale/unsupported selectors, keywords and oversized results without partial persistence.
- [x] Measure a live supplied-layout task with the current OpenCode model through actual MCP, independently verify
  native state and persisted storage bindings; publish source/executable/fixture hashes and measured totals.
- [x] Repeat a real ARM64 audio-core decompilation read-only: six descriptors, three editable and three explicit
  refusals, recovery warnings retained. No commercial annotations or inputs changed.

Limits: one whole register/stack mapping and same-size types. No UI local editor, type library or cross-call
propagation. The accepted Phase 0 publication is unchanged; the current capability probe now expects this feature.
Evidence and measurement limits are in `docs/benchmarks.md` and `docs/local-variables.md`.

## Phase 1.2: project type library completed

- [x] Project-level named declarations, bounded native layout inventory/inspection and dependency-checked deletion.
- [x] Bounded C header import and permissively licensed minimal C/POSIX/Win32 type profiles.
- [x] Native/API/MCP undo/replay acceptance, compiler-matched layouts, measured owned workload and independent review.
- [x] Preserve ordinary legacy undo refresh, oversized-comment/long-history compatibility and empty-history no-op.
- [x] Read queries use bounded detached snapshots; real protected-image inspection creates no annotation/lock files.
- [x] Publish the first live run without retry/regrading: correct native state, workflow and fresh-server persistence,
  10 MCP calls / 6 model turns; strict final-summary contract failed and remains `task_verified=false`.

Implementation `e01d0bd`; protected-input read fix `67b5f03`. All six changed-crate suites and scoped all-target
Clippy passed. C/header limits and the failed strict-summary result are recorded in `docs/benchmarks.md`.

## Phase 1.3: data and operand typing completed

- [x] Measure typed arrays/struct data, enum/offset operands and typed range display on owned x64/AArch64 fixtures.
- [x] Apply native named types to data without changing binary bytes; preserve annotation undo/replay.
- [x] Bounded typed data and disassembly views, exact-entry/worker acceptance and independent review.
- [x] First live run passed: seven MCP calls, three model turns; native state and fresh-server persistence verified.
- [x] Preserve source offsets/statuses, exact large integers, invalid/partial text and unknown pointer semantics.
- [x] Fix anonymous typedef registration, lossless displacement evidence and complete-prefix first typed-log checks.

Implementation `24ba0dd`; audited evidence is in `docs/benchmarks.md`. All seven changed-crate suites, scoped
Clippy and grader regressions passed. Instruction operands are supported; arbitrary C constant-token edits are not.

## Phase 1.4: stack-frame inspection completed

- [x] Measure missing per-function frame inventory against source-known native storage and stack tracking.
- [x] Expose bounded locals, parameters and register-preservation candidates with current 1.1 names/types through MCP.
- [x] Native address-space widths and configured base context are direct evidence; tracker coordinates stay separate.
- [x] Bound repeated metadata, preserve complete paged rows and propagate infrastructure failures.
- [x] Native/worker/MCP and first live read-only workflow passed: one query / two turns; fresh-server/log/byte checks.
- [x] Revalidate an installed ARM64 core frame without annotations or warning suppression.

Implementation `8fdfb2b`; audited metrics and limits are in `docs/benchmarks.md`. All seven changed-crate suites
and scoped Clippy passed. No complete frame-size or ABI callee-save claim is made.

## Phase 1.5: type propagation completed

- [x] Measure caller/callee/return/global propagation on owned fixtures with explicit analyst types taking priority.
- [x] Derive bounded direct-call candidates with provenance, conflicts and unknowns through MCP.
- [x] Apply separate unlocked hints and target-model import prototypes without hard analyst replacements.
- [x] Validate complete retained hint state, full payload receipts, native/worker replay and source fingerprints.
- [x] Preserve fatal error categories, ordinary C at unsupported optional boundaries and exact-entry observations.
- [x] Publish the first live run without retry/regrading: nine MCP calls, zero tool errors; workflow/native/fresh
  state verified, but one model-side error leaves `task_verified=false` and usage unknown.

Implementation `321ea28`; audited metrics and limits are in `docs/benchmarks.md`. Changed-crate suites and scoped
Clippy passed, with a full worker rerun after its new error-category test expectation was corrected. Some
multi-hop/refinement cases remain explicit unsupported boundaries; automatic ephemeral display is not durable apply.

## Phase 1.6: checked PDB/DWARF type-import implementation completed

- [x] Measure PDB names-only and flat checked-DWARF limits against owned PE/PDB and nested/AArch64 fixtures.
- [x] Import identity/machine-matched PDB type records into the project library with whole-plan review/apply.
- [x] Add nested DWARF aggregates/arrays and AArch64 counterpart checks, preserving unknown alignment/bitfield facts.
- [x] Validate complete atomic proof/library/signature edits, stale-source refusal, cold native/worker replay and history.
- [x] Controlled MCP C++ reconstruction passes: Owner/Cell fields and one-wrapper DWARF agreement improve to 3/3.
- [x] Preserve first live attempt: four successful MCP calls, then one model-side error before apply/retype;
  workflow/native/task verification false, usage unknown, no retries/regrading.
- [x] Revalidate audio and original firmware static workloads without annotation changes or target execution.

Implementation `02e6173`; audited evidence is in `docs/benchmarks.md`. Changed-crate suites, scoped Clippy and
actual MCP/collector fixtures passed. Bitfields, qualifiers, ambiguous C CodeView forwards and unsupported ABIs
remain explicit preview-only boundaries. The old checked layouts and PDB names contracts are preserved.

## Open acceptance gate: live Phase 1 completion

- [ ] Genuine live checked import → central C++ struct retype → owner-linked field verification and fresh replay.
- [ ] Record successful reconstruction call bound N and independent DWARF agreement; execution caps are not N.
- [ ] Diagnose the model-side failure only with new evidence; keep first attempts and prior publications frozen.
- [ ] Do not claim full Phase 1 acceptance from controlled test success alone. The user explicitly authorized
  proceeding through Phases 2–6 while this live acceptance gate remains open; frozen results are unchanged.
- [ ] Carry forward the native C++ class-evidence limit: stripped exceptions workload currently yields no class
  rows; symbolized vtables are skipped as not mapped read-only. Do not relax evidence rules to inflate scores.

## Phase 2.1: bounded reproducible corpus delivery complete

- [x] Measure current bundled recognition on cross-program public-library builds, with symbolized twins as truth.
- [x] Build an offline zlib/LZ4/Lua pilot with pinned sources, explicit ownership, commands and provenance.
- [x] Add deterministic gzip, lazy builtin architecture loading and collision-safe corpus combination.
- [x] Preserve reference-only negative collision evidence without exporting runtime/harness names.
- [x] Disable linker GC and refuse lost public definitions; distinguish public from hidden/local/weak coverage.
- [x] Publish the bounded SQLite x64/AArch64 O1 and LZ4 i386/Thumb evidence, preserving every failed recall gate.
- [x] Measure reloaded SQLite/LZ4/musl aggregates with full-sized-twin proposal precision and checked input orders.
- [x] Record paired Thumb EHABI recall and actual MCP metadata evidence, keeping baseline revision unattested.
- [x] Measure serialized artifacts per materialized library/architecture/profile; preserve misses, wrong names and unrun coverage.
- [x] Close the finite delivery roster with measured, quarantined and unrun coverage explicit;
  the full roadmap library/version/architecture matrix is not a prerequisite for this delivery pass.
- [x] Add atomic training-reference conflict filtering, preserving negative evidence without exporting names.
- [x] Enforce a global held-out image split and retain separate cases for byte-identical stripped targets.
- [x] Deliver reviewed compressed default databases and provenance indexes for the four-architecture ELF cohort.
- [x] Extend x64 delivery with checked Windows zlib/LZ4 profiles and the declared nine-function MinGW subset.
- [x] Deliver the bounded LLVM/glibc portable supplement with retained v3 evidence and unchanged historical records.
- [x] Pass parent portable-asset Rust tests, pack integration, Clippy and independent publication audit;
  these checks do not imply release/CI acceptance.
- [x] Complete the bounded SDK/runtime delivery pass: promote precision-safe aggregates and publish technical
  quarantines and remaining coverage gaps; do not ship a precision failure or exclude solely for low recall.
- [x] Prepare the three precision-safe SDK/Rust database/index pairs and publish the finite technical disposition.
- [x] Pass bundled-asset admission/index/legacy-preservation tests and independent final publication audit.
- [x] Review the corpus producer and publish bounded delivery; native MCP contracts are unchanged.

Status: **bounded 2.1 delivery complete; full Phase 2 recall acceptance remains unearned.**
The signatures suite passed 138 tests with one ignored, including actual gzip/index admission, lazy loading,
legacy-byte preservation and exact-fallback withholding. Final cross-phase API/CLI/MCP checks remain tracked
with the import/fuzzy implementation below; they are not a new SDK-coverage requirement.
Three exact precision-safe exports revalidate 81 cases: x64 39, AArch64 27 and i386 15; 14 historical Thumb cases
are unchanged, giving 95 accounted cases, not 95 rerun. Current entries/callee keys/profiles are x64 11,369/822/40,
AArch64 7,037/402/28 and i386 2,123/90/15; Thumb stays 2,117/0/14.
All four Rust profiles are included. Raw std 1.87's one wrong remains retained; generic source-reference conflict
rejection and exact-fallback withholding remove unsafe answers without blacklists or owned-gold deletion.
The SDK delivery/disposition JSONs record eight technical quarantines and all recall failures. Native archive,
member, compiler and source/header identities are evidence, not publisher authentication or full SDK coverage.
The 80% matched-version recall target belongs to Phase 2 acceptance, not a separate 2.1 completion gate.
Known recall failures remain visible; wrong/spurious names still prevent candidate promotion.

The original pilot was not full 2.1 acceptance. Early GC-enabled linked-subset measurements remain separate from the
full-retention cohort. Pinned slice `198c024`: zlib and Lua pass the tested x64/AArch64 O1 gates; LZ4 remains
77.9%/65.4% recall, with zero wrong/spurious names. All six results are published in `docs/benchmarks.md`.
That pilot publication promoted no new default database. The later delivery slice below adds reviewed assets;
the earlier results and live Phase 1 gate remain unchanged.

Further reviewed slices: `5f5a7e4` adds SQLite, aggregate validation and exact-match diagnostics; `1b67d7c` adds
ARM EHABI candidate starts (Thumb LZ4 2/104 → 73/104, still below gate). `8640ae7` expands the pinned catalog to
ten profiles/six families, including second versions. `7f58743` fixes large MCP identification replies: all 935
mbedTLS matches are available in four complete bounded pages instead of truncated JSON. Current source suites,
targeted large-corpus MCP acceptance, Clippy, Python tests and reviews passed. Remaining roster/recall and
promotion gates are still open; Phases 3–6 are not started.

Reviewed core/default delivery expands the pinned catalog to thirteen profiles/nine families, adds explicit
PE/PDB production and exact stripping, and provisions hash-pinned Rust target-library data without installers.
Core and ELF32 cohorts cover x64, AArch64, i386 and Thumb. Cross-library evaluation exposed false names that
per-library scoring missed; reference-only filtering removes those measured core collisions. The hardened
AArch64 OpenSSL profile still reports two wrong names; the final curated corpus withholds raw exact fallbacks
and has zero wrong/spurious proposals across all 80 ELF aggregate cases. Tool snapshots,
raw failed attempts and the one invalidated collector-hash-drift attempt remain separate. Runtime byte-binding
and broader SDK coverage require fresh measurements. The four lazy-loaded default corpora and their indexes are
recorded in `docs/benchmarks/phase2-1-delivery-2026-10-18.json`; 2.1 was incomplete at that checkpoint.
The Windows supplement records 31 precision-clean x64 ELF/PE cases and the declared MinGW `pesect.c` unit at 9/9.
At the portable checkpoint, the x64 index had 7,575 entries, 670 callee keys and 34 profiles;
the other architectures were unchanged.
The reviewed portable supplement is `docs/benchmarks/phase2-1-portable-delivery-2026-10-18.json`; parent asset
tests, pack integration, Clippy and independent provenance reconciliation passed. Its 33 x64 cases have zero
wrong/spurious names, LLVM 8/8 and glibc 1/1 owned
recall, with ten remaining recall failures. That checkpoint accounted for 87 cases:
x64 33 + AArch64 26 + i386 14 + Thumb 14.
LLVM 22.1.8 covers eight original generic C units; glibc 2.40 covers only original `strverscmp.c`, with strong
`__strverscmp` and its real weak alias retained. Both are O2 freestanding x64 Linux-musl builds without CRT or target
execution, not whole-library or native configured glibc coverage. The finite alias configuration and exact header
bytes are pinned; the vendored musl header revision remains unknown.
Opt-in producer-alias policy v3 preserves raw proposals, strict original owned gold, and original/selected callee
contexts. Strict remains the default; PE/PDB alias policy is unchanged. The prior strict refusal and v1 glibc 0/1
remain frozen, not regraded. All 32 historical profile records are unchanged; nine signature keys were added and
58 conservatively retired. Alias metadata is not publisher authentication or runtime object identity. Earlier
80-case core and 31-case Windows publications remain unchanged; current SDK/Rust validation is tracked above.

The follow-up `5f5a7e4` / `1b67d7c` evidence is pinned in
`docs/benchmarks/phase2-1-parallel-2026-10-18.json`: SQLite x64 is 243/262; AArch64 is 201/262 and fails.
Both same-architecture SQLite/LZ4/musl aggregate runs fail overall despite all-named precision 1.0 in every
case; x64 aggregate LZ4 is 80/104, not its per-library 81/104. i386 LZ4 is 83/104 (79.80769%, fail).
Thumb improves from 2/104 to 73/104 on identical artifacts after EHABI, still below 80%; wrong/spurious stay zero.
The i386/Thumb reports retain a measured empty-database baseline (0 correct, 104 missed), despite no bundled DB.
The full trace's 100 missing owned starts and the earlier pre-final-review matrix's zero are separate evidence;
the final reviewed report omits its matrix. Actual paired MCP metadata receipts do not attest the baseline
binary revision or prove complete boundaries. This is a bounded publication, not full matrix acceptance,
default promotion, fresh validation, a live model result, or authorization to skip the remaining 2.1 gate.

The latest requested order is to finish all of Phase 2, then top-level Phases 3–6. Bounded 2.1 delivery and
the supported 2.2/2.3 implementation are complete. Source-corpus infrastructure is not full acceptance of the library-recognition phase;
the independent live Phase 1 gate remains open.

### Phases 2.2 and 2.3: implementation complete

- [x] Validate and publish bounded user-supplied PAT imports, including persistence and ambiguity preservation.
- [x] Validate and publish genuine FID import/query with explicitly trusted Ghidra/JVM configuration.
- [x] Complete API/CLI/MCP regressions before accepting the new import/candidate surfaces.
- [x] Publish the measured fuzzy candidate results, preserving incorrect candidates, extraction failures and
  the reused-holdout caveat; never report candidate-only results as qualified naming gains.
- [x] Review, test and publish the remaining Phase 2 implementation before advancing through Phases 3–6.

Phase 2 implementation is complete in the supported scopes documented in `docs/signature-imports.md` and
`docs/fuzzy-signatures.md`; `docs/benchmarks/phase2-validation-2026-10-18.json` records validation boundaries.
The full Phase 2 recall target is still unmet, not regraded. Fuzzy top candidates are 2 correct / 2 incorrect,
with zero qualified naming gain. FID is API-only trusted-host static analysis, not automatic CLI/MCP execution.
The next implementation milestone is Phase 3; the independent live Phase 1 and recall gates remain open.

## Phase 3.1: bounded search complete

- [x] Add address-sorted, paginated search for byte wildcards, ASCII/UTF-16 text and regex.
- [x] Add immediate/instruction-pattern search and functions referencing strings/imports/constants.
- [x] Expose search through API/CLI/MCP with function context, scan bounds and explicit truncation.
- [x] Measure an owned investigation without rewriting the frozen Phase 0 baseline.
- [x] Review, test and publish search before the Phase 3.2 patch/assemble/export slice.

The API library passed 651 tests with nine ignored, including 60 search-core cases; API/CLI/MCP search
integration passed 6/2/2, and all-targets scoped Clippy passed. Independent reviews cover source mapping,
virtual continuity, shared-block context, decoder lookahead/read budgets, cancellation and transport bounds.
The owned mechanical MCP comparison is 2 calls → 1 with complete equivalent evidence, but slower and larger
in that observation. It is not a Phase 0/live-model improvement or the Phase 3 token/call acceptance gate.

## Phase 3.2: checked patch/assemble/export complete

- [x] Persist bounded identity/preimage-checked patches in the existing annotation log with undo/redo.
- [x] Publish immutable effective projects so listing, discovery, strings and decompilation agree on bytes.
- [x] Add bounded x86/x64 and AArch64 assembly feeding the same checked patch path.
- [x] Export only to a new file; verify original bytes unchanged and export/reopen/decompile round trips.
- [x] Finish the final publication audit and publish patching before measured Phase 3.3 ergonomics.

The current API library passed 692 tests with nine ignored. Core, annotation, variable/workspace, migrated
read, cache/plugin, agent/UI lifecycle and API/CLI/MCP frontend checks passed with their overlapping scopes
kept separate. Scoped all-targets Clippy passed. The owned x64 MCP round trip verifies exact C returns
5/7/5/7/7, five fail-closed negative cases and unchanged originals; no target execution occurred.
The patch profile is static little-endian ELF64 x64/AArch64 only, not universal patch support.

Next: Phase 3.3 measures consistent compact views, name resolution and existing batch ergonomics against
appropriate frozen tasks. The new mechanical search/patch experiments do not earn Phase 0/live-token credit.

## Phase 3.3: ergonomics implementation complete, live improvement gate open

- [x] Audit current tools against the frozen Phase 0 transcript and address-taking schemas.
- [x] Add consistent summary/code/full views where they preserve required evidence and diagnostics.
- [x] Reuse/extend the existing atomic annotation batch API rather than creating a parallel history path.
- [x] Measure comparable agent-call/token outcomes with the current provider/model and existing auth;
  preserve first failures and frozen baselines without regrading or claiming mechanical runs as live results.
- [x] Finish publication audit and publish the supported Phase 3 implementation before Phase 4.

Implementation tests: 721 API library passes/nine ignored; 20 projection tests, nine mixed-batch and nine
legacy-batch passes, 6/3/3 API/CLI/MCP ergonomics passes, scoped all-targets Clippy green. Views preserve raw
native storage coordinates and reject malformed shapes; batch declarations reject internal checked-import
encodings through the same public guard as individual setters.
Mechanical full/summary MCP responses saved 1,647 serialized bytes (42.9%) on the fixed owned workload.
One unchanged live helper attempt answered 22 correctly: five calls, 21,518 input tokens versus 23,904 baseline.
Catalog retention is truncated in both reports, so completeness acceptance fails: no token-improvement credit,
no call reduction, no causal attribution to compact/batch tools, and no retry. The other 19 tasks remain unrun.

## Active milestone: Phase 4.1, explicit Sleigh-backed processor breadth

- [x] Inventory existing native/Capstone/Sleigh paths and published processor-spec licensing/provenance.
- [ ] Expose bounded Sleigh instruction/flow/p-code decoding for explicitly selected supported processors.
- [ ] Add owned per-processor fixtures and record disassembly/discovery comparison limits without executing bytes.
- [ ] Review, test and publish the finite supported processor set before Phase 4.2 raw/firmware loading.

The first MSP430/AVR8/6502 resource closures are a pilot, not completion of the full 16-family roadmap roster.
All 16 families have resource-admitted closures from the pinned local public SDK and finite native/oracle
comparison coverage. The standalone MCP/window interface exposes the closed twenty-ID registry (sixteen
selected families plus four existing x86/AArch64 profiles). Ordinary Project routing remains separately gated.
Compiled SLA is materialized, not lazily compiled from SLASPEC. AVR code uses two-byte address units and
distinct Harvard spaces; 6502 compiler C widths remain unknown rather than defaulting to host values.
The admission helper's aggregate source-read cap passed tests and independent review. The x86 parser-bounds
and context-mediated AVR-flow fixes passed source review, 120 decompiler-library tests and a scoped parser
sanitizer run. The window API passed 27 tests; both manual-seed and call-only discovery recovered 6/6 oracle
entries and exact extents. API/CLI/MCP frontend checks and independent resource/oracle/measurement audits
passed; the full API library passed 749 tests with nine ignored. The explicit-window checkpoint is
implemented at `342084d`, with resources at `e9657d3` and parser safety at `4aa67d2`.
Ordinary Project backend integration is still missing: its approved migration guide separates optional
legacy pointer defaults, exact-profile ABI models and code-space coordinates rather than fabricating an
existing architecture for raw bytes. The explicit-window pilot alone does not complete Phase 4.1.
The first width/model pilot is implemented at `0d9dbb5`: optional defaults coexist with the unchanged
fourteen-architecture legacy method, scalar grouping does not invent pointer evidence, and missing reviewed
C facts do not block existing typed Go/external native routes. Targeted direct/worker, source-failure,
external-alias and ABI checks passed. Actual small-model native queries, unknown-width Project identities,
real-profile factory routing and Raw admission still require their own gates. The classified consumer
migration and checked RTTI result are implemented at `166f30e`: zero production callers depend on the legacy
total-width API. Its 895 distinct scoped tests and full API run (761 passed, nine ignored) are green.
The retained legacy definition and five known fixtures remain; new identities and real unknown-width
Project coverage have not yet been admitted.
The native roster is implemented at `5708906`: all 104 additional oracle rows match after a narrow CR16
conditional-flow improvement, with original failures preserved. Hexagon remains helper-gated. The decompiler
library passed 131 tests with one ignored; this is not a full-ISA or C-ABI claim. Checked factory/gate plumbing
at `d330163` passed its scoped 402 distinct cases and source review, but real-profile gate projection and
Raw/ordinary selector/listing/search integration remain pending.
The combined API regression run after the width, native-roster and factory changes passed 756 tests with
nine ignored. The reviewed full-roster window/gate integration is the next execution gate; its matrix
retains both 32-function denominators and reports computed/gated misses rather than assuming full recall.
The applied full-roster window core passed source review and 30 window tests. Measured manual-seed entry
retention is 32/32 with 23/32 exact extents; call-only discovery is 27/32 entries and 20/32 exact extents.
PIC computed calls and context/delay/helper gates remain explicit misses. Native validation passed 133
tests with one ignored. All eight API/CLI/MCP frontend checks and source re-review passed after aligning
valid-unknown retention and generating the schema from the central registry. The interface checkpoint is
`8d52a25`; this is not ordinary Project, packet-helper or C-ABI acceptance.

Phases 4.2–4.4, analysis-depth Phase 5 and scale/persistence Phase 6 follow in roadmap order. Implementation
completion of earlier phases does not close the independent live/N, library-recall or agent-efficiency gates.

Earlier Phase 3 delivery implemented annotation-backed effective bytes, bounded assembly, create-new export,
compact views and batching through existing history. Its mechanical and live measurements retain their separate
acceptance limits. No commercial target execution or in-place binary modification is authorized.

### Implemented Phase 1 milestones

- [x] 1.3 Apply types to data and operands.
- [x] 1.4 Stack-frame inspection.
- [x] 1.5 Type propagation with analyst edits taking priority.
- [x] 1.6 PDB/DWARF type import with identity and layout checks (implementation complete; live sign-off above).

## Audio/firmware investigation acceptance workloads

The batches below track investigation outcomes and remaining blockers, not a competing feature queue.
The goal is to answer: what features exist, where their code lives, how parameters reach processing, and
which links are static candidates versus observed execution. Ship reusable improvements driven by actual
investigation obstacles, not a plugin-specific analyzer or another extension framework.

### Validated investigation baseline

- [x] Reproduce and fix native decompilation rejecting mapped code reached below the requested entry;
  owned x86-64/AArch64 regression and real installed-image retest.
- [x] Add explicit MCP `decompile(view="code")`: complete C text without token/graph bulk, retaining native
  diagnostics, recovery status, exact-entry context and visible detail omissions; oversized code still refuses.
- [x] Recognize ARM64 literal-load import stubs and preserve Mach-O entry-leading NOPs without changing ELF
  resolver-padding handling; owned positive/negative regressions and real installed-image retest.
- [x] Close the baseline batch with scoped validation and independent review; retain the broader-run timeout
  limitation and keep machine-local MCP configuration separate. Full-workspace/release acceptance is not claimed.

### Next three execution batches

#### Batch 1 / P0: navigate static data and descriptors without external tools

Question: starting from a named processing block, which record identifies it and which functions does it reference?

- [x] Reproduce the current manual descriptor-table traversal and record the external-tool handoffs and
  unresolved links. Choose one already-located block and a second block as a transfer check.
  Repeated two related block traversals with MCP data inspection/decompilation; the table/string inspection
  handoffs to external tools are no longer required. This is not the second-vendor transfer gate.
- [x] Add bounded read-only mapped-data inspection to the shared API, CLI and MCP. Reuse existing image
  identity/address/mapping logic; report image addresses separately from file offsets, and preserve gaps,
  unavailable backing and declared zero-fill rather than manufacturing bytes.
- [x] Expose bounded pointer-table inspection with explicit pointer width/data byte order, raw values and
  available relocation/fixup evidence. Distinguish encoded on-disk words, decoded candidates, declared entries
  and runtime observations; never call a raw word a resolved pointer solely because it resembles an address.
  `inspect_data` preserves import library identity, partial-slot refusals and corroborated Thumb address adjustment;
  only retained Mach-O chained rebases are decoded, not arbitrary relocation families.
- [x] Connect inspected entries to existing strings, code locations and references where evidence supports it.
  Unresolved or conflicting entries remain visible; no automatic signatures, renames or annotations.
- [x] Verify the encountered layout on a small owned optimized/stripped fixture, including malformed backing
  and pointer/relocation cases, then repeat both real-block traversals entirely through rampage MCP.
  Owned ARM64/x86-64 Mach-O descriptor fixtures, encoded/partial-slot checks and a native ELF TLS-overlap
  regression passed. Cold metadata opening skips optional language recovery and Project naming indexes;
  independent review findings were corrected and re-reviewed. Publication state is tracked in git history;
  these results do not constitute full-workspace or release acceptance.

Done: name/ID -> descriptor -> initialization, update and processing candidates can be followed in MCP with
source addresses, evidence and unresolved fields. No Python/otool adapter is needed for the two selected cases.
This is descriptor navigation, not proof that a live render invokes every candidate.

#### Batch 2 / P0: explain one complete named effect

Question: how does one simple user-visible effect turn its parameters and input buffers into output?
Choose an accessible EQ/filter/delay-sized effect, not an entire amp suite or a protection wrapper.

- [x] Match the selected catalogue ID and parameter metadata to code/data evidence, keeping resource
  declarations distinct from binary associations and runtime availability.
  One simple mono/stereo catalogue pair is corroborated by symbolic indices and native model records.
  A separately registered matching primitive is located; their composition link remains unproven.
- [ ] Trace the host/core entry, model creation, parameter-update path, processing schedule and sample kernel.
  Record buffer shapes, state, coefficient updates, bypass and sample-rate/block-size behavior where supported.
- [ ] Produce an evidence-linked feature map using existing annotations/workflows where sufficient:
  feature, module/slice identity, address, role, supporting references, confidence and unresolved links.
  Keep the actual commercial investigation local; repository examples use owned inputs and generic descriptions.
- [ ] Fix only the highest-impact blockers on that path. Current candidates are an unresolved bounded ARM64
  parameter-routing jump table and incorrect/missing recovered signatures or mixed integer/float storage types.
  Diagnose the specific shape before choosing a recovery change; warnings remain visible until actually resolved.
  - [x] Bounded fatal-wrapper recognition prevents a real primitive-update function from absorbing adjacent code
    after its assertion wrapper. Re-tested through MCP; throwing imports, conditional/unknown transfers and
    resumable/system traps are excluded, and wrapper reads consume shared preparation budgets.
- [ ] For each fix, show the failing owned case, corrected result and repeated real investigation. Check the
  important arithmetic/control flow against assembly; use source-known fixtures for independent ground truth.

Done: a reader can follow one named effect from controls to sample processing, locate the relevant code in MCP,
and see exactly which associations remain uncertain. A primitive alone or a plausible decompilation is not enough.

#### Batch 3 / P0: transfer to another vendor before expanding scope

- [ ] Apply the same catalogue -> descriptor -> code workflow to one normally installed second-vendor plugin.
  Do not add vendor-name conditions to make the case pass.
- [ ] Find a meaningful processing or parameter/state path, not just exports or a factory forwarding wrapper.
  If activation/protection blocks investigation, record the boundary and select another accessible candidate;
  no license changes, protection bypass, installer execution or security-setting changes.
- [ ] Compare manual handoffs, critical unresolved links and query cost against the starting investigation.
  Record regressions as well as gains; an explicit refusal is honest reporting, not transfer success.

Done: the improvements support a second independent implementation and produce another useful code map.
If they do not transfer, fix the demonstrated general limitation before starting another feature family.

### P1: confirm selected links at runtime (after the first static effect map)

- [ ] Add bounded read-only stack-frame enumeration to the existing stop-token-pinned LLDB protocol and
  API/CLI/MCP; include thread/frame identity and qualified module/image/load addresses with explicit failures.
- [ ] Replace the custom stack-walk script in the authorized disposable-host experiment with rampage queries.
- [ ] Observe one selected processing callback and one parameter/state path when safely reachable, then compare
  them with the static map. Keep registered, reachable and observed-execution claims separate.
- [ ] Preserve the stop identity and DATA-order evidence requirements; ARM64 order remains unknown without
  affirmative stop-bound evidence. No automatic launch/attach/resume/stepping/breakpoints/expressions/writes.

Done: an explicitly operator-stopped disposable host can confirm selected links through rampage alone,
without audio-device output, DAW/project changes or unsupported capture claims. This is not full flow coverage.

### Parallel track: efficient unknown-firmware/binary investigation

Decoder-provider implementation and static investigations can run independently from the plugin queue.
Shared API/CLI/MCP edits and builds remain coordinated; each parallel worker owns a disjoint file scope.

- [x] Initial read-only inventory found a raw update header, an updater label, plausible Thumb instructions
  and readable effect/preset names. Standard executable carving found no validated embedded image; this is
  partial visibility, not a recovered container, proven architecture or evidence of encryption.
- [x] Corroborate two compressed component extents and decode both in memory with explicit LZSS parameters:
  exact declared input consumption/output lengths and matching stored additive checksums; no payload files.
  Traceable initial-vector/startup evidence supports a local Thumb mapping, not a proven physical device map.
- [x] Reproduce the actual tool gap: unknown-file inspect/triage/strings and explicit-offset disassembly refuse
  before useful inspection because they require native executable headers. Zero carve candidates missed the
  proprietary components; it did not establish that the image was empty or encrypted.
- [ ] First enabling slice: format-independent byte/ASCII-string triage on explicit file ranges, with offsets,
  bounded previews, fill/occupied-region summaries and range hashes; no native loader or extraction required.
- [x] Second enabling slice: explicit raw-code windows with file range, address base, architecture, code mode
  and byte order supplied as analyst assertions. Use the existing decoder; no guessed executable layout or seeds.
  MCP and CLI expose bounded original-file windows; owned compiler/IT/literal/boundary cases and a real loader
  window passed. Unknown backward literals and prior out-of-window IT context remain explicit limitations.
- [ ] Use that raw Thumb view to corroborate the initial loader's decode loop, callers and component address
  fields, then follow one decoded startup/control path. Exact chip, field roles and full memory map remain open.
  - [x] Corroborate the ring start, flags, reference assembly and ring wrapping through MCP raw inspection.
- [x] Promote the corroborated codec experiment into an explicit internal decoder-provider interface with
  a built-in LZSS-4K variant, not a public SDK or triage-plugin ABI change. Shared API/CLI/MCP accept an explicit
  file range, codec, dictionary parameters and supplied output size, returning transient bytes/receipts only.
  Source-range/output hashes, consumed/trailing counts and decoded-offset previews remain separate from
  container authentication, source offsets and load addresses. No file publication or execution is supplied.
  Both real components reproduced the independent decoded hashes, exact input/output lengths and stored
  byte sums through the CLI; raw-code loading and the complete loader contract are still open.
- Static only: no updater/installer execution, flashing, emulator execution or security changes. Do not turn
  this into an automatic unpacker or a generic firmware framework before the first traced loader path.

### Execution rules for speed

- One active slice per independent track; shared-file edits and the central build queue stay serialized.
  Each batch ends with a usable investigation result and a short next blocker.
- Use MCP first. Scripts are for genuinely necessary host/process coordination, not routine JSON consumption.
- Timebox an unproductive investigation to 60-90 minutes; record the exact missing evidence or failing query,
  then choose the smallest enabling fix or another accessible target rather than expanding the framework.
- Run changed-area regressions and a real before/after first; expand validation for the touched consumers
  before publication. Use shared `target/`, two build jobs and the existing low-debug/non-incremental profiles.
  Review nontrivial diffs independently; retain timeout/failure limits instead of reporting an unearned pass.
- Keep commercial binaries, payloads, extracted code, captures and secrets out of git. Commit only generic
  implementation, owned fixtures and generic documentation. No release tags or CI dispatch for ordinary work.
- Defer general resource-import frameworks, broad C++ reconstruction, new component-plugin infrastructure,
  raw-firmware support and UI expansion unless the active investigation demonstrates they are the next blocker.

## IDA/Ghidra gap-closing wave 2 (done this round)

- [x] Signatures extended to the fixed-width sets: 32-bit ARM (A32 and Thumb), MIPS/MIPS64 and PowerPC/PowerPC64,
  masking PC-relative branch/call targets in the target's byte order (`function_hash`/`identify` take a `Target`).
  Conservative: MIPS HI/LO address pairs are left unmasked (lowers match rate, never a false match).
- [x] Stripped C++ RTTI recovery: `rampage_analysis::rtti` scans Itanium type_info chains and MSVC RTTI (COL /
  TypeDescriptor / class hierarchy) to recover class names and base-class edges with no symbols, bounded and
  image-backed, surfaced via `ClassRecovery.rtti_classes` (de-duplicated against the symbol path). Pointer
  arithmetic is overflow-hardened. MSVC path is synthetic-tested only (no MSVC toolchain locally).
- [x] Go binaries: `rampage_loaders::gopclntab` recovers function names from the pclntab
  (go1.2/1.16/1.18/1.20+ magics, either endianness) and `Binary::open` attaches them automatically, so stripped
  Go names surface everywhere. Section-based (`.gopclntab`/`__gopclntab`), with a bounded magic-scan fallback
  over read-only/relro sections when the dedicated section is absent or renamed; a text-section anchor is required.

## IDA/Ghidra gap-closing wave 1 (done earlier)

- [x] Library identification (FLIRT/Function-ID style): `rampage-signatures` masks position-dependent bytes
  (relative branch/call targets, x86 RIP-relative displacements, AArch64 PC-relative encodings) and matches a
  function across differently linked builds. `SignatureDb` build/apply; `rampage signatures`/`identify` CLI;
  `build_signatures`/`identify_functions` agent tools. x86, x86-64, AArch64.
- [x] MSVC name demangling and C++ class names recovered from Itanium/MSVC vtables (analysis metadata).
- [x] Discovery recall: PLT resolver and stub functions are seeded (closes the dynamic-fixture recall gap).
- [x] Decompiler: flaky worker-timeout test made deterministic; prototype table expanded (C++ runtime, Win32);
  jump-table recovery confirmed surfaced in structured results.
- [x] PDB reader: `rampage_loaders::pdb::pdb_symbols` reads MSVC procedure/public symbols to names+RVAs,
  bounded and panic-free (error paths tested).
- [x] Capability detection: `rampage-capabilities` tags behaviors (networking, injection, anti-debug, crypto,
  filesystem, registry, input capture, dynamic loading) from imports/symbols/strings. `capabilities` tool + CLI.

### Pending follow-ups from this wave

- [x] Explicit PDB name preview/apply API with matching PE/PDB GUID and age, checked RVA/VA arithmetic and
  readable executable backing. Names only discovered unnamed entries, preserving labels in one undoable batch;
  real owned LLVM/LLD PE/PDB fixture. OMAP, types/layouts and a dedicated UI import action remain separate.
- [x] Types-group `import_pdb_names` shared tool/MCP: explicit path, preview default and whole-batch apply,
  undoable with preserved labels. Byte-capped JSON pages retain identity, totals and success status independently
  of detail selection. Malformed architecture selectors refuse before project loading or edits.
- [x] Canonical CLI `type import-pdb-names`: explicit PDB path, preview default, bounded receipts and whole-batch
  atomic apply. Existing annotation values persist; undo history is process-local and is not recovered after CLI
  exit. Non-UTF-8 PDB arguments reject before loading; native non-UTF-8 PE fixture coverage is Linux-only.
- [x] Checked PDB consent core: opaque immutable Project-bound preview, selected-image and same-buffer PDB digests,
  current provenance validation, and application restricted to originally approved pairs still eligible under lock.
  Late stale errors discard staged annotation cache/history/cursor changes, preserving external disk edits.
  This does not expose a UI action or strengthen legacy path-based CLI/MCP import into frozen consent.
- [x] Bundled starter signature databases: `rampage identify` applies a bundled musl libc database for the
  binary's architecture (x86-64, aarch64) out of the box; a user `--db` overlays on top, `--no-bundled` opts out.
  Generated reproducibly by `tools/gen-signatures.sh` (pinned zig). Follow-ups: more libs (libstdc++/libc++),
  more arches, and glibc/other musl versions; a database matches only the exact library build it was made from.
- [ ] MIPS signatures: mask `lui`/`addiu` HI/LO address pairs. Needs relocation/dataflow to avoid false matches
  (without it, a masked constant could collide two different functions); do it relocation-gated, not heuristic.
- [ ] Verify the MSVC RTTI path against a real PE (no MSVC toolchain locally; synthetic-tested only).
- [x] Signature confidence: `function_hash` gates out non-discriminating bodies (single-branch thunks, all-nop
  padding, too-few-instruction stubs) by minimum instruction count, non-masked content bytes and distinct
  encodings, so such bodies are neither stored nor matched. Malformed/truncated/unaligned regressions added;
  hashing is unchanged for accepted bodies. Thresholds are conservative heuristics (only ever stricter).
- [x] PE enrichment: TLS callbacks seed function starts and delay-load imports surface as slots (bounded,
  panic-free on malformed PEs).
- [x] Go pclntab: bounded magic-scan fallback over read-only/relro sections when the dedicated section is
  absent or renamed; absent section headers/text anchors remain unsupported.
- [ ] C++ class LAYOUT reconstruction (fields/sizes), building on the RTTI name/hierarchy recovery now in place.

### Capability-detection rules (capa-style, defensive triage)

These are static metadata indicators, not proof of execution or malicious intent. New rules require independent
corroborating groups; aliases and duplicate inputs cannot replace missing groups. Each has positive and benign
negative regressions. Existing rules retain their detection thresholds and canonical evidence contract.

- [x] Bounded persistence indicators: anchored registry Run/RunOnce keys, string-corroborated task registration,
  and service installation APIs.
- [x] Process discovery / enumeration (snapshot + first/next-process walk APIs).
- [x] Code-injection refinements: corroborated `remote-process-injection` rule (remote-process access, remote
  code placement incl. section mapping, and remote execution-start groups), alongside the legacy threshold rule.
- [x] Token / privilege indicators (token-open + privilege lookup/adjust APIs, corroborated SeDebugPrivilege).
- [x] VM/sandbox fingerprinting: firmware-table/adapter reads corroborated by a hypervisor artifact string.
  Import-based only; CPUID-based detection is an instruction, not an import, so it is out of reach here.
- [x] Bounded GDI capture, clipboard read and registered raw-input indicators with independent API groups.
- [x] Credential-access indicators: marker-corroborated LSA private-data access and protected-registry
  open/query/path groups with optional recognized machine-hive prefixes; no extraction or execution attribution.
- [x] Service control, named-pipe/IPC, DNS resolution / network-communication refinements.
  - [x] Corroborated service control, named-pipe client/server and DNS-plus-network indicators. C2 attribution
    is deliberately out of scope: static metadata cannot establish it.
- [x] Narrow ransomware indicators requiring encryption, enumeration start/walk, file writes and two ransom-note
  string groups; ordinary encryption/file access is insufficient.
- [x] Shutdown/reboot and environment/system-info gathering.
  - [x] Corroborated system-information/host-name/environment indicators.
  - [x] Corroborated `system-shutdown` rule: a shutdown/reboot API with a shutdown-privilege indicator.

### Licensing

- [x] Adopt Apache-2.0 project-wide (all crates and the workspace). Added a root `LICENSE` (Apache-2.0 text,
  previously missing) and a `NOTICE` attributing the vendored Ghidra decompiler (Apache-2.0) and the Arm AARCHMRS
  decoder tables (BSD-3-Clause). The audit found no copyleft blocker: deps are permissive except `colored`
  (MPL-2.0, dev-dependency only, not shipped) and a few `... OR GPL/LGPL` multi-licenses where the permissive
  option is elected. Trade-off accepted: Apache-2.0-only is one-way incompatible with GPLv2-only downstreams,
  which the former `MIT OR Apache-2.0` dual avoided.
- [x] Generated `THIRD-PARTY-NOTICES` for binary distributions (`python3 -I tools/third-party-notices.py`): the
  crates linked into `rampage`/`rampage-worker`/`rampage-ui` (no dev, build or proc-macro crates), deduplicated
  texts, plus the vendored Ghidra and Arm texts. Crates that publish no licence file are covered from the
  upstream file (yara-x), a same-repository package under the identical licence, or the standard text of the
  elected licence with holders from package metadata -- each labelled with its source. No copyleft-only crate.
  Regenerate whenever Cargo.lock changes.
- [x] UI About window (click the brand label): version, Apache-2.0, NOTICE, the bundled egui fonts' licences
  (UFL-1.0, OFL-1.1, MIT/Bitstream Vera, MIT) and THIRD-PARTY-NOTICES; snapshot `about.png`.


## Heuristic-database layer (pluggable detection DBs)

One pluggable detection layer: each database is a data file, permissive defaults bundled in-tree, everything
else user-supplied at runtime; every hit is a tagged finding (kind, name, confidence, evidence), not proof.
Licensing discipline: bundle only permissive, author our own starter sets, load the rest at runtime.

- [x] Packer/compiler/protector/installer/linker identification (`rampage-detect`): EP byte-pattern + section +
  import + overlay/entropy signatures with Strong/Tentative confidence, an authored Apache-clean starter DB, and a
  user-supplied PEiD `userdb.txt` parser. Packer path is synthetic-tested only (no packed fixture: no UPX here).
- [x] YARA engine (`rampage-yara`): `yara-x` 1.21 (BSD-3-Clause) runs user-supplied rule files/directories or
  inline source; per-rule matched-string capture is bounded. Rule corpora stay user-supplied.
- [x] capa-rules import (`rampage-capabilities::capa`): file-scope import/string/substring/section/export subset
  with and/or/not/optional/N-or-more; disasm features, `match:` references and non-file scopes are skipped.
  `Capability` now owns its strings (`Cow`), so loading rules repeatedly does not leak.
- [x] Integration: `Project::{detect_tools, yara_scan, yara_scan_path, detect_capa}`, CLI `detect`/`yara`/`capa`,
  MCP `detect_tools`/`yara_scan`/`capa_detect`. NOTICE unchanged: nothing upstream is vendored.
- [x] Confidence tuning: a `UniqueSectionName` condition marks tool-branded section names (`.gopclntab`, `.vmp0`,
  `.themida`, `.MPRESS1`, ...) as distinctive, so a lone match reports Strong; shared names stay corroborating.
- [x] Crypto/compression constants (`rampage-constants`): 74 spec-derived constants (AES, DES, Blowfish,
  Twofish, MD5, SHA-1/2/3, RIPEMD-160, ChaCha/Salsa, GHASH, CRC families, Deflate, Base64/32, P-256,
  secp256k1, Ed25519), most generated in code; both byte orders; min-length and information guards. Not
  detectable by constants: RC4, Adler-32, HMAC, TEA, Poly1305. Misses SIMD-interleaved and immediate-encoded
  constants.
- [x] `find_crypto` workflow: constants (crypto vs checksum/compression/encoding), crypto library APIs, the
  functions referencing either via xrefs, and crypto capability tags. Links Go's ChaCha constant to
  `internal/chacha8rand.block` on the arm64 fixture. No committed fixture carries AES/SHA tables yet.
- [ ] A real packed fixture (UPX or similar) once a packer is available, to test the packer path end to end.
- Won't do: `yara-x` feature trimming. Its build weight is `wasmtime`/cranelift, a mandatory dependency on
  native targets (rules compile to WebAssembly); disabling modules would not remove it and would break user
  rules that `import` those modules.
- [ ] Later DB kinds: Ghidra FidDb import (Apache, library-function ID, format conversion); ClamAV `.ndb/.ldb`
  as a user-supplied runtime input (GPL data -- never bundled); richer capa features once disasm extraction lands.

## Heuristic flywheel (propose -> measure -> gate -> promote)

Strategy: `docs/plans/2026-10-12-heuristic-self-improvement-flywheel.md`. The model proposes heuristic edits, a
corpus with ground truth judges them, and the versioned DBs hold what passes. The gate is the boss: promote only
on held-out, per-slice improvement with provenance and rollback.

- [x] Phase 1 (`docs/plans/2026-10-12-flywheel-phase1-execution.md`): `rampage-eval` crate and binary,
  strip-and-compare matched-pair corpus (`tools/eval-corpus.sh`), precision/recall and a disagreement set for
  library identification per slice, gate = no wrong and no spurious names, committed baselines.
- [x] First turn of the loop: the disagreement set showed aliased functions (`malloc`/`c.malloc.malloc`) being
  dropped as ambiguous hashes. Fixed in `SignatureDb::from_binary` (one spelling per address, shared
  `alias_rank` with the eval truth): recall 0.400 -> 0.723 (x86_64), 0.296 -> 0.580 (aarch64), precision 1.000;
  bundled musl DBs regenerated (96 -> 166, 98 -> 173 signatures). Correction: an earlier note here called the
  Phase 1 target a stripped twin of the reference; it was always a different program (`signatures-target.c`),
  so these gains were already cross-program (with a truth that still counted program code such as `main`).
- [x] Slices: `libid-twin-*` (stripped copy of the reference), `libid-cross-*` (a different program, truth limited
  to identifiable library code via `truth --library --program`), `discovery-*` (function starts vs symbols).
  Per-slice gates: no wrong names, no spurious library names, recall floors.
- [x] Second turn: absolute-address masking (hash scheme 2). x86/x86-64 displacements and immediates pointing
  into the image, and AArch64 ADRP low-12-bit offsets, are masked; databases carry their scheme so legacy ones
  keep matching exactly; ambiguous masked hashes fall back to exact hashes (gmtime/localtime). Measured:
  libid-cross recall 0.746 -> 0.921 (x86_64), 0.595 -> 0.823 (aarch64), precision 1.000, twins unchanged.
  (An earlier note here claimed 47 names from `rampage identify` on each musl fixture; re-measured after the
  review fixes it was 58 and 66, and is now 59 and 71 -- see below.)
- [x] Discovery false positives on aarch64: AArch64 switch jump-table bases (`adr` + `add ..., lsl` + `br`) inside
  a function no longer seed functions (they cascaded into interior blocks of `printf_core`/`vfscanf`); every other
  in-body code address still seeds (callbacks, code after noreturn calls). Precision 0.737 -> 0.990; the two left
  (`_start`, `__set_thread_area`) are real functions the truth omits (no symbol size).
- [x] AArch64 switch jump tables resolved in discovery: a `cmp` immediately followed by `b.hi`/`b.hs` bounds the
  index; byte/half/word/doubleword tables (signed and unsigned) through `adr`/`adrp+add` with lsl/extends, plus the
  absolute 64-bit form; entries only from read-only file-backed data; every target aligned decodable code; at most
  4096 entries; no branch may join between the `cmp` and the `br`. Cases are `switch` CFG edges (function_graph,
  SSA, summaries, export-cfg) and jump xrefs, not seeds. Bounds survive only instructions whose register writes are
  fully modelled. aarch64 reference extents equal to symbol size: 188 -> 193 of 193; AArch64 chain agreement with
  Ghidra 100% on blocks and edges.
- [x] Resolved switches retain table-order entries and the guard address; native SSA pseudocode prints cases
  and recovers the index operand when available. Bounded non-fall-through switch regions structure explicitly;
  unsupported shapes retain the
  labelled fallback (`ddeed9c`, `a5a07e2`).
- [x] AArch64 inverse `b.ls`/`b.lo` bounds are applied only on the taken edge; scheduled immediate comparisons
  survive audited NZCV/index-preserving instructions and agreeing joins. Weaker/incomparable proofs retain the
  original bound/guard; native SSA consumers locate the actual flag-consuming branch and bounded successor.
- [ ] Additional bound/comparison forms (including `BC.cond`) and broader compiled scheduling acceptance.
- [x] x86/x86-64 switch jump tables: absolute `jmp [reg*8+table]` (i386 `[reg*4+table]`), `mov`+`jmp`, relative
  `lea`/`movsxd`/`add`, MSVC image-base form; bounds from unsigned `cmp`+`ja`/`jae` or a low-bits `and` mask; the
  same join, read-only-table and 4096-entry rules. Register facts are forgotten where a branch joins the run
  (`Disassembler::join`, all architectures). Ghidra-only blocks: eval-ref-x86_64 328 -> 8, hello-x64.exe 239 -> 44.
- [x] Cross-block switch facts: must-dataflow carries only facts agreed on by every incoming edge; added cases
  are revalidated against the expanded graph. The earlier eval-ref-x86_64 and hello-x64.exe dispatches resolve
  (`e8622fd`); the updated x86-64 chain-block/edge benchmark agrees with Ghidra on the affected fixtures.
- [x] Real compiler-generated PIC i386 acceptance fixture, including combined memory-source addition,
  native-width dispatch and modulo-32-bit target arithmetic. Case-order/default and malformed-table regressions
  pass; this is not acceptance of all compiler or dispatch variants.
- [x] Noreturn analysis: a curated, case-sensitive list (C/POSIX, C++ ABI, Win32/CRT, Rust, Go; stubs, thunks and
  slots by name) plus incremental all-paths inference; conditional calls/returns and resumable traps handled; noreturn
  calls are terminal in structure/pseudocode, marked for the decompiler, and carry `listed`/`inferred` evidence in
  function_graph and export-cfg. Go edge precision vs Ghidra 95.3% -> 99.3%; go-arm64 structured functions 578 -> 755.
- [x] Noreturn inference through mutual tail calls (`3f0eeaf`): a greatest fixpoint over the tail-call graph,
  requiring a path to an evidenced non-returning call or trap. Cycles without that evidence remain unknown.
- [x] Get-PC call-to-next only when the following code reads the return address (delay-slot aware; x86, MIPS, PPC,
  SPARC, ARM/Thumb/AArch64); PE import thunks seeded so tail jumps stay tail calls; undecodable starts dropped in
  discovery phase 2; RISC-V branch targets rendered absolute.
- [x] Memory read/write addresses are data, not code-pointer seeds (`b4c5b3f`). Formed code addresses and loaded
  read-only pointer values remain separate evidence; the hello-arm literal-pool phantom functions are gone.
- [x] Library-ID misses explained and mostly fixed: signatures also hash the extent discovery finds (it stops at
  unresolved jump tables), and callee-name keys (`identify_program`, iterated) separate bodies that differ only in
  their callee (`mbstowcs`/`wcstombs`, `fprintf`/`sscanf`, `fmodl`/`__addtf3`). Callee keys apply only to bodies
  that pass the confidence gate (ignoring landing pads and the final branch) and whose masked hash is ambiguous; a
  user database's lookups outrank the bundled one's. Recall: twin x86_64 0.920 -> 0.977, cross x86_64 0.921 ->
  0.937, twin aarch64 0.876 -> 0.927, cross aarch64 0.848 -> 0.886; precision 1.000. (A first version also named
  gate-rejected tail-call stubs -- `atof`, `gmtime`, `localtime`, `strftime`, `__stdio_seek` -- and briefly reached
  0.953/0.899; review found it would misname user thunks and wrappers, so those floors were set back.)
  Remaining: musl `dummy` stubs (ambiguous), gate-rejected 2-3 instruction stubs and leaves (`__errno_location`,
  `difftime`, the above), `__lctrans`. Rebuild the bundled DBs whenever discovery extents change.
- [ ] Masking for 32-bit ARM literal pools and MIPS `lui`/`addiu` pairs, once a cross-program fixture exists.
- [x] Tool-identification slice (`toolid`, `tests/fixtures/data/eval-truth-toolid.json`): `detect_tools` against
  the build-script toolchains of 46 committed fixtures; recall 0.4397, precision 0.9538.
- [x] Tool-ID flywheel turn 1: a runtime kind (MinGW-w64/glibc/musl), MinGW/GCC -> MinGW-w64 runtime, LLD on PE from
  the CodeView record, Apple ld/LLD from Mach-O `LC_BUILD_VERSION`, Zig from `compiler_rt.` symbols. Rules are scoped
  to their format and region (no whole-file strong matches; overlay excluded; PeID entries PE-only). toolid recall
  0.4397 -> 0.7872, precision 0.9538 -> 1.0; out of sample (1,354 system binaries) no implausible strong detection.
- [ ] Tool-ID remaining: Zig on stripped builds and PEs, Clang on Mach-O/PE (no producer record), the whole-file
  "rustc version" rule (tentative; scope or drop), real NSIS/Inno Setup installer fixtures, a Zig-language Mach-O
  fixture.
- [x] DWARF-backed type-recovery evaluation: freestanding stripped twins per architecture, scoring parameter
  count, void/value returns and parameter type classes against bounded debug truth, with per-metric gates.
  This measures signature recovery, not aggregate/class-layout recovery or general type correctness.
- [ ] PDB-backed type truth and automated proposal/gate/promote stages with held-out provenance and rollback.

## Ideas from adjacent projects (REA, Ghidra-MCP)

REA ("Reverse Engineer Anything") is an open CLI+MCP orchestrator over external engines (Ghidra/Hopper/IDA) with
multi-format front-ends and guided workflows. rampage builds its own engine and embeds Ghidra, so the value is
in UX/workflow ideas, not the multi-engine dispatch:

- [x] Guided investigation workflows (`crates/rampage-api/src/workflows/`): `triage_report`, `find_main`,
  `network_surface`, `find_crypto`, `diff_builds`. Uniform bounded report (findings with evidence, source tool and
  confidence; truncation stated; next-step tool calls; limitations); MCP tools, `rampage report`, and the MCP
  instructions now point clients at `triage_report` first. Follow-ups: MSVC CRT startup chain in `find_main`
  (no MSVC fixture), startup heuristics beyond x86-64/AArch64 ELF, more workflows (e.g. persistence, unpacking
  triage, string decoding).
- [x] .NET/ECMA-335 metadata (`rampage_loaders::dotnet`): CLI header, streams, Module/TypeRef/TypeDef/Field/
  MethodDef/Param/MemberRef/Assembly/AssemblyRef/NestedClass with every other table sized; IL body headers;
  never seeded as native code. API `dotnet_metadata` (paged, filterable), `rampage dotnet`, MCP tool, and
  `triage_report` routes managed assemblies to it. Validated on Microsoft.Bcl.HashCode 1.1.1 (MIT, committed with
  its licence). Signatures/generics, primitive attributes, P/Invoke and IL/exception decoding were added below;
  remaining metadata includes resource payload interpretation and richer attribute arguments.
- [x] Embedded-binary carving (`rampage carve`, MCP `carve`, `rampage_api::carve`): bounded scan for ELF, PE,
  Mach-O (thin and universal) and zip/gzip/xz/zstd/LZMA/squashfs/cpio/uImage/Android boot, with validated header
  facts, header-derived extents, validated or magic-only confidence and a 4096-candidate cap.
- [x] Open an embedded executable: `Binary::open_at`, `Session::open_at`, global `--image-offset` / MCP
  `image_offset`, offset-keyed sidecars, triage reports the image's own hashes and where it sits.
  `--image-length`/`image_length`, `Embedded.trailing` with a triage hint, `.rampage-image` sidecars that cannot
  collide with plain ones, offset 0 without a length is the plain file.
- [x] Open embedded images in the UI (`a8ac21e`): Carve window, validated executable candidates, explicit offsets
  and optional lengths, including files that do not open as a whole image. Sessions reload changed binaries;
  diff-builds supports `--other-image-offset`.
- [ ] APK (JADX) and Electron unpacking are lower-priority follow-ons; carving is not archive extraction.
- [x] Bounded standalone ZIP32 central-directory metadata inventory through API, canonical CLI and MCP, with
  archive/member references, ordinals for duplicate names, explicit name/count/work limits and byte-bounded pages.
  Tail search may overlap member data; no local/member offset is followed, payload validated, decompressed,
  extracted or automatically opened. ZIP64, multi-disk, SFX inference and directory gaps remain unsupported.
- [x] .NET: ECMA-335 blob signatures (method/field/MemberRef, TypeSpec, GenericParam names) rendered ILAsm-style
  with depth/node/text caps and an `<unreadable>` fallback; ImplMap P/Invoke (DLL + import per method);
  CustomAttribute rows with type, target and primitive/string/Type fixed arguments; nested types as `Outer/Inner`.
  In dotnet_metadata/CLI/MCP with a `list` selector (types/pinvokes/attributes). Decode work (blob bytes and text)
  is charged to one image-wide budget; array shapes are bounded by rank.
- [x] CIL disassembler: `dotnet_il` (API, `rampage dotnet --il`, MCP in the dotnet group): all Partition III
  opcodes with resolved tokens and signatures, generic instantiations, escaped capped `ldstr`, branch/switch labels,
  LocalVarSig locals, small and fat exception clauses; bounded and fuzzed; hand-verified (no ildasm locally).
- [x] .NET property signatures, including ref returns, generic/index parameters and bounded same-owner accessor
  tokens, with PropertyPtr order preserved. Fixed/named primitive/string/type, single-dimensional arrays and
  verified local integral enums decode within shared budgets; named failures retain valid fixed arguments.
- [x] .NET events: tokens/names/flags, bounded type rendering and same-owner add/remove/fire/other bindings through
  API/CLI/MCP metadata, with EventPtr order and event-name filtering. Invalid/duplicate map owners cannot steal
  later valid targets. Strict alias/function-pointer grammar and shared-budget regressions retain unreadable evidence.
- [x] Bounded ManifestResource inventory and independent API/CLI/MCP resource pages, preserving raw offsets/flags,
  File/AssemblyRef and invalid/unsupported link evidence. Directory bounds/backing are numeric checks, not payload
  validation. Row/name budgets, UTF-8 truncation and declared/readable/retained/returned counts are explicit;
  `declared_known` preserves unknown versus observed zero and recovered partial-header counts.
- [x] Bounded fixed/named boxed custom-attribute values and `object[]` elements, including supported boxed vectors,
  with explicit serialized-type rendering and failed-work budget regressions. Direct jagged constructor/attribute
  types remain rejected; ordinary signature rendering and boxed vectors are distinct serialization cases.
- [x] Verified local enum field constants through existing API/CLI/MCP type metadata: exact integral-type/value
  strings across all eight widths, aliases retained, strict VALUETYPE/owner/flags/type/padding/blob checks.
  Works without custom attributes. Duplicate parents invalidate field evidence; incomplete/over-limit Constant
  tables yield none. Numeric/boxed attribute rendering is unchanged; no symbolic substitution or flags synthesis.
- [x] Exact canonical escaped local enum identities, with structural nesting distinct from literal reserved
  characters, complete unique local identity evidence and verified widths. Initial nesting reads reserve shared
  work before inspection and cap readable rows at 100,000. Partial/invalid indexes cannot prove uniqueness.
- [ ] .NET external or assembly-qualified enums, symbolic enum-attribute names, resource payloads,
  and comparison of `dotnet_il` with ildasm/ILSpy once available. Metadata bindings do not establish accessor behavior.
- [x] Agent batch annotation: `annotate_batch` (all-or-nothing, at most 1000 entries, one undo step, per-entry
  outcomes) and the read-only `check_names` pre-flight, over MCP and CLI. Undo/redo return the step's edits. Name
  checks run under the cross-process log lock; batches are logged under a header line and replay all-or-nothing;
  undo/redo refuse to restore a name another client has taken.
- [x] `discard_undo` drops an undo step another client blocks (refuses unblocked steps unless forced). Reloads keep
  undo history; annotation logs record the image SHA-256 and warn when annotations were made on different bytes.
- [x] UI action for discarding a blocked undo step (`ab31d28`), showing the conflict without forcing the undo.
- [x] CLI `compare-runtime` / `runtime bytes compare` original-image offset and optional length, preserving
  architecture selection, selected-image hash/UUID/address domains and annotation-free loading. Independent
  identity/hash goldens plus malformed universal/truncation/overflow/mismatch controls pass.
- [x] Shared-tool/MCP original-image offset/length selection for runtime-byte comparisons, using the capture's
  architecture and fresh annotation-free inputs. Strict top-level arguments reject misspelled selectors; integer,
  decimal/hex and null forms, identity goldens, malformed headers and changed capture architectures are tested.
- [ ] Per-path pointer-comparison offsets. Nontrivial image selection
  does not load embedded snapshot JSON; pointer-peer flags alone would not establish usable support.
- [x] MCP tool groups: every registry tool has a group; `rampage mcp` lists core + `enable_tools` (lists groups,
  enables them, sends tools/list_changed); `--all-tools` / `RAMPAGE_MCP_TOOLS` for clients without list_changed;
  calls to disabled tools error naming the group. The in-app agent and UI assistant still offer every tool.
- [x] `persistence_surface` workflow: autostart-location strings (Windows Run/services/tasks/Startup, launchd,
  systemd, cron, XDG autostart, rc/init), service/registry-write APIs, referencing functions, capability tags.
- [x] `string_decoding` workflow: static candidate decoders (bounded byte load/transform/store loops), call sites
  and the encoded-looking blobs passed to them; no emulation.

## Plugin system (later)

Native `.so`/`.dylib` plugins are out: Rust has no stable ABI, and a tool that reads hostile input should not load
unsandboxed native code. Three layers instead, in this order:

- [x] Data packs: `rampage-pack.toml` packs (signatures/peid/yara/capa) loaded strictly with contained paths and
  size caps via `--pack`/`RAMPAGE_PACKS`; applied to identify (before bundled, in pack order), detect, yara and
  capa; `rampage packs list|check` and MCP `list_packs` with licence/provenance and per-content status.
  Review fixes: YARA `include` refused in every rule set; files opened without following links and checked against
  what was budgeted; running per-pack and overall budgets, at most 64 packs, lazy loading; signature matches carry
  their `source`; pack problems reach detection `warnings` and the MCP instructions.
- [x] Constants packs (`f5eecda`), UI pack loading/status (`d769e82`), pack-only `identify --no-bundled`
  (`8379e5d`) and single-reporting of pack PeID problems (`8e7de84`). Constants retain information guards and
  pack provenance; packs remain bounded data inputs, not executable extensions.
- [x] Internal trait registries: guided workflows implement `Workflow` and are listed once in `WORKFLOWS`; the
  tool list (MCP, assistant) and `rampage report` enumerate it, with tests that each is unique, a tool of its group,
  served by MCP, named in the instructions and parsed by the CLI (docs/plugins.md). CLI and MCP output unchanged
  byte for byte. Not done, because nothing hand-dispatches over them: `Detector` (detectors take different inputs
  and return different evidence; packs extend them), `Loader` (ELF/PE/Mach-O already load through `object`; worth
  it when a format `object` cannot parse arrives) and a separate `ToolProvider` (workflows contribute their tools
  through their registry).
- [ ] WASM component plugins (wasmtime is already a dependency via yara-x): sandboxed, language-agnostic code for
  detectors, format loaders and workflows behind a WIT interface; bytes plus read-only analysis queries in,
  findings out. The output schema enforces the evidence/confidence/limitations contract.
  The bounded triage-component milestone below implements the first explicit executable lane and genuine guest
  composition, not general detector/loader plugins, automatic discovery, or a stable public SDK. Static builtin
  registries remain separate. Broader capabilities and module migration require independent acceptance.
- Freeze a public plugin API only after the internal traits settle. Many extensions need no in-process plugin:
  another MCP server composes with rampage at the agent level.

### Experimental triage component milestone

- [x] Owned Rust source builds to core Wasm and then a genuine WIT component. The import-free ABI 0.0.1 uses
  schema-1 fact/report bytes, a scalar output length and fixed 32-byte chunks; output admission precedes copying.
  The guest performs classification, ranking, grouping, report composition and recommendations, not a builtin
  workflow callback. All 14 native guest oracles and six compiled differential cases passed.
- [x] Separate trusted plugin worker reuses owned byte supervision without decompiler protocol spoofing or inline
  fallback. Raw recursive counts/types and flat JSON/hex envelopes are admitted before allocating readers;
  unsupported component forms are explicit. Wasmtime 49.0.3 is pinned for this lane, separately from YARA.
- [x] Actual compiled probes cover fuel, execution epochs, memory growth, oversized and malformed output,
  wrong interface version, ambient imports, pre-cancellation and recovery. Process isolation is not an OS sandbox;
  neither guest fuel nor execution epochs cover native preparation or compilation.
- [x] Host-fixed target/hash/provenance wraps all guest output as plugin claims. References are not proof;
  suggestions remain inert. Exact emitted JSON/text bounds and terminal-control escaping preserve the boundary.
  Complete-or-reject preparation refuses configured packs, unavailable databases and unsupported managed inputs.
- [x] Fresh CLI loading uses descriptor-bound admission before parsing and checked sidecars, with canonical
  unwind spans budgeted against the actual producer. Its conservative profile is unmanaged little-endian x86-64
  ELF only; already-loaded API targets have separate admission. Cold host analysis requires explicit opt-in.
- [x] Ordinary combined workspace: 2,334 passes across 180 groups in 317.7 seconds, 63 opt-ins skipped;
  all 50 evaluation tests passed separately. Initial dependency-rebuild run hit its cap, not an assertion failure.
  Workspace and host/Wasm guest Clippy passed with warnings denied; targeted compiled API/CLI gates passed.
- [x] Additional startup reproduction: 54/54 owned native/isolated attempts passed in three fresh cached-harness
  processes without retries. No stall reproduced, no cause identified and no startup-fix claim.
- [ ] Linux component gate is wired but not locally executed; cancellation inside compilation and uninstrumented
  guest-cancellation latency,
  broader source loading and component grammar, other workflow migrations, MCP/UI providers and a stable SDK
  remain unearned. The follow-up below adds opt-in installation and an instrumented activation checkpoint.
- [x] Protected 1,008-file candidate-source audit, scanner-bypass regressions and committed-tree/history scans;
  controlled Python: 804 tests and 797 subtests passed, six live opt-ins skipped. Owned scratch is removed;
  publication is private main only, without a release tag or CI dispatch.

### Component usability and cancellation follow-up

- [x] Fresh whole-file unmanaged AMD64 PE32+ admission on the actual checked mapping. Regular import/IAT,
  exports/forwarders, TLS, version-1 unwind, matching raw/RVA debug and DIR64 relocation extents are bounded.
  COFF tables/long names, delay imports, resources, security/load-config/bound-import directories, chained
  unwind, CLR/Go and other unsupported profiles remain refused. Code and execute-only sections both fund
  constructor thunk/name expansion before parsing. Independent review closed the classification bypass.
- [x] Central PE/source gates: 39 focused API tests; 15 explicit API and four CLI cases, including the unchanged
  compiler hello fixture, crafted hostile/consumer controls and the renamed owned provider. Target images
  remain static inputs, never executed.
- [x] Opt-in private-control v2 cancellation checkpoints retain the actual Wasm activation and permit through
  owned cleanup. Both call boundaries, panic recovery, uncancelled observers, final-callback cancellation,
  retained cleanup measurements and ordinary recovery passed through the real worker. This is not a loop-body
  or inside-compiler witness, resumable instrumentation or a latency benchmark. Default v1/p4 behavior remains.
  Supervisor library: 97 passed and one isolated helper ignored; fresh ownership/runtime reviews found no blockers.
- [x] `tools/install.sh --plugins` builds the matching trusted worker, retaining an existing regular optional
  worker on upgrades. Owned fake-root tests passed on macOS; no actual user installation was performed.
  Separate exclusive publications preserve unrelated `.new`/backup occupants, retain staging and report partial
  outcomes without rollback or whole-bundle atomicity. Concurrent/hostile staging writers remain unsupported.
- [x] Combined-tree ordinary workspace: 2,372 passes across 181 executable/doctest groups in 401.6 seconds,
  with 66 opt-ins skipped; all 50 evaluation tests passed separately. Clippy/format checks and all three real
  component/resource/cancellation gates passed. No broad latency, inside-compiler or Linux acceptance claim.
- [x] Protected 1,014-file candidate-source audit, scanner-bypass regressions and committed-tree/history scans;
  804 Python tests and 797 subtests passed, six live opt-ins skipped. Owned scratch is removed; publication
  remains private main only, without tags or CI dispatch.

### Mandatory cleanup admission and thin Mach-O follow-up

- [x] Parent-owned mandatory byte-cleanup proof is independent of optional diagnostics/RSS. No spawn, confirmed
  owned-group cleanup plus direct-root reap, and uncertainty are distinct. Guarded callbacks run exactly once
  after cleanup/scoped I/O joins, including unwind. Missing/uncertain proof quarantines future plugin requests;
  the primary failure remains intact, packets cannot clear quarantine, and there is no in-process reset.
- [x] Composed proof tests: 105 supervisor and 27 plugin cases passed, including safely reaped uncertainty
  injection, real permit transitions, missing/duplicate proof and unwind. Healthy real-worker cancellation,
  observer panic and ordinary recovery still passed. A genuine live-worker ownership-loss drill is unearned:
  it must not gain guessed-PID cleanup authority merely for acceptance.
- [x] Conservative fresh thin x86-64 PIE Mach-O admission: canonical mapped layout, format-6 bind-only chains,
  regular non-replayed export trees, symbols/starts and per-stub-byte constructor-name budgets. ARM64/arm64e,
  universal/embedded inputs, dylibs/bundles, classic dyld streams, chained rebases/addends/MULTI starts, signatures
  and language/debug/EH recovery remain refused. Compact unwind remains backed opaque data, not recovery.
- [x] Native consumer oracles cover unchanged full/stripped hello files, multi-page/skipped-page/nonzero-start
  chains, decoys, reserved bits, exact slots/imports/exports/starts/backing and constructor names. A test-only
  observation at real native-open/object-parse entry verifies raw rejection before parsing, without a public hook.
  Focused source preparation: 55 cases; checked loader: four cases; explicit API/CLI gates: 17 and four passed.
- [x] Ten compiled report cases—normal/stripped ELF, PE, normal/stripped thin Mach-O at limits 1/25—matched the
  unchanged builtin body after fresh admission. All component/resource/checkpoint gates and Clippy passed.
- [x] Combined-tree ordinary suite: 2,404 passes across 181 executable/doctest groups in 240.9 seconds after
  compilation was cached, with 66 opt-ins skipped; all 50 evaluation tests passed separately. The first pass
  capped after an 88-second rebuild and 155 completed groups; it was not a suite pass or a startup-stall fix.
  Clippy, format, healthy real-worker recovery, component/resource and explicit source/CLI gates passed.
- [x] Protected 1,017-file candidate-source audit, scanner-bypass regressions and committed-tree/history scans;
  804 Python tests and 797 subtests passed, six live opt-ins skipped. Owned scratch is removed; private main
  publication only, without release tags or CI dispatch.


## Decompiler: embedded Ghidra (the decompilation path)

Decompilation is provided by `rampage-decompiler`, which embeds Ghidra's decompiler (Apache-2.0) in process and
exposes it through `Project::decompile`, the `decompile` tool (API/MCP/assistant) and `rampage decompile`. It
covers every architecture rampage decodes except s390x, renders calls by rampage's own names, applies common
libc prototypes (so string arguments show), and decodes Thumb in Thumb mode.

- [x] Embed the library, build from vendored sources, in-memory image, language-id mapping.
- [x] Decompile to C on demand over all executable segments; read-only data mapped for string folding.
- [x] Feed rampage's function names; apply libc prototypes; Thumb mode for 32-bit ARM.
- [x] Vendor the SLEIGH specs so no external Ghidra install is required (prefer bundled, override with
  `GHIDRA_INSTALL_DIR`).
- [x] Expand the library prototype set to the common C runtime (~130 stdio/string/memory/stdlib/ctype/POSIX/
  math/pthread functions), applied per present symbol, with a test that every prototype parses.
- [x] Function-discovery accuracy benchmark against Ghidra (`tools/benchmark.sh`, `docs/benchmarks.md`).
- [ ] C++ class recovery: typed vtables/RTTI and `this` pointers in the decompiler. The embedded library reads
  types from C declarations or XML, not Ghidra `.gdt` archives, so this needs a header/type pipeline, not a
  `.gdt` import. Larger, separate effort.
- [x] Apply user-set types/signatures to the decompiler and import bounded embedded debug signatures.
- [ ] Richer automatic `main`/entry signature recovery without debug metadata.
- [x] Bundle for relocated/installed binaries (embed specs or install them), so a `cargo install` binary that is
   moved away from its build tree still finds specs without `GHIDRA_INSTALL_DIR`.

### Integration acceptance order

Each increment requires regressions, review and targeted simplification. Sharing Ghidra's engine does not
guarantee identical output: memory mappings, ABI, mode context, symbols/types and options must agree too.

1. [x] Memory correctness: explicit backed/zero-fill/unavailable mappings, read/execute permissions, strict
   instruction-range checks after speculative SLEIGH lookahead and real string terminators. Review fixes cover
   partial-flow retries, target-width bounds, wrapped reads and UTF-16 boundary terminators.
2. [x] Mode correctness: ARM/Thumb transitions independent of request order; merge loader and discovery context,
   preserve equal-valued barriers and accept padding/end boundaries. Each image owns its translator; caches
   invalidate safely. Reviewed regressions cover corrupt specs, interleaved images and a million mode points.
3. [x] Compiler ABI selection: PE Windows and Darwin PowerPC defaults, explicit API/CLI overrides, strict
   compiler-ID/data-model validation and target-sized runtime declarations. Reviewed coverage includes
   ILP32/LP64/LLP64, Windows x86 cdecl, clangwindows aliases and all 13 bundled processor targets.
   - [x] ARM BE8 mixed instruction/data endian selection, preserved by compiler overrides.
   - [x] Darwin ARM64 fixed stack packing and explicit variadic slot allocator/compiler model.
   - [x] OS/library-specific typedefs: off_t/time_t/mode_t/pid_t prototypes sized by width placeholders, with the
     POSIX I/O and time functions that use them (documented 32-bit Linux off_t and 32-bit Darwin time_t edges).
    - [x] Declared Darwin ARM64 narrow integer input extension to 32 bits, preserving unknown upper bits and
      existing return rules. Owned compiled/recompiled C covers 58 comparisons; input-window controls include
      cloned models, packing, promotions and conservative malformed-spec refusals.
    - [ ] Remaining ABI-specific work: general Darwin ARM64 variadic call recovery and broader ABI/call correctness.
4. [x] Symbol/type synchronization: address-bound prototypes, independent import slots, metadata identity
   separate from display spelling, reported failures, cached engine refresh on name/type edits and undo/redo.
5. [x] Portable specification packaging and supervised resource/cancellation integration,
   including allocation-failure containment at the C ABI. This is not an OS sandbox or native memory-safety proof.
   - [x] Embed specifications, versioned verified cache and relocated executable regression without Ghidra.
   - [x] Bound text/token output; contain standard exceptions during decompilation.
   - [x] Opt-in supervised worker with wall-clock cancellation, bounded concurrent pipe I/O and memory enforcement
     (Linux hard limits; macOS sampled RSS), API/CLI/session integration without native fallback.
   - [x] Packaged sessions automatically select a sibling worker; install script ships worker and CLI together.
   - [x] Complete C ABI exception containment with allocation-free fallback and poisoned-state handling.
   - [ ] Other supervisor platforms and native upstream memory-safety remediation.
6. [ ] Persistent user types/signatures/calling conventions and typed globals, then debug-type imports and
   class recovery.
   - [x] Validated persistent signatures and type declarations, API/MCP tools and shared-log dependency checks.
   - [x] Validated persistent typed globals with complete mapped-data storage and dependency checks.
   - [x] Bounded embedded-DWARF scalar/pointer signature preview/import with non-overwriting application.
    - [x] Bounded named Itanium vtable/RTTI/code-slot class evidence; no asserted object layouts.
    - [x] Bounded read-only verification of parsed flat-struct layouts and ordered worker assertions for x86-64 GCC;
      independent compiled size/alignment/offset and field-use gates. Assertions are ephemeral, not debug imports.
    - [x] Separate checked embedded-DWARF flat-struct pointer import: explicit producer struct alignment, bounded
      C metadata, identity-qualified types, persistent assertions, frozen consent and one atomic dependency batch.
   - [ ] Exact aggregate/debug-layout import, external PDB/dSYM support and automatic class-layout recovery.
7. [x] Address-linked structured results and clickable pseudocode, including engine-derived flow evidence.
   - [x] Semantic address-linked tokens and background UI pseudocode/navigation panel.
   - [x] Variable/storage/block/signature schemas and recovered call/jump-table destinations.
   - [x] Rendered-byte spans, inline pseudocode navigation and raw jump-table labels with absent-label nulls.
8. [ ] Versioned differential benchmarks: precision/recall, thunks, signatures/calls/strings/switches, warnings,
   coverage and time/memory across stripped/symbolized compiler/optimization/ABI corpora.
   - [x] Discovery precision/recall and installed Ghidra version instead of a hard-coded version.
   - [x] Versioned bounded corpus runner with explicit signature/call/string/switch assertions, failure coverage,
     timing and resource diagnostics; not an equivalence score.
   - [ ] Matched-setting differential decompilation corpus and coverage/runtime/memory metrics.

**This supersedes the hand-written "Deep ARM64 track" below as the route to decompiled output.** That native
IR/SSA/pseudocode work stays as complementary, evidence-bounded diagnostics (and feeds the function list the
decompiler works from); it is no longer the path to source recovery, so it is not worth hand-reimplementing what
Ghidra already provides (types, structuring, FP/SIMD, every architecture). Keep only the parts that improve
rampage's own discovery and CFG, which the decompiler depends on.

## Current status (native analysis track, now complementary)

Deep ARM64 support is **in progress**, not IDA/Ghidra parity or complete typed-source recovery.
Checked items below describe bounded, tested capabilities; sections marked partial still have acceptance work remaining.

### Committed milestones

- `ce8d78c`: integer/NZCV semantics, AAPCS64 calls, constant/stack evidence, dominance/natural loops,
  labeled pseudocode, explicit jump-table inspection, snapshot metadata and comparison foundations.
- `e5adb73`: conservative control regions, conditional selects and common bitfield aliases.
- `94d0936`: checked X0/X1 return candidates, without inferring a signature or inventing argument uses.
- `35508ff`: successful controlled live LLDB capture with ASLR enabled and UUID/header-slide correlation.
- `07110f5`: phi-alias simplification without expression expansion; bounded long-chain allocation regression.
- `d969847`: extended-register ADD/SUB, including SP/ZR and signed/unsigned extension rules.
- `1c9c737`: scalar memory widths/extensions, proven constant-store forwarding and complete phi-path validation.
- `a2c9ec0`: word-sized STP/LDP and signed LDPSW pairs with full-width SP writeback.
- `1556f22`: opt-in structured SSA pseudocode, parallel phi bindings and CFG-versus-region execution tests.

### Earlier native-analysis increment — reviewed and committed

- [x] Local operand-use evidence: integer widths, address/code operands, signed/unsigned operation roles.
  This is not source-type inference; shift counts do not inherit pointer roles. Traversal is bounded.
- [x] Explicit indirect-branch target observations in IR/SSA and constant-target evidence from dataflow.
- [x] Image validation requires an entire aligned instruction in backed, readable executable code.
  Evidence does not insert CFG edges or function seeds; mutable snapshot-pointer inference stays disabled.
- [x] Independent reviews completed; reported bugs fixed and retained as regressions.
- [x] Latest release workspace suite and warnings-denied Clippy passed.
- [x] Full debug workspace run completes (~1m45s); the earlier timeout was the one-time vendored C++ build of
  the decompiler, now cached. Suite is green with the decompiler integrated.
- [x] Final formatting/diff checks, line-length cleanup and commit of this increment.

### Previous todo-wave validation (`ffc84e7`)

- [x] Ordinary release workspace suite, including CLI hierarchy, UI snapshots and the unchanged evaluation gate.
- [x] Focused debug API/CLI and core regressions, plus controlled LLDB query/capture tests and merge-history
  secret-scanner regression. Ignored scale/performance gates are not implied by an ordinary suite pass.
- [x] Hosted CI at `ffc84e7`: formatting/full-history secrets, Linux core subset and ordinary macOS debug
  workspace/UI/accuracy gates, including both selected opt-ins. This does not cover later uncommitted work.
- [x] Standard full debug workspace rerun completed after artifact regeneration with the smaller profiles.
  The earlier artifact stalled at `_dyld_start`; the underlying host launch-policy/cache cause is not established.
  No security settings changed. The current run includes unchanged UI snapshots and the 13-slice gate with its
  newly raised tool-ID floor.

### Build footprint and published transport validation (`d18b95f`)

- [x] Dev/test debug information and incremental compilation disabled without disabling assertions or overflow
  checks. One coordinated target directory is used; 10 completed, clean, integrated old agent worktrees retired.
  Their reported build caches totaled about 190 GiB; branches, commits and source work were preserved.
- [x] Cold CLI/worker/UI build passed; its target directory measured 2.9 GiB afterward. This is an observation,
  not a disk quota or full-workspace size guarantee.
- [x] Ordinary debug workspace suite, warnings-denied Clippy, Rust formatting, and selected corpus regressions.
- [x] Controlled live transport plus complete Python suite: 571 tests and 108 subtests passed; scoped Ruff/ty pass.
  Actual Rust CLI queries also passed against a stopped owned native fixture, with target identity unchanged.
- [x] Full ordinary release workspace suite, including PDB arithmetic/corruption, compiled switch routing,
  debugger API/CLI/MCP/UI and unchanged UI snapshots. Ignored scale/performance tests are separate gates.
- [x] Selected opt-ins: native compiled ARM64 fixture and isolated CLI/worker acceptance passed on the final source.
- [x] Hosted CI at `d18b95f`: macOS workspace/UI/accuracy, Linux core subset and formatting/HEAD/history secrets.

### Published metadata and qualified-resolution wave (`3e82a71`)

- [x] Fresh-context review fixes retained for event grammar/ownership, malformed MCP architecture selectors,
  independent original-image test oracles and bounded SDK section/ancestor resolution.
- [x] Full ordinary debug and release workspace suites, including new CLI/MCP/PDB/event/debugger regressions,
  unchanged UI snapshots and the unchanged 13-slice evaluation gate. Ignored performance/scale gates remain separate.
- [x] Warnings-denied Clippy, Rust formatting, scoped Ruff/ty and complete Python suite: 677 tests / 108 subtests.
- [x] Actual Rust CLI-to-stopped owned LLDB interoperability, including UUID-qualified address resolution and
  stale-token errors; target identity unchanged. SDK/native results cover this controlled Apple LLDB fixture only.
- [x] Protected source/fixture preflight plus committed-tree/full-history secret audit before publication.
- [x] Hosted CI at `3e82a71`: macOS workspace/UI/accuracy and selected opt-ins, Linux core, formatting and
  committed-tree/full-history secrets. This covers the published wave, not the next uncommitted surface additions.

### Published comparison/import/resource surface wave (`dbe5e4f`)

- [x] Fresh reviews and retained regressions for original-selector validation/fixture layout, CLI native-path
  serialization, process-local undo semantics, resource backing spans and partial-header/count provenance.
- [x] Full ordinary debug workspace suite, including actual MCP comparison/resource calls, CLI imports, unchanged
  UI snapshots and the unchanged 13-slice evaluation gate. The MCP resource test covers empty-inventory wiring;
  populated resource evidence is exercised by synthetic loader/API and renderer tests, not payload interpretation.
- [x] Complete controlled Python suite: 677 tests and 108 subtests; working-tree secret preflight.
- [x] Full ordinary release workspace suite, warnings-denied Clippy and Rust formatting. Ignored scale/performance
  gates and Linux-only native non-UTF-8 PE filesystem acceptance remain outside the local macOS test results.
- [x] Protected committed-tree/full-history secret audit before publication; no commercial inputs or private keys.
- [x] Hosted CI at `dbe5e4f`: macOS workspace/UI/accuracy and selected opt-ins, Linux core, formatting and
  committed-tree/full-history secrets. This does not establish acceptance of later boxed-value/archive additions.

### Published boxed-attribute and ZIP-metadata wave (`ae4daba`)

- [x] Fresh source reviews of boxed grammar/budgets, ZIP parser/resource/descriptor boundaries and API/CLI/MCP glue.
  Adversarial argument-error expansion is capped before publication; successful pages preserve whole records/counts.
- [x] Full ordinary debug workspace suite on final source, including boxed and archive regressions, unchanged UI
  snapshots and the unchanged 13-slice evaluation gate. Warnings-denied Clippy and protected working-tree preflight.
- [x] Full ordinary release suite, final formatting/Clippy, and complete controlled Python suite: 677 tests and
  108 subtests. Ignored scale/performance and broader archive/platform acceptance remain separate gates.
- [x] Protected committed-tree/full-history secret audit before publication; owned audit scratch removed afterward.
- [x] Hosted CI at `ae4daba`: macOS workspace/UI/accuracy and selected opt-ins, Linux core, formatting and
  committed-tree/full-history secrets. Later navigation/enum-constant work has separate acceptance gates.

### Published static-navigation and enum-constant wave (`c097515`)

- [x] Fresh reviews of mapped-source identity/ownership, typed navigation evidence and invalidation, runtime
  address-width bounds, and local enum Constant ownership/grammar/budgets. Review fixes retain targeted regressions.
- [x] Full ordinary debug workspace suite on final source: backing-source detection, 38 UI unit tests, debugger
  integration, populated enum API/CLI/MCP output, unchanged UI snapshots and the unchanged 13-slice evaluation gate.
- [x] Warnings-denied Clippy, scoped formatting/whitespace checks and protected working-tree secret preflight.
- [x] Complete controlled Python regression rerun: 677 tests and 108 subtests.
- [x] Protected committed-tree/full-history secret audit before publication.
- [x] Later frozen-source release workspace validation includes this foundation plus the checked-PDB/escaped-enum
  additions below. This is not a claim of an exact `c097515` release rerun. The original run was interrupted during
  compilation before the harness to avoid mixing source waves; that interruption was not an assertion failure.

### Current checked-PDB and escaped-enum wave

- [x] Independent reviews of same-buffer PDB provenance, Project-bound consent/intersection, staged annotation
  refresh, canonical escaped identities, initial nesting work budgets and API/CLI/MCP surface regressions.
- [x] Full ordinary debug workspace suite, warnings-denied Clippy, Rust formatting and protected working-tree
  secret preflight. Controlled Python suite: 677 tests / 108 subtests. Ordinary UI snapshots and the 13-slice gate
  are unchanged.
- [x] Full frozen-source release workspace suite, preserving ordinary UI snapshots and the 13-slice gate.
- [x] Protected committed-tree/full-history audit before publication; owned audit scratch removed afterward.
- [x] Assessed decompiler ABI, stack/alias and aggregate-layout gaps. Native SSA stack facts do not feed primary
  Ghidra C; model selection/allocation tests are not recovered-call correctness, and parsed C is not layout proof.

### Darwin narrow inputs and aggregate-verification bridge

- [x] Independently reproduced wrong Darwin signed fixed-input C using compiler assembly and recompiled output:
  byte `-1 + 7` produced 262 instead of 6; signed-to-unsigned conversion failed while unsigned controls passed.
- [x] Corrected the proven narrow-input extension errors. Caller guarantees stop at 32 bits; general variadic recovery
  and return rules remain separate.
- [x] Bounded inspection/assertion of already parsed flat plain-struct layouts, with exact leaf descriptors,
  offsets, sizes and alignment, plus ordered worker validation. No DWARF import or persisted assertions yet.
- [x] Independent reviews resolved extension-window, invalid-spec, Serde buffering and alternate-representation
  findings. Raw JSON is bounded before materialization; malformed schema diagnostics do not echo input strings.
- [x] Owned compiler arithmetic/layout/field-use gates and full debug workspace suite, including complete API/worker
  token parity, ordinary UI snapshots and unchanged 13-slice evaluation gates. Warnings-denied Clippy and formatting.
- [x] Controlled Python suite: 677 tests / 108 subtests; no new target-control or external-host acceptance claims.
- [x] Focused optimized ABI/layout/API/worker regressions, decompiler unit tests and both compiled layout gates.
  The final compiler-family refusal test registers a valid type before checking the specific unsupported-model error.
- [ ] Full-workspace release gate: interrupted during compilation after an excessive optimized test-link rebuild;
  this is neither a suite pass nor an assertion failure. Focused release validation above passed with unchanged
  profiles.
- [x] Protected committed-tree/history audit; owned audit/compiler scratch removed before publication.

### Verified-DWARF layout batch — initial bounded scope

- [x] Bounded embedded-DWARF extraction of complete flat-struct pointer dependencies and producer layout facts,
  initially x86-64 little-endian ELF C. Missing struct alignment remains preview-only; unknown member/leaf facts
  remain unknown and need a separately measured native counterpart. `.debug_info` is at most 128 KiB.
- [x] Persistent layout assertions replayed before dependent prototypes on every engine rebuild; Project-bound,
  non-widening checked consent and atomic non-overwriting type/signature batches with one same-process undo step.
- [x] Owned compiled fixtures with independent layout/field-use oracles, refusal cases, reopen/undo and worker parity.
  No general by-value ABI, recursive aggregates, union/bitfield/inheritance or inferred class-layout acceptance.
- [x] Fresh reviews closed pre-read/base/address uniqueness, contextual-cache, compiler-context, ingestion/copy,
  encoded-log/history and indexed-name replay findings. No authentication or atomic filesystem-snapshot claims.
- [x] Pre-reconciliation full debug workspace suite and compiled loader/API/worker acceptance; unchanged ordinary
  snapshots and 13-slice gates. The first time-boxed run was incomplete; the cached rerun passed in 158 seconds.
- [x] Reconciled upstream capability evidence, Go compiler selection and caller-derived Go prototypes through
  `24df5cf`, preserving author history. Independently reviewed generated-type/analyst replay ordering; reproduced
  and fixed copied Go result declarations/signatures, with earlier-dependency and native/worker regressions.
- [x] Combined-tree focused loader/architecture/API/CLI/worker tests and all 20 compiled DWARF acceptance tests;
  post-fix API/ABI/worker regressions, workspace warnings-denied Clippy and formatting. Controlled Python: 678 tests.
- [x] Uninterrupted ordinary debug workspace pass on the combined tree: 2,270 passes across 170 executable/doctest
  groups in 244.6 seconds, with 59 explicit opt-ins skipped; all 50 evaluation tests passed separately.
  Earlier capped runs do not establish a delay cause; no startup-stall fix is claimed.
- [ ] Initial layout-batch optimized acceptance: the selected API/worker fixture build hit its five-minute cap
  while linking, before assertions. No optimized-suite success is claimed;
  release ThinLTO/codegen settings are unchanged.
- [x] Final independent reconciliation review, 845-file private-key/artifact preflight and protected committed-tree/
  full-history secret audit. Owned scanner scratch and generated compiler outputs removed before publication.
  Refreshed architecture/decompiler/API/CLI/worker, manifest, compiled-DWARF, Clippy and format checks passed in
  258 seconds after the ARM64 Go update. Full-workspace release is not a routine increment gate.
- [x] Hosted CI at `a3d4fb1`: full ordinary macOS debug workspace/UI/accuracy, compiled-DWARF and selected opt-in
  gates, Linux core and protected HEAD/history secrets. This does not cover the next typed-decompilation push.

### Usable typed-decompilation push

- [x] Reviewed checked-layout CLI/MCP and UI workflow, preserving exact content approval, analyst edits, one atomic
  dependency batch and process-local undo; preview remains read-only and old scalar import behavior unchanged.
- [x] Independent compiled acceptance through actual CLI processes, shared/MCP routes and offscreen UI, including
  stale approvals, workspace identity/revision changes, refusal visibility and persistent native/worker replay.
- [x] Initial producer-described C++ slice: base-free non-polymorphic records with explicit object-pointer evidence,
  exact layout facts and bounded same-CU method-definition/declaration association. No inferred vptr or class fields.
- [x] Owned C++ record-layout constants, source field-use and refusal oracles. RTTI/vtable evidence remains separate
  from object-layout proof and indirect-call destinations; those initial gates did not cover polymorphic projection
  or inheritance. The next bounded storage/evidence slice is recorded below.
- [x] Finite local worker-startup/native/supervisor diagnostic probes, capturing owned-process phases if a stall
  recurs. Existing worker timeout is not an end-to-end deadline for native validation, synchronous spawn or reaping.
  Published-binary probes passed in 1.00 s, 3.02 s and 14.35 s (two exact tests, then the complete API suite);
  no stall was reproduced, so no root-cause or resolution claim is earned.
- [x] Fresh reviews closed C++ declaration/address-index and C budget regressions, non-vacuous overload gates,
  App-wide preview accounting, verification labels, post-apply output failures and relative fixture tool paths.
- [x] Combined compiled acceptance: 50 tests / zero ignored in 101 seconds, covering both independent C/C++ recipes,
  actual cross-process CLI approval, shared/MCP atomic apply, offscreen UI, reopen/undo and native/worker parity.
- [x] Debug workspace coverage completed in bounded runs: the runner's long temporary path first exceeded macOS
  Unix-socket limits; short paths passed. The additive MCP tool-list expectation was updated, then its full server
  suite, UI/worker/YARA remainder and all workspace doctests passed. This is not one uninterrupted local suite pass.
  Ordinary UI snapshots and the 13-slice accuracy gate are unchanged. Controlled Python: 691 tests.
- [x] Optimized loader-only acceptance: 38 raw layout regressions plus two compiled C++ gates passed in 65 seconds,
  without API/YARA/Wasmtime or full-workspace release linking. Workspace Clippy, Rust formatting and scoped
  Python Ruff/format/ty checks passed. Release optimization settings are unchanged.
- [ ] Broader matched-setting C/C++ differential decompilation corpus and runtime/memory metrics. These initial
  independent compiler/source oracles are not that benchmark or general class-layout/virtual-dispatch acceptance.
- [x] Protected committed-tree/full-history audit and 877-file secret/private-key/artifact preflight. Generated
  compiler outputs and owned validation scratch are removed; the verified audit scanner is removed before publication.

### Bounded virtual-method evidence

- [x] Producer-proved opaque vptr storage for base-free, explicitly aligned C++ records; exact record/member and
  pointer/pointer/subroutine roles remain separate from the generated flat-C `void *` storage counterpart.
  Unknown producer widths/alignments remain unknown. This does not recover a callback prototype or native C++ ABI.
- [x] Projection-sensitive v2 type persistence, unchanged projection-free v1 bundles and v1 dependent signature seals;
  bounded metadata preflight and source/context validation precede native initialization. Older clients refuse v2.
- [x] One fresh, detached native source-closure check for exact virtual-slot/method-entry associations, including
  preserved analyst signatures and persistent reopen. Named-table recovery is separately bounded and skips RTTI
  scanning. Raw header confidence is unchanged; no table owner, arbitrary object-vptr or indirect-call target is proved.
- [x] Read-only paged CLI/MCP rows and UI evidence with explicit exact-entry navigation. Approval binds all projection,
  raw-table and source-method facts. Independent review closed unrelated C++ variable-name budget regressions,
  unowned virtual-declaration index exemptions and non-vacuous row/capacity/rendering coverage gaps.
- [x] Local core gates: 408 library tests and seven bounded named-table regressions. Virtual acceptance: 20 tests,
  zero ignored, in 73 seconds across both owned variants, including actual worker/native parity and UI navigation.
  Existing C acceptance: 43 tests in 99 seconds; existing C++ acceptance: nine tests, zero ignored. The former C++
  virtual control now projects storage but correctly refuses its writable table as raw slot evidence.
- [x] Loader-only optimized gate: 166 library tests plus two compiled virtual controls passed in 32 seconds, without
  API/YARA/Wasmtime or full-workspace release linking. Workspace all-target Clippy, all 50 UI library tests, class
  evidence regressions and the unchanged accuracy/evaluation gate passed in a separate 42-second bounded run.
- [x] Complete ordinary API/native-decompiler/worker suites and their doctests passed in a 150-second bounded run;
  compiled opt-in acceptance is recorded separately above. The installed-Ghidra exporter compiles against the
  existing SDK/JDK without running the reference backend or any target.
- [x] Remaining affected analysis/loader/CLI/MCP/UI suites and doctests passed in a separate 136-second bounded run,
  including unchanged ordinary UI snapshots. Controlled existing Python and fixture checks: 713 tests plus 168 subtests.
- [x] The remaining workspace packages and doctests passed in a separate 66-second bounded debug run. Together with
  the three scoped runs above this completes ordinary workspace coverage, not one uninterrupted full-suite run.
- [x] Actual installed-Ghidra 12.1.4 / JDK 21.0.12.1 comparison: six selected methods per DWARF/optimization variant,
  all 12 cases passed both backend oracles, matched settings/storage and CLI persistence checks in 37.3 seconds.
  Raw table-word checks and memory/layout readback passed; unverified prefixes stayed unverified. Sanitized hashes
  and observed timing/RSS scopes are recorded in `docs/cpp-virtual-corpus.md`, not general quality/performance scores.
- [x] Fresh runner reviews closed Java-option directory escapes, coupled reference scoring, both-wrong agreement,
  missing RSS observations and unsafe startup/process cleanup. Cleanup authority is the held direct guardian group,
  never a sampled PID. Controlled CLI copies explicitly avoid automatic sibling-worker selection; the standalone
  protocol-4 comparison stays isolated. Per-record parser operations match normal replay, not concatenated definitions.
- [x] Final controlled Python gate including 64 runner regressions: 777 tests and 236 subtests passed. Scoped Ruff,
  formatting and ty checks passed; fixture formatting preserved parsed expressions and literals. Both recorded image
  hashes were reproduced from the final recipe, and owned compiler/reference/export scratch was removed.
- [x] Protected 904-file secret/private-key/artifact preflight, scanner regressions and committed-tree/full-history
  audits passed. The checksum-verified scanner and owned audit scratch were removed; raw reports are not committed.
- [ ] Broad C++ differential/corpus/performance acceptance, typed virtual dispatch, inheritance and adjusting thunks.
  The owned source/compiler oracles and exact slot correlations do not earn these broader capabilities.
- [x] CI automatically builds only numeric version-tag pushes (`vMAJOR.MINOR.PATCH`, including prerelease suffixes)
  or explicit manual dispatches, never ordinary branch pushes or pull requests. No release tag was created and no
  workflow was dispatched during this work. The virtual acceptance wrapper is wired but has not run in Actions.
  Release optimization settings and the two-job shared target are unchanged.

### Exact-entry analysis and local debugger workspace

- [x] Separate exact-entry API, opt-in CLI hierarchy/compatibility flag and shared/MCP decompile argument, with
  fresh native/worker context, full-image permissions/backing and no whole-program discovery/cache consumption.
  Actual type/global/signature dependencies, v1/v2 assertions and canonical Go dependencies replay or refuse;
  metadata/analyst entry assertions remain separate from boundary proof and native recovery diagnostics.
- [x] Independent bounded entry diagnostics through API, `binary audit --entries [--at]` and paged MCP, retaining
  origins, local evidence, counts, omissions and explicit caps without encryption or function-verification claims.
- [x] Structured local stopped-session Connect/Refresh, explicit module/thread pages, raw register/memory reads
  and guarded matching-static navigation. Separate client-local Prepare/Compare/Save/Open uses unchanged queries,
  retained original identity, private no-clobber publication, retained staging and uncertain-publication refusals.
  New capture is x86-64 Darwin only; broader existing standalone-exporter support remains separate and unchanged.
- [x] Independent reviews reconciled import-stub NOP boundaries, covered data extents, conditional transfers,
  whole-JSON byte-budget progress and publication/resource lifecycle issues, with retained regressions.
- [x] Ordinary debug workspace tests and doctests passed in bounded package slices, including the accuracy/
  evaluation gate and unchanged UI snapshots. New gates include 36 entry samples, 22 capture API cases, 74 UI
  library tests, native/worker parity, both CLI spellings and actual v1/v2 checked exact-entry replay.
  The explicitly selected isolated CLI dispatch test passed; compiled opt-in gates remain separately scoped.
- [x] All-target workspace Clippy passed with warnings denied. One combined API/native validation batch reached
  its outer 150-second cap; API completed and the remaining native/worker suite passed separately. This does not
  establish a fix for the earlier intermittent startup stall or the local LLVM stripping warning.
- [x] Final formatting, 120-column and diff checks passed. Changed/new files contain only Rust source/tests and
  Markdown in the implementation batch; wrap-up adds controlled Python acceptance tooling. CI triggers, build
  settings, commercial inputs and capture artifacts are unchanged or absent.
- [ ] New live end-to-end LLDB workspace acceptance, broader ABI/platform coverage and performance measurements.
  Owned protocol mocks and image fixtures do not establish arbitrary-host or commercial-runtime acceptance.
  The owned x86-64 live gate compiled but Apple LLDB refused launch with `Bad CPU type in executable` on the
  arm64 host, before UI observations. No Rosetta installation or ARM64 data-order guess bypassed that blocker.
- [x] Final publication review closed 32-bit sample-width handling and capture paint-time mapped-header reads.
  Metadata-only painting and explicit-action physical checks retain separate authority, with regressions.
- [x] Protected 929-file candidate-source scan, scanner bypass regressions and committed-tree/full-history audits
  passed before private publication. No release tag or Actions dispatch is part of publication; capture artifacts
  and scanner scratch stay outside commits.
- [x] Measurement tooling: 17 tests and 621 subtests passed, with scoped Ruff/format/ty checks. The 64-test combined
  CI runner command passed. Its initial run returned an unavailable baseline in an unchanged corpus regression;
  a focused diagnostic matched the baseline and the unchanged command passed, not evidence of a startup fix.
- [x] Final capture regression exposed inherited nonblocking flags on accepted controlled-server sockets on macOS.
  The API helper now matches the UI helper's explicit clearing before framed reads, with a descriptor-state
  regression rather than relaxed deadlines or retries. Production debugger socket behavior is unchanged.
- [x] Inline exact/legacy measurements on owned ELF, PE and Mach-O: 18/18 source-oracle attempts passed in
  6.986 seconds, with wall-time, sampled RSS and exact API phase ranges recorded in `docs/entry-measurements.md`.
  No speedup or constant-latency claim is earned. The separate mixed pilot retained six passes, one unsupported
  separate-worker-group failure and 29 unrun attempts; isolated wall/RSS remain unavailable under this guardian.
- [x] Owned isolated exact-entry API pilot now records full-image ELF/PE/Mach-O attempts and actual root lifecycle;
  see the scoped integration milestone below. The existing CLI guardian remains inline-only.
- [ ] Larger matched-setting corpora; bounded host context does not promise constant latency, complete discovery
  context or cropped-image behavior.
- [x] First bounded static multi-module workspace slice is implemented below; broader type/ABI recovery and
  runtime cross-module resolution still require independent acceptance.
- [ ] Future: read-only GDB and Windows debugger inspection backends, each with separate platform acceptance.
- [ ] Any execution-control debugger integration requires separate design/review; launch, attach, resume, step,
  breakpoints, expressions and target writes are not part of the read-only workspace milestone.

### Deferred exact-entry UI and reviewed static workspaces

- [x] Explicit exact-entry window and deferred Open route: no functions, triage, strings, listing, xrefs or legacy
  pseudocode work starts merely from opening or painting the deferred workspace. Explicit global analysis restores
  the ordinary workflow. Existing Session caches may already contain analysis; this is not a pristine-history claim.
- [x] Actual API phase observations, cooperative cancellation and nonserialized configuration identities. Callbacks
  execute outside Project locks, count toward the original worker deadline and revalidate source backing before
  mapped-byte/native work. Native FFI remains noninterruptible; execution owns the App-wide exact-job permit.
- [x] Retained eight-module bank with explicit ID-qualified navigation, independent editors/undo/selection and
  per-module histories. Switching invalidates request authority even across same-frame A→B→A; a missing retained
  source does not prevent adding an unrelated module. Critical rereads still require fresh backing checks.
- [x] Strict reviewed manifest persistence: Save, manifest-only Preview and Open reviewed are separate actions.
  Fresh checked sessions retain exact loaded Project Arcs, explicit configured options and recognized persistent
  annotations. Missing/changed/nth-failing sources or logs leave the old bank and its editors intact.
- [x] Checked admission before allocation: 256 KiB manifest, eight modules, 128 MiB/source and 256 MiB aggregate;
  snapshot sources additionally preflight 16 MiB documents, 1 MiB raw strings, depth eight, 4096 array items and
  65536 structural units before copying/serde. Save rejects legacy snapshots outside the restorable checked profile.
  Ordinary legacy snapshot loading remains unchanged. Navigation uses exact 64-bit hexadecimal strings.
- [x] Independent review closed original snapshot descriptor retention, sidecar-directory context, address precision,
  callback source invalidation, cross-module egui state and retained-source deduplication findings with regressions.
- [x] Native ARM64 UI inspection acceptance: one controlled real-LLDB gate, six protocol operations, explicit static
  navigation, unknown DATA order, disabled Prepare and no capture publication. ASLR stayed enabled; fixture/source,
  annotations, editor and stopped-process identity were preserved. Full ARM64 capture is not earned.
- [x] ARM64 exporter correctness correction: target/process byte-order getters delegate to architecture defaults,
  not an independent EL0 DATA-order observation. Export now refuses ARM64 before thread/mapping/memory/file work.
  Historical ARM64-positive export acceptance is superseded for DATA-order provenance, not erased as a byte/identity
  observation. Native export-refusal tests passed; x86-64 and ARM32 export coverage remains separate.
- [x] Final ordinary workspace tests and doctests passed in bounded package slices, including the accuracy gate,
  219 API library tests, 23 workspace API tests, 23 capture API cases, 96 UI library tests, 14 public workspace UI
  cases and unchanged snapshots. Broad combined batches hit their outer caps; their remaining package/snapshot
  slices passed separately. This is not an uninterrupted full-suite or startup-stall-fix claim.
- [x] Full controlled Python gate: 804 tests and 797 subtests passed, with six default-skipped opt-in cases.
  Native ARM64 inspection and exporter-refusal opt-ins passed separately. Scoped Ruff/format/ty and all-target
  warnings-denied workspace Clippy passed; source/descriptor and callback-race fixes retain regressions.
- [x] Protected 940-file candidate-source audit and scanner bypass regressions passed. Committed-tree/full-history
  audit is required before private push; no release tag or Actions dispatch is part of this milestone.
- [ ] Broader derived analysis caches and runtime cross-module resolution; the historical inventory and static PE
  declaration slices below do not complete these. Broader ABI/type recovery, GDB/Windows backends and affirmative
  ARM64 runtime DATA-order evidence remain open. Execution controls require separate reviewed scope.

### Static references, responsive file operations and historical inventory

- [x] Explicit loaded-PE module-reference query/window: raw import DLL versus producer export-directory identity,
  whole ASCII case comparison and exact symbol bytes. No basename or runtime/function-proof join. Ordinals,
  forwarders, snapshots, ELF and Mach-O remain unsupported coverage, not inferred edges. Matching comparisons,
  sorting and whole-row pages are bounded. Central owned-compiler acceptance: 23 loader, 28 API and three UI cases.
- [x] Workspace file operations use one background execution lease across cancellation and bank changes, bounded
  progress, metadata-only adoption checks and typed publication history retained before stale-binding handling.
  Normal annotation refresh still has existing synchronous I/O; this does not claim all desktop I/O is asynchronous.
- [x] Optional worker/API host observations preserve failures, actual pipe delivery/EOF and root-only sampled RSS.
  Private completion holds the Rust worker root alive through owned-group cleanup without changing protocol v4.
  Ambient control descriptors are duplicated, not adopted; completion followed by EOF/reset revokes authority.
  Decompiler library: 81 passed plus one isolated helper; actual worker entry/parity/error gates: seven passed.
  Legacy/custom workers require successful anchored cleanup; custom SIGCHLD handlers remain unsupported.
- [x] Full-image owned ELF/PE/Mach-O exact-entry API measurement: all 18 attempts passed independent source oracles
  and per-format output/token/structure parity. Three native and three isolated attempts per format, no retries
  or fallback. Actual SIGKILL/reap/EOF/cleanup observations retained. No stall reproduced or stall-fix claim.
- [x] Bounded historical inventory API: explicit private read/save, complete dependency key and permanently
  cached/unverified rows; no Program/native/solver/type restoration or function-entry authority. The names-only
  token ignores comment/no-op replay while meaningful rename ABA invalidates. Central API integration: 18 passed;
  lexical and real annotation-contention regressions and all 229 API library tests passed (four opt-ins skipped).
- [x] Selected generated-fixture cache GO: median full reopen 93.86 ms fresh versus 22.41 ms cached (4.19x),
  with 2,048 of 2,301 historical rows. The two-function control was slower (0.294 versus 1.083 ms). No generic
  cache speedup, cold-disk or RSS claim. Reproduction and limitations are documented separately.
- [x] Cache desktop acceptance: 12 explicitly selected cases passed, including forged-checksum labeling,
  no-discovery load/save controls, source replacement, name ABA and shared cancellation/resource retention.
  Ordinary UI library tests: 125 passed, one host-tool opt-in; unchanged snapshots: 16 passed, one Chrome opt-in.
- [x] All-target workspace Clippy passed with warnings denied; format, 120-column and diff checks passed.
  The installed rust-objcopy/libLLVM stripping warning remains visible and unresolved.
- [x] Final independent worker, metadata-reference, cache/UI and journal reviews closed their findings; ordinary
  workspace, explicit compiler fixtures and the durable 18-attempt journal passed after corrections.
  Controlled Python: 804 tests and 797 subtests passed, six live opt-ins skipped.
- [x] Protected 969-file candidate-source audit, scanner-bypass regressions and committed-tree/full-history scans.
  Publication is private main only, without a release tag or Actions dispatch; owned audit scratch is removed.
- [ ] Runtime/converted executable plugins, broader recovery and remaining TODOs are not part of this milestone.

### Validation and external blockers

- [x] LLVM-checked encodings and native ARM64 boundary comparisons, including all 16 conditions × 16 NZCV states.
- [x] Opt-in optimized C fixtures: native execution plus evaluated lifted arithmetic/selects and recovered byte spills.
- [x] Controlled live export on Apple LLDB `2103.0.34.103`: executable bytes, module identities and registers;
  explicit original Mach-O correlation verified with ASLR enabled. Capture artifacts were removed.
  This is a historical byte/identity result: the later DATA-order review supersedes its ARM64 export-provenance
  claim, and current export refuses ARM64 rather than inferring DATA order from target architecture.
- [x] Previous committed milestones passed full debug/release suites and fresh-context review.
- [x] Ghidra comparisons for rampage's own analysis: `tools/cfg-benchmark.py` (+ `tools/ghidra_cfg_export.java`,
  hidden `rampage export-cfg`) compares blocks, CFG edges and call edges on 18 fixtures (docs/benchmarks.md), Ghidra
  as reference, not ground truth. IDA is still absent.
- [ ] Resolve the local `rust-objcopy` missing-`libLLVM.dylib` stripping warning; release tests still execute.
  - Command-local `DYLD_LIBRARY_PATH=<rustc-sysroot>/lib` resolves the installed tool's library lookup;
    permanent managed-toolchain repair remains open rather than patching rustup-owned executables.

## Deep ARM64 track and remaining work

### 1. Instruction semantics — partial

- [x] Immediate, shifted and extended ADD/SUB; logical operations; wide moves; multiply/divide; variable shifts.
- [x] NZCV, B.cond, CBZ/CBNZ/TBZ/TBNZ, CSEL/CSINC/CSINV/CSNEG, ADR/ADRP and plain BL/BLR/BR/RET.
- [x] Common non-wrapping bitfield aliases; 8/16/32/64-bit scalar memory with separate result/access widths.
- [x] Literal/register/unsigned/unscaled/pre/post addressing; 32/64-bit pairs and signed LDPSW.
- [x] Remaining common integer families: carry arithmetic (ADC/ADCS/SBC/SBCS, NGC/NGCS), conditional compares
  (CCMP/CCMN register/immediate), wrapping bitfields (SBFIZ/UBFIZ/BFI/BFXIL/BFC), long/high multiply
  (S/UMADDL, S/UMSUBL, SMULH/UMULH), EXTR/ROR immediate, CLZ/CLS/RBIT/REV/REV16/REV32, each with native
  boundary regressions (all 16 NZCV inputs for flag-dependent families, also through SSA/dataflow) and
  natively recorded expected values that replay on any host. FEAT_CSSC, RMIF and SETF8/16 remain barriers.
- [x] Valid no-writeback pair loads with base/destination overlap; capture both original addresses before
  assignments for LDP X/W and LDPSW. Writeback overlaps and duplicate destinations remain barriers.
- [ ] FP/SIMD, atomic/exclusive and selected system semantics, with effects and memory ordering explicit.
- [ ] PAC/authenticated flow, exceptions and platform-specific behavior; unsupported forms must remain barriers.

### 2. Stack, memory and signatures — partial

- [x] Integer AAPCS64 caller clobbers/callee preservation; X8 result-buffer and SP call dependencies.
- [x] Entry-SP-relative slots, conflicting-path unknowns, per-RET X0/X1 candidates and input-use argument evidence.
- [x] Exact-width constant-store forwarding with source IDs and all-path agreement; conservative alias boundaries.
- [x] Exact-width nonconstant entry-SP spill/reload aliases when all reaching paths agree. Original load
  observations and recovered-load provenance remain explicit; recovered pointers cannot restart stack-memory
  inference. Source clobbers, width/sign extension, aliases and budgets have behavioral regressions.
- [ ] Partial-width overlap reconstruction, safe cyclic-memory fixpoints and broader alias proofs. Calls,
  unknown aliases, conflicting paths and cyclic proofs remain unresolved.
- [ ] Stack-frame boundaries, outgoing stack arguments, saved-register roles and escaped-stack alias handling.
- [ ] Interprocedural signatures: argument count/types, void versus value, aggregate returns, varargs and FP/SIMD ABI.
- [ ] Propagate type constraints and reconstruct pointer/struct/class layouts; local operand roles alone are not types.

### 3. SSA and pseudocode — partial

- [x] Bounded register/memory SSA, predecessor-indexed phis, constants/affine stack reasoning and semantic gaps.
- [x] Redundant phi aliases, dominators, natural-loop evidence and conservative sequence/branch/single-body regions.
- [x] Labeled and `--structured` SSA pseudocode with explicit predecessor tokens and simultaneous phi bindings.
- [x] Execution comparisons cover both diamond arms, repeated loops and both loop-condition polarities.
- [ ] Minimal phi placement, dead-definition elimination and broader expression simplification without amplification.
- [x] Bounded non-fall-through switch regions with retained table entries and guard evidence; unsupported
  switch shapes preserve labelled SSA diagnostics rather than invented structure.
- [ ] Nested/multi-block loops, broader branch joins, fall-through switch regions and irreducible-flow handling.
- [ ] Typed variables, source-level expressions/returns and readable decompiler output distinct from SSA diagnostics.

### 4. Jump tables and indirect flow — partial

- [x] Conservative ADR/ADRP/ADD/MOV/LDR/BR/BLR discovery; calls/stores invalidate captured-memory assumptions.
- [x] Explicit bounded absolute64/signed-relative32 table inspection, without guessed dispatch bounds.
- [x] Image-validated SSA target evidence, including a spilled constant target.
- [x] Bounded AArch64 and x86/x86-64 dispatch recognition with proven unsigned bounds, read-only backed tables,
  validated destinations and branch-site evidence. Cross-block facts are revalidated after graph expansion.
- [x] Proven immutable switch cases feed discovery/CFG/xrefs as case edges, not function seeds, retaining table
  order and guard evidence. Other indirect-flow forms remain separate acceptance work.
- [ ] Mutable pointers only after alias/reaching-store proof; authenticated or unmapped targets remain unresolved.
- [ ] Fixtures for relative tables, duplicate targets, joins, loops, truncation, overflow and hostile index bounds.

### 5. Controlled runtime capture — initial gate complete

- [x] Successful permitted stopped-process capture, module UUIDs/bases, register provenance and original correlation.
- [x] Mapping-aware snapshot identity and durable identity-scoped annotation persistence, including addresses,
  permissions and endianness. Per-file provenance/register observations are not conflated by identity reuse.
- [x] Persist explicit decompiler configuration, module/source identities and navigation in reviewed workspace files.
- [ ] Persist derived analysis caches and broader reproducible analysis state; the manifest is not an engine cache.
- [ ] Multiple modules/threads and stripped/relocated images; module-qualified navigation and cross-module references.
- [ ] Broader debugger/platform integration, capture failure handling and provenance validation on larger fixtures.

### 6. Accuracy benchmark — partial

- [x] Synthetic snapshots, native instruction oracles, compiled fixtures and malformed-input/resource regressions.
- [x] Versioned, hash-/architecture-matched function-start reference imports; snapshot comparisons reject
  ambiguous identity.
- [x] Versioned x86-64/AArch64 matched-pair corpus for library ID, discovery, tool detection and DWARF-backed
  signature recovery. The committed 13-slice baseline gate passes at `6122f64`.
- [ ] Broader compiler/optimization/ABI coverage with instruction/stack/semantic and time/memory metrics.
- [x] Pinned read-only CI workflow: format, warnings-denied Clippy, ordinary macOS workspace/UI tests and selected
  opt-ins, the 13-slice evaluation gate, an explicit Linux core subset, and redacted HEAD/full merge-history
  secret scans that cannot silently inherit repository allowlists. Hosted gates passed at `ffc84e7`.
- [ ] Quantitative unsupported-coverage and per-analysis time/memory gates; CI job/step timeouts are not substitutes.
  - [x] Explicit corpus recovery-status/flag/count assertions and configurable elapsed-time assertions, with missing
    diagnostics/measurements and identity mismatches retained as unavailable. Controlled fixture recovery gates
    and runner regressions are wired into CI; these do not measure unsupported coverage or per-case peak memory.
  - [x] Three owned compiled-switch fixtures are included in tool-ID truth. The expanded slice measures 129/163
    correct expected tools (recall 0.791411, precision 1.0); its floor is raised to 0.7914, not weakened. This is a
    corpus-denominator change, not a detector improvement or a rewrite of historical measurements.
- [x] Ghidra exports compare function starts, blocks, CFG edges and calls on 18 fixtures; reference output is
  not ground truth, and normalized chain agreement is not decompiler or semantic equivalence.
- [ ] IDA exports/comparisons once an installation is available.
- [ ] Expand beyond current CFG/call and signature metrics to dispatch truth, stack evidence and semantics.

### Next execution order

1. [x] Resolve the earlier full-debug timeout and complete debug/release workspace validation.
2. Extend common integer semantics and nonconstant spill recovery, keeping alias boundaries conservative.
3. Recover bounded dispatch tables and integrate proven targets into CFG/discovery with regression fixtures.
4. Broaden structuring and type/signature propagation; keep SSA diagnostics separate from recovered source.
5. Build the versioned accuracy corpus/CI gates and complete persistence/cross-module runtime work.

Native IR/SSA remains complementary to the embedded Ghidra decompiler above. Vendored Ghidra implementation
and specifications retain their Apache-2.0 license and attribution; any additional copied/ported components
require their applicable license and attribution.

## General-purpose reverse-engineering roadmap

### Transformed static code and runtime analysis

Successful loading, discovery and C emission do not establish usable recovery. High entropy, invalid decoding,
unresolved wrapper jumps, missing debug types and absent named vtables need explicit diagnostics. These are
evidence and limitations, not proof of encryption or verified function counts.

Work in this order, with synthetic regressions and fresh-context review for each increment:

1. [x] Structured recovery diagnostics: export engine warnings, bad-data/unimplemented flags and unresolved
   calls/jump tables. Surface warnings in CLI/API/MCP/UI and separate successful output from usable recovery in
   benchmarks; no unqualified "complete" or "clean implies correct" label.
2. [x] Discovery-confidence summaries: relate candidates to bounded sampled regions and preserve evidence for
   suspicious tiny fragments, invalid decode and code/data ambiguity. Do not silently delete candidate functions
   or infer encryption from entropy alone. Use cached discovery modes; whole-program discovery is an explicit
   opt-in (`audit --include-discovery` / MCP `include_discovery`), not a hidden prerequisite for sampling.
3. [ ] Authorized capture workflow: bounded module/range selection and actual memory-permission checks in the
   stopped-process LLDB exporter, capture failures and provenance. No automatic plugin launch, installation,
   debugger attachment, licensing changes or target-memory writes; controlled live tests use our own fixtures.
   - [x] Exact mapping permissions, bounded inspection, complete reads, expression-stop identity checks and
     atomic no-clobber publication; breakpoint normalization recorded in provenance.
   - [x] Explicit UUID/original-address range and seed selection with checked slides, section coverage and
     conflicting-mapping rejection; controlled live fixture validation.
   - [ ] Broader multi-thread/module capture acceptance and module-specific byte-order context.
   - [x] Explicit bounded thread selectors/all-thread register capture, stop-context and module-provenance
     revalidation; controlled live acceptance covers two owned modules and two threads.
4. [ ] Runtime target identity: persist platform/compiler context, mapping-aware capture identity and module/
   thread provenance so an ARM64 macOS capture does not silently use generic AAPCS64 decompilation defaults.
   - [x] Validated optional platform/compiler context, exported by LLDB and used by native/worker defaults.
   - [x] Canonical mapping-aware triage identity and normalized UUID-duplicate validation.
   - [ ] Broader thread/module provenance consistency checks, module-specific code/data endian validation
     (including ARM BE8), and persisted session reuse by capture identity.
   - [x] Identity-scoped annotation persistence and snapshot revalidation; equal captures can share logs without
     conflating per-file provenance/register observations. Legacy unscoped logs are reported, not migrated.
5. [ ] UUID-validated static/runtime comparison: compare explicit matching captured ranges, retain byte-change
   and unavailable-range evidence, transfer only justified symbol/type information with checked ASLR slides.
   - [x] Bounded API/CLI byte comparison with equal/changed/unavailable spans and capture/original identities;
     annotation-free explicit inputs and controlled live comparison.
   - [ ] Reviewed symbol/type-transfer policy and runtime comparison navigation/agent integration.
   - [x] Shared agent/MCP byte comparisons with paginated spans, full-range totals and identities;
     fresh explicit MCP inputs bypass annotation sidecars and discovery.
6. [ ] Captured indirect-call evidence: show wrapper slot/value/target observations separately from proven flow;
   writable, authenticated, unmapped or incomplete pointers remain unresolved without additional evidence.
   - [x] Explicit API/CLI/MCP pointer-slot observations with raw values, permissions and mapping identity;
     no edge insertion, no authentication/high-bit stripping and checked ARM mode tags.
   - [ ] Link observations to decoded branch sites, module-qualified targets and before/after capture evidence.
   - [x] Bounded explicit ARM64 branch-window links to decoded slot loads, retaining indirect flow and
     raw observations; unsupported/control-flow/authenticated/incomplete cases remain explicit.
   - [x] Explicit API/CLI/MCP paired-slot comparisons across captures with raw equal/changed/unavailable outcomes,
     independent mapping/target assessments and capture identities; no inferred chronology or module ownership.
7. [ ] Authorized runtime acceptance: user supplies an already-loaded/stopped instance in a legitimate host;
   capture selected code and referenced data, correlate the original UUID, rerun diagnostics/decompilation and
   report before/after warning/coverage metrics. This is blocked on an authorized host capture, not static parsing.

Commercial plugin bytes and captured process contents are local investigation inputs, not committed fixtures.
No protection bypass, patching or claims of license-state recovery are part of this work.

Acceptance gate for each milestone: behavioral regressions, malformed-input tests, `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, workspace tests, and independent review. Commercial samples are
read-only triage inputs, never bypass or patch fixtures. Runtime tests use programs we build ourselves.

- [x] Initial runtime images: validated sparse snapshot format, CLI/API/UI loading, explicit code seeds, provenance,
  virtual-address handling and controlled LLDB export/correlation. Persistence and cross-module work remain above.
- [ ] Indirect flow: the conservative AArch64 ADR/ADRP/ADD/MOV/LDR/BR/BLR foundation is done (below). Remaining:
  other architectures, and proven targets feeding discovery/CFG (Deep ARM64 track 4). Unknown, authenticated,
  mutable and unmapped targets must remain unresolved.
- [x] Analysis confidence: `audit`/`analysis_diagnostics` explain decode coverage and unreliable-code evidence over
  sparse memory without asserting encryption (below).
- [x] Language metadata: C++/Rust demangling with original lookup names, named/stripped Itanium/MSVC RTTI,
  and bounded Objective-C classes/categories/methods/ivars/properties/protocols with malformed-pointer tests.
  Objective-C metadata handles relative methods and static chained-fixup rebases; it is not runtime PAC recovery
  or automatic C++ object-layout reconstruction.
- [x] Data-flow/decompilation: structured function summaries shipped, and decompilation comes from the embedded
  Ghidra decompiler. The native IR/SSA work continues as diagnostics in the Deep ARM64 track; it is never
  labelled a decompiler.
- [ ] Containers and workspaces: bundle discovery and inventory of already-extracted packages are done (below).
  Remaining: nested-archive inspection with extraction budgets (never executing installers) and cross-module
  navigation with address/module identities.

### Implemented foundations

- [x] Sparse snapshot loader with virtual addresses, region/seed validation, provenance and resource bounds.
- [x] Snapshot loading through CLI/API/MCP/UI and controlled integration fixtures.
- [x] Read-only LLDB snapshot export command with preflight validation and no-overwrite behavior for its documented
  x86-64/ARM32 paths. Historical ARM64 byte/identity capture tests ran with ASLR enabled, but their assumed DATA
  order is superseded: current ARM64 export refuses until an affirmative runtime evidence path is implemented.
  Static snapshot loading remains available; raw ARM64 query/UI inspection keeps DATA order unknown.
- [x] AArch64 conservative ADR/ADRP/ADD/MOV/LDR/BR/BLR tracking with stores/calls invalidating memory inference.
  Writable capture regions remain excluded from pointer evidence. Exact-store forwarding exists in summaries,
  but is not a general alias proof or a reason to enable mutable-pointer discovery.
- [x] Final discovery closure and retained per-function resolved flows, keeping CFGs/listings consistent.
- [x] `audit`/`analysis_diagnostics`: bounded coverage and unreliable-code evidence, not proof of encryption.
- [x] Bounded C++/Rust demangling; original lookup aliases and collision-safe display names.
- [x] Sized, named Itanium vtable targets/RTTI labels and Objective-C selector string inventory.
- [x] Plist-authoritative bundle opening and bounded inventory of already-extracted packages/directories.
- [x] Structural function summaries with paginated references, CFG and explicit non-decompiler limitations.
- [x] Partial typed AArch64 IR for the integer/NZCV/scalar-memory families listed in track 1 above.
  Unsupported instructions remain explicit barriers; no source-level reconstruction is claimed.
- [x] Bounded register/memory SSA with block-entry phi nodes, entry/backedge inputs, unreachable-block handling,
  zero-extended 32-bit results and full semantic barriers; exposed through structural function summaries.
  Memory access widths and conditional polarity/tested bits are retained. Generated-definition and input-node
  budgets reject amplification before SSA allocation.
  Minimal phi placement, alias analysis and decompilation remain open; bounded dominance queries are available.

Full instruction semantics, production decompilation, arbitrary debugger control and multi-module runtime
resolution have separate acceptance cases. The embedded decompiler is implemented above; full native semantics,
arbitrary debugger control and multi-module runtime resolution must not be inferred from those foundations.

### Next acceptance-driven milestones

1. **Runtime integration:** extend the verified controlled capture to persistence, mapping-aware identities,
   multiple modules/threads and module-qualified navigation.
2. **Data-flow:** extend exact constant-store forwarding to nonconstant values, partial overlaps and safe loops;
   establish alias proofs before enabling mutable snapshot pointer inference.
3. **IR and SSA:** extend semantics/calling conventions, minimal phi placement and expression simplification;
   compare lifted execution with native fixtures at overflow, width, zero-register and flag boundaries.
4. **Language recovery:** stripped Itanium/MSVC vtables, class layouts, Objective-C method/class references,
   relative/authenticated pointers, DWARF/PDB integration and fixture-based malformed metadata validation.
5. **Decompilation:** expressions, conditions, loops, returns and typed variables over SSA; output must explicitly
   show semantic gaps and must not present unsupported paths as recovered source.
6. **Containers/workspaces:** safe archive indexing/extraction budgets, module-qualified names/addresses,
   dependencies, cross-module references and UI/MCP navigation; never execute installer scripts.
7. **CLI batch workflow:** first-class multi-architecture analysis reports with bounded function selection,
   per-command timeouts, recovery diagnostics and comparison summaries; avoid external orchestration for routine
   static/runtime retests. Keep candidate counts, weak signature proposals and recovered code distinct.
   - [x] Single-image guided reports through `rampage report` and the shared workflow registry, with bounded
     findings, evidence/confidence, explicit truncation and next-step tool calls.
   - [x] `rampage binary analyze` composes selected workflows and supervised function decompilations across supported
     declared architectures; slice failures, identities, warnings and output-limit outcomes are retained in
     bounded valid JSON. Text output includes workflow findings and failed previews, not just query completion.
   - [ ] Runtime comparison report composition and workflow-wide wall-clock/memory supervision. The current
     deadline bounds each supervised decompilation request; workflows retain their existing work/output budgets.
   - [x] Noun/verb command hierarchy with shared argument definitions and typed normalization; flat spellings
     remain hidden compatibility commands. Nested pack ordering and cross-level image dependencies are validated.
8. **Debugger integration:** plan an LLDB-first read-only bridge after static acceptance, with explicit session/
   stop identities, module/thread navigation, quiescent capture manifests and agent/UI queries. Attach, resume,
   breakpoint insertion and target writes require separately reviewed controls; no automatic host or plugin launch.
   - [x] In-session `rampage-query` foundation for session/module/thread, fresh-register and raw-memory queries,
     with bounded JSON, stale stop tokens, exact known permissions and honest endian/stop evidence. Controlled
     owned-fixture acceptance covers Apple LLDB; no command passthrough, attach/resume/evaluation/writes/listener.
    - [x] Explicit local Unix transport, typed API/CLI/MCP and local-only UI window, with reviewed cancellation safety;
      EOF before querying, bounded framing/I/O, stale tokens and structured errors retained. Endpoint paths remain
      for operator cleanup; no automatic attach/resume/expression/target-write controls.
     - [x] Stop-pinned UUID-qualified image/load address observations via bounded section/ancestor evidence,
       surfaced in typed queries and a manual local UI template. No basename/slide fallback or automatic navigation.
     - [x] Explicit local navigation to an already-open matching static Mach-O's file address, with typed
       request/result/workspace bindings, UUID/variant/width/endian/backing/permission gates and input invalidation.
       Original mapping-descriptor identity guards observable source changes; debugger painting avoids mapped reads.
       This is neither atomic source reading nor equal-byte/current-stop/flow/layout proof.
     - [ ] Broader static-format navigation and SDK/platform acceptance.
      Query observations remain non-atomic. A disposable-host experiment subsequently exercised live read-only
      queries; broader external-plugin runtime acceptance remains open (see the active investigation queue above).

Committed-foundation validation includes full debug/release suites, warnings-denied Clippy, UI snapshots,
CLI/API/MCP regressions, malformed-input bounds, native/compiled fixtures, exporter tests, the opt-in live
capture test, debugger-cleanup regressions, Ruff/ty and fresh-context reviews. The earlier full-debug timeout
was the one-time vendored C++ build; subsequent debug/release workspace suites passed.

Checklist from the second code-review round. Most of it is in `crates/rampage-arch/src/aarch32/flow.rs`.
After each group: `cargo fmt`, `cargo clippy --all-targets`, `cargo test`, and the AArch32 golden tests
(`tests/data/{a32,t16,t32}_golden.tsv`; current rates A32 97.95%, T16 100%, T32 97.49%). Add cases to
`crates/rampage-arch/tests/flow.rs` with encodings checked against llvm-mc.

## Prerequisites

- [x] `Target::data_big_endian`, set by `Binary::target()` and read by literal-pool tracking.
- [x] PowerPC64 `addis` starts an address; the TOC-pair regression reports only the completed sum.

## AArch32 flow and tracking bugs

- [x] **Thumb high registers.** T16 encodings split the destination into `D:Rd`, `DN:Rdn` or `DM:Rdm`, but `kind()`
   and `track()` read only the low 3 bits. So `mov pc, lr` (f746), `mov pc, r0` (8746) and `add pc, r3` (9f44)
   are classified as `Next`, and `mov r8, r1` (8846) and `add r8, pc` (f844) track the wrong register.
   Fix: one helper that reads a register operand by name (`<Rd>`, `<Rdn>`, `<Rdm>`, `<Rm>`, ...) through
   `Encoding::operand_bits`, which concatenates all of the operand's fields; fall back to the plain field.
- [x] **PC writers.** `subs pc, lr, #4` (A32 04f05ee2, T32 def3048f) is `Next`: SUBS is missing from the PC-writer
   list, and the `SUBS_PC_LR` name prefix never matches (the T32 encoding is `SUBS_PC_T5_AS`). It should be a
   return, as `movs pc, lr` is. Shifted moves such as `lsl pc, r0, #2` (A32 00f1a0e1) are also `Next`. Accept the
   S-suffixed and shift mnemonics (LSL, LSR, ASR, ROR, RRX) when the destination is PC.
- [x] **Unclear destinations.** Registers written as RdLo/RdHi (UMULL), Rt (MRC, VMOV to core registers, loads) and
   STREX's status Rd are never cleared. Clear every destination operand, treating Rt/Rt2 as written except for
   stores, MCR and PUSH. Over-clearing only loses tracking.
- [x] **LDRD.** T32 LDRD's Rt2 is not cleared (covered by 3). A32 literal LDRD doesn't clear Rt, or Rt+1.
- [x] **16-bit LDM/STM writeback.** T16 LDM/STM have no W field but write back the base (LDM unless the base is in the
   list). Clear Rn for them.
- [x] **Offset scaling.** T32 LDRD/STRD/LDREX imm8 is a word offset (x4). The T16 imm5 forms are not tracked at all:
   LDR/STR imm5 scales x4, LDRH/STRH x2, LDRB/STRB x1; SP-relative imm8 x4.
- [x] **ADD (register).** It ignores the shift (`add r0, pc, r1, lsl #2`, 01018fe0), and RRX encodings. Track only
   unshifted forms. It also reports data references for conditional ADDs (`addeq r0, pc, r1`, 01008f00); report
   only unconditional ones.
- [x] **Literal pools.** Read in instruction byte order, which is wrong for BE8 images (code little-endian, data
   big-endian). Read them with `Target::data_big_endian`.
- [x] **Over-strong classifications.**
   - `ldm r0, {r1, pc}` (A32 028090e8, T32 90e80280) is a `Return`; only a POP or SP-based LDM should be. Others
     are `IndirectJump`.
   - `ldr pc, [pc, #x]` should jump to the literal's value when the pool is readable (keeping the Thumb bit's
     meaning: even in A32, odd in T32), not be an `IndirectJump`.
   - Thumb `blx label` switches to A32, but `Target::thumb` is a fixed set of ranges, so the target decodes in the
      wrong mode. Decoders now report mode hints; discovery merges them between rounds and records instruction
      modes for listing/graph decoding, including when the target was already seeded.
- [x] **Overflow.** `address + size` overflows (and panics in debug builds) near `u64::MAX`: flow.rs `flow()`,
    `track()`'s `pc`, `decode()`'s `next`, and cs.rs:241. Use `wrapping_add`.

## AArch32 rendering bugs

- [x] The `hint` alias renders as `clrbhb`.
- [x] VCVT_is shows u32 where it should be s32.
- [x] VCVT_xs prints the wrong types and fbits.

## DRY and refactors (behaviour must not change)

- [x] One mnemonic helper instead of three: `aarch32/mod.rs` `mnemonic`, mrs `root_mnemonic`, operands
  `Context::mnemonic`.
- [x] Remove the `field()` wrapper in flow.rs; call `Decoded::field`.
- [x] One destination-register helper in flow.rs (from bug 1), used by `kind()` and `track()`.
- [x] The LDM/POP mnemonic list appears twice in flow.rs; make it one constant or function.
- [x] A `wide_immediate` helper for the MOVW/MOVT imm4:i:imm3:imm8 (T32) and imm4:imm12 (A32) values.
- [x] `is_non_canonical` should reuse `operands::canonical_rotation`.
- [x] One `read_u32(bytes, offset, big_endian)` for the A32 word, literal pools and similar reads.
- [x] Share the kind-to-`Flow` mapping (conditions applied) between flow.rs and cs.rs.
- [x] An `or()` helper in track.rs for the MIPS/PowerPC/SPARC `ori`/`or` arms.
- [x] Move `sign_extend`, `ones` and `Field::mask` into mrs; `a64/helpers.rs` and `aarch32/spec_types.rs` duplicate
  them. Keep A64 armgen output byte-identical (hash 9814543386b94709d07f666db386d8bdede961c3 over
  scratchpad `words.txt`). The original scratchpad is unavailable; a 500,000-word deterministic rendering sweep
  is byte-identical to HEAD (SHA-1 `e5ac54acb63f7e70a31d5a9bb2965f48b984ea75`), and generated tables are unchanged.
- [x] Consolidate the `.w` qualifier handling and the chain of text `.replace` passes in `aarch32::format`.

## Smaller, outside rampage-arch (optional)

- [x] The UI assistant (`rampage-ui/src/assistant.rs`) recognises effects by tool-name strings ("rename",
  "set_comment", "show_address"); have the tool registry say which tools change annotations or move the view.
- [x] `rampage-api/src/graph.rs` recomputes block ends from line bytes; it could use the analysis `Block.end`.
- [x] The `binary_info` tool serializes its result twice.
- [x] The graph view computes row widths twice.

## Verification

- Debug/release workspace tests, including unchanged UI snapshots; Clippy with warnings denied; format/diff checks.
- The ignored Chrome large-binary UI test passes (debug build; subsequent frames 5–9 ms).
- Debug and release decoder suites, llvm-mc-checked regressions, and the A32/T16/T32 golden corpora.
- Interworking tested in both directions, with one/four threads and pre-existing/new call-target seeds.
- Review regressions cover stale mode hints, conditional fall-through calls, BLX-to-next, formatting and boundaries.
- Mode changes rebuild discovery from original seeds; contradictory mode cycles terminate without phantom functions.
- SP implicit writes, split DM operands, comparison/vector source preservation and graph layer centering are covered.
- Known seeds inherit incoming modes; cycle handling preserves downstream modes; invalid bytes retain decode mode.
- Invalid instructions advance IT slots; backward/interior interworking cycles have bounded termination regressions.
- Every Thumb halfword tested at the top of the address space in both byte orders; all 32 VCVT fraction widths.
- Literal pools tested with all code/data byte-order combinations and truncated reads.
- A64 rendering compared against the pre-change code on 500,000 deterministic words (identical SHA-1 above).
- Release builds report a local `rust-objcopy`/`libLLVM.dylib` stripping warning; the tests still pass.
